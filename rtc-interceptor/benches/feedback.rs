//! Feedback cost: NACK generation and handling, receiver reports, and TWCC feedback.
//!
//! Run with `cargo bench --package rtc-interceptor --bench feedback`.
//!
//! Each benchmark drives a public interceptor through its sans-IO `Protocol` methods, as a
//! connection does, so the numbers include the packet and report construction around the
//! receipt-bitmap and arrival-map scans rather than the scans alone:
//!
//! * `Feedback/NackGenerator/<loss>/<window>/<streams>` is one NACK round: `handle_timeout`
//!   and draining the NACKs it queues, across many remote streams whose receive logs are in a
//!   steady state under a loss pattern (1% or 10% random loss, or a 200-packet burst). The
//!   round scans each log's window for missing packets and builds a NACK per stream.
//! * `Feedback/NackResponder/<pattern>` handles one RTCP NACK of eight pairs against a full
//!   1,024-packet send history and drains the retransmissions it queues. `dense` sets all 16
//!   bitmask bits (136 packets), `sparse` two (24 packets), `dense-rtx` rewrites each packet
//!   as RFC 4588 RTX, and `absent` names only packets the history no longer holds, which
//!   leaves the pair iteration and history lookups without the cost of retransmitting.
//! * `Feedback/ReceiverReport/<interval>/<streams>` is one report interval: a second of RTP at
//!   a realistic rate on every stream, then the report round. Reports go out about once a
//!   second, so their loss count is paid once per interval rather than per packet; this
//!   measures it next to the per-packet work it accompanies. `video-outage` puts a
//!   10,000-packet gap in each interval, more than the 8,192 packets of receipt history, where
//!   clearing and counting the gap is most of the work.
//! * `Feedback/TwccReceiver/<pattern>` is one 100 ms feedback interval: recording each
//!   packet's transport-wide sequence number and arrival time, then building the feedback.
//!   `steady` has 1% loss and light reordering; `gap-1000` and `gap-8000` also lose that many
//!   consecutive transport sequence numbers in every interval, the long runs of not-received
//!   entries the arrival-time map fills, scans and trims.
//!
//! Deliberately not measured: marshalling (no packet reaches the wire), the rest of an
//! interceptor chain, and the construction of the input packets, which happens outside the
//! timed region. The NACK generator's per-packet bookkeeping is also left out: its benchmark
//! times only the timeout that reads the receive logs.
//!
//! Every case is checked before it is timed — each stream gets a NACK (for the burst, exactly
//! its 200 packets), the responder retransmits exactly the requested packets it still holds,
//! each stream gets a receiver report that counts the loss, and every TWCC interval produces
//! feedback — so a benchmark cannot quietly measure a path that does nothing.

use bytes::Bytes;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rtc_interceptor::{
    AttributedPacket, Interceptor, NackGeneratorBuilder, NackGeneratorInterceptor,
    NackResponderBuilder, NackResponderInterceptor, Packet, RTCPFeedback, RTPHeaderExtension,
    ReceiverReportBuilder, ReceiverReportInterceptor, StreamInfo, TaggedPacket,
    TwccReceiverBuilder, TwccReceiverInterceptor,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::hint::black_box;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_EXTENSION_ID: u8 = 5;

/// A deterministic pseudo-random sequence, so every run and both sides of a comparison see the
/// same losses.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// True with probability `percent`/100.
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn stream_info(ssrc: u32, nack: bool, twcc: bool) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: if nack {
            vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }]
        } else {
            vec![]
        },
        rtp_header_extensions: if twcc {
            vec![RTPHeaderExtension {
                uri: TRANSPORT_CC_URI.to_string(),
                id: TWCC_EXTENSION_ID as u16,
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

fn rtp(now: Instant, ssrc: u32, seq: u16, timestamp: u32, payload: Bytes) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                ssrc,
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            payload,
        })),
    }
}

fn rtcp_packets(packet: &TaggedPacket) -> &[Box<dyn rtcp::Packet>] {
    match &packet.message.packet {
        Packet::Rtcp(packets) => packets,
        _ => &[],
    }
}

// =============================================================================
// NACK generator
// =============================================================================

/// A generator whose `streams` receive logs each hold `4 × window` packets, received except
/// where `lost` says otherwise.
fn nack_generator(
    window: u16,
    streams: u32,
    lost: &mut dyn FnMut(u16) -> bool,
    t0: Instant,
) -> NackGeneratorInterceptor {
    let mut generator = NackGeneratorBuilder::new()
        .with_size(window)
        .with_interval(Duration::from_millis(100))
        .build();
    for ssrc in 1..=streams {
        generator.bind_remote_stream(&stream_info(ssrc, true, false));
    }
    let total = 4 * window as u32;
    for ssrc in 1..=streams {
        for n in 0..total {
            // Start below the wrap so the logs cross it.
            let seq = (65_000 + n) as u16;
            // The newest packet always arrives, so the log's end is the same for every pattern.
            if n + 1 < total && lost(n as u16) {
                continue;
            }
            generator
                .handle_read(rtp(t0, ssrc, seq, n * 3_000, Bytes::new()))
                .unwrap();
            while generator.poll_read().is_some() {}
        }
    }
    generator
}

/// Runs one NACK round at `now` and returns the number of NACK packets and lost sequence
/// numbers it asked for.
fn nack_round(generator: &mut NackGeneratorInterceptor, now: Instant) -> (usize, usize) {
    generator.handle_timeout(now).unwrap();
    let mut packets = 0;
    let mut asked = 0;
    while let Some(packet) = generator.poll_write() {
        for rtcp in rtcp_packets(&packet) {
            if let Some(nack) = rtcp.as_any().downcast_ref::<TransportLayerNack>() {
                packets += 1;
                asked += nack
                    .nacks
                    .iter()
                    .map(|pair| 1 + pair.lost_packets.count_ones() as usize)
                    .sum::<usize>();
            }
        }
    }
    (packets, asked)
}

fn bench_nack_generator(c: &mut Criterion) {
    let mut group = c.benchmark_group("Feedback/NackGenerator");
    let streams = 16;

    type Pattern = (&'static str, u16, fn(&mut XorShift, u16, u16) -> bool);
    let patterns: [Pattern; 4] = [
        ("loss-1pct", 512, |rng, _, _| rng.chance(1)),
        ("loss-10pct", 512, |rng, _, _| rng.chance(10)),
        // 200 consecutive packets lost in the middle of the last window.
        ("burst-200", 512, |_, n, window| {
            let last_window = 3 * window;
            (last_window + 150..last_window + 350).contains(&n)
        }),
        ("loss-1pct", 8192, |rng, _, _| rng.chance(1)),
    ];

    for (name, window, pattern) in patterns {
        let t0 = Instant::now();
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        let mut generator =
            nack_generator(window, streams, &mut |n| pattern(&mut rng, n, window), t0);

        // Every stream is asked about, for the losses its window still holds.
        let interval = Duration::from_millis(100);
        let mut now = t0 + interval;
        let (packets, asked) = nack_round(&mut generator, now);
        assert_eq!(
            packets, streams as usize,
            "{name}/{window}: one NACK per stream"
        );
        assert!(
            asked >= streams as usize,
            "{name}/{window}: every stream has losses to report"
        );
        if name == "burst-200" {
            assert_eq!(
                asked,
                200 * streams as usize,
                "the whole burst, nothing else"
            );
        }
        // The round leaves the logs as it found them, so every iteration repeats it.
        now += interval;
        assert_eq!(nack_round(&mut generator, now), (packets, asked));

        group.bench_function(format!("{name}/{window}/{streams}-streams"), |b| {
            b.iter(|| {
                now += interval;
                generator.handle_timeout(now).unwrap();
                while let Some(packet) = generator.poll_write() {
                    black_box(packet);
                }
            });
        });
    }

    group.finish();
}

// =============================================================================
// NACK responder
// =============================================================================

const RESPONDER_SSRC: u32 = 0x5EED;
const HISTORY: u16 = 1024;
/// The newest packet in the history; the history runs across the 16-bit wrap.
const NEWEST: u16 = 500;

fn nack_responder(rtx: bool, t0: Instant) -> NackResponderInterceptor {
    let mut responder = NackResponderBuilder::new().with_size(HISTORY).build();
    let mut info = stream_info(RESPONDER_SSRC, true, false);
    if rtx {
        info.ssrc_rtx = Some(RESPONDER_SSRC + 1);
        info.payload_type_rtx = Some(97);
    }
    responder.bind_local_stream(&info);
    let payload = Bytes::from(vec![0xAB; 1_200]);
    for n in 0..HISTORY {
        let seq = NEWEST.wrapping_sub(HISTORY - 1).wrapping_add(n);
        responder
            .handle_write(rtp(
                t0,
                RESPONDER_SSRC,
                seq,
                n as u32 * 3_000,
                payload.clone(),
            ))
            .unwrap();
        while responder.poll_write().is_some() {}
    }
    responder
}

fn nack_request(t0: Instant, nacks: &[NackPair]) -> TaggedPacket {
    TaggedPacket {
        now: t0,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: RESPONDER_SSRC,
            nacks: nacks.to_vec(),
        })])),
    }
}

/// Hands `request` to the responder and returns how many retransmissions it queued.
fn respond(responder: &mut NackResponderInterceptor, request: TaggedPacket) -> usize {
    responder.handle_read(request).unwrap();
    while let Some(packet) = responder.poll_read() {
        black_box(packet);
    }
    let mut sent = 0;
    while let Some(packet) = responder.poll_write() {
        black_box(packet);
        sent += 1;
    }
    sent
}

fn bench_nack_responder(c: &mut Criterion) {
    let mut group = c.benchmark_group("Feedback/NackResponder");

    // Eight pairs spaced so their packets do not overlap, ending just below the newest packet
    // and so straddling the 16-bit wrap.
    let pairs = |mask: u16, behind: u16| -> Vec<NackPair> {
        (0..8u16)
            .map(|k| NackPair {
                packet_id: NEWEST.wrapping_sub(behind).wrapping_add(17 * k),
                lost_packets: mask,
            })
            .collect()
    };
    let cases = [
        ("dense", false, pairs(0xFFFF, 400), 8 * 17),
        ("sparse", false, pairs(0x8001, 400), 8 * 3),
        ("dense-rtx", true, pairs(0xFFFF, 400), 8 * 17),
        // Named packets are older than the whole history.
        ("absent", false, pairs(0xFFFF, 3 * HISTORY), 0),
    ];

    for (name, rtx, nacks, expected) in cases {
        let t0 = Instant::now();
        let mut responder = nack_responder(rtx, t0);
        assert_eq!(
            respond(&mut responder, nack_request(t0, &nacks)),
            expected,
            "{name}: retransmissions"
        );

        group.bench_function(name, |b| {
            b.iter_batched(
                || nack_request(t0, &nacks),
                |request| respond(&mut responder, request),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// Receiver reports
// =============================================================================

/// Generates each second of RTP for a set of streams: `rate` packets per stream, 1% lost at
/// random, and optionally a gap of `outage` sequence numbers halfway through.
struct ReportTraffic {
    streams: u32,
    rate: u32,
    outage: u16,
    rng: XorShift,
    next_seq: Vec<u16>,
    interval_start: Instant,
}

impl ReportTraffic {
    fn new(streams: u32, rate: u32, outage: u16, t0: Instant) -> Self {
        Self {
            streams,
            rate,
            outage,
            rng: XorShift(0x2545_f491_4f6c_dd1d),
            // Spread the streams' sequence numbers, some just below the wrap.
            next_seq: (0..streams)
                .map(|s| 65_500u16.wrapping_add((s as u16).wrapping_mul(4_099)))
                .collect(),
            interval_start: t0,
        }
    }

    /// One second of packets, interleaved across streams, and the instant the report is due.
    fn interval(&mut self) -> (Vec<TaggedPacket>, Instant) {
        let mut packets = Vec::with_capacity((self.streams * self.rate) as usize);
        let spacing = Duration::from_secs(1) / self.rate;
        for n in 0..self.rate {
            let now = self.interval_start + spacing * n;
            for stream in 0..self.streams {
                let seq = &mut self.next_seq[stream as usize];
                if n == self.rate / 2 {
                    *seq = seq.wrapping_add(self.outage);
                }
                let this = *seq;
                *seq = seq.wrapping_add(1);
                if self.rng.chance(1) {
                    continue;
                }
                let timestamp = n * (90_000 / self.rate);
                packets.push(rtp(now, stream + 1, this, timestamp, Bytes::new()));
            }
        }
        self.interval_start += Duration::from_secs(1);
        (packets, self.interval_start)
    }
}

/// Feeds one interval's packets and runs the report round; returns the number of reports.
fn report_interval(
    reporter: &mut ReceiverReportInterceptor,
    (packets, report_at): (Vec<TaggedPacket>, Instant),
) -> usize {
    for packet in packets {
        reporter.handle_read(packet).unwrap();
        while let Some(packet) = reporter.poll_read() {
            black_box(packet);
        }
    }
    reporter.handle_timeout(report_at).unwrap();
    let mut reports = 0;
    while let Some(packet) = reporter.poll_write() {
        reports += rtcp_packets(&packet).len();
        black_box(packet);
    }
    reports
}

fn bench_receiver_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("Feedback/ReceiverReport");

    let cases = [
        ("audio-50pps", 64, 50, 0),
        ("video-1000pps", 16, 1_000, 0),
        ("video-outage", 16, 1_000, 10_000),
    ];

    for (name, streams, rate, outage) in cases {
        let t0 = Instant::now();
        let mut reporter = ReceiverReportBuilder::new().build();
        for ssrc in 1..=streams {
            reporter.bind_remote_stream(&stream_info(ssrc, false, false));
        }
        let mut traffic = ReportTraffic::new(streams, rate, outage, t0);

        // Every interval ends in one report per stream, including the loss the pattern caused.
        for _ in 0..3 {
            let (packets, report_at) = traffic.interval();
            for packet in packets {
                reporter.handle_read(packet).unwrap();
                while reporter.poll_read().is_some() {}
            }
            reporter.handle_timeout(report_at).unwrap();
            let mut reports = 0;
            let mut lost = 0;
            while let Some(packet) = reporter.poll_write() {
                for rtcp in rtcp_packets(&packet) {
                    let rr = rtcp
                        .as_any()
                        .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                        .expect("a receiver report");
                    reports += 1;
                    lost = lost.max(rr.reports[0].total_lost);
                }
            }
            assert_eq!(reports, streams as usize, "{name}: one report per stream");
            assert!(lost > 0, "{name}: the loss is counted");
        }

        group.bench_function(format!("{name}/{streams}-streams"), |b| {
            b.iter_batched(
                || traffic.interval(),
                |interval| report_interval(&mut reporter, interval),
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// TWCC receiver
// =============================================================================

const TWCC_SSRC: u32 = 0x7CC;

/// Generates each 100 ms feedback interval of transport-wide sequence numbers: 100 packets a
/// millisecond apart, 1% lost, 2% swapped with their successor, and optionally a run of `gap`
/// lost sequence numbers halfway through.
struct TwccTraffic {
    gap: u16,
    rng: XorShift,
    transport_seq: u16,
    rtp_seq: u16,
    interval_start: Instant,
}

impl TwccTraffic {
    fn packet(&mut self, now: Instant, transport_seq: u16) -> TaggedPacket {
        let seq = self.rtp_seq;
        self.rtp_seq = seq.wrapping_add(1);
        let mut packet = rtp(now, TWCC_SSRC, seq, seq as u32 * 900, Bytes::new());
        let extension = rtp::extension::transport_cc_extension::TransportCcExtension {
            transport_sequence: transport_seq,
        }
        .marshal()
        .unwrap()
        .freeze();
        if let Packet::Rtp(rtp) = &mut packet.message.packet {
            rtp.header
                .set_extension(TWCC_EXTENSION_ID, extension)
                .unwrap();
        }
        packet
    }

    /// One interval's packets and the instant its feedback is due.
    fn interval(&mut self) -> (Vec<TaggedPacket>, Instant) {
        let mut packets: Vec<TaggedPacket> = Vec::with_capacity(100);
        for n in 0..100u32 {
            if n == 50 {
                self.transport_seq = self.transport_seq.wrapping_add(self.gap);
            }
            let transport_seq = self.transport_seq;
            self.transport_seq = transport_seq.wrapping_add(1);
            if self.rng.chance(1) {
                continue;
            }
            let now = self.interval_start + Duration::from_millis(n as u64);
            let packet = self.packet(now, transport_seq);
            packets.push(packet);
        }
        // Reorder: swap some packets with their successor, keeping arrival instants in order.
        for i in 0..packets.len() - 1 {
            if self.rng.chance(2) {
                let (earlier, later) = packets.split_at_mut(i + 1);
                std::mem::swap(&mut earlier[i].message.packet, &mut later[0].message.packet);
            }
        }
        self.interval_start += Duration::from_millis(100);
        (packets, self.interval_start)
    }
}

/// Feeds one interval and builds its feedback; returns the number of feedback packets.
fn twcc_interval(
    receiver: &mut TwccReceiverInterceptor,
    (packets, feedback_at): (Vec<TaggedPacket>, Instant),
) -> usize {
    for packet in packets {
        receiver.handle_read(packet).unwrap();
        while let Some(packet) = receiver.poll_read() {
            black_box(packet);
        }
    }
    receiver.handle_timeout(feedback_at).unwrap();
    let mut feedback = 0;
    while let Some(packet) = receiver.poll_write() {
        feedback += rtcp_packets(&packet).len();
        black_box(packet);
    }
    feedback
}

fn bench_twcc_receiver(c: &mut Criterion) {
    let mut group = c.benchmark_group("Feedback/TwccReceiver");

    for (name, gap) in [("steady", 0), ("gap-1000", 1_000), ("gap-8000", 8_000)] {
        let t0 = Instant::now();
        let mut receiver = TwccReceiverBuilder::new()
            .with_interval(Duration::from_millis(100))
            .build();
        receiver.bind_remote_stream(&stream_info(TWCC_SSRC, false, true));
        let mut traffic = TwccTraffic {
            gap,
            rng: XorShift(0x3c6e_f372_fe94_f82b),
            transport_seq: 65_000,
            rtp_seq: 0,
            interval_start: t0,
        };

        // Past the 500 ms history window, so old packets are being trimmed, and every
        // interval produces feedback.
        for _ in 0..10 {
            let interval = traffic.interval();
            assert!(
                twcc_interval(&mut receiver, interval) > 0,
                "{name}: feedback"
            );
        }

        group.bench_function(name, |b| {
            b.iter_batched(
                || traffic.interval(),
                |interval| twcc_interval(&mut receiver, interval),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_nack_generator,
    bench_nack_responder,
    bench_receiver_report,
    bench_twcc_receiver
);
criterion_main!(benches);
