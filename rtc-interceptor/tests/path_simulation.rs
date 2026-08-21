//! The path simulator, and the four path shapes GCC will be validated against (CC-TEST-01).
//!
//! These tests are about the *harness*, not about any estimator. They prove the simulator is
//! deterministic and that each fixture actually produces the condition it is named for — because a
//! fixture that quietly fails to build a queue would let a delay-based estimator pass P7-05 without
//! ever detecting overuse.

mod path_simulator;

use path_simulator::{Arrival, Path, PathProfile, twcc_feedback_for};
use rtc_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor, PacerBuilder,
    Packet, PacketReport, RTCPFeedback, RTPHeaderExtension, Registry, StreamInfo, TaggedPacket,
    TwccSenderBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const SSRC: u32 = 0x00C0_FFEE;
/// 1.2 Mb/s offered: one 12 000-bit packet every 10 ms.
const OFFERED_BITS_PER_SECOND: f64 = 1_200_000.0;
const PACKET_BITS: f64 = 12_000.0;
const PAYLOAD_BYTES: usize = 1488;
/// How often the far end reports, matching a browser's TWCC cadence.
const FEEDBACK_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<PacketReport>>>,
}

impl Recorder {
    fn reports(&self) -> Vec<PacketReport> {
        self.seen.lock().unwrap().clone()
    }
}

impl BandwidthEstimator for Recorder {
    fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
        self.seen.lock().unwrap().extend_from_slice(reports);
    }
    fn target_bitrate(&self) -> f64 {
        OFFERED_BITS_PER_SECOND
    }
}

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3_000,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: vec![0xC0; PAYLOAD_BYTES].into(),
            ..Default::default()
        })),
    }
}

/// The transport-wide sequence number the TWCC sender wrote into a released packet.
fn twcc_sequence_number_of(packet: &TaggedPacket) -> Option<u16> {
    use shared::marshal::Unmarshal;
    let Packet::Rtp(ref rtp_packet) = packet.message.packet else {
        return None;
    };
    let mut extension = rtp_packet.header.get_extension(5)?;
    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut extension)
        .ok()
        .map(|extension| extension.transport_sequence)
}

/// Run one closed loop: send, pace, cross the path, report back, for `duration`.
///
/// Everything is driven by explicit instants, so the whole run is a pure function of its inputs.
fn run(profile: PathProfile, duration: Duration, widen_after: Option<Duration>) -> Vec<PacketReport> {
    let epoch = Instant::now();
    let estimator = Recorder::default();

    let mut chain = Registry::new()
        .with(CongestionControlBuilder::new(estimator.clone()).build())
        .with(TwccSenderBuilder::new().build())
        .with(
            PacerBuilder::new()
                .with_target_bitrate(OFFERED_BITS_PER_SECOND)
                .with_burst_bits(PACKET_BITS)
                .build(),
        )
        .build();
    chain.bind_local_stream(&stream());

    let mut path = Path::new(profile, epoch);
    if let Some(after) = widen_after {
        path = path.widening_after(after);
    }

    let mut sent = 0u16;
    let mut departures: std::collections::HashMap<u16, Instant> = std::collections::HashMap::new();
    let mut last_feedback = epoch;

    // One step per millisecond: fine enough to resolve a 10 ms release spacing.
    let steps = duration.as_millis() as u64;
    for step in 0..steps {
        let now = epoch + Duration::from_millis(step);

        // The application offers a packet every 10 ms.
        if step % 10 == 0 {
            chain.handle_write(rtp(now, sent)).expect("write");
            sent = sent.wrapping_add(1);
        }

        chain.handle_timeout(now).expect("timeout");

        // Whatever the pacer released goes onto the path.
        while let Some(packet) = chain.poll_write() {
            if let Some(twcc) = twcc_sequence_number_of(&packet) {
                departures.insert(twcc, packet.now);
                path.offer(now, twcc, PACKET_BITS);
            }
        }

        path.drain_to(now);

        // The far end reports periodically.
        if now.duration_since(last_feedback) >= FEEDBACK_INTERVAL {
            last_feedback = now;
            let arrivals = path.take_arrivals();
            if let Some(feedback) = twcc_feedback_for(now, epoch, SSRC, &arrivals) {
                chain.handle_read(feedback).expect("read");
                while chain.poll_read().is_some() {}
            }
        }
    }

    estimator.reports()
}

/// The property everything else rests on: the same schedule produces the same reports, exactly.
///
/// Without this a bitrate trajectory cannot be asserted — only that something eventually happened,
/// which is what pion's own tests are reduced to.
#[test]
fn the_same_schedule_produces_identical_reports() {
    let first = run(PathProfile::steady(), Duration::from_secs(2), None);
    let second = run(PathProfile::steady(), Duration::from_secs(2), None);

    assert!(!first.is_empty(), "the run reported nothing at all");
    assert_eq!(first.len(), second.len(), "different number of reports");

    // `Instant`s differ between runs (each starts at its own epoch), so compare everything else
    // plus the *relative* departure schedule, which is what an estimator actually reads.
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.twcc_sequence_number, b.twcc_sequence_number);
        assert_eq!(a.arrived, b.arrived);
        assert_eq!(a.size, b.size);
        assert_eq!(a.arrival, b.arrival, "quantised arrival times must match");
    }

    let relative = |reports: &[PacketReport]| -> Vec<Duration> {
        let base = reports[0].departure;
        reports
            .iter()
            .map(|report| report.departure.duration_since(base))
            .collect()
    };
    assert_eq!(
        relative(&first),
        relative(&second),
        "the release schedule must be reproducible to the packet"
    );
}

/// A steady path delivers everything, and delay does not grow.
#[test]
fn the_steady_fixture_neither_queues_nor_loses() {
    let reports = run(PathProfile::steady(), Duration::from_secs(2), None);

    let lost = reports.iter().filter(|report| !report.arrived).count();
    assert_eq!(0, lost, "a steady path must not lose packets");
    assert!(
        reports.len() > 50,
        "too few packets to say anything: {}",
        reports.len()
    );
}

/// The queue-building fixture must actually build a queue: **delay grows, nothing is lost**. If it
/// silently did not, a delay-based estimator would pass P7-05 without ever detecting overuse.
///
/// Asserted against the path directly rather than through the feedback. `PacketReport::arrival` is
/// an offset on the *receiver's* clock that each TWCC report restarts from its own reference time,
/// so arrivals from different reports are not on one timeline and comparing across them compares
/// nothing — a first attempt at this test did exactly that and passed on a path with ample
/// capacity.
#[test]
fn the_queue_building_fixture_grows_delay_without_loss() {
    let epoch = Instant::now();
    let mut path = Path::new(PathProfile::queue_building(), epoch);

    // Offer at 1.2 Mb/s into a 600 kb/s bottleneck: twice what it can drain.
    let mut offered = Vec::new();
    for step in 0..100u64 {
        let at = epoch + Duration::from_millis(step * 10);
        let accepted = path.offer(at, step as u16, PACKET_BITS);
        assert!(
            accepted,
            "this fixture must congest by delay, not by overflowing: packet {step} was refused"
        );
        offered.push(at);
        path.drain_to(at);
    }

    // Let everything drain, then look at when each packet actually turned up.
    path.drain_to(epoch + Duration::from_secs(30));
    let arrivals = path.take_arrivals();
    assert_eq!(100, arrivals.len(), "every packet is accounted for");
    assert!(
        arrivals.iter().all(|arrival| arrival.at.is_some()),
        "nothing may be lost: loss would let an estimator pass on the wrong signal"
    );

    // One-way delay is arrival minus offer, both on this endpoint's clock, so this is a real
    // duration. On a bottleneck slower than the offered rate it must climb.
    let delay_of = |index: usize| -> Duration {
        arrivals[index]
            .at
            .expect("arrived")
            .duration_since(offered[index])
    };

    let first = delay_of(0);
    let last = delay_of(99);
    assert!(
        last > first * 5,
        "queueing delay must grow as the bottleneck falls behind: {first:?} → {last:?}"
    );
}

/// The lossy fixture loses packets **without** building a queue — the wireless shape, and what D4's
/// divergence from pion is tested against.
#[test]
fn the_lossy_fixture_loses_without_queueing() {
    let reports = run(
        PathProfile::lossy_without_queueing(),
        Duration::from_secs(2),
        None,
    );

    let lost = reports.iter().filter(|report| !report.arrived).count();
    assert!(
        lost > 0,
        "the lossy fixture lost nothing, so a loss-based estimator would have no signal"
    );

    // One in twenty, so roughly 5% — assert the order of magnitude, not the exact count.
    let loss_fraction = lost as f64 / reports.len() as f64;
    assert!(
        (0.02..0.10).contains(&loss_fraction),
        "loss should be about one in twenty, got {loss_fraction:.3}"
    );
}

/// The recovering fixture starts congested and then widens, so an estimator has something to climb
/// back to rather than staying where the congestion left it.
///
/// Against the path directly, for the same reason as the queue-building fixture: per-report arrival
/// offsets are not on one timeline. A first attempt compared them and passed with the widening
/// removed entirely.
#[test]
fn the_recovering_fixture_widens() {
    let epoch = Instant::now();
    let widen_after = Duration::from_secs(2);
    let mut path = Path::new(PathProfile::recovering(), epoch).widening_after(widen_after);

    let mut offered = Vec::new();
    for step in 0..400u64 {
        let at = epoch + Duration::from_millis(step * 10);
        path.offer(at, step as u16, PACKET_BITS);
        offered.push(at);
        path.drain_to(at);
    }
    path.drain_to(epoch + Duration::from_secs(60));

    let arrivals = path.take_arrivals();
    let delay_at = |index: usize| -> Option<Duration> {
        arrivals
            .iter()
            .find(|arrival| usize::from(arrival.twcc_sequence_number) == index)
            .and_then(|arrival| arrival.at)
            .map(|at| at.duration_since(offered[index]))
    };

    // Just before the path widens, the backlog is at its worst.
    let worst = delay_at(199).expect("packet 199 arrived");
    // Well after, the bottleneck drains faster than packets are offered, so the backlog is gone.
    let recovered = delay_at(399).expect("packet 399 arrived");

    assert!(
        worst > Duration::from_millis(500),
        "the first phase must actually congest, or there is nothing to recover from: {worst:?}"
    );
    assert!(
        recovered < worst / 2,
        "once the path widens the backlog must drain: {worst:?} → {recovered:?}"
    );
}

/// The simulator itself: a full queue refuses, rather than growing without bound.
#[test]
fn a_full_bottleneck_queue_refuses_packets() {
    let epoch = Instant::now();
    let mut path = Path::new(
        PathProfile {
            propagation: Duration::from_millis(10),
            capacity_bits_per_second: 100_000.0,
            queue_capacity_bits: 24_000.0,
            drop_one_in: None,
        },
        epoch,
    );

    assert!(path.offer(epoch, 0, PACKET_BITS), "first fits");
    assert!(path.offer(epoch, 1, PACKET_BITS), "second fits");
    assert!(
        !path.offer(epoch, 2, PACKET_BITS),
        "a third must be refused: the queue holds two packets' worth"
    );

    let arrivals: Vec<Arrival> = path.take_arrivals();
    assert_eq!(
        vec![Arrival {
            twcc_sequence_number: 2,
            at: None
        }],
        arrivals,
        "the refused packet is reported lost, which is what the far end would observe"
    );
}

// ---------------------------------------------------------------------------------------
// P7-04 — the delay trend, against the fixtures
// ---------------------------------------------------------------------------------------

/// The delay trend must separate the two fixtures: flat on a steady path, clearly positive on a
/// queueing one. Everything P7-05 and P7-06 do rests on that separation being real.
///
/// Note what this does **not** cover: the fixture offers one packet every 10 ms, well outside the
/// 5 ms burst interval, so every packet is its own group and the accumulator's grouping is a no-op
/// here. Widening or disabling the burst interval leaves this test green. Grouping is pinned by
/// `gcc::arrival_group`'s own tests instead, against hand-built bursts.
#[test]
fn the_delay_trend_separates_a_steady_path_from_a_queueing_one() {
    use rtc_interceptor::SlopeEstimator;

    let trend_over = |profile: PathProfile| -> f64 {
        let epoch = Instant::now();
        let mut path = Path::new(profile, epoch);
        let mut slope = SlopeEstimator::new();
        let mut offered = Vec::new();

        for step in 0..150u64 {
            let at = epoch + Duration::from_millis(step * 10);
            path.offer(at, step as u16, PACKET_BITS);
            offered.push(at);
            path.drain_to(at);
        }
        path.drain_to(epoch + Duration::from_secs(60));

        for arrival in path.take_arrivals() {
            let Some(at) = arrival.at else { continue };
            let index = usize::from(arrival.twcc_sequence_number);
            slope.accumulate(&PacketReport {
                ssrc: SSRC,
                id: index as u64,
                rtp_sequence_number: arrival.twcc_sequence_number,
                is_twcc: true,
                twcc_sequence_number: arrival.twcc_sequence_number,
                size: (PACKET_BITS / 8.0) as usize,
                arrived: true,
                departure: offered[index],
                // The far end's clock: an offset from the run's start.
                arrival: Some(at.duration_since(epoch)),
                ecn: rtcp::transport_feedbacks::cc_feedback_report::Ecn::default(),
            });
        }
        slope.flush();
        slope.estimate_ms()
    };

    let steady = trend_over(PathProfile::steady());
    let queueing = trend_over(PathProfile::queue_building());

    assert!(
        steady.abs() < 1.0,
        "a steady path must read flat, got {steady}"
    );
    assert!(
        queueing > 5.0,
        "a queue building must read clearly positive, got {queueing}"
    );
    assert!(
        queueing > steady + 5.0,
        "the two fixtures must be separable: steady {steady}, queueing {queueing}"
    );
}
