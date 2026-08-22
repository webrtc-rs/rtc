//! RFC 8888 congestion control feedback, in a chain.
//!
//! The report this produces is the input a remote sender's congestion control runs on, so what
//! matters is that it says what actually happened: which packets arrived, which did not, and how
//! long before the report each one did. The reports are also round-tripped through the wire codec
//! from PRE-01, since a report that cannot be encoded and decoded is worth nothing.

use rtc_interceptor::{
    AttributedPacket, Interceptor, Packet, Registry, Rfc8888Builder, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::time::{Duration, Instant};

const SSRC: u32 = 1000;
const SENDER_SSRC: u32 = 7;
const INTERVAL: Duration = Duration::from_millis(100);

struct Harness {
    chain: Box<dyn Interceptor>,
    epoch: Instant,
}

impl Harness {
    fn new() -> Self {
        let chain = Registry::new()
            .with(
                Slot::Rfc8888,
                Rfc8888Builder::new()
                    .with_interval(INTERVAL)
                    .with_sender_ssrc(SENDER_SSRC)
                    .build(),
            )
            .build();

        Self {
            chain: Box::new(chain),
            epoch: Instant::now(),
        }
    }

    fn bind(&mut self, ssrc: u32) {
        self.chain.bind_remote_stream(&StreamInfo {
            ssrc,
            clock_rate: 90_000,
            ..Default::default()
        });
    }

    fn arrive(&mut self, at: Duration, ssrc: u32, sequence_number: u16) {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![1, 2, 3].into(),
                })),
            })
            .expect("handle_read");
    }

    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
    }

    /// Drain whatever feedback the interceptor has produced.
    fn drain_reports(&mut self) -> Vec<CcFeedbackReport> {
        let mut reports = Vec::new();
        while let Some(packet) = self.chain.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
                for rtcp_packet in rtcp_packets {
                    if let Some(report) = rtcp_packet.as_any().downcast_ref::<CcFeedbackReport>() {
                        reports.push(report.clone());
                    }
                }
            }
        }
        reports
    }

    fn next_timeout(&mut self) -> Option<Duration> {
        self.chain
            .poll_timeout()
            .map(|instant| instant.saturating_duration_since(self.epoch))
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

/// Which packets a report block says arrived.
fn received(report: &CcFeedbackReport, index: usize) -> Vec<bool> {
    report.report_blocks[index]
        .metric_blocks
        .iter()
        .map(|metric| metric.received)
        .collect()
}

// ---------------------------------------------------------------------------------------
// What the report says
// ---------------------------------------------------------------------------------------

#[test]
fn arrivals_are_reported_on_the_interval() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 101);
    assert!(
        harness.drain_reports().is_empty(),
        "arrival alone does not send feedback; the interval does"
    );

    harness.tick(ms(100));
    let reports = harness.drain_reports();
    assert_eq!(1, reports.len());
    assert_eq!(SENDER_SSRC, reports[0].sender_ssrc);
    assert_eq!(SSRC, reports[0].report_blocks[0].media_ssrc);
    assert_eq!(100, reports[0].report_blocks[0].begin_sequence);
    assert_eq!(vec![true, true], received(&reports[0], 0));
}

/// The whole point of the format: telling the sender which packets did *not* arrive.
#[test]
fn a_gap_is_reported_as_a_packet_that_did_not_arrive() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 102);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    assert_eq!(
        vec![true, false, true],
        received(&reports[0], 0),
        "101 never came"
    );
}

/// Arrival-time offsets are what congestion control actually reads: the spread between them is
/// the delay variation the path is imposing.
#[test]
fn arrival_time_offsets_reflect_when_each_packet_arrived() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    // Two packets, 50 ms apart, reported at 100 ms.
    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(50), SSRC, 101);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    let metrics = &reports[0].report_blocks[0].metric_blocks;

    // Units of 1/1024 s: 100 ms ≈ 102, 50 ms ≈ 51.
    assert!(
        (100..=104).contains(&metrics[0].arrival_time_offset),
        "the older packet is ~100 ms back, got {}",
        metrics[0].arrival_time_offset
    );
    assert!(
        (49..=53).contains(&metrics[1].arrival_time_offset),
        "the newer one ~50 ms, got {}",
        metrics[1].arrival_time_offset
    );
    assert!(
        metrics[0].arrival_time_offset > metrics[1].arrival_time_offset,
        "an older packet is further back than a newer one"
    );
}

#[test]
fn several_streams_each_get_a_report_block() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.bind(SSRC + 1);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(0), SSRC + 1, 500);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    assert_eq!(2, reports[0].report_blocks.len());
    assert_eq!(
        vec![SSRC, SSRC + 1],
        rtcp::packet::Packet::destination_ssrc(&reports[0]),
        "and every reported stream is a destination"
    );
}

#[test]
fn a_second_report_covers_only_what_arrived_since_the_first() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.tick(ms(100));
    assert_eq!(1, harness.drain_reports().len());

    harness.arrive(ms(110), SSRC, 101);
    harness.tick(ms(200));

    let reports = harness.drain_reports();
    assert_eq!(
        101, reports[0].report_blocks[0].begin_sequence,
        "100 was already reported; saying so again would claim it arrived twice"
    );
    assert_eq!(vec![true], received(&reports[0], 0));
}

// ---------------------------------------------------------------------------------------
// When nothing is reported
// ---------------------------------------------------------------------------------------

#[test]
fn nothing_is_reported_when_nothing_arrived() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.tick(ms(100));
    harness.tick(ms(200));

    assert!(harness.drain_reports().is_empty());
}

#[test]
fn packets_from_unbound_streams_are_not_reported() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), 9999, 1);
    harness.tick(ms(100));

    assert!(
        harness.drain_reports().is_empty(),
        "nothing bound has arrived, so there is nothing to feed back"
    );
}

#[test]
fn unbinding_stops_the_reports() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.arrive(ms(0), SSRC, 100);

    harness.chain.unbind_remote_stream(&StreamInfo {
        ssrc: SSRC,
        ..Default::default()
    });

    harness.tick(ms(100));
    assert!(harness.drain_reports().is_empty());
    assert_eq!(None, harness.next_timeout(), "and the timer is disarmed");
}

/// Delivery rule 3: idle means `None`, and an armed timeout advances rather than repeating.
#[test]
fn poll_timeout_is_none_until_something_arrives() {
    let mut harness = Harness::new();

    assert_eq!(None, harness.next_timeout(), "nothing bound");

    harness.bind(SSRC);
    assert_eq!(
        None,
        harness.next_timeout(),
        "bound, but no instant has been handed over yet"
    );

    harness.arrive(ms(0), SSRC, 100);
    assert_eq!(Some(INTERVAL), harness.next_timeout());

    harness.tick(ms(100));
    assert_eq!(
        Some(INTERVAL * 2),
        harness.next_timeout(),
        "advances rather than repeating a past instant"
    );
}

// ---------------------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------------------

/// A report that cannot survive the wire codec is worth nothing. This closes the loop with
/// PRE-01: build a report from observed arrivals, marshal it, and unmarshal it back.
#[test]
fn a_generated_report_round_trips_through_the_wire_codec() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 102);
    harness.arrive(ms(20), SSRC, 103);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    let report = &reports[0];

    let mut buffer = vec![0u8; report.marshal_size()];
    report.marshal_to(&mut buffer).expect("marshal");

    let mut raw = buffer.as_slice();
    let decoded = CcFeedbackReport::unmarshal(&mut raw).expect("decode");

    assert_eq!(report, &decoded, "byte round trip preserves the report");
    assert_eq!(vec![SSRC], rtcp::packet::Packet::destination_ssrc(&decoded));
    assert_eq!(
        vec![true, false, true, true],
        decoded.report_blocks[0]
            .metric_blocks
            .iter()
            .map(|metric| metric.received)
            .collect::<Vec<_>>(),
        "including the gap"
    );
}

/// A report is terminal — complete when built, with nothing below to transform it — so it comes
/// out of `poll_write` rather than traversing `inner`.
#[test]
fn reports_are_drained_from_the_write_side() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.arrive(ms(0), SSRC, 100);
    harness.tick(ms(100));

    assert_eq!(1, harness.drain_reports().len());
    assert!(
        harness.drain_reports().is_empty(),
        "drained once, not queued forever"
    );
}
