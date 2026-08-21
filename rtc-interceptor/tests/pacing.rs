//! Pacing, asserted as a release *schedule*.
//!
//! The budget is a pure function of the instants handed in, so the schedule is reproducible: a
//! test can say exactly when each packet should leave, not merely that everything eventually
//! does. Upstream cannot do this without a fake clock, which is why its own tests check only that
//! packets come out.
//!
//! A marker below the pacer records what the rest of the chain saw and when — that placement is
//! the point, since everything below the pacer must observe the release instant rather than the
//! instant the application enqueued.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, PacerBuilder, Packet, Registry, StreamInfo,
    TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One released packet: which it was, and when the layer below saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Released {
    sequence_number: u16,
    at: Duration,
}

struct Marker {
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Marker {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message.packet {
            self.released.lock().unwrap().push(Released {
                sequence_number: rtp.header.sequence_number,
                at: msg.now.saturating_duration_since(self.epoch),
            });
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for Marker {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// A maximum-sized packet: 12-byte RTP header plus payload makes 1500 bytes on the wire.
///
/// Full-sized because the smallest burst a pacer allows is one such packet — a burst below that
/// would make every packet take the larger-than-burst path and stop enforcing the rate at all.
const PAYLOAD_BYTES: usize = 1488;
const PACKET_BITS: f64 = 12_000.0;

/// 1.2 Mb/s: one 12 000-bit packet every 10 ms, which makes the schedule easy to read.
const BITRATE: f64 = 1_200_000.0;

struct Harness {
    chain: Box<dyn Interceptor>,
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
}

impl Harness {
    /// A pacer with a burst of exactly one packet, so releases are one at a time and the schedule
    /// is the rate rather than the burst.
    fn new() -> Self {
        Self::with_burst(PACKET_BITS)
    }

    fn with_burst(burst_bits: f64) -> Self {
        let epoch = Instant::now();
        let released = Arc::new(Mutex::new(Vec::new()));
        let marker_released = Arc::clone(&released);

        let chain = Registry::new()
            .with(Marker {
                released: marker_released,
                epoch,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            })
            .with(
                PacerBuilder::new()
                    .with_target_bitrate(BITRATE)
                    .with_burst_bits(burst_bits)
                    .build(),
            )
            .build();

        Self {
            chain: Box::new(chain),
            released,
            epoch,
        }
    }

    fn send(&mut self, at: Duration, sequence_number: u16) {
        self.send_sized(at, sequence_number, PAYLOAD_BYTES);
    }

    fn send_sized(&mut self, at: Duration, sequence_number: u16, payload_bytes: usize) {
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc: 1,
                        ..Default::default()
                    },
                    payload: vec![0u8; payload_bytes].into(),
                })),
            })
            .expect("handle_write");
    }

    /// Fire a timeout and then drain, which is what a driver does.
    ///
    /// The draining is load-bearing on the belt and was not under nesting: a released packet is
    /// handed on by the pacer's `poll_write`, so it only reaches the stages between the pacer and
    /// the wire when the chain's `poll_write` walk runs. `handle_timeout` alone moves a packet out
    /// of the pacer's queue and no further.
    /// Tell the pacer a new target rate.
    ///
    /// With no event channel the estimate travels as an attribute on an outgoing packet, which is
    /// how a congestion controller application-ward of the pacer would deliver it.
    /// Tell the pacer a new target rate.
    ///
    /// On the **read** leg, because that is the only one the estimate can cross on: the congestion
    /// controller is wire-*ward* of the pacer, so on the write leg it never sees a packet before the
    /// pacer does. It attaches the attribute to the inbound feedback packet that produced the
    /// estimate, and the pacer reads it on the way past.
    fn retarget(&mut self, bits_per_second: f64) {
        let mut msg = TaggedPacket {
            now: self.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        msg.message
            .add(Attribute::TargetBitrateChanged { bits_per_second });
        self.chain.handle_read(msg).expect("handle_read");
        while self.chain.poll_read().is_some() {}
    }

    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
        self.drain();
    }

    /// Pull everything the chain is ready to send.
    fn drain(&mut self) {
        while self.chain.poll_write().is_some() {}
    }

    /// Advance the clock the way the driver does: fire every deadline the chain asks for, in
    /// order, up to `at`. This is what turns "eventually" into a schedule.
    fn advance_to(&mut self, at: Duration) {
        let deadline = self.epoch + at;
        let mut fired_deadline = false;
        // Bounded so a pacer that reports a non-advancing deadline fails the test rather than
        // hanging it — the webrtc#862 failure mode.
        for _ in 0..10_000 {
            let Some(next) = self.chain.poll_timeout() else {
                break;
            };
            if next > deadline {
                break;
            }
            fired_deadline |= next == deadline;
            self.chain.handle_timeout(next).expect("handle_timeout");
            self.drain();
        }
        // Only if the loop did not already reach it: a driver fires each deadline once, and a
        // harness that fires twice would hide an interceptor that treats timeouts as edge
        // triggered. `repeated_timeouts_at_one_instant_release_nothing_extra` asserts that
        // property directly rather than leaning on this having covered it by accident.
        if !fired_deadline {
            self.tick(at);
        }
    }

    fn released(&self) -> Vec<Released> {
        self.released.lock().unwrap().clone()
    }

    fn schedule(&self) -> Vec<(u16, Duration)> {
        self.released()
            .iter()
            .map(|packet| (packet.sequence_number, packet.at))
            .collect()
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

// ---------------------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------------------

/// A packet's size in bits over the rate is its spacing: 1000 bits at 100 kb/s is 10 ms.
#[test]
fn a_burst_is_released_at_the_configured_rate() {
    let mut harness = Harness::new();

    // Five packets handed over at once.
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }
    assert!(
        harness.released().is_empty(),
        "enqueueing releases nothing; only the clock does"
    );

    harness.advance_to(ms(100));

    assert_eq!(
        vec![
            (0, ms(0)),
            (1, ms(10)),
            (2, ms(20)),
            (3, ms(30)),
            (4, ms(40))
        ],
        harness.schedule(),
        "one packet per 10 ms, in order"
    );
}

/// Changing the rate changes the spacing of everything after it — this is the knob a bandwidth
/// estimator turns, and it has to take effect on the next release rather than the next block.
#[test]
fn changing_the_rate_changes_the_subsequent_schedule() {
    let mut harness = Harness::new();
    for sequence_number in 0..4 {
        harness.send(ms(0), sequence_number);
    }

    harness.advance_to(ms(20));
    assert_eq!(
        vec![(0, ms(0)), (1, ms(10)), (2, ms(20))],
        harness.schedule(),
        "three released at the original rate"
    );

    // Twice the rate: the next packet is due half as long after the last one.
    harness.retarget(BITRATE * 2.0);
    harness.advance_to(ms(40));

    let schedule = harness.schedule();
    assert_eq!(4, schedule.len());
    assert_eq!(
        ms(25),
        schedule[3].1,
        "5 ms after the previous release, not 10: {schedule:?}"
    );
}

#[test]
fn a_larger_burst_releases_more_at_once() {
    let mut harness = Harness::with_burst(PACKET_BITS * 3.0);
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));

    assert_eq!(
        vec![(0, ms(0)), (1, ms(0)), (2, ms(0))],
        harness.schedule(),
        "a three-packet burst goes at once; the rest waits"
    );
}

/// Packets arriving while the queue drains join the back of it and keep their order.
#[test]
fn packets_arriving_mid_drain_keep_their_order() {
    let mut harness = Harness::new();
    harness.send(ms(0), 0);
    harness.send(ms(0), 1);

    harness.advance_to(ms(10));
    harness.send(ms(12), 2);
    harness.advance_to(ms(40));

    assert_eq!(
        vec![0, 1, 2],
        harness
            .schedule()
            .iter()
            .map(|(sequence_number, _)| *sequence_number)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------------------
// The chain contract
// ---------------------------------------------------------------------------------------

/// Rule 3. Everything below the pacer must see the release instant; recording the enqueue instant
/// would charge this queueing delay to the network, which is what makes a bandwidth estimate
/// collapse.
#[test]
fn a_released_packet_carries_the_release_instant_not_the_enqueue_instant() {
    let mut harness = Harness::new();
    harness.send(ms(0), 0);
    harness.send(ms(0), 1);

    harness.advance_to(ms(50));

    let schedule = harness.schedule();
    assert_eq!(ms(0), schedule[0].1);
    assert_eq!(
        ms(10),
        schedule[1].1,
        "the second packet departed 10 ms later and says so"
    );
}

/// Rule 2. Released packets travel through `inner`, so a downstream layer sees each exactly once.
#[test]
fn each_packet_reaches_the_layer_below_exactly_once() {
    let mut harness = Harness::new();
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }

    harness.advance_to(ms(200));

    let mut sequence_numbers: Vec<u16> = harness
        .schedule()
        .iter()
        .map(|(sequence_number, _)| *sequence_number)
        .collect();
    sequence_numbers.sort_unstable();
    assert_eq!(
        vec![0, 1, 2, 3, 4],
        sequence_numbers,
        "no duplicates, none lost"
    );
}

// ---------------------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------------------

/// Delivery rule 3: an idle pacer must not wake the chain, and an armed deadline must advance.
#[test]
fn poll_timeout_is_none_when_the_queue_is_empty() {
    let mut harness = Harness::new();

    assert_eq!(None, harness.next_timeout(), "nothing queued");

    harness.send(ms(0), 0);
    harness.send(ms(0), 1);
    assert_eq!(
        Some(ms(0)),
        harness.next_timeout(),
        "the head can go immediately"
    );

    harness.tick(ms(0));
    assert_eq!(
        Some(ms(10)),
        harness.next_timeout(),
        "and the next is due a packet-time later"
    );

    harness.advance_to(ms(100));
    assert_eq!(
        None,
        harness.next_timeout(),
        "drained, so idle again rather than waking at the pacing interval"
    );
}

/// The deadline is derived from when the head can afford to go, so it is always in the future —
/// a repeated past instant is the webrtc#862 busy-loop, and `advance_to` would spin on it.
#[test]
fn the_reported_deadline_advances() {
    let mut harness = Harness::new();
    for sequence_number in 0..3 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));
    let first = harness.next_timeout().expect("armed");
    harness.tick(first);
    let second = harness.next_timeout().expect("armed");

    assert!(second > first, "{second:?} follows {first:?}");
}

// ---------------------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------------------

/// RTCP is not paced: feedback is only useful while it is fresh, and holding it back would delay
/// the very reports congestion control depends on.
#[test]
fn rtcp_is_not_paced() {
    let mut harness = Harness::new();

    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        })
        .expect("handle_write");

    assert!(
        harness.chain.poll_write().is_some(),
        "RTCP leaves immediately rather than waiting for a release deadline"
    );
}

/// A driver may hand the same instant over more than once — two protocols' deadlines can coincide.
/// Releasing again on the second call would put a packet on the wire that the budget never paid
/// for.
#[test]
fn repeated_timeouts_at_one_instant_release_nothing_extra() {
    let mut harness = Harness::new();
    for sequence_number in 0..4 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));
    let once = harness.schedule();
    harness.tick(ms(0));
    harness.tick(ms(0));

    assert_eq!(
        vec![(0, ms(0))],
        once,
        "one packet fits the one-packet burst"
    );
    assert_eq!(
        once,
        harness.schedule(),
        "and repeating the instant adds none"
    );
}

/// A burst the caller configured is not a function of the rate, so an estimator raising the rate
/// must not widen it. Otherwise the first rate update silently turns a one-at-a-time sender into a
/// bursty one, which is exactly what a pacer exists to prevent.
///
/// The pacer has to be left *idle* across the rate change for this to bite: a widened burst only
/// shows up once the budget has had time to accumulate into it. Draining continuously hides it.
#[test]
fn a_configured_burst_survives_a_rate_change() {
    let mut harness = Harness::new();
    harness.tick(ms(0));

    // Twenty times the rate. A burst derived from this would be 240 000 bits — twenty packets.
    harness.retarget(BITRATE * 20.0);

    // Idle long enough for the budget to fill whatever the burst now is.
    harness.advance_to(ms(100));
    for sequence_number in 0..6 {
        harness.send(ms(100), sequence_number);
    }
    harness.tick(ms(100));

    assert_eq!(
        vec![(0, ms(100))],
        harness.schedule(),
        "one packet, not a burst at the widened rate"
    );
}

/// Packets larger than the burst are paced too. Releasing them unconditionally — the only way to
/// keep them from stalling the queue — would let a run of them leave all at once, defeating the
/// pacer for exactly the traffic that stresses the path most.
#[test]
fn oversized_packets_are_paced_not_dumped() {
    let mut harness = Harness::with_burst(PACKET_BITS);
    for sequence_number in 0..4 {
        harness.send_sized(ms(0), sequence_number, 4000);
    }

    harness.advance_to(ms(0));
    assert_eq!(
        1,
        harness.schedule().len(),
        "one oversized packet per release: {:?}",
        harness.schedule()
    );

    // 4012 bytes is 32 096 bits; at 1.2 Mb/s that is 26.7 ms of debt before the next may go.
    harness.advance_to(ms(26));
    assert_eq!(1, harness.schedule().len(), "the next still owes");
    harness.advance_to(ms(27));
    assert_eq!(2, harness.schedule().len(), "and then goes");

    harness.advance_to(ms(500));
    assert_eq!(4, harness.schedule().len(), "all of them get out");
}

/// A packet larger than a full burst can never become affordable, since the budget caps at the
/// burst. It must still get out, or it stalls the whole queue behind it forever.
#[test]
fn a_packet_larger_than_the_burst_is_still_released() {
    let mut harness = Harness::with_burst(PACKET_BITS);

    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    sequence_number: 99,
                    ssrc: 1,
                    ..Default::default()
                },
                // Far bigger than the one-packet burst.
                payload: vec![0u8; 4000].into(),
            })),
        })
        .expect("handle_write");
    harness.send(ms(0), 100);

    harness.advance_to(ms(500));

    let sequence_numbers: Vec<u16> = harness
        .schedule()
        .iter()
        .map(|(sequence_number, _)| *sequence_number)
        .collect();
    assert!(
        sequence_numbers.contains(&99),
        "the oversized packet was released: {sequence_numbers:?}"
    );
    assert!(
        sequence_numbers.contains(&100),
        "and did not stall the packet behind it"
    );
}

/// The queue is bounded. Under sustained overload the arrival is refused rather than a queued
/// packet evicted, since the queued ones are older and dropping one would put a hole mid-stream.
#[test]
fn the_queue_is_bounded_and_refuses_new_arrivals_when_full() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(
            PacerBuilder::new()
                .with_target_bitrate(BITRATE)
                .with_queue_limit(3)
                .build(),
        )
        .build();

    for sequence_number in 0..10u16 {
        chain
            .handle_write(TaggedPacket {
                now: epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        sequence_number,
                        ssrc: 1,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD_BYTES].into(),
                })),
            })
            .expect("handle_write");
    }

    // Drain everything the pacer will ever release: only what fitted in the queue comes out.
    let mut released = 0;
    let mut now = epoch;
    for _ in 0..100 {
        chain.handle_timeout(now).expect("handle_timeout");
        while chain.poll_write().is_some() {
            released += 1;
        }
        now += Duration::from_millis(10);
    }

    assert_eq!(
        3, released,
        "capped at the queue limit; the other seven arrivals were refused"
    );
}

/// A packet's size is its size on the wire, since that is what occupies the path.
#[test]
fn pacing_meters_the_wire_size() {
    let packet = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number: 0,
            ssrc: 1,
            ..Default::default()
        },
        payload: vec![0u8; PAYLOAD_BYTES].into(),
    };
    assert_eq!(
        PACKET_BITS as usize,
        packet.marshal_size() * 8,
        "the fixture is the size the schedule assumes"
    );
}
