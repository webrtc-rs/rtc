//! The jitter buffer's depth is the window in which a retransmission is still useful (webrtc#846).
//!
//! #846 observes that these two interceptors interact and asks how they should agree on a depth.
//! The answer taken here is **document and test, do not couple**: a mechanism for the two to
//! negotiate would tie together interceptors that are otherwise independent, and the relationship
//! is simple enough to state and to check.
//!
//! The relationship: a lost packet cannot be recovered before
//!
//! ```text
//!     detection (up to one NACK interval) + round trip + the sender's response
//! ```
//!
//! has elapsed. The jitter buffer plays out a packet's position one *depth* after that position's
//! playout instant. So a depth shallower than that sum means every retransmission arrives after
//! its position has been played past, and is dropped — the NACK traffic is spent for nothing.
//!
//! These tests make that executable: the same loss and the same round trip, recovered under a
//! depth chosen to accommodate it and lost under one chosen not to.

use rtc_interceptor::{
    Interceptor, JitterBufferBuilder, NackGeneratorBuilder, NoopInterceptor, Packet, RTCPFeedback,
    Registry, StreamInfo, TaggedPacket, interceptor,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------

#[derive(Interceptor)]
struct Marker<P> {
    #[next]
    inner: P,
    released: Arc<Mutex<Vec<u16>>>,
}

#[interceptor]
impl<P: Interceptor> Marker<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message {
            self.released
                .lock()
                .unwrap()
                .push(rtp.header.sequence_number);
        }
        self.inner.handle_read(msg)
    }
}

const SSRC: u32 = 1;
const CLOCK: u32 = 90_000;
const NACK_INTERVAL: Duration = Duration::from_millis(100);
/// How long the peer takes to hear the NACK and get the retransmission back to us.
const ROUND_TRIP: Duration = Duration::from_millis(60);
/// Packets are sent every 20 ms of media time.
const SPACING: Duration = Duration::from_millis(20);

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

fn ticks(duration: Duration) -> u32 {
    (duration.as_secs_f64() * f64::from(CLOCK)) as u32
}

struct Harness {
    chain: Box<dyn Interceptor>,
    released: Arc<Mutex<Vec<u16>>>,
    epoch: Instant,
}

impl Harness {
    /// NACK generator **outermost**, jitter buffer below it.
    ///
    /// Loss has to be detected from arrivals, not from playout: a generator sitting below the
    /// buffer would only see packets after they were released, delaying every NACK by the depth.
    /// That is measured in `a_generator_below_the_buffer_detects_loss_a_whole_depth_late`.
    fn new(depth: Duration) -> Self {
        let epoch = Instant::now();
        let released = Arc::new(Mutex::new(Vec::new()));

        let marker_released = Arc::clone(&released);
        let chain = Registry::new()
            .with(move |inner: NoopInterceptor| Marker {
                inner,
                released: marker_released,
            })
            .with(JitterBufferBuilder::new().with_depth(depth).build())
            .with(
                NackGeneratorBuilder::new()
                    .with_interval(NACK_INTERVAL)
                    .with_skip_last_n(0)
                    .build(),
            )
            .boxed()
            .build();

        let mut harness = Self {
            chain,
            released,
            epoch,
        };
        harness.bind();
        harness
    }

    fn bind(&mut self) {
        self.chain.bind_remote_stream(&StreamInfo {
            ssrc: SSRC,
            clock_rate: CLOCK,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
    }

    /// A packet arrives at `at`. The clock is advanced there first: time really does pass while a
    /// packet is in flight, so every playout deadline before its arrival has already fired.
    fn arrive(&mut self, at: Duration, sequence_number: u16, media_time: Duration) {
        self.advance_to(at);
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: SSRC,
                        sequence_number,
                        timestamp: ticks(media_time),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            })
            .expect("handle_read");
    }

    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
    }

    /// Advance the clock to `at` the way the driver does: fire every timeout the chain asks for
    /// along the way, rather than jumping straight to the end.
    ///
    /// This matters for the boundary. Ticking only at the start and the end leaves playout frozen
    /// in between, so a retransmission that arrives late still finds its position open — the
    /// buffer looks deeper than it is.
    fn advance_to(&mut self, at: Duration) {
        let deadline = self.epoch + at;
        while let Some(next) = self.chain.poll_timeout() {
            if next > deadline {
                break;
            }
            self.chain.handle_timeout(next).expect("handle_timeout");
        }
        self.tick(at);
    }

    /// Drain any NACK the generator has produced, returning the sequence numbers it asks for.
    fn drain_nacks(&mut self) -> Vec<u16> {
        let mut requested = Vec::new();
        while let Some(packet) = self.chain.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = &packet.message {
                for rtcp_packet in rtcp_packets {
                    if let Some(nack) = rtcp_packet
                        .as_any()
                        .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                        )
                    {
                        for pair in &nack.nacks {
                            requested.extend(pair.packet_list());
                        }
                    }
                }
            }
        }
        requested
    }

    fn released(&self) -> Vec<u16> {
        self.released.lock().unwrap().clone()
    }
}

/// Sends packets 0..=4 with sequence 2 lost, ticking the clock as it goes, and returns the
/// harness with the loss detected and the NACK emitted.
///
/// Returns the instant the retransmission would arrive: one NACK interval to detect, plus the
/// round trip.
fn run_until_retransmission(harness: &mut Harness) -> Duration {
    // 0 and 1 arrive; 2 is lost; 3 and 4 arrive.
    harness.arrive(ms(0), 0, Duration::ZERO);
    harness.arrive(ms(20), 1, SPACING * 1);
    harness.arrive(ms(60), 3, SPACING * 3);
    harness.arrive(ms(80), 4, SPACING * 4);

    // The generator's timer fires one interval after the first tracked packet.
    let nack_at = NACK_INTERVAL;
    harness.advance_to(nack_at);

    let requested = harness.drain_nacks();
    assert!(
        requested.contains(&2),
        "precondition: the generator asked for the lost packet, got {requested:?}"
    );

    nack_at + ROUND_TRIP
}

// ---------------------------------------------------------------------------------------
// The relationship
// ---------------------------------------------------------------------------------------

/// A depth wide enough for detection plus the round trip: the retransmission lands before its
/// position is played out, and the stream is delivered complete and in order.
#[test]
fn a_deep_enough_buffer_still_has_a_place_for_the_retransmission() {
    // Sequence 2's playout instant is its arrival-time anchor plus the depth. The depth must
    // cover detection (one NACK interval) plus the round trip.
    let depth = NACK_INTERVAL + ROUND_TRIP + ms(40);
    let mut harness = Harness::new(depth);

    let retransmission_at = run_until_retransmission(&mut harness);
    assert!(
        harness.released().is_empty(),
        "nothing has been played out yet, so 2's position is still open"
    );

    harness.arrive(retransmission_at, 2, SPACING * 2);
    harness.advance_to(ms(1000));

    assert_eq!(
        vec![0, 1, 2, 3, 4],
        harness.released(),
        "the recovered packet took its place in order"
    );
}

/// The same loss and the same round trip, with a depth too shallow to hold the position open.
/// The retransmission arrives after 2's slot has been played past, so it is dropped rather than
/// emitted out of order — and the NACK was spent for nothing.
#[test]
fn a_buffer_shallower_than_the_recovery_window_cannot_use_the_retransmission() {
    let depth = ms(20);
    assert!(
        depth < NACK_INTERVAL + ROUND_TRIP,
        "the point of this test is a depth below the recovery window"
    );
    let mut harness = Harness::new(depth);

    let retransmission_at = run_until_retransmission(&mut harness);
    assert_eq!(
        vec![0, 1, 3, 4],
        harness.released(),
        "playout has already moved past 2's position with the gap unfilled"
    );

    harness.arrive(retransmission_at, 2, SPACING * 2);
    harness.advance_to(ms(1000));

    assert_eq!(
        vec![0, 1, 3, 4],
        harness.released(),
        "the retransmission is dropped: emitting 2 after 3 and 4 would break ordering, which is \
         the one thing the buffer exists to preserve"
    );
}

/// The boundary, stated as an inequality rather than a coupling: recovery works when the depth
/// exceeds detection plus the round trip, and stops working when it does not.
#[test]
fn the_boundary_is_detection_plus_the_round_trip() {
    let window = NACK_INTERVAL + ROUND_TRIP;

    for (depth, expected, label) in [
        (window + ms(40), vec![0u16, 1, 2, 3, 4], "comfortably above"),
        (window / 2, vec![0, 1, 3, 4], "half the window"),
    ] {
        let mut harness = Harness::new(depth);
        let retransmission_at = run_until_retransmission(&mut harness);
        harness.arrive(retransmission_at, 2, SPACING * 2);
        harness.advance_to(ms(1000));

        assert_eq!(
            expected,
            harness.released(),
            "depth {depth:?} ({label}) against a {window:?} recovery window"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Why the generator sits above the buffer
// ---------------------------------------------------------------------------------------

/// A NACK generator placed *below* the jitter buffer sees packets only once they are released, so
/// it cannot notice a gap until a whole depth after the packet went missing. Every NACK is then
/// late by the depth, and the recovery window has to be that much wider to compensate.
///
/// This is why the read-side order is generator above buffer, and it is the reason worth having
/// executable: nothing else about the chain makes the cost visible.
#[test]
fn a_generator_below_the_buffer_detects_loss_a_whole_depth_late() {
    let depth = ms(200);
    let epoch = Instant::now();

    // Generator innermost, buffer outermost — the inverse of the working arrangement.
    let mut chain = Registry::new()
        .with(|inner: NoopInterceptor| {
            NackGeneratorBuilder::new()
                .with_interval(NACK_INTERVAL)
                .with_skip_last_n(0)
                .build()(inner)
        })
        .with(JitterBufferBuilder::new().with_depth(depth).build())
        .boxed()
        .build();

    chain.bind_remote_stream(&StreamInfo {
        ssrc: SSRC,
        clock_rate: CLOCK,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        ..Default::default()
    });

    let arrive = |chain: &mut Box<dyn Interceptor>, at: Duration, sequence_number: u16| {
        chain
            .handle_read(TaggedPacket {
                now: epoch + at,
                transport: TransportContext::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: SSRC,
                        sequence_number,
                        timestamp: ticks(SPACING * u32::from(sequence_number)),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            })
            .expect("handle_read");
    };

    arrive(&mut chain, ms(0), 0);
    arrive(&mut chain, ms(20), 1);
    // 2 is lost.
    arrive(&mut chain, ms(60), 3);

    // One NACK interval after arrival — when a generator above the buffer would already have
    // asked for the retransmission.
    chain
        .handle_timeout(epoch + NACK_INTERVAL)
        .expect("handle_timeout");

    let mut asked = false;
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &packet.message {
            asked |= !rtcp_packets.is_empty();
        }
    }
    assert!(
        !asked,
        "the generator below the buffer has not seen a single packet yet, so it cannot have \
         noticed the gap — every NACK it eventually sends is late by the depth"
    );
}
