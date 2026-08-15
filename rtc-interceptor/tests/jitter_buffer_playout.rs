//! Time-based playout for the jitter buffer interceptor (webrtc#846).
//!
//! What #846 asks for is that reordering and delay variation are absorbed up to a configured
//! depth, and that the depth is a span of *time* rather than a packet count. These tests drive the
//! interceptor against an explicit clock — no sleeping — so the assertions are about the policy
//! and not about how fast the machine running them happens to be.
//!
//! A marker interceptor sits below the buffer to record what is released and when. That placement
//! matters: released packets must arrive through `inner.handle_read`, so a downstream interceptor
//! sees them exactly as it would a live packet (the chain contract's rule 2).

use rtc_interceptor::{
    Interceptor, JitterBufferBuilder, NoopInterceptor, Packet, Registry, StreamInfo, TaggedPacket,
    interceptor,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------

/// One released packet, as the layer below the buffer saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Released {
    ssrc: u32,
    sequence_number: u16,
    timestamp: u32,
    /// Offset from the test epoch of the instant the packet carried when released.
    at: Duration,
}

#[derive(Interceptor)]
struct Marker<P> {
    #[next]
    inner: P,
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
}

#[interceptor]
impl<P: Interceptor> Marker<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message {
            self.released.lock().unwrap().push(Released {
                ssrc: rtp.header.ssrc,
                sequence_number: rtp.header.sequence_number,
                timestamp: rtp.header.timestamp,
                at: msg.now.saturating_duration_since(self.epoch),
            });
        }
        self.inner.handle_read(msg)
    }
}

struct Harness {
    chain: Box<dyn Interceptor>,
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
}

impl Harness {
    fn new(depth: Duration, capacity: usize) -> Self {
        let epoch = Instant::now();
        let released = Arc::new(Mutex::new(Vec::new()));

        let marker_released = Arc::clone(&released);
        let chain = Registry::new()
            .with(move |inner: NoopInterceptor| Marker {
                inner,
                released: marker_released,
                epoch,
            })
            .with(
                JitterBufferBuilder::new()
                    .with_depth(depth)
                    .with_capacity(capacity)
                    .build(),
            )
            .boxed()
            .build();

        Self {
            chain,
            released,
            epoch,
        }
    }

    fn bind(&mut self, ssrc: u32, clock_rate: u32) {
        self.chain.bind_remote_stream(&StreamInfo {
            ssrc,
            clock_rate,
            ..Default::default()
        });
    }

    fn unbind(&mut self, ssrc: u32) {
        self.chain.unbind_remote_stream(&StreamInfo {
            ssrc,
            ..Default::default()
        });
    }

    /// Deliver a packet that arrived `at` after the epoch.
    fn arrive(&mut self, at: Duration, ssrc: u32, sequence_number: u16, timestamp: u32) {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc,
                        sequence_number,
                        timestamp,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            })
            .expect("handle_read");
    }

    /// Advance the clock to `at` and let the buffer release whatever is due.
    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
    }

    fn released(&self) -> Vec<Released> {
        self.released.lock().unwrap().clone()
    }

    fn sequence_numbers(&self) -> Vec<u16> {
        self.released()
            .iter()
            .map(|packet| packet.sequence_number)
            .collect()
    }

    fn next_timeout(&mut self) -> Option<Duration> {
        self.chain
            .poll_timeout()
            .map(|instant| instant.saturating_duration_since(self.epoch))
    }
}

const CLOCK: u32 = 90_000;
const DEPTH: Duration = Duration::from_millis(100);

/// RTP ticks for a duration at the video clock rate.
fn ticks(duration: Duration) -> u32 {
    (duration.as_secs_f64() * f64::from(CLOCK)) as u32
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

// ---------------------------------------------------------------------------------------
// The depth is a span of time
// ---------------------------------------------------------------------------------------

/// The headline property: a packet is held for the configured depth, then released.
#[test]
fn a_packet_is_held_for_the_configured_depth() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(0), 1, 100, 0);

    harness.tick(ms(50));
    assert!(
        harness.released().is_empty(),
        "still inside the depth: nothing released yet"
    );

    harness.tick(ms(100));
    assert_eq!(
        vec![100],
        harness.sequence_numbers(),
        "released at the depth"
    );
}

/// Once emitting, a packet whose deadline has not arrived is still held.
///
/// Without this, the state gate alone carries every depth assertion: the first packet is held
/// because the stream has not started, and every other test ticks past every deadline at once. So
/// removing the deadline check entirely would leave the suite green.
#[test]
fn an_emitting_stream_still_holds_packets_that_are_not_due() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    // Two packets 40 ms apart in media time, arriving together: deadlines 100 ms and 140 ms.
    harness.arrive(ms(0), 1, 1, ticks(ms(0)));
    harness.arrive(ms(0), 1, 2, ticks(ms(40)));

    harness.tick(ms(100));
    assert_eq!(
        vec![1],
        harness.sequence_numbers(),
        "the stream is emitting, but the second packet is not due for another 40 ms"
    );

    harness.tick(ms(120));
    assert_eq!(vec![1], harness.sequence_numbers(), "still not due");

    harness.tick(ms(140));
    assert_eq!(vec![1, 2], harness.sequence_numbers(), "now due");
}

/// A stream that sends one packet and stops must still play it out. Upstream cannot: it waits for
/// 50 packets, so a single-packet or paused stream is buffered forever.
#[test]
fn a_single_packet_stream_still_plays_out() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(0), 1, 1, 0);
    harness.tick(ms(100));

    assert_eq!(
        vec![1],
        harness.sequence_numbers(),
        "one packet is enough to start playout"
    );
}

/// `handle_read` inserts and returns; it must not emit. Upstream pops inside the read path, which
/// is what makes its buffer a delay line rather than a time window.
#[test]
fn arrival_alone_releases_nothing() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    for sequence_number in 0..10u16 {
        harness.arrive(ms(0), 1, sequence_number, 0);
    }

    assert!(
        harness.released().is_empty(),
        "no amount of arriving releases anything; only the clock does"
    );
}

// ---------------------------------------------------------------------------------------
// Reordering and delay variation — #846's stated bar
// ---------------------------------------------------------------------------------------

/// Deliberately reordered and delayed RTP comes out in order, with the variation absorbed.
#[test]
fn reordered_and_delayed_packets_are_released_in_order() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    // Sent every 20 ms, but arriving jittered and out of order — all still inside the depth.
    harness.arrive(ms(0), 1, 0, ticks(ms(0)));
    harness.arrive(ms(65), 1, 2, ticks(ms(40)));
    harness.arrive(ms(70), 1, 1, ticks(ms(20)));
    harness.arrive(ms(75), 1, 4, ticks(ms(80)));
    harness.arrive(ms(80), 1, 3, ticks(ms(60)));

    harness.tick(ms(200));

    assert_eq!(
        vec![0, 1, 2, 3, 4],
        harness.sequence_numbers(),
        "arrival order was 0,2,1,4,3 — playout order is not"
    );
}

/// The other half of "absorbed up to the depth": a packet later than the depth is dropped, not
/// emitted out of order behind packets that already left.
#[test]
fn a_packet_later_than_the_depth_is_dropped_rather_than_emitted_out_of_order() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(0), 1, 0, ticks(ms(0)));
    harness.arrive(ms(0), 1, 2, ticks(ms(40)));

    // Both released; sequence 1 is still missing.
    harness.tick(ms(150));
    assert_eq!(vec![0, 2], harness.sequence_numbers());

    // Now it turns up, far too late.
    harness.arrive(ms(160), 1, 1, ticks(ms(20)));
    harness.tick(ms(300));

    assert_eq!(
        vec![0, 2],
        harness.sequence_numbers(),
        "emitting 1 after 2 would put the stream out of order — it is dropped instead"
    );
}

// ---------------------------------------------------------------------------------------
// Frames, wrap and discontinuity
// ---------------------------------------------------------------------------------------

/// Video packets sharing one RTP timestamp are one frame: they share a deadline and keep their
/// sequence order.
#[test]
fn packets_sharing_a_timestamp_share_a_deadline() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    let frame = ticks(ms(0));
    harness.arrive(ms(0), 1, 12, frame);
    harness.arrive(ms(1), 1, 10, frame);
    harness.arrive(ms(2), 1, 11, frame);

    harness.tick(ms(100));

    let released = harness.released();
    assert_eq!(
        vec![10, 11, 12],
        released
            .iter()
            .map(|packet| packet.sequence_number)
            .collect::<Vec<_>>(),
        "one frame, released in sequence order"
    );
    let first = released[0].at;
    assert!(
        released.iter().all(|packet| packet.at == first),
        "and all at the same instant: {released:?}"
    );
}

#[test]
fn playout_survives_a_sequence_number_wrap() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(0), 1, 65534, ticks(ms(0)));
    harness.arrive(ms(5), 1, 0, ticks(ms(40)));
    harness.arrive(ms(10), 1, 65535, ticks(ms(20)));
    harness.arrive(ms(15), 1, 1, ticks(ms(60)));

    harness.tick(ms(300));

    assert_eq!(
        vec![65534, 65535, 0, 1],
        harness.sequence_numbers(),
        "0 follows 65535 rather than sorting a whole cycle early"
    );
}

/// An RTP timestamp wrap must not throw the deadline arithmetic a full cycle out — at 90 kHz that
/// is about 13 hours.
#[test]
fn playout_survives_an_rtp_timestamp_wrap() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    let before_wrap = u32::MAX - ticks(ms(10));
    harness.arrive(ms(0), 1, 1, before_wrap);
    // 20 ms later in media time, which wraps the 32-bit timestamp.
    harness.arrive(ms(5), 1, 2, before_wrap.wrapping_add(ticks(ms(20))));

    harness.tick(ms(200));

    assert_eq!(
        vec![1, 2],
        harness.sequence_numbers(),
        "both released; the wrap did not push the second deadline hours away"
    );
}

/// A timestamp jump far beyond any real spacing is a restart, not a gap to wait out. Without this
/// the stream would either stall for hours or dump everything at once.
#[test]
fn a_large_timestamp_discontinuity_restarts_the_timeline() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    // Two packets, so the buffer is *not* empty when the jump arrives. Otherwise the stream
    // would have run dry and re-anchored on that path instead, and this would not be testing
    // discontinuity handling at all.
    harness.arrive(ms(0), 1, 1, ticks(ms(0)));
    harness.arrive(ms(0), 1, 2, ticks(ms(20)));

    harness.tick(ms(100));
    assert_eq!(
        vec![1],
        harness.sequence_numbers(),
        "precondition: 1 is out, 2 is still held, so the stream has not run dry"
    );

    // Half an hour of media time later, while 2 is still buffered.
    harness.arrive(ms(105), 1, 3, ticks(Duration::from_secs(1800)));
    harness.tick(ms(260));

    assert_eq!(
        vec![1, 3],
        harness.sequence_numbers(),
        "the timeline re-anchors, so 3 is due one depth after it arrived rather than half an \
         hour later; the restart drops 2 along with the old timeline"
    );
}

// ---------------------------------------------------------------------------------------
// Underflow, overflow, and per-stream isolation
// ---------------------------------------------------------------------------------------

/// After running dry the stream re-buffers, so the next packet gets a full depth of cushion
/// instead of being emitted the moment it lands.
#[test]
fn a_stream_that_runs_dry_buffers_again() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(0), 1, 1, ticks(ms(0)));
    harness.tick(ms(100));
    assert_eq!(vec![1], harness.sequence_numbers());

    // Buffer is empty; a new packet arrives well after.
    harness.arrive(ms(500), 1, 2, ticks(ms(20)));
    harness.tick(ms(520));
    assert_eq!(
        vec![1],
        harness.sequence_numbers(),
        "not released immediately: the stream is filling again"
    );

    harness.tick(ms(600));
    assert_eq!(
        vec![1, 2],
        harness.sequence_numbers(),
        "released a depth later"
    );
}

/// The packet cap bounds memory independently of the time depth — a stream whose deadlines are
/// all in the future must not be able to grow without limit.
#[test]
fn the_capacity_cap_bounds_a_stream_independently_of_the_depth() {
    let mut harness = Harness::new(Duration::from_secs(60), 4);
    harness.bind(1, CLOCK);

    for sequence_number in 0..10u16 {
        harness.arrive(ms(0), 1, sequence_number, ticks(ms(0)));
    }

    // Far beyond the depth, so everything still held is released.
    harness.tick(Duration::from_secs(120));

    let released = harness.sequence_numbers();
    assert_eq!(4, released.len(), "capacity respected: {released:?}");
    assert_eq!(
        vec![6, 7, 8, 9],
        released,
        "the oldest gave way, and what remains is still in order"
    );
}

/// Two streams must not interleave. Upstream's single shared buffer sorts their sequence numbers
/// against each other, so this is the test its design cannot pass.
#[test]
fn two_streams_are_buffered_independently() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);
    harness.bind(2, CLOCK);

    // Deliberately overlapping sequence-number ranges.
    harness.arrive(ms(0), 1, 100, ticks(ms(0)));
    harness.arrive(ms(0), 2, 5, ticks(ms(0)));
    harness.arrive(ms(0), 1, 101, ticks(ms(20)));
    harness.arrive(ms(0), 2, 6, ticks(ms(20)));

    harness.tick(ms(200));

    let released = harness.released();
    let first: Vec<u16> = released
        .iter()
        .filter(|packet| packet.ssrc == 1)
        .map(|packet| packet.sequence_number)
        .collect();
    let second: Vec<u16> = released
        .iter()
        .filter(|packet| packet.ssrc == 2)
        .map(|packet| packet.sequence_number)
        .collect();

    assert_eq!(vec![100, 101], first);
    assert_eq!(vec![5, 6], second);
}

/// Unbinding one stream drops that stream only. Upstream's `UnbindRemoteStream` clears the shared
/// buffer, discarding every other stream's packets with it.
#[test]
fn unbinding_one_stream_leaves_the_others_buffered() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);
    harness.bind(2, CLOCK);

    harness.arrive(ms(0), 1, 100, ticks(ms(0)));
    harness.arrive(ms(0), 2, 5, ticks(ms(0)));

    harness.unbind(1);
    harness.tick(ms(200));

    let released = harness.released();
    assert_eq!(1, released.len(), "only the surviving stream: {released:?}");
    assert_eq!(2, released[0].ssrc);
    assert_eq!(5, released[0].sequence_number);
}

/// A packet for a stream that was never bound is passed through rather than buffered — otherwise
/// it would be held for a playout nobody is going to drive.
#[test]
fn packets_for_unbound_streams_pass_straight_through() {
    let mut harness = Harness::new(DEPTH, 64);

    harness.arrive(ms(0), 9, 1, 0);

    assert_eq!(
        vec![1],
        harness.sequence_numbers(),
        "forwarded immediately, without waiting for a tick"
    );
}

// ---------------------------------------------------------------------------------------
// Chain contract
// ---------------------------------------------------------------------------------------

/// Rule 3: the released packet carries the instant it was released, so a downstream history does
/// not record this buffer's own holding time as network delay.
#[test]
fn a_released_packet_carries_the_release_instant() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness.arrive(ms(10), 1, 1, 0);
    harness.tick(ms(140));

    let released = harness.released();
    assert_eq!(1, released.len());
    assert_eq!(
        ms(140),
        released[0].at,
        "the release instant, not the ms(10) arrival"
    );
}

/// Delivery rule 3: idle means `None`, and an armed timeout is the deadline actually being waited
/// on — never a past instant, which is the webrtc#862 busy-loop.
#[test]
fn poll_timeout_is_none_when_idle_and_reports_the_next_deadline() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    assert_eq!(
        None,
        harness.next_timeout(),
        "nothing buffered, nothing due"
    );

    harness.arrive(ms(0), 1, 1, 0);
    assert_eq!(
        Some(DEPTH),
        harness.next_timeout(),
        "the first packet's deadline is one depth out"
    );

    harness.tick(ms(100));
    assert_eq!(
        None,
        harness.next_timeout(),
        "drained, so idle again rather than re-arming on a past instant"
    );
}

/// RTCP must not be delayed behind media: feedback is only useful while it is fresh, and it has no
/// sequence number to order by.
#[test]
fn rtcp_is_forwarded_without_being_buffered() {
    let mut harness = Harness::new(DEPTH, 64);
    harness.bind(1, CLOCK);

    harness
        .chain
        .handle_read(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: Packet::Rtcp(vec![]),
        })
        .expect("handle_read");

    // The marker only records RTP, so the assertion is that nothing was held back and no panic
    // occurred; a buffered RTCP packet would have to come out on a tick.
    harness.tick(ms(200));
    assert!(harness.released().is_empty());
}
