//! Executable form of the chain contract documented on [`rtc_interceptor::Registry`].
//!
//! The rules being pinned here are the ones that a compiler cannot check and that a
//! single-interceptor unit test cannot see, because they are properties of *composition*:
//!
//! 1. a packet returned from an interceptor's own `poll_*` queue is terminal — it does not
//!    traverse the layers below it;
//! 2. a packet re-injected through `inner.handle_*` traverses every layer below **exactly once**;
//! 3. a delaying interceptor replaces `TaggedPacket::now` with the release instant, so a
//!    downstream history records departure rather than enqueue.
//!
//! Rules 1 and 2 are opposites of each other, and the failure modes are silent in both
//! directions: re-injecting *and* queueing locally delivers a packet twice, while queueing
//! locally when downstream processing was required skips layers without any error. So both are
//! asserted, with counting markers rather than "did it arrive" assertions — arrival alone cannot
//! tell one packet from two.
//!
//! The delaying interceptor here stands in for the pacer (P6) and the jitter buffer (P1), neither
//! of which exists yet. That is deliberate: this fixes the contract they will be built against,
//! and it fails today if the framework's routing does not actually support it.

use rtc_interceptor::{
    Interceptor, NoopInterceptor, Registry, StreamInfo, TaggedPacket, interceptor,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------
// Markers
// ---------------------------------------------------------------------------------------

/// What a marker observed. Shared so assertions can read it after the chain has consumed it.
#[derive(Default)]
struct Counts {
    reads: AtomicUsize,
    writes: AtomicUsize,
    /// Nanoseconds since the test epoch of the last packet seen on the write path, so a test can
    /// assert *which* instant a packet carried when it passed this layer.
    last_write_offset_nanos: AtomicUsize,
    last_read_offset_nanos: AtomicUsize,
}

impl Counts {
    fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
    fn writes(&self) -> usize {
        self.writes.load(Ordering::Acquire)
    }
}

/// A pass-through interceptor that counts what reaches it.
///
/// This is the whole measuring apparatus: it forwards everything untouched, so inserting one
/// changes nothing about the chain's behaviour, and its counts answer "did this layer see the
/// packet, and how many times".
#[derive(Interceptor)]
struct Marker<P> {
    #[next]
    inner: P,
    counts: Arc<Counts>,
    epoch: Instant,
}

impl<P> Marker<P> {
    fn new(inner: P, counts: Arc<Counts>, epoch: Instant) -> Self {
        Self {
            inner,
            counts,
            epoch,
        }
    }
}

#[interceptor]
impl<P: Interceptor> Marker<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.counts.reads.fetch_add(1, Ordering::AcqRel);
        self.counts.last_read_offset_nanos.store(
            msg.now.saturating_duration_since(self.epoch).as_nanos() as usize,
            Ordering::Release,
        );
        self.inner.handle_read(msg)
    }

    #[overrides]
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.counts.writes.fetch_add(1, Ordering::AcqRel);
        self.counts.last_write_offset_nanos.store(
            msg.now.saturating_duration_since(self.epoch).as_nanos() as usize,
            Ordering::Release,
        );
        self.inner.handle_write(msg)
    }
}

// ---------------------------------------------------------------------------------------
// The delaying interceptor under test — models a pacer / jitter buffer
// ---------------------------------------------------------------------------------------

/// Holds each packet for `delay`, then releases it on `handle_timeout`.
///
/// `Route::Reinject` is the contract (rule 2); `Route::LocalQueue` is the terminal shape
/// (rule 1). Having both in one interceptor is what lets the tests show that the difference is
/// observable, rather than asserting one and assuming the other.
#[derive(Clone, Copy, PartialEq)]
enum Route {
    Reinject,
    LocalQueue,
}

#[derive(Interceptor)]
struct Delayer<P> {
    #[next]
    inner: P,
    delay: Duration,
    route: Route,
    /// (release deadline, packet) in arrival order.
    pending_writes: VecDeque<(Instant, TaggedPacket)>,
    pending_reads: VecDeque<(Instant, TaggedPacket)>,
    /// Released packets awaiting collection, used only by `Route::LocalQueue`.
    local_writes: VecDeque<TaggedPacket>,
    local_reads: VecDeque<TaggedPacket>,
}

impl<P> Delayer<P> {
    fn new(inner: P, delay: Duration, route: Route) -> Self {
        Self {
            inner,
            delay,
            route,
            pending_writes: VecDeque::new(),
            pending_reads: VecDeque::new(),
            local_writes: VecDeque::new(),
            local_reads: VecDeque::new(),
        }
    }
}

#[interceptor]
impl<P: Interceptor> Delayer<P> {
    #[overrides]
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Held, not forwarded: nothing below sees it until the deadline.
        self.pending_writes.push_back((msg.now + self.delay, msg));
        Ok(())
    }

    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.pending_reads.push_back((msg.now + self.delay, msg));
        Ok(())
    }

    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        while let Some((deadline, _)) = self.pending_writes.front() {
            if *deadline > now {
                break;
            }
            let (_, mut msg) = self.pending_writes.pop_front().expect("front just checked");
            // Rule 3: the packet departs *now*, not when the application enqueued it.
            msg.now = now;
            match self.route {
                Route::Reinject => self.inner.handle_write(msg)?,
                Route::LocalQueue => self.local_writes.push_back(msg),
            }
        }

        while let Some((deadline, _)) = self.pending_reads.front() {
            if *deadline > now {
                break;
            }
            let (_, mut msg) = self.pending_reads.pop_front().expect("front just checked");
            msg.now = now;
            match self.route {
                Route::Reinject => self.inner.handle_read(msg)?,
                Route::LocalQueue => self.local_reads.push_back(msg),
            }
        }

        self.inner.handle_timeout(now)
    }

    #[overrides]
    fn poll_write(&mut self) -> Option<Self::Wout> {
        // A locally queued packet is returned *instead of* delegating inward — which is precisely
        // why it never reaches the layers below (rule 1).
        if let Some(pkt) = self.local_writes.pop_front() {
            return Some(pkt);
        }
        self.inner.poll_write()
    }

    #[overrides]
    fn poll_read(&mut self) -> Option<Self::Rout> {
        if let Some(pkt) = self.local_reads.pop_front() {
            return Some(pkt);
        }
        self.inner.poll_read()
    }

    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        // Rule 3 of the delivery rules: the earliest deadline we are actually waiting on, and
        // `None` when idle — never a stale instant that would spin the driver (webrtc#862).
        let mine = self
            .pending_writes
            .front()
            .map(|(deadline, _)| *deadline)
            .into_iter()
            .chain(self.pending_reads.front().map(|(deadline, _)| *deadline))
            .min();

        match (mine, self.inner.poll_timeout()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn rtp_packet(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: rtc_interceptor::Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                sequence_number,
                ..Default::default()
            },
            ..Default::default()
        }),
    }
}

fn sequence_number_of(pkt: &TaggedPacket) -> Option<u16> {
    match &pkt.message {
        rtc_interceptor::Packet::Rtp(p) => Some(p.header.sequence_number),
        _ => None,
    }
}

/// Chain: `Delayer` wrapping `Marker`(below) — plus a `Marker` above, so a test can tell
/// "reached the layer below the delayer" from "was returned to the caller".
///
/// Built innermost-first, per `Registry::with`.
fn chain(
    delay: Duration,
    route: Route,
    epoch: Instant,
) -> (
    impl Interceptor,
    Arc<Counts>, // below the delayer
    Arc<Counts>, // above the delayer
) {
    let below = Arc::new(Counts::default());
    let above = Arc::new(Counts::default());

    let (b, a) = (Arc::clone(&below), Arc::clone(&above));
    let chain = Registry::new()
        .with(move |inner: NoopInterceptor| Marker::new(inner, b, epoch))
        .with(move |inner| Delayer::new(inner, delay, route))
        .with(move |inner| Marker::new(inner, a, epoch))
        .build();

    (chain, below, above)
}

// ---------------------------------------------------------------------------------------
// Rule 2 — re-injected packets traverse downstream layers exactly once
// ---------------------------------------------------------------------------------------

#[test]
fn a_reinjected_write_traverses_the_layer_below_exactly_once() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, above) = chain(delay, Route::Reinject, epoch);

    chain
        .handle_write(rtp_packet(epoch, 1))
        .expect("handle_write");

    assert_eq!(1, above.writes(), "the outer marker sees it on the way in");
    assert_eq!(
        0,
        below.writes(),
        "held by the delayer: nothing below has seen it yet"
    );
    assert!(
        chain.poll_write().is_none(),
        "nothing is released before the deadline"
    );

    // Before the deadline: still held.
    chain
        .handle_timeout(epoch + Duration::from_millis(10))
        .expect("handle_timeout");
    assert_eq!(0, below.writes(), "deadline has not arrived");

    // At the deadline: released downward.
    chain.handle_timeout(epoch + delay).expect("handle_timeout");
    assert_eq!(
        1,
        below.writes(),
        "released through `inner.handle_write`, so the layer below sees it — exactly once"
    );

    let released = chain.poll_write().expect("the packet is collectable");
    assert_eq!(Some(1), sequence_number_of(&released));
    assert!(
        chain.poll_write().is_none(),
        "exactly one packet comes out; re-injecting must not also leave a local copy"
    );

    // Draining must not re-deliver it to the layer below.
    assert_eq!(1, below.writes(), "no second traversal on collection");
}

#[test]
fn a_reinjected_read_traverses_the_layer_below_exactly_once() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, above) = chain(delay, Route::Reinject, epoch);

    chain
        .handle_read(rtp_packet(epoch, 7))
        .expect("handle_read");

    assert_eq!(1, above.reads());
    assert_eq!(0, below.reads(), "held by the delayer");

    chain.handle_timeout(epoch + delay).expect("handle_timeout");
    assert_eq!(
        1,
        below.reads(),
        "a released read packet continues through downstream receive processing"
    );

    let released = chain.poll_read().expect("the packet is collectable");
    assert_eq!(Some(7), sequence_number_of(&released));
    assert!(chain.poll_read().is_none(), "exactly one packet comes out");
    assert_eq!(1, below.reads(), "no second traversal on collection");
}

#[test]
fn several_packets_each_traverse_the_layer_below_exactly_once() {
    // One packet cannot distinguish "forwarded once" from "forwarded once per release pass".
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, _above) = chain(delay, Route::Reinject, epoch);

    for sequence_number in 0..5 {
        chain
            .handle_write(rtp_packet(epoch, sequence_number))
            .expect("handle_write");
    }
    assert_eq!(0, below.writes());

    chain.handle_timeout(epoch + delay).expect("handle_timeout");
    assert_eq!(5, below.writes(), "five packets, five traversals");

    let mut collected = Vec::new();
    while let Some(pkt) = chain.poll_write() {
        collected.push(sequence_number_of(&pkt).expect("rtp"));
    }
    assert_eq!(
        vec![0, 1, 2, 3, 4],
        collected,
        "released in arrival order, each exactly once"
    );
    assert_eq!(5, below.writes(), "collection adds no traversals");
}

// ---------------------------------------------------------------------------------------
// Rule 1 — locally queued packets are terminal
// ---------------------------------------------------------------------------------------

#[test]
fn a_locally_queued_packet_does_not_re_enter_the_layers_below() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, _above) = chain(delay, Route::LocalQueue, epoch);

    chain
        .handle_write(rtp_packet(epoch, 3))
        .expect("handle_write");
    chain.handle_timeout(epoch + delay).expect("handle_timeout");

    // This is the property that makes rule 1 a real choice rather than a description: the packet
    // *is* delivered to the caller, but it skipped the layer below entirely.
    let released = chain.poll_write().expect("still reaches the caller");
    assert_eq!(Some(3), sequence_number_of(&released));
    assert_eq!(
        0,
        below.writes(),
        "a locally queued packet bypasses `inner` — that is why it is only correct when \
         downstream processing is genuinely complete"
    );
    assert!(chain.poll_write().is_none(), "not delivered twice either");
}

#[test]
fn a_locally_queued_read_packet_does_not_re_enter_the_layers_below() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, _above) = chain(delay, Route::LocalQueue, epoch);

    chain
        .handle_read(rtp_packet(epoch, 9))
        .expect("handle_read");
    chain.handle_timeout(epoch + delay).expect("handle_timeout");

    let released = chain.poll_read().expect("still reaches the caller");
    assert_eq!(Some(9), sequence_number_of(&released));
    assert_eq!(0, below.reads(), "bypassed the layer below");
}

// ---------------------------------------------------------------------------------------
// Rule 3 — departure is recorded at release, not at enqueue
// ---------------------------------------------------------------------------------------

#[test]
fn the_layer_below_a_pacer_observes_the_release_instant_not_the_enqueue_instant() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, below, above) = chain(delay, Route::Reinject, epoch);

    // The application enqueues at the epoch.
    chain
        .handle_write(rtp_packet(epoch, 1))
        .expect("handle_write");
    assert_eq!(
        0,
        above.last_write_offset_nanos.load(Ordering::Acquire),
        "above the pacer, the packet still carries its enqueue instant"
    );

    let release = epoch + delay;
    chain.handle_timeout(release).expect("handle_timeout");

    let observed = below.last_write_offset_nanos.load(Ordering::Acquire);
    assert_eq!(
        delay.as_nanos() as usize,
        observed,
        "a send history below the pacer must record departure at the release instant; recording \
         the enqueue instant would charge the pacer's own buffering delay to the network"
    );

    // And the packet handed back to the caller carries it too, so a transport-level history sees
    // the same instant as an interceptor-level one.
    let released = chain.poll_write().expect("collectable");
    assert_eq!(
        delay,
        released.now.saturating_duration_since(epoch),
        "the released packet itself carries the release instant"
    );
}

#[test]
fn a_released_read_packet_carries_the_release_instant() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(30);
    let (mut chain, below, _above) = chain(delay, Route::Reinject, epoch);

    chain
        .handle_read(rtp_packet(epoch, 2))
        .expect("handle_read");
    chain.handle_timeout(epoch + delay).expect("handle_timeout");

    assert_eq!(
        delay.as_nanos() as usize,
        below.last_read_offset_nanos.load(Ordering::Acquire),
        "a jitter buffer's own holding time is not arrival jitter"
    );
}

// ---------------------------------------------------------------------------------------
// Delivery rule 3 — `poll_timeout` is `None` when idle and always advances
// ---------------------------------------------------------------------------------------

#[test]
fn poll_timeout_is_none_when_idle_and_advances_when_armed() {
    let epoch = Instant::now();
    let delay = Duration::from_millis(20);
    let (mut chain, _below, _above) = chain(delay, Route::Reinject, epoch);

    assert!(
        chain.poll_timeout().is_none(),
        "nothing buffered: an idle chain must not ask to be woken (webrtc#862)"
    );

    chain
        .handle_write(rtp_packet(epoch, 1))
        .expect("handle_write");
    let armed = chain.poll_timeout().expect("armed once a packet is held");
    assert_eq!(
        epoch + delay,
        armed,
        "the deadline is the release instant, which is strictly in the future"
    );

    chain.handle_timeout(armed).expect("handle_timeout");
    assert!(
        chain.poll_timeout().is_none(),
        "after the queue drains the chain is idle again — a repeated past instant is the \
         busy-loop this rule exists to prevent"
    );
}
