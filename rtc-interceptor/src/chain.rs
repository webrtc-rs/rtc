//! The interceptor chain: a flat list walked directionally over a shared belt.
//!
//! # The model
//!
//! Interceptors are held in one list ordered by **distance from the wire** — index 0 is closest to
//! the network, the last index closest to the application. Direction is a property of the walk,
//! not of the structure:
//!
//! ```text
//! read   (network → application)   walk forward:  0 → 1 → 2 → … → N
//! write  (application → network)   walk reverse:  N → … → 2 → 1 → 0
//! ```
//!
//! Each interceptor is fed from a belt and its output is collected back onto it, so **what an
//! interceptor emits is seen by every interceptor still ahead of it in the walk**. That is the
//! whole point: a retransmission emitted mid-chain still gets paced, tagged and recorded, because
//! there is no way out of the chain except through the interceptors that follow.
//!
//! The same list serves both directions, so "closest to the wire" means one thing rather than
//! opposite things per direction — the send history and FEC decode both sit near index 0, one
//! being the last thing on the way out and the other the first on the way in.
//!
//! # Ordering
//!
//! | # | Interceptor | Why there |
//! |---|---|---|
//! | 0 | packet dump | observation at the wire: last to see a departure, first to see an arrival |
//! | 1 | congestion control — send history, feedback ingest | records what actually left, after everything |
//! | 2 | TWCC sender | tags every departing packet, before the history keys on it |
//! | 3 | pacer | gates departures; everything that generates a packet sits above it |
//! | 4 | NACK responder | its retransmissions reach 3, 2, 1, 0 |
//! | 5 | FEC encoder | its repair packets reach 4, 3, 2, 1, 0 |
//! | 6 | FEC decoder | recovery before anything inspects sequence numbers |
//! | 7 | NACK generator | loss detected from arrivals, not from released packets |
//! | 8–10 | TWCC receiver, RFC 8888, RTCP receiver reports | **arrival recorders — must precede the jitter buffer** |
//! | 11–12 | RTCP sender reports, interval PLI | generators with no read-side ordering constraint |
//! | 13 | jitter buffer | delays and re-stamps; releases toward the application |
//!
//! TWCC receiver and RFC 8888 do the same job in different formats — a chain carries one or the
//! other — so they are listed together; the receiver reports beside them are RFC 3550 reception
//! quality, not congestion-control feedback. Their order relative to each other does not matter.
//!
//! Arrival recorders precede the jitter buffer because the buffer re-stamps a packet with its
//! *release* instant. A recorder below it would report local playout times to the remote as
//! arrival times, and the remote's congestion controller would read this endpoint's buffering
//! depth as network delay variation.

use crate::Interceptor;
use crate::TaggedPacket;
use crate::stream_info::StreamInfo;
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// A flat list of interceptors, driven as one [`Protocol`].
///
/// The chain is the interceptor too; the interceptors are interceptors inside it.
#[derive(Default)]
pub(crate) struct Chain {
    /// Ordered by distance from the wire: index 0 is closest to the network.
    interceptors: Vec<Box<dyn Interceptor>>,
    read_outs: VecDeque<TaggedPacket>,
    write_outs: VecDeque<TaggedPacket>,
    /// Which interceptors only pass outgoing packets along (`Interceptor::writes_pass_through`),
    /// in the same order as `interceptors`.
    write_pass_through: Vec<bool>,
    /// The belt of a walk, kept between walks so that a packet does not allocate one.
    belt: VecDeque<TaggedPacket>,
    /// Every interceptor has been polled for reads since the last input that could give one
    /// something to emit, so polling again would only find the queues empty.
    read_idle: bool,
    /// The same for writes.
    write_idle: bool,
}

impl Chain {
    /// Build a chain from interceptors already in wire-to-application order.
    ///
    /// Crate-private: a chain is built by [`Registry`](crate::Registry), which also appends the
    /// terminus that ends the inbound RTCP path. A caller assembling the vector directly could
    /// leave it out, and the omission would look like working code.
    pub(crate) fn new(interceptors: Vec<Box<dyn Interceptor>>) -> Self {
        Self {
            write_pass_through: interceptors
                .iter()
                .map(|i| i.writes_pass_through())
                .collect(),
            interceptors,
            ..Self::default()
        }
    }

    /// How many interceptors the chain has.
    pub(crate) fn len(&self) -> usize {
        self.interceptors.len()
    }

    /// Whether the chain has no interceptors.
    pub(crate) fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    /// One pass over `interceptors`, feeding each from the belt and collecting what it emits back onto
    /// the belt.
    ///
    /// `handle` and `poll` pick the direction's method pair; the iterator picks the direction. A
    /// packet an interceptor emits lands on the belt *behind* the ones it passed through, and is then
    /// carried to every interceptor still ahead — which is what makes injected packets impossible to
    /// bypass with.
    fn walk<'a>(
        interceptors: impl Iterator<Item = &'a mut Box<dyn Interceptor>>,
        belt: &mut VecDeque<TaggedPacket>,
        handle: fn(&mut dyn Interceptor, TaggedPacket) -> Result<(), Error>,
        poll: fn(&mut dyn Interceptor) -> Option<TaggedPacket>,
    ) {
        for interceptor in interceptors {
            while let Some(next) = belt.pop_front() {
                // An interceptor takes the packet and decides what becomes of it: hold it, drop
                // it, or put it on its own queue to be collected below.
                if let Err(err) = handle(interceptor.as_mut(), next) {
                    log::warn!("interceptor handle failed: {err}");
                }
            }
            // Whatever it has ready — passed through, transformed, generated, or released — is
            // what the next interceptor in the walk receives.
            while let Some(next) = poll(interceptor.as_mut()) {
                belt.push_back(next);
            }
        }
    }

    /// A walk over the whole chain in the read direction, starting from `first` if there is one.
    fn walk_read(&mut self, first: Option<TaggedPacket>) {
        let mut belt = std::mem::take(&mut self.belt);
        belt.extend(first);
        Self::walk(
            self.interceptors.iter_mut(),
            &mut belt,
            |s, p| s.handle_read(p),
            |s| s.poll_read(),
        );
        self.read_outs.append(&mut belt);
        self.belt = belt;
        self.read_idle = true;
    }

    /// A walk over the whole chain in the write direction, starting from `first` if there is one.
    ///
    /// When every interceptor has been polled and none has anything waiting (`write_idle`), one
    /// that only passes packets along cannot change what a packet becomes, so a packet skips it.
    fn walk_write(&mut self, first: Option<TaggedPacket>) {
        let mut belt = std::mem::take(&mut self.belt);
        belt.extend(first);
        let skip = self.write_idle && !belt.is_empty();
        let pass_through = &self.write_pass_through;
        Self::walk(
            self.interceptors
                .iter_mut()
                .zip(pass_through)
                .rev()
                .filter(|(_, pass)| !(skip && **pass))
                .map(|(interceptor, _)| interceptor),
            &mut belt,
            |s, p| s.handle_write(p),
            |s| s.poll_write(),
        );
        self.write_outs.append(&mut belt);
        self.belt = belt;
        self.write_idle = true;
    }

    /// Something other than a packet moved (time, a stream bound or unbound): any interceptor may
    /// have something to emit now.
    fn wake(&mut self) {
        self.read_idle = false;
        self.write_idle = false;
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Chain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.walk_read(Some(msg));
        // What was read may have asked for something to be sent: a retransmission, a keyframe.
        self.write_idle = false;
        Ok(())
    }

    /// Walks with an **empty belt** when something other than a packet has moved, because a jitter
    /// buffer may have released a packet on `handle_timeout` with no inbound packet since to carry it
    /// forward. After a walk that polled every interceptor, and until the next such event, there is
    /// nothing more to find, so the walk is skipped.
    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.read_outs.is_empty() && !self.read_idle {
            self.walk_read(None);
        }
        self.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.walk_write(Some(msg));
        Ok(())
    }

    /// Same reason as [`poll_read`](Self::poll_read): the pacer releases on a timeout, and
    /// generated RTCP appears with no outbound packet to ride along with.
    fn poll_write(&mut self) -> Option<Self::Wout> {
        if self.write_outs.is_empty() && !self.write_idle {
            self.walk_write(None);
        }
        self.write_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.handle_timeout(now)?;
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.interceptors
            .iter_mut()
            .filter_map(|interceptor| interceptor.poll_timeout())
            .min()
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.close()?;
        }
        Ok(())
    }
}

/// A chain is itself an interceptor: it implements the same `Protocol`, and binding a stream
/// on it binds that stream on every interceptor inside it.
impl Interceptor for Chain {
    /// A local stream this endpoint is now sending.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.bind_local_stream(info);
        }
    }

    /// A local stream this endpoint has stopped sending.
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.unbind_local_stream(info);
        }
    }

    /// A remote stream this endpoint is now receiving.
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.bind_remote_stream(info);
        }
    }

    /// A remote stream this endpoint has stopped receiving.
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.wake();
        for interceptor in self.interceptors.iter_mut() {
            interceptor.unbind_remote_stream(info);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{AttributedPacket, Packet};
    use shared::TransportContext;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Passes packets through, counts how often it is polled, and emits one extra packet to the
    /// wire when time passes, when something is read or when a stream is bound.
    struct Probe {
        pass_through: bool,
        handled: Arc<AtomicUsize>,
        polls: Arc<AtomicUsize>,
        read_queue: VecDeque<TaggedPacket>,
        write_queue: VecDeque<TaggedPacket>,
    }

    impl Probe {
        fn new(polls: &Arc<AtomicUsize>) -> Self {
            Self {
                pass_through: false,
                handled: Arc::new(AtomicUsize::new(0)),
                polls: polls.clone(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            }
        }
    }

    fn packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(Vec::new())),
        }
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Probe {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Error> {
            self.read_queue.push_back(msg);
            self.write_queue.push_back(packet());
            Ok(())
        }
        fn poll_read(&mut self) -> Option<TaggedPacket> {
            self.read_queue.pop_front()
        }
        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Error> {
            self.handled.fetch_add(1, Ordering::Relaxed);
            self.write_queue.push_back(msg);
            Ok(())
        }
        fn poll_write(&mut self) -> Option<TaggedPacket> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            self.write_queue.pop_front()
        }
        fn handle_timeout(&mut self, _now: Instant) -> Result<(), Error> {
            self.write_queue.push_back(packet());
            Ok(())
        }
        fn poll_timeout(&mut self) -> Option<Instant> {
            None
        }
    }

    impl Interceptor for Probe {
        fn writes_pass_through(&self) -> bool {
            self.pass_through
        }
        fn bind_local_stream(&mut self, _info: &StreamInfo) {
            self.write_queue.push_back(packet());
        }
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
    }

    fn chain(polls: &Arc<AtomicUsize>) -> Chain {
        Chain::new(vec![
            Box::new(Probe::new(polls)),
            Box::new(Probe::new(polls)),
        ])
    }

    fn drain(chain: &mut Chain) -> usize {
        std::iter::from_fn(|| chain.poll_write()).count()
    }

    /// The walk a write makes has polled every interceptor already; asking again for what is ready
    /// does not walk the chain a second time.
    #[test]
    fn a_written_packet_is_not_followed_by_a_second_walk() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut chain = chain(&polls);
        chain.handle_write(packet()).unwrap();
        // Each of the two interceptors is polled until it has nothing: twice for the packet and
        // once to find it gone.
        let walked = polls.load(Ordering::Relaxed);
        assert_eq!(drain(&mut chain), 1);
        assert_eq!(polls.load(Ordering::Relaxed), walked);
    }

    #[test]
    fn a_packet_emitted_on_a_timeout_is_found_after_writes_have_settled() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut chain = chain(&polls);
        chain.handle_write(packet()).unwrap();
        assert_eq!(drain(&mut chain), 1);
        chain.handle_timeout(Instant::now()).unwrap();
        // One from each interceptor.
        assert_eq!(drain(&mut chain), 2);
        assert_eq!(drain(&mut chain), 0);
    }

    #[test]
    fn a_packet_a_read_asks_to_send_is_found_after_writes_have_settled() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut chain = chain(&polls);
        chain.handle_write(packet()).unwrap();
        assert_eq!(drain(&mut chain), 1);
        chain.handle_read(packet()).unwrap();
        // The read goes up through both interceptors and each answers with a packet.
        assert_eq!(drain(&mut chain), 2);
        assert_eq!(chain.poll_read().map(|_| ()), Some(()));
    }

    #[test]
    fn a_packet_emitted_when_a_stream_is_bound_is_found_after_writes_have_settled() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut chain = chain(&polls);
        chain.handle_write(packet()).unwrap();
        assert_eq!(drain(&mut chain), 1);
        chain.bind_local_stream(&StreamInfo::default());
        assert_eq!(drain(&mut chain), 2);
    }

    /// Nothing is found twice, and a new belt is not needed for each packet.
    #[test]
    fn the_belt_is_reused() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut chain = chain(&polls);
        chain.handle_write(packet()).unwrap();
        drain(&mut chain);
        let capacity = chain.belt.capacity();
        assert!(capacity > 0);
        for _ in 0..100 {
            chain.handle_write(packet()).unwrap();
            assert_eq!(drain(&mut chain), 1);
        }
        assert_eq!(chain.belt.capacity(), capacity);
    }

    /// An interceptor that only passes packets along is not handed an outgoing packet while the
    /// chain is idle, and is again once something wakes the chain (its own packets come first).
    #[test]
    fn a_pass_through_interceptor_is_skipped_only_while_the_chain_is_idle() {
        let polls = Arc::new(AtomicUsize::new(0));
        let (mut wire, mut middle, mut app) =
            (Probe::new(&polls), Probe::new(&polls), Probe::new(&polls));
        middle.pass_through = true;
        let (wire_saw, middle_saw, app_saw) = (
            wire.handled.clone(),
            middle.handled.clone(),
            app.handled.clone(),
        );
        wire.pass_through = false;
        app.pass_through = false;
        let mut chain = Chain::new(vec![Box::new(wire), Box::new(middle), Box::new(app)]);
        let seen = || {
            (
                wire_saw.load(Ordering::Relaxed),
                middle_saw.load(Ordering::Relaxed),
                app_saw.load(Ordering::Relaxed),
            )
        };

        // Nothing has been polled yet: the first packet takes the whole walk.
        chain.handle_write(packet()).unwrap();
        assert_eq!(seen(), (1, 1, 1));
        assert_eq!(drain(&mut chain), 1);

        // The chain is idle now: the next ones skip the middle.
        for _ in 0..3 {
            chain.handle_write(packet()).unwrap();
        }
        assert_eq!(seen(), (4, 1, 4));
        assert_eq!(drain(&mut chain), 3);

        // A timeout wakes it: the next packet goes through all three, and so do the packets they
        // emitted. All four reach the wire.
        let before = seen();
        chain.handle_timeout(Instant::now()).unwrap();
        chain.handle_write(packet()).unwrap();
        let woken = seen();
        assert!(woken.1 > before.1, "the middle was skipped on a full walk");
        assert_eq!(drain(&mut chain), 4);

        // And it is idle again afterwards.
        chain.handle_write(packet()).unwrap();
        assert_eq!(seen().1, woken.1);
        assert_eq!(seen().0, woken.0 + 1);
    }
}
