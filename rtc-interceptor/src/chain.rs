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
//! | 0 | congestion control — send history, feedback ingest | records what actually left, after everything |
//! | 1 | TWCC sender | tags every departing packet, before the history keys on it |
//! | 2 | pacer | gates departures; everything that generates a packet sits above it |
//! | 3 | NACK responder | its retransmissions reach 2, 1, 0 |
//! | 4 | FEC encoder | its repair packets reach 3, 2, 1, 0 |
//! | 5 | FEC decoder | recovery before anything inspects sequence numbers |
//! | 6 | NACK generator | loss detected from arrivals, not from released packets |
//! | 7–9 | TWCC receiver, RTCP receiver reports, RFC 8888 | **arrival recorders — must precede the jitter buffer** |
//! | 10–11 | RTCP sender reports, interval PLI | generators with no read-side ordering constraint |
//! | 12 | jitter buffer | delays and re-stamps; releases toward the application |
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
/// The chain is the protocol; the interceptors are interceptors inside it. `InterceptorChain` does not
/// itself implement [`Interceptor`], so chains cannot nest and there is exactly one belt.
#[derive(Default)]
pub(crate) struct InterceptorChain {
    /// Ordered by distance from the wire: index 0 is closest to the network.
    interceptors: Vec<Box<dyn Interceptor>>,
    read_outs: VecDeque<TaggedPacket>,
    write_outs: VecDeque<TaggedPacket>,
    event_outs: VecDeque<()>,
}

impl InterceptorChain {
    /// Build a chain from interceptors already in wire-to-application order.
    ///
    /// Crate-private: a chain is built by [`Registry`](crate::Registry), which also appends the
    /// terminus that ends the inbound RTCP path. A caller assembling the vector directly could
    /// leave it out, and the omission would look like working code.
    pub(crate) fn new(interceptors: Vec<Box<dyn Interceptor>>) -> Self {
        Self {
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
    fn walk<'a, T>(
        interceptors: impl Iterator<Item = &'a mut Box<dyn Interceptor>>,
        mut belt: VecDeque<T>,
        handle: fn(&mut dyn Interceptor, T) -> Result<(), Error>,
        poll: fn(&mut dyn Interceptor) -> Option<T>,
    ) -> VecDeque<T> {
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
        belt
    }

    fn drain_read(&mut self) {
        let belt = Self::walk(
            self.interceptors.iter_mut(),
            VecDeque::new(),
            |s, p| s.handle_read(p),
            |s| s.poll_read(),
        );
        self.read_outs.extend(belt);
    }

    fn drain_write(&mut self) {
        let belt = Self::walk(
            self.interceptors.iter_mut().rev(),
            VecDeque::new(),
            |s, p| s.handle_write(p),
            |s| s.poll_write(),
        );
        self.write_outs.extend(belt);
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for InterceptorChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let belt = Self::walk(
            self.interceptors.iter_mut(),
            VecDeque::from([msg]),
            |s, p| s.handle_read(p),
            |s| s.poll_read(),
        );
        self.read_outs.extend(belt);
        Ok(())
    }

    /// Walks with an **empty belt** when nothing is pending, because a jitter buffer may have
    /// released a packet on `handle_timeout` with no inbound packet since to carry it forward.
    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.read_outs.is_empty() {
            self.drain_read();
        }
        self.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let belt = Self::walk(
            self.interceptors.iter_mut().rev(),
            VecDeque::from([msg]),
            |s, p| s.handle_write(p),
            |s| s.poll_write(),
        );
        self.write_outs.extend(belt);
        Ok(())
    }

    /// Same reason as [`poll_read`](Self::poll_read): the pacer releases on a timeout, and
    /// generated RTCP appears with no outbound packet to ride along with.
    fn poll_write(&mut self) -> Option<Self::Wout> {
        if self.write_outs.is_empty() {
            self.drain_write();
        }
        self.write_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
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
        for interceptor in self.interceptors.iter_mut() {
            interceptor.close()?;
        }
        Ok(())
    }
}

/// A chain is itself an interceptor: it implements the same `Protocol`, and binding a stream
/// on it binds that stream on every interceptor inside it.
impl Interceptor for InterceptorChain {
    /// A local stream this endpoint is now sending.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        for interceptor in self.interceptors.iter_mut() {
            interceptor.bind_local_stream(info);
        }
    }

    /// A local stream this endpoint has stopped sending.
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for interceptor in self.interceptors.iter_mut() {
            interceptor.unbind_local_stream(info);
        }
    }

    /// A remote stream this endpoint is now receiving.
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        for interceptor in self.interceptors.iter_mut() {
            interceptor.bind_remote_stream(info);
        }
    }

    /// A remote stream this endpoint has stopped receiving.
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        for interceptor in self.interceptors.iter_mut() {
            interceptor.unbind_remote_stream(info);
        }
    }
}
