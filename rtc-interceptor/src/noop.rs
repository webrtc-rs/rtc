//! Where the inbound RTCP path ends.

use crate::Interceptor;
use crate::{Packet, StreamInfo, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// Decides what becomes of inbound RTCP once the interceptors have had it, and passes everything
/// else through.
///
/// # Why this exists
///
/// Inbound RTCP is **for the interceptors**: a receiver report feeds the sender-side statistics, a
/// NACK is answered by the responder, transport-wide feedback drives the bandwidth estimate.
/// Handing it onward by default would give an application a stream of control traffic it did not
/// ask for and cannot act on, mixed in with its media — so by default it stops here.
///
/// An application that *does* read RTCP asks for it when building the chain, with
/// [`Registry::with_rtcp_readable`](crate::Registry::with_rtcp_readable). See below for why that is
/// the only way to get it.
///
/// # Where this belongs in the chain
///
/// **Last**, so every interceptor that reads RTCP has already seen it by the time it is dropped.
/// Anywhere else it would starve the ones beyond it — a NACK responder placed after this would
/// never see a NACK. [`Registry::build`](crate::Registry::build) appends it for that reason,
/// rather than leaving the position to each caller.
///
/// # Why an interceptor of your own cannot do it instead
///
/// Under the nested chain an application could add an interceptor that kept a copy of each RTCP
/// packet and returned it from its own `poll_read` ahead of delegating inward. That worked because
/// a local `poll_read` queue was *terminal*: the copy bypassed everything below and escaped this
/// one.
///
/// On the belt it does not. What an interceptor emits from `poll_read` rejoins the belt **behind
/// itself**, so it arrives here like any other packet and is dropped like any other packet — the
/// original *and* the copy, twice over. Since this is always the last interceptor, no position
/// exists from which to forward past it, which is why the decision belongs to whoever builds the
/// chain rather than to an interceptor in it.
///
/// # Naming
///
/// It was a no-op in the nested chain, where its job was to terminate the recursion and hand
/// packets back. The belt needs no terminator, so all that is left is the one decision it always
/// quietly made.
#[derive(Default)]
pub struct NoopInterceptor {
    rtcp_readable: bool,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl NoopInterceptor {
    /// A terminus.
    ///
    /// `rtcp_readable` decides whether inbound RTCP carries on to the application after every
    /// interceptor has seen it. [`Registry::build`](crate::Registry::build) supplies it from
    /// [`Registry::with_rtcp_readable`](crate::Registry::with_rtcp_readable).
    pub fn new(rtcp_readable: bool) -> Self {
        Self {
            rtcp_readable,
            ..Default::default()
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NoopInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let keep = match msg.message.packet {
            Packet::Rtp(_) => true,
            // The end of the line for inbound control traffic, unless the chain asked for it.
            Packet::Rtcp(_) => self.rtcp_readable,
        };
        if keep {
            self.read_queue.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for NoopInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributedPacket, Registry, StreamInfo};
    use sansio::Protocol;
    use shared::TransportContext;
    use shared::error::Error;
    use std::collections::VecDeque;
    use std::time::Instant;

    fn packet(message: Packet) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(message),
        }
    }

    #[test]
    fn inbound_rtcp_does_not_reach_the_application() {
        let mut chain = Registry::new().build();

        chain.handle_read(packet(Packet::Rtcp(vec![]))).unwrap();
        assert!(chain.poll_read().is_none());
    }

    #[test]
    fn inbound_rtp_passes_through() {
        let mut chain = Registry::new().build();

        chain
            .handle_read(packet(Packet::Rtp(rtp::Packet::default())))
            .unwrap();
        assert!(chain.poll_read().is_some());
    }

    /// Outbound RTCP is untouched: this ends the *inbound* path only.
    #[test]
    fn outbound_rtcp_is_not_affected() {
        let mut chain = Registry::new().build();

        chain.handle_write(packet(Packet::Rtcp(vec![]))).unwrap();
        assert!(chain.poll_write().is_some());
    }

    /// An interceptor wire-ward of the terminus still sees inbound RTCP — that is the whole point of it
    /// being application-most.
    #[test]
    fn stages_before_it_still_see_inbound_rtcp() {
        #[derive(Default)]
        struct Counter {
            seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
            read_queue: VecDeque<TaggedPacket>,
            write_queue: VecDeque<TaggedPacket>,
        }
        impl Protocol<TaggedPacket, TaggedPacket, ()> for Counter {
            type Rout = TaggedPacket;
            type Wout = TaggedPacket;
            type Eout = ();
            type Error = Error;
            type Time = Instant;

            fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
                if matches!(msg.message.packet, Packet::Rtcp(_)) {
                    self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                self.read_queue.push_back(msg);
                Ok(())
            }

            fn poll_read(&mut self) -> Option<Self::Rout> {
                self.read_queue.pop_front()
            }

            fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
                self.write_queue.push_back(msg);
                Ok(())
            }

            fn poll_write(&mut self) -> Option<Self::Wout> {
                self.write_queue.pop_front()
            }

            fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_timeout(&mut self) -> Option<Self::Time> {
                None
            }
        }
        impl Interceptor for Counter {
            fn bind_local_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
            fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
        }
        let counter = Counter::default();
        let seen = counter.seen.clone();
        let mut chain = Registry::new().with(counter).build();

        chain.handle_read(packet(Packet::Rtcp(vec![]))).unwrap();

        assert_eq!(1, seen.load(std::sync::atomic::Ordering::Relaxed));
        assert!(chain.poll_read().is_none(), "but it stops at the terminus");
    }
}
