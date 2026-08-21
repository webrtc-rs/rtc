//! Building a chain.

use crate::chain::Chain;
use crate::noop::NoopInterceptor;
use crate::{BoxedInterceptor, Interceptor};

/// Collects interceptors and assembles them into an [`Chain`].
///
/// # Order
///
/// Interceptors run in the order they are added, measured by **distance from the wire**: the first is
/// closest to the network, the last closest to the application. Read walks that order, write walks
/// it in reverse, so one list serves both directions and "closest to the wire" means one thing
/// rather than opposite things per direction.
///
/// ```text
/// Registry::new()
///     .with(a)   // closest to the wire
///     .with(b)
///     .with(c)   // closest to the application
///     .build()
///
/// read:   a → b → c → application
/// write:  application → c → b → a → wire
/// ```
///
/// A registry reads the way the chain runs, so getting the order right is a matter of reading it
/// top to bottom. The nested registry it replaces added *innermost* first, which meant the list
/// ran application-to-network on read and the composed order was the reverse of what the file
/// looked like — `register_default_interceptors` ended up assembling TWCC receiver → RTCP reports
/// → NACK generator, the opposite of what the chain contract documented, with nothing to catch it.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{NackGeneratorBuilder, Registry, TwccSenderBuilder};
///
/// let chain = Registry::new()
///     .with(TwccSenderBuilder::new().build())     // closest to the wire
///     .with(NackGeneratorBuilder::new().build())  // sees arrivals after it
///     .build();                                   // the terminus is appended here
/// # let _ = chain;
/// ```
#[derive(Default)]
pub struct Registry {
    interceptors: Vec<Box<dyn Interceptor>>,
    rtcp_readable: bool,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interceptor on the application side of everything added so far.
    pub fn with(mut self, interceptor: impl Interceptor + 'static) -> Self {
        self.interceptors.push(Box::new(interceptor));
        self
    }

    /// Add an interceptor that is already boxed, for a caller assembling a chain dynamically.
    pub fn with_boxed(mut self, boxed_interceptor: BoxedInterceptor) -> Self {
        self.interceptors.push(boxed_interceptor);
        self
    }

    /// Make inbound RTCP readable by the application — it arrives from
    /// [`poll_read`](sansio::Protocol::poll_read) like media does — as well as acted on by the
    /// interceptors.
    ///
    /// Off by default. RTCP is control traffic the interceptors act on: a receiver report feeds
    /// the sender statistics, a NACK is answered by the responder, transport-wide feedback drives
    /// the bandwidth estimate. An application that did not ask for it would find a stream of
    /// packets it cannot use interleaved with its media. Turn it on for an SFU relaying feedback,
    /// or a tool inspecting a session.
    ///
    /// Outbound RTCP is unaffected; this is only about what arrives.
    ///
    /// It has to be asked for here rather than arranged by an interceptor of your own. One that
    /// captured an RTCP packet and re-emitted it from `poll_read` would put the copy back on the
    /// belt *behind* itself, where [`NoopInterceptor`] is still ahead of it and drops it — the
    /// original and the copy both. The nested chain allowed that trick because a local `poll_read`
    /// queue was terminal and bypassed everything below it, which is precisely the bypass this
    /// design removes.
    pub fn with_rtcp_readable(mut self) -> Self {
        self.rtcp_readable = true;
        self
    }

    /// Assemble the interceptor chain.
    ///
    /// [`NoopInterceptor`] is appended last, so every chain decides what becomes of inbound RTCP.
    /// That is a property of a chain rather than something a caller opts into: left out, an
    /// application would get a stream of control traffic it never asked for, and the omission
    /// would look like working code. [`with_rtcp_readable`] is how a chain asks for it deliberately.
    ///
    /// [`with_rtcp_readable`]: Registry::with_rtcp_readable
    pub fn build(mut self) -> impl Interceptor {
        self.interceptors
            .push(Box::new(NoopInterceptor::new(self.rtcp_readable)));
        Chain::new(self.interceptors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StreamInfo;
    use crate::{AttributedPacket, Packet, TaggedPacket};
    use sansio::Protocol;
    use shared::TransportContext;
    use shared::error::Error;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<&'static str>>>);

    struct Marker {
        name: &'static str,
        log: Log,
        read_queue: VecDeque<TaggedPacket>,
        write_queue: VecDeque<TaggedPacket>,
    }

    impl Marker {
        fn new(name: &'static str, log: Log) -> Self {
            Self {
                name,
                log,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            }
        }
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Marker {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.log.0.lock().unwrap().push(self.name);
            self.read_queue.push_back(msg);
            Ok(())
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.read_queue.pop_front()
        }

        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.log.0.lock().unwrap().push(self.name);
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

    impl Interceptor for Marker {
        fn bind_local_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
    }

    fn packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
        }
    }

    fn chain(log: &Log) -> impl Interceptor {
        Registry::new()
            .with(Marker::new("wire", log.clone()))
            .with(Marker::new("middle", log.clone()))
            .with(Marker::new("app", log.clone()))
            .build()
    }

    /// Read runs the list forwards: the first interceptor added is closest to the wire.
    #[test]
    fn read_runs_in_the_order_stages_were_added() {
        let log = Log::default();
        let mut chain = chain(&log);

        chain.handle_read(packet()).unwrap();
        while chain.poll_read().is_some() {}

        assert_eq!(vec!["wire", "middle", "app"], *log.0.lock().unwrap());
    }

    /// Write runs it backwards, so the same list describes both directions.
    #[test]
    fn write_runs_in_reverse() {
        let log = Log::default();
        let mut chain = chain(&log);

        chain.handle_write(packet()).unwrap();
        while chain.poll_write().is_some() {}

        assert_eq!(vec!["app", "middle", "wire"], *log.0.lock().unwrap());
    }

    /// Ending the inbound RTCP path is a property of every chain, not something a caller adds.
    #[test]
    fn a_registry_with_nothing_added_still_has_the_terminus() {
        let mut chain = Registry::new().build();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![])),
            })
            .unwrap();
        assert!(
            chain.poll_read().is_none(),
            "inbound RTCP stops before the application"
        );
    }

    /// The terminus goes last, so every interceptor sees inbound RTCP before it is dropped.
    #[test]
    fn the_terminus_is_application_most() {
        let log = Log::default();
        let mut chain = Registry::new()
            .with(Marker::new("wire", log.clone()))
            .build();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![])),
            })
            .unwrap();

        assert_eq!(
            vec!["wire"],
            *log.0.lock().unwrap(),
            "the stage saw the RTCP packet; the terminus dropped it afterwards"
        );
        assert!(chain.poll_read().is_none());
    }
}
