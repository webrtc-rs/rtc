//! Interceptor Registry - Type-safe builder for constructing interceptor chains.
//!
//! The [`Registry`] provides a fluent API for composing interceptor chains. Each call
//! to [`with()`](Registry::with) wraps the current chain with a new interceptor layer.
//!
//! # Chain Construction
//!
//! Interceptors are added from innermost to outermost. The first interceptor added
//! becomes the innermost (closest to [`NoopInterceptor`](crate::NoopInterceptor)),
//! and the last becomes the outermost (processes packets first).
//!
//! ```text
//! Registry::new()
//!     .with(InterceptorA)  // Innermost
//!     .with(InterceptorB)  // Middle
//!     .with(InterceptorC)  // Outermost
//!     .build()
//!
//! Results in: C wraps B wraps A wraps NoopInterceptor
//! ```
//!
//! # The chain contract
//!
//! Interceptors that only transform the packet in front of them compose in any order. The ones
//! that **delay** a packet (a jitter buffer, a pacer) or **generate** one (an RTCP report, a FEC
//! repair packet, a recovered packet) do not: for those, where the packet re-enters the chain is
//! a correctness property, not a preference. This section is the contract they are written
//! against. It is verified by `tests/chain_order.rs`, which is where to look for what each rule
//! means in practice.
//!
//! ## Rule 1 — a local `poll_*` queue is terminal
//!
//! `handle_*` and `poll_*` both walk **outer → inner**. An interceptor that returns a packet from
//! its own queue in `poll_read`/`poll_write` returns it *instead of* delegating inward, so that
//! packet **never passes through `inner`**:
//!
//! ```text
//! poll_write: C ──▶ B ──▶ A ──▶ Noop
//!                  └── B returns its own queued packet here;
//!                      A never sees it.
//! ```
//!
//! That is the right shape for a packet whose processing is complete — an RTCP Sender Report is
//! generated fully formed and nothing further downstream needs to touch it. It is the wrong shape
//! for a packet that still needs the rest of the chain.
//!
//! ## Rule 2 — re-inject through `inner` when processing must continue
//!
//! A packet released later but still needing downstream work is handed to
//! `inner.handle_read(pkt)` / `inner.handle_write(pkt)` and collected afterwards from the
//! delegating `poll_*`. It then traverses every layer below exactly once, in the same order a
//! live packet would.
//!
//! | Situation | Route | Why |
//! |---|---|---|
//! | RTCP report generated on a timer | local queue (terminal) | complete when built; nothing below acts on it |
//! | Retransmission answering a NACK | local queue (terminal) | already went through the chain when first sent |
//! | Packet released by a jitter buffer | `inner.handle_read` | downstream receive processing has not run yet |
//! | Packet recovered by FEC | `inner.handle_read` | it is a media packet the rest of the chain has never seen |
//! | FEC repair packet being sent | `inner.handle_write` | still needs the outbound layers below |
//! | Packet released by the pacer | `inner.handle_write` | must pick up send-time state at the release instant |
//!
//! **Exactly once** is the part worth testing. Re-injecting and *also* queueing locally delivers
//! the packet twice; queueing locally when downstream work was required silently skips layers.
//! Neither shows up as a compile error.
//!
//! ## Rule 3 — record departure at release, not at enqueue
//!
//! [`TaggedPacket::now`](shared::transport::TransportMessage::now) is a timestamp on the packet,
//! and a delaying interceptor must **replace** it with the instant it actually releases the
//! packet before handing it inward. Anything below that records departure — a send history
//! feeding congestion control — otherwise attributes the interceptor's own buffering delay to
//! the network, which is exactly the measurement congestion control must not get wrong.
//!
//! The same applies on the read side: a packet released by a jitter buffer carries the instant it
//! was released, not the instant it arrived, once it re-enters the chain.
//!
//! ## Rule 4 — default relative order
//!
//! Listed outermost first, which is the order each packet meets them. `Registry::with` adds
//! **innermost first**, so a registry builds this list bottom-up.
//!
//! ```text
//!            write (application → network)          read (network → application)
//!            ────────────────────────────           ───────────────────────────
//! outermost  pacing                                 FEC decode / recover
//!            FEC encode (repair packets)            NACK generator
//!            RTCP reports (SR)                      jitter buffer
//!            NACK responder (retransmit buffer)     RTCP reports (RR)
//!            TWCC sender (tags seq numbers)         TWCC receiver (records arrivals)
//! innermost  rtpfb / send history                   rtpfb / feedback ingest
//! ```
//!
//! The constraints that fix these positions, as opposed to the ones that are conventional:
//!
//! - **Pacing is outermost on write.** Everything below it must observe the release instant
//!   (rule 3), so nothing that timestamps or records a packet may sit above it.
//! - **Send history is innermost on write.** It records what actually left, after every layer
//!   that may rewrite the packet — including the TWCC sequence number it is keyed by.
//! - **FEC decode is outermost on read.** A recovered packet has to look to every other
//!   interceptor exactly like a packet that arrived normally, so recovery happens before anything
//!   below inspects sequence numbers.
//! - **The NACK generator sits above the jitter buffer.** Loss has to be detected from *arrivals*.
//!   A generator below the buffer sees a packet only once it is released, so it cannot notice a
//!   gap until a whole depth after the packet went missing, and every NACK it sends is late by
//!   that much. (This corrects the order first written here, which had them the other way round;
//!   `tests/jitter_buffer_nack_depth.rs` measures the cost.)
//! - **The jitter buffer sits below FEC.** Recovery gets its chance before the buffer has to
//!   decide whether to wait for a gap, and a recovered packet is then indistinguishable from one
//!   that arrived normally.
//! - **The buffer's depth bounds how long a retransmission stays useful.** A depth shallower than
//!   NACK detection plus the round trip means every retransmission arrives after its position has
//!   been played past. The two are deliberately *not* coupled — see
//!   [`JitterBufferBuilder::with_depth`](crate::JitterBufferBuilder::with_depth).
//! - **TWCC receiver is innermost on read**, recording arrival after the packet set is final —
//!   including packets FEC recovered.
//!
//! Interceptors outside these groups compose freely. When adding one that delays or generates,
//! state its required position and which rule fixes it.

use crate::noop::NoopInterceptor;
use crate::{BoxedInterceptor, Interceptor};

/// Registry for constructing interceptor chains.
///
/// `Registry` wraps an interceptor chain and allows adding more interceptors
/// via the [`with`](Registry::with) method. The chain can be extracted with [`build`](Registry::build).
///
/// # Example
///
/// ```
/// use rtc_interceptor::{ReceiverReportBuilder, Registry, SenderReportBuilder};
///
/// // Each `with` changes the registry's type, so rebind rather than reassign.
/// let registry = Registry::new()
///     .with(SenderReportBuilder::new().build())
///     .with(ReceiverReportBuilder::new().build());
///
/// // Build the final chain
/// let chain = registry.build();
/// ```
///
/// # Helper Function Pattern
///
/// ```
/// use rtc_interceptor::{Interceptor, ReceiverReportBuilder, Registry, SenderReportBuilder};
///
/// fn register_default_interceptors<P: Interceptor>(
///     registry: Registry<P>,
/// ) -> Registry<impl Interceptor + use<P>> {
///     registry
///         .with(SenderReportBuilder::new().build())
///         .with(ReceiverReportBuilder::new().build())
/// }
///
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry);
/// let chain = registry.build();
/// ```
#[derive(Clone)]
pub struct Registry<P> {
    inner: P,
}

impl Registry<NoopInterceptor> {
    /// Create a new empty registry.
    ///
    /// This creates a `NoopInterceptor` as the innermost layer.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::Registry;
    ///
    /// let registry = Registry::new();
    /// ```
    pub fn new() -> Self {
        Registry {
            inner: NoopInterceptor::new(),
        }
    }
}

impl Default for Registry<NoopInterceptor> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Interceptor> Registry<P> {
    /// Create a registry from an existing interceptor.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{NoopInterceptor, Registry};
    ///
    /// let custom = NoopInterceptor::new();
    /// let registry = Registry::from(custom);
    /// ```
    pub fn from(inner: P) -> Self {
        Registry { inner }
    }

    /// Wrap the current chain with another interceptor.
    ///
    /// Returns a new `Registry` with the updated chain type.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{ReceiverReportBuilder, Registry, SenderReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(SenderReportBuilder::new().build())
    ///     .with(ReceiverReportBuilder::new().build());
    /// ```
    pub fn with<O, F>(self, f: F) -> Registry<O>
    where
        F: FnOnce(P) -> O,
        O: Interceptor,
    {
        Registry {
            inner: f(self.inner),
        }
    }

    /// Build and return the interceptor chain.
    ///
    /// Consumes the registry and returns the inner interceptor chain.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{Registry, SenderReportBuilder};
    ///
    /// let registry = Registry::new().with(SenderReportBuilder::new().build());
    /// let chain = registry.build();
    /// ```
    pub fn build(self) -> P {
        self.inner
    }

    /// Erase the chain's type, turning this into a `Registry<BoxedInterceptor>`.
    ///
    /// The chain an application assembles at runtime is a deep nest of generic types
    /// (`TwccSender<NackResponder<...<NoopInterceptor>>>`), which otherwise leaks into every
    /// type that holds the peer connection. Boxing it collapses that to one concrete type, so
    /// a struct can store an `RTCPeerConnection<BoxedInterceptor>` field directly.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{BoxedInterceptor, Registry, SenderReportBuilder};
    ///
    /// // Whatever the chain was composed of, the result has one concrete type.
    /// let chain: BoxedInterceptor = Registry::new()
    ///     .with(SenderReportBuilder::new().build())
    ///     .boxed()
    ///     .build();
    /// ```
    ///
    /// The `rtc` crate accepts the erased registry directly, so a peer connection can be stored
    /// as `RTCPeerConnection<BoxedInterceptor>`:
    ///
    /// ```ignore
    /// let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_interceptor_registry(registry.boxed())
    ///     .build()?;
    /// ```
    ///
    /// `P: 'static` is required because [`BoxedInterceptor`] is `Box<dyn Interceptor + 'static>`,
    /// so the chain must not borrow anything shorter-lived. This is the only operation that needs
    /// the bound, which is why [`Interceptor`] itself does not require `'static`.
    pub fn boxed(self) -> Registry<BoxedInterceptor>
    where
        P: 'static,
    {
        Registry {
            inner: Box::new(self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaggedPacket;
    use sansio::Protocol;
    use shared::error::Error;
    use std::time::Instant;

    fn dummy_rtp_packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: crate::Packet::Rtp(rtp::Packet::default()),
        }
    }

    // A simple test interceptor that wraps an inner protocol
    struct TestInterceptor<P> {
        inner: P,
        name: &'static str,
    }

    impl<P> TestInterceptor<P> {
        fn new(inner: P) -> Self {
            Self {
                inner,
                name: "test",
            }
        }

        fn with_name(name: &'static str) -> impl FnOnce(P) -> Self {
            move |inner| Self { inner, name }
        }
    }

    impl<P: Interceptor> Protocol<TaggedPacket, TaggedPacket, ()> for TestInterceptor<P> {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.inner.handle_read(msg)
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.inner.poll_read()
        }

        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.inner.handle_write(msg)
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            self.inner.poll_write()
        }
    }

    impl<P: Interceptor> Interceptor for TestInterceptor<P> {
        fn bind_local_stream(&mut self, info: &crate::StreamInfo) {
            self.inner.bind_local_stream(info);
        }
        fn unbind_local_stream(&mut self, info: &crate::StreamInfo) {
            self.inner.unbind_local_stream(info);
        }
        fn bind_remote_stream(&mut self, info: &crate::StreamInfo) {
            self.inner.bind_remote_stream(info);
        }
        fn unbind_remote_stream(&mut self, info: &crate::StreamInfo) {
            self.inner.unbind_remote_stream(info);
        }
    }

    #[test]
    fn test_registry_new() {
        let registry = Registry::new();
        let mut chain = registry.build();
        let pkt = dummy_rtp_packet();
        chain.handle_read(pkt).unwrap();
        assert!(chain.poll_read().is_some());
    }

    #[test]
    fn test_registry_with_single_interceptor() {
        let registry = Registry::new().with(TestInterceptor::new);
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        chain.handle_read(pkt).unwrap();
        assert!(chain.poll_read().is_some());
        assert_eq!(chain.name, "test");
    }

    #[test]
    fn test_registry_with_multiple_interceptors() {
        let registry = Registry::new()
            .with(TestInterceptor::with_name("inner"))
            .with(TestInterceptor::with_name("outer"));
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        chain.handle_read(pkt).unwrap();
        assert!(chain.poll_read().is_some());
        assert_eq!(chain.name, "outer");
        assert_eq!(chain.inner.name, "inner");
    }

    #[test]
    fn test_registry_from_inner() {
        let custom = NoopInterceptor::new();
        let registry = Registry::from(custom).with(TestInterceptor::new);
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.handle_write(pkt).unwrap();
        assert_eq!(chain.poll_write().unwrap().message, pkt_message);
    }

    // Test the helper function pattern
    fn register_test_interceptors<P: Interceptor>(
        registry: Registry<P>,
    ) -> Registry<TestInterceptor<TestInterceptor<P>>> {
        registry
            .with(TestInterceptor::with_name("first"))
            .with(TestInterceptor::with_name("second"))
    }

    #[test]
    fn test_helper_function_pattern() {
        let registry = Registry::new();
        let registry = register_test_interceptors(registry);
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        chain.handle_read(pkt).unwrap();
        assert!(chain.poll_read().is_some());
        assert_eq!(chain.name, "second");
        assert_eq!(chain.inner.name, "first");
    }
}
