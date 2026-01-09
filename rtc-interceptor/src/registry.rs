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

use crate::Interceptor;
use crate::noop::NoopInterceptor;

/// Registry for constructing interceptor chains.
///
/// `Registry` wraps an interceptor chain and allows adding more interceptors
/// via the [`with`](Registry::with) method. The chain can be extracted with [`build`](Registry::build).
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::Registry;
///
/// // Create a new registry
/// let mut registry = Registry::new();
///
/// // Add interceptors (can be done in helper functions)
/// registry = registry
///     .with(SenderReportBuilder::new().build())
///     .with(ReceiverReportBuilder::new().build());
///
/// // Build the final chain
/// let chain = registry.build();
/// ```
///
/// # Helper Function Pattern
///
/// ```ignore
/// fn register_default_interceptors<P: Interceptor>(
///     registry: Registry<P>,
/// ) -> Registry<impl Interceptor> {
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
    /// ```ignore
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
    /// ```ignore
    /// let custom = MyCustomInterceptor::new();
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
    /// ```ignore
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
    /// ```ignore
    /// let registry = Registry::new().with(MyInterceptor::new);
    /// let chain = registry.build();
    /// ```
    pub fn build(self) -> P {
        self.inner
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
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);
    }

    #[test]
    fn test_registry_with_single_interceptor() {
        let registry = Registry::new().with(TestInterceptor::new);
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);
        assert_eq!(chain.name, "test");
    }

    #[test]
    fn test_registry_with_multiple_interceptors() {
        let registry = Registry::new()
            .with(TestInterceptor::with_name("inner"))
            .with(TestInterceptor::with_name("outer"));
        let mut chain = registry.build();

        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);
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
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);
        assert_eq!(chain.name, "second");
        assert_eq!(chain.inner.name, "first");
    }
}
