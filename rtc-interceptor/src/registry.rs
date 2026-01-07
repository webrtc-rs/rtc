//! Interceptor Registry - Type-safe builder for constructing interceptor chains.

use crate::noop::NoopInterceptor;

/// Registry for constructing interceptor chains.
///
/// `Registry` uses a type-state pattern where each call to `.with()`
/// transforms the registry's type parameter, creating a new registry that wraps
/// the current chain with another interceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::Registry;
///
/// // Build a chain of interceptors
/// let chain = Registry::new()
///     .with(SenderReportInterceptor::new)
///     .with(ReceiverReportInterceptor::new)
///     .with(|p| NackInterceptor::with_config(p, config))
///     .build();
///
/// // The resulting type is fully known at compile time:
/// // NackInterceptor<ReceiverReportInterceptor<SenderReportInterceptor<NoopInterceptor<...>>>>
/// ```
///
/// # Type Safety
///
/// The builder pattern ensures that interceptor chains are type-safe.
/// Each `.with()` call changes the return type, so the compiler can verify
/// that the chain is properly constructed.
pub struct Registry<P> {
    inner: P,
}

impl Registry<()> {
    /// Start building a new interceptor chain.
    ///
    /// This creates a registry with a `NoopInterceptor` as the innermost layer.
    /// The `NoopInterceptor` serves as a simple pass-through terminal.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let chain = Registry::new()
    ///     .with(MyInterceptor::new)
    ///     .build();
    /// ```
    pub fn new<Rin, Win, Ein>() -> Registry<NoopInterceptor<Rin, Win, Ein>> {
        Registry {
            inner: NoopInterceptor::new(),
        }
    }
}

impl<P> Registry<P> {
    /// Start building from an existing protocol.
    ///
    /// This allows using a custom innermost layer instead of `NoopInterceptor`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let custom_inner = MyCustomProtocol::new();
    /// let chain = Registry::from(custom_inner)
    ///     .with(MyInterceptor::new)
    ///     .build();
    /// ```
    pub fn from(inner: P) -> Self {
        Registry { inner }
    }

    /// Wrap the current chain with another interceptor.
    ///
    /// The wrapper function receives the current chain and returns a new
    /// interceptor that wraps it. This changes the registry's type parameter
    /// to reflect the new outer layer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let chain = Registry::new()
    ///     .with(SenderReportInterceptor::new)  // Returns Registry<SenderReportInterceptor<...>>
    ///     .with(ReceiverReportInterceptor::new)  // Returns Registry<ReceiverReportInterceptor<...>>
    ///     .build();
    /// ```
    pub fn with<O, F>(self, f: F) -> Registry<O>
    where
        F: FnOnce(P) -> O,
    {
        Registry {
            inner: f(self.inner),
        }
    }

    /// Finish building and return the interceptor chain.
    ///
    /// This consumes the registry and returns the constructed chain.
    pub fn build(self) -> P {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sansio::Protocol;

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

    impl<P: Protocol<i32, i32, ()>> Protocol<i32, i32, ()> for TestInterceptor<P> {
        type Rout = P::Rout;
        type Wout = P::Wout;
        type Eout = P::Eout;
        type Error = P::Error;
        type Time = P::Time;

        fn handle_read(&mut self, msg: i32) -> Result<(), Self::Error> {
            self.inner.handle_read(msg)
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.inner.poll_read()
        }

        fn handle_write(&mut self, msg: i32) -> Result<(), Self::Error> {
            self.inner.handle_write(msg)
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            self.inner.poll_write()
        }
    }

    #[test]
    fn test_registry_new() {
        let chain: NoopInterceptor<i32, i32, ()> = Registry::new().build();
        let mut chain = chain;
        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
    }

    #[test]
    fn test_registry_with_single_interceptor() {
        let mut chain = Registry::new().with(TestInterceptor::new).build();

        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
        assert_eq!(chain.name, "test");
    }

    #[test]
    fn test_registry_with_multiple_interceptors() {
        let mut chain = Registry::new()
            .with(TestInterceptor::with_name("inner"))
            .with(TestInterceptor::with_name("outer"))
            .build();

        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
        assert_eq!(chain.name, "outer");
        assert_eq!(chain.inner.name, "inner");
    }

    #[test]
    fn test_registry_from_custom_inner() {
        let custom = NoopInterceptor::<i32, i32, ()>::new();
        let mut chain = Registry::from(custom).with(TestInterceptor::new).build();

        chain.handle_write(100).unwrap();
        assert_eq!(chain.poll_write(), Some(100));
    }
}
