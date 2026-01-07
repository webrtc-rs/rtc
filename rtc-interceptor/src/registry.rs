//! Interceptor Registry - Type-safe builder for constructing interceptor chains.

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
///     .with(SenderReportInterceptor::new)
///     .with(ReceiverReportInterceptor::new);
///
/// // Build the final chain
/// let chain = registry.build();
/// ```
///
/// # Helper Function Pattern
///
/// ```ignore
/// fn register_default_interceptors<P: Interceptor<Msg, Msg, Evt>>(
///     registry: Registry<P>,
/// ) -> Registry<impl Interceptor<Msg, Msg, Evt>> {
///     registry
///         .with(SenderReportInterceptor::new)
///         .with(ReceiverReportInterceptor::new)
/// }
///
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry);
/// let chain = registry.build();
/// ```
pub struct Registry<P> {
    inner: P,
}

impl<Rin, Win, Ein> Registry<NoopInterceptor<Rin, Win, Ein>> {
    /// Create a new empty registry.
    ///
    /// This creates a `NoopInterceptor` as the innermost layer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rtc_interceptor::Registry;
    ///
    /// let registry: Registry<_> = Registry::new();
    /// ```
    pub fn new() -> Self {
        Registry {
            inner: NoopInterceptor::new(),
        }
    }
}

impl<Rin, Win, Ein> Default for Registry<NoopInterceptor<Rin, Win, Ein>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Registry<P> {
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
    ///     .with(SenderReportInterceptor::new)
    ///     .with(ReceiverReportInterceptor::new);
    /// ```
    pub fn with<O, F>(self, f: F) -> Registry<O>
    where
        F: FnOnce(P) -> O,
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
        let registry: Registry<NoopInterceptor<i32, i32, ()>> = Registry::new();
        let mut chain = registry.build();
        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
    }

    #[test]
    fn test_registry_with_single_interceptor() {
        let registry = Registry::new().with(TestInterceptor::new);
        let mut chain = registry.build();

        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
        assert_eq!(chain.name, "test");
    }

    #[test]
    fn test_registry_with_multiple_interceptors() {
        let registry = Registry::new()
            .with(TestInterceptor::with_name("inner"))
            .with(TestInterceptor::with_name("outer"));
        let mut chain = registry.build();

        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
        assert_eq!(chain.name, "outer");
        assert_eq!(chain.inner.name, "inner");
    }

    #[test]
    fn test_registry_from_inner() {
        let custom = NoopInterceptor::<i32, i32, ()>::new();
        let registry = Registry::from(custom).with(TestInterceptor::new);
        let mut chain = registry.build();

        chain.handle_write(100).unwrap();
        assert_eq!(chain.poll_write(), Some(100));
    }

    // Test the helper function pattern
    fn register_test_interceptors<P: Protocol<i32, i32, ()>>(
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

        chain.handle_read(42).unwrap();
        assert_eq!(chain.poll_read(), Some(42));
        assert_eq!(chain.name, "second");
        assert_eq!(chain.inner.name, "first");
    }
}
