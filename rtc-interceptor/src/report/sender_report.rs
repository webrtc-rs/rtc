//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

/// Interceptor that filters hop-by-hop RTCP reports.
///
/// This interceptor filters out RTCP Receiver Reports and Transport-Specific
/// Feedback, which are hop-by-hop reports that should not be forwarded
/// end-to-end.
///
/// # Type Parameters
///
/// - `P`: The inner protocol being wrapped
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, report::SenderReportInterceptor};
///
/// let chain = Registry::new()
///     .with(SenderReportInterceptor::new)
///     .build();
/// ```
pub struct SenderReportInterceptor<P> {
    inner: P,
}

impl<P> SenderReportInterceptor<P> {
    /// Create a new SenderReportInterceptor.
    pub fn new(inner: P) -> Self {
        Self { inner }
    }

    /// Check if an RTCP packet type should be filtered.
    ///
    /// Returns `true` for hop-by-hop report types that should not be forwarded:
    /// - Receiver Report (201)
    /// - Transport-Specific Feedback (205)
    pub fn should_filter(packet_type: u8) -> bool {
        matches!(packet_type, 201 | 205)
    }

    /// Get a reference to the inner protocol.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// Get a mutable reference to the inner protocol.
    pub fn inner_mut(&mut self) -> &mut P {
        &mut self.inner
    }
}

// Note: The Protocol implementation below is a template.
// In practice, you would implement this for specific message types
// used in your application (e.g., TaggedRtpMessage, etc.)
//
// Example implementation for a generic message type:
//
// impl<P, Msg, Evt> Protocol<Msg, Msg, Evt> for SenderReportInterceptor<P>
// where
//     P: Protocol<Msg, Msg, Evt>,
//     Msg: RtcpMessage,  // Trait that provides access to RTCP packet data
// {
//     type Rout = P::Rout;
//     type Wout = P::Wout;
//     type Eout = P::Eout;
//     type Error = P::Error;
//     type Time = P::Time;
//
//     fn handle_read(&mut self, msg: Msg) -> Result<(), Self::Error> {
//         // Filter out hop-by-hop RTCP reports
//         if let Some(rtcp) = msg.as_rtcp() {
//             if Self::should_filter(rtcp.packet_type()) {
//                 return Ok(()); // Don't forward
//             }
//         }
//         self.inner.handle_read(msg)
//     }
//
//     fn poll_read(&mut self) -> Option<Self::Rout> {
//         self.inner.poll_read()
//     }
//
//     fn handle_write(&mut self, msg: Msg) -> Result<(), Self::Error> {
//         self.inner.handle_write(msg)
//     }
//
//     fn poll_write(&mut self) -> Option<Self::Wout> {
//         self.inner.poll_write()
//     }
//
//     fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
//         self.inner.handle_timeout(now)
//     }
//
//     fn poll_timeout(&mut self) -> Option<Self::Time> {
//         self.inner.poll_timeout()
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopInterceptor;

    #[test]
    fn test_sender_report_interceptor_creation() {
        let inner: NoopInterceptor<(), (), ()> = NoopInterceptor::new();
        let _interceptor = SenderReportInterceptor::new(inner);
    }

    #[test]
    fn test_should_filter() {
        // Receiver Report (RR) - should filter
        assert!(SenderReportInterceptor::<()>::should_filter(201));

        // Transport-Specific Feedback - should filter
        assert!(SenderReportInterceptor::<()>::should_filter(205));

        // Sender Report (SR) - should NOT filter
        assert!(!SenderReportInterceptor::<()>::should_filter(200));

        // Source Description (SDES) - should NOT filter
        assert!(!SenderReportInterceptor::<()>::should_filter(202));

        // Goodbye (BYE) - should NOT filter
        assert!(!SenderReportInterceptor::<()>::should_filter(203));
    }

    #[test]
    fn test_inner_access() {
        let inner: NoopInterceptor<i32, i32, ()> = NoopInterceptor::new();
        let mut interceptor = SenderReportInterceptor::new(inner);

        // Test immutable access
        let _ = interceptor.inner();

        // Test mutable access - can modify inner
        use sansio::Protocol;
        interceptor.inner_mut().handle_write(42).unwrap();
        assert_eq!(interceptor.inner_mut().poll_write(), Some(42));
    }
}
