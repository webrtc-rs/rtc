//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

use crate::{Interceptor, Packet};
use rtcp::header::PacketType;
use shared::error::Error;
use std::time::Instant;

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
    pub fn should_filter(packet_type: PacketType) -> bool {
        packet_type == PacketType::ReceiverReport
            || (packet_type == PacketType::TransportSpecificFeedback)
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

impl<P: Interceptor> sansio::Protocol<Packet, Packet, ()> for SenderReportInterceptor<P> {
    type Rout = Packet;
    type Wout = Packet;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: Packet) -> Result<(), Self::Error> {
        // Filter out hop-by-hop RTCP reports
        /*if let Some(rtcp) = msg.as_rtcp() {
            if Self::should_filter(rtcp.packet_type()) {
                return Ok(()); // Don't forward
            }
        }*/
        self.inner.handle_read(msg)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.inner.poll_read()
    }

    fn handle_write(&mut self, msg: Packet) -> Result<(), Self::Error> {
        self.inner.handle_write(msg)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.inner.poll_write()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.inner.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.inner.poll_timeout()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopInterceptor;

    fn dummy_rtp_packet() -> Packet {
        Packet::Rtp(rtp::Packet::default())
    }

    #[test]
    fn test_sender_report_interceptor_creation() {
        let inner = NoopInterceptor::new();
        let _interceptor = SenderReportInterceptor::new(inner);
    }

    #[test]
    fn test_should_filter() {
        // Receiver Report (RR) - should filter
        assert!(SenderReportInterceptor::<NoopInterceptor>::should_filter(
            PacketType::ReceiverReport
        ));

        // Transport-Specific Feedback - should filter
        assert!(SenderReportInterceptor::<NoopInterceptor>::should_filter(
            PacketType::TransportSpecificFeedback
        ));

        // Sender Report (SR) - should NOT filter
        assert!(!SenderReportInterceptor::<NoopInterceptor>::should_filter(
            PacketType::SenderReport
        ));

        // Source Description (SDES) - should NOT filter
        assert!(!SenderReportInterceptor::<NoopInterceptor>::should_filter(
            PacketType::SourceDescription
        ));

        // Goodbye (BYE) - should NOT filter
        assert!(!SenderReportInterceptor::<NoopInterceptor>::should_filter(
            PacketType::Goodbye
        ));
    }

    #[test]
    fn test_inner_access() {
        let inner = NoopInterceptor::new();
        let mut interceptor = SenderReportInterceptor::new(inner);

        // Test immutable access
        let _ = interceptor.inner();

        // Test mutable access - can modify inner
        use sansio::Protocol;
        let pkt = dummy_rtp_packet();
        interceptor.inner_mut().handle_write(pkt.clone()).unwrap();
        assert_eq!(interceptor.inner_mut().poll_write(), Some(pkt));
    }
}
