//! Receiver Report Interceptor - Generates RTCP Receiver Reports.

use crate::report::receiver_stream::ReceiverStream;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for the ReceiverReportInterceptor.
#[derive(Debug, Clone)]
pub struct ReceiverReportConfig {
    /// Interval between receiver reports.
    pub interval: Duration,
}

impl Default for ReceiverReportConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
        }
    }
}

/// Interceptor that generates RTCP Receiver Reports.
///
/// This interceptor monitors incoming RTP packets, tracks statistics per stream,
/// and periodically generates RTCP Receiver Reports.
///
/// # Type Parameters
///
/// - `P`: The inner protocol being wrapped
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, report::ReceiverReportInterceptor};
///
/// let chain = Registry::new()
///     .with(ReceiverReportInterceptor::new)
///     .build();
/// ```
pub struct ReceiverReportInterceptor<P> {
    inner: P,
    config: ReceiverReportConfig,
    streams: HashMap<u32, ReceiverStream>,
    next_report_time: Option<Instant>,
}

impl<P> ReceiverReportInterceptor<P> {
    /// Create a new ReceiverReportInterceptor with default configuration.
    pub fn new(inner: P) -> Self {
        Self::with_config(inner, ReceiverReportConfig::default())
    }

    /// Create a new ReceiverReportInterceptor with custom configuration.
    pub fn with_config(inner: P, config: ReceiverReportConfig) -> Self {
        Self {
            inner,
            config,
            streams: HashMap::new(),
            next_report_time: None,
        }
    }

    /// Create a builder function for use with InterceptorBuilder.
    pub fn builder(config: ReceiverReportConfig) -> impl FnOnce(P) -> Self {
        move |inner| Self::with_config(inner, config)
    }

    /// Process an incoming RTP packet for statistics.
    pub fn process_rtp(&mut self, now: Instant, ssrc: u32, seq: u16, timestamp: u32) {
        // Create stream if it doesn't exist
        let stream = self.streams.entry(ssrc).or_insert_with(|| {
            // Default clock rate, should be configured per stream in real usage
            ReceiverStream::new(ssrc, 90000)
        });

        // Create a minimal RTP packet for processing
        let pkt = rtp::packet::Packet {
            header: rtp::header::Header {
                ssrc,
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            ..Default::default()
        };

        stream.process_rtp(now, &pkt);
    }

    /// Process an incoming RTCP Sender Report.
    pub fn process_sender_report(&mut self, now: Instant, sr: &rtcp::sender_report::SenderReport) {
        if let Some(stream) = self.streams.get_mut(&sr.ssrc) {
            stream.process_sender_report(now, sr);
        }
    }

    /// Generate receiver reports for all tracked streams.
    pub fn generate_reports(&mut self, now: Instant) -> Vec<rtcp::receiver_report::ReceiverReport> {
        self.streams
            .values_mut()
            .map(|stream| stream.generate_report(now))
            .collect()
    }

    /// Register a new stream with its clock rate.
    pub fn register_stream(&mut self, ssrc: u32, clock_rate: u32) {
        self.streams
            .entry(ssrc)
            .or_insert_with(|| ReceiverStream::new(ssrc, clock_rate));
    }
}

// Note: The Protocol implementation below is a template.
// In practice, you would implement this for specific message types
// used in your application (e.g., TaggedRtpMessage, etc.)
//
// Example implementation for a generic message type:
//
// impl<P, Msg, Evt> Protocol<Msg, Msg, Evt> for ReceiverReportInterceptor<P>
// where
//     P: Protocol<Msg, Msg, Evt>,
//     Msg: RtpMessage,  // Trait that provides access to RTP packet data
// {
//     type Rout = P::Rout;
//     type Wout = P::Wout;
//     type Eout = P::Eout;
//     type Error = P::Error;
//     type Time = Instant;
//
//     fn handle_read(&mut self, msg: Msg) -> Result<(), Self::Error> {
//         // Extract RTP/RTCP data and process
//         if let Some(rtp) = msg.as_rtp() {
//             self.process_rtp(Instant::now(), rtp.ssrc, rtp.seq, rtp.timestamp);
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
//     fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
//         if self.next_report_time.map_or(true, |t| now >= t) {
//             let _reports = self.generate_reports(now);
//             // Queue reports for sending via poll_write
//             self.next_report_time = Some(now + self.config.interval);
//         }
//         self.inner.handle_timeout(now)
//     }
//
//     fn poll_timeout(&mut self) -> Option<Instant> {
//         match (self.next_report_time, self.inner.poll_timeout()) {
//             (Some(a), Some(b)) => Some(a.min(b)),
//             (a, b) => a.or(b),
//         }
//     }
// }

/*
    /// An interceptor that wraps an inner protocol and can transform messages.
    ///
    /// - `Rin`: Input read message type (from network)
    /// - `Win`: Input write message type (from application)
    /// - `Ein`: Input event type
    /// - `P`: The inner protocol being wrapped
    pub struct ReceiverReportInterceptor<P> {
        inner: P,
        interval: Duration,
        eto: Option<Instant>,
        streams: HashMap<u32, ReceiverStream>,
        outbound_queue: VecDeque<P::Wout>,  // Generated RTCP reports
    }

    impl<P, Rin, Win, Ein> Protocol<Rin, Win, Ein> for ReceiverReportInterceptor<P>
    where
        P: Protocol<Rin, Win, Ein>,  // Inner protocol
        Rin: AsRef<RtpPacket>,       // Can extract RTP from input
    {
        type Rout = P::Rout;         // Pass through read output
        type Wout = P::Wout;         // May inject additional writes
        type Eout = P::Eout;
        type Error = P::Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: Rin) -> Result<(), Self::Error> {
            // Process RTP/RTCP for stats
            self.process_incoming(&msg);
            // Forward to inner
            self.inner.handle_read(msg)
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.inner.poll_read()
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            // Return generated RTCP reports first, then inner's writes
            if let Some(report) = self.outbound_queue.pop_front() {
                return Some(report);
            }
            self.inner.poll_write()
        }

        fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
            // Generate periodic receiver reports
            if self.eto.map_or(false, |t| t <= now) {
                self.generate_reports(now);
                self.eto = Some(now + self.interval);
            }
            self.inner.handle_timeout(now)
        }

        fn poll_timeout(&mut self) -> Option<Instant> {
            // Return earliest timeout between self and inner
            match (self.eto, self.inner.poll_timeout()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }
        // ... other methods delegate to inner
    }
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopInterceptor;

    #[test]
    fn test_receiver_report_interceptor_creation() {
        let inner = NoopInterceptor::new();
        let interceptor = ReceiverReportInterceptor::new(inner);
        assert!(interceptor.streams.is_empty());
    }

    #[test]
    fn test_receiver_report_with_config() {
        let inner = NoopInterceptor::new();
        let config = ReceiverReportConfig {
            interval: Duration::from_millis(500),
        };
        let interceptor = ReceiverReportInterceptor::with_config(inner, config);
        assert_eq!(interceptor.config.interval, Duration::from_millis(500));
    }

    #[test]
    fn test_register_stream() {
        let inner = NoopInterceptor::new();
        let mut interceptor = ReceiverReportInterceptor::new(inner);

        interceptor.register_stream(12345, 48000);
        assert!(interceptor.streams.contains_key(&12345));
    }

    #[test]
    fn test_process_rtp() {
        let inner = NoopInterceptor::new();
        let mut interceptor = ReceiverReportInterceptor::new(inner);

        let now = Instant::now();
        interceptor.process_rtp(now, 12345, 1, 1000);

        assert!(interceptor.streams.contains_key(&12345));
    }

    #[test]
    fn test_generate_reports() {
        let inner = NoopInterceptor::new();
        let mut interceptor = ReceiverReportInterceptor::new(inner);

        let now = Instant::now();
        interceptor.process_rtp(now, 12345, 1, 1000);
        interceptor.process_rtp(now, 12345, 2, 2000);

        let reports = interceptor.generate_reports(now);
        assert_eq!(reports.len(), 1);
    }
}
