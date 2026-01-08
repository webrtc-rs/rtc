//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

use super::sender_stream::SenderStream;
use crate::{Interceptor, Packet, TaggedPacket};
use rtcp::header::PacketType;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Builder for the SenderReportInterceptor.
pub struct SenderReportBuilder<P> {
    /// Interval between sender reports.
    interval: Duration,
    _phantom: PhantomData<P>,
}

impl<P> Default for SenderReportBuilder<P> {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            _phantom: PhantomData,
        }
    }
}

impl<P> SenderReportBuilder<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// with customized interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Create a builder function for use with Registry.
    pub fn build(self) -> impl FnOnce(P) -> SenderReportInterceptor<P> {
        move |inner| SenderReportInterceptor::new(inner, self.interval)
    }
}

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

    interval: Duration,
    eto: Instant,

    streams: HashMap<u32, SenderStream>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> SenderReportInterceptor<P> {
    /// Create a new SenderReportInterceptor.
    fn new(inner: P, interval: Duration) -> Self {
        Self {
            inner,

            interval,
            eto: Instant::now(),

            streams: HashMap::new(),

            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Check if an RTCP packet type should be filtered.
    ///
    /// Returns `true` for hop-by-hop report types that should not be forwarded:
    /// - Receiver Report (201)
    /// - Transport-Specific Feedback (205)
    fn should_filter(packet_type: PacketType) -> bool {
        packet_type == PacketType::ReceiverReport
            || (packet_type == PacketType::TransportSpecificFeedback)
    }

    /// Get a reference to the inner protocol.
    fn inner(&self) -> &P {
        &self.inner
    }

    /// Get a mutable reference to the inner protocol.
    fn inner_mut(&mut self) -> &mut P {
        &mut self.inner
    }
}

impl<P: Interceptor> sansio::Protocol<TaggedPacket, TaggedPacket, ()>
    for SenderReportInterceptor<P>
{
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
        if let Packet::Rtp(rtp_packet) = &msg.message
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.process_rtp(msg.now, rtp_packet);
        }

        self.inner.handle_write(msg)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.inner.poll_write()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        if self.eto <= now {
            self.eto = now + self.interval;

            for stream in self.streams.values_mut() {
                let rr = stream.generate_report(now);
                self.write_queue.push_back(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: Packet::Rtcp(vec![Box::new(rr)]),
                });
            }
        }

        self.inner.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        if let Some(eto) = self.inner.poll_timeout()
            && eto < self.eto
        {
            Some(eto)
        } else {
            Some(self.eto)
        }
    }
}

impl<P: Interceptor> Interceptor for SenderReportInterceptor<P> {
    fn bind_local_stream(&mut self, info: &crate::StreamInfo) {
        let stream = SenderStream::new(info.ssrc, info.clock_rate);
        self.streams.insert(info.ssrc, stream);

        self.inner.bind_local_stream(info);
    }
    fn unbind_local_stream(&mut self, info: &crate::StreamInfo) {
        self.streams.remove(&info.ssrc);

        self.inner.unbind_local_stream(info);
    }
    fn bind_remote_stream(&mut self, info: &crate::StreamInfo) {
        self.inner.bind_remote_stream(info);
    }
    fn unbind_remote_stream(&mut self, info: &crate::StreamInfo) {
        self.inner.unbind_remote_stream(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoopInterceptor, Registry};
    use sansio::Protocol;

    fn dummy_rtp_packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: crate::Packet::Rtp(rtp::Packet::default()),
        }
    }

    #[test]
    fn test_sender_report_builder_default() {
        // Build with default interval (1 second)
        let chain = Registry::new()
            .with(SenderReportBuilder::default().build())
            .build();

        assert_eq!(chain.interval, Duration::from_secs(1));
    }

    #[test]
    fn test_sender_report_builder_with_custom_interval() {
        // Build with custom interval
        let chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_millis(500))
                    .build(),
            )
            .build();

        assert_eq!(chain.interval, Duration::from_millis(500));
    }

    #[test]
    fn test_sender_report_chain_handle_read_write() {
        // Build a chain and test packet flow
        let mut chain = Registry::new()
            .with(SenderReportBuilder::default().build())
            .build();

        // Test read path
        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);

        // Test write path
        let pkt2 = dummy_rtp_packet();
        let pkt2_message = pkt2.message.clone();
        chain.handle_write(pkt2).unwrap();
        assert_eq!(chain.poll_write().unwrap().message, pkt2_message);
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
        let mut chain = Registry::new()
            .with(SenderReportBuilder::default().build())
            .build();

        // Test immutable access
        let _ = chain.inner();

        // Test mutable access - can modify inner
        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.inner_mut().handle_write(pkt).unwrap();
        assert_eq!(chain.inner_mut().poll_write().unwrap().message, pkt_message);
    }
}
