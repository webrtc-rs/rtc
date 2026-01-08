//! Receiver Report Interceptor - Generates RTCP Receiver Reports.

use crate::report::receiver_stream::ReceiverStream;
use crate::{Interceptor, Packet, TaggedPacket};
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Builder for the ReceiverReportInterceptor.
pub struct ReceiverReportBuilder<P> {
    /// Interval between receiver reports.
    interval: Duration,
    _phantom: PhantomData<P>,
}

impl<P> Default for ReceiverReportBuilder<P> {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            _phantom: PhantomData,
        }
    }
}

impl<P> ReceiverReportBuilder<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// with customized interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Create a builder function for use with Registry.
    pub fn build(self) -> impl FnOnce(P) -> ReceiverReportInterceptor<P> {
        move |inner| ReceiverReportInterceptor::new(inner, self.interval)
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

    interval: Duration,
    eto: Instant,

    streams: HashMap<u32, ReceiverStream>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> ReceiverReportInterceptor<P> {
    /// Create a new ReceiverReportInterceptor with default configuration.
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

    /// Process an incoming RTP packet for statistics.
    fn process_rtp(&mut self, now: Instant, ssrc: u32, seq: u16, timestamp: u32) {
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
    fn process_sender_report(&mut self, now: Instant, sr: &rtcp::sender_report::SenderReport) {
        if let Some(stream) = self.streams.get_mut(&sr.ssrc) {
            stream.process_sender_report(now, sr);
        }
    }

    /// Generate receiver reports for all tracked streams.
    fn generate_reports(&mut self, now: Instant) -> Vec<rtcp::receiver_report::ReceiverReport> {
        self.streams
            .values_mut()
            .map(|stream| stream.generate_report(now))
            .collect()
    }

    /// Register a new stream with its clock rate.
    fn register_stream(&mut self, ssrc: u32, clock_rate: u32) {
        self.streams
            .entry(ssrc)
            .or_insert_with(|| ReceiverStream::new(ssrc, clock_rate));
    }
}

impl<P: Interceptor> sansio::Protocol<TaggedPacket, TaggedPacket, ()>
    for ReceiverReportInterceptor<P>
{
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        /*if let Packet::Rtcp(rtcp_packets) = &msg {
            for rtcp_packet in rtcp_packets {
                if let Some(sr) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                {
                    if let Some(stream) = self.streams.get_mut(&sr.ssrc) {
                        stream.process_sender_report(msg.now, sr);
                    }
                }
            }
        } else if let MessageEvent::Rtp(RTPMessageEvent::Rtp(rtp_packet)) = &msg.message {
            if let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc) {
                stream.process_rtp(msg.now, rtp_packet);
            }
        }*/

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

impl<P: Interceptor> Interceptor for ReceiverReportInterceptor<P> {
    fn bind_local_stream(&mut self, info: &crate::StreamInfo) {
        self.inner.bind_local_stream(info);
    }
    fn unbind_local_stream(&mut self, info: &crate::StreamInfo) {
        self.inner.unbind_local_stream(info);
    }
    fn bind_remote_stream(&mut self, info: &crate::StreamInfo) {
        let stream = ReceiverStream::new(info.ssrc, info.clock_rate);
        self.streams.insert(info.ssrc, stream);

        self.inner.bind_remote_stream(info);
    }
    fn unbind_remote_stream(&mut self, info: &crate::StreamInfo) {
        self.streams.remove(&info.ssrc);

        self.inner.unbind_remote_stream(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;
    use sansio::Protocol;

    fn dummy_rtp_packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: crate::Packet::Rtp(rtp::Packet::default()),
        }
    }

    #[test]
    fn test_receiver_report_builder_default() {
        // Build with default interval (1 second)
        let chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
            .build();

        assert_eq!(chain.interval, Duration::from_secs(1));
        assert!(chain.streams.is_empty());
    }

    #[test]
    fn test_receiver_report_builder_with_custom_interval() {
        // Build with custom interval
        let chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_millis(500))
                    .build(),
            )
            .build();

        assert_eq!(chain.interval, Duration::from_millis(500));
    }

    #[test]
    fn test_receiver_report_chain_handle_read_write() {
        // Build a chain and test packet flow
        let mut chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
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
    fn test_register_stream() {
        let mut chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
            .build();

        chain.register_stream(12345, 48000);
        assert!(chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_process_rtp() {
        let mut chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
            .build();

        let now = Instant::now();
        chain.process_rtp(now, 12345, 1, 1000);

        assert!(chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_generate_reports() {
        let mut chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
            .build();

        let now = Instant::now();
        chain.process_rtp(now, 12345, 1, 1000);
        chain.process_rtp(now, 12345, 2, 2000);

        let reports = chain.generate_reports(now);
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn test_chained_interceptors() {
        use crate::report::sender_report::SenderReportBuilder;

        // Demonstrate chaining multiple interceptors
        let mut chain = Registry::new()
            .with(ReceiverReportBuilder::default().build())
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_millis(250))
                    .build(),
            )
            .build();

        // Test packet flow through the chain
        let pkt = dummy_rtp_packet();
        let pkt_message = pkt.message.clone();
        chain.handle_read(pkt).unwrap();
        assert_eq!(chain.poll_read().unwrap().message, pkt_message);

        let pkt2 = dummy_rtp_packet();
        let pkt2_message = pkt2.message.clone();
        chain.handle_write(pkt2).unwrap();
        assert_eq!(chain.poll_write().unwrap().message, pkt2_message);
    }
}
