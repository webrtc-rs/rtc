//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

use super::sender_stream::SenderStream;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket};
use rtcp::header::PacketType;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Builder for the SenderReportInterceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, SenderReportBuilder};
/// use std::time::Duration;
///
/// // With default interval (1 second)
/// let chain = Registry::new()
///     .with(SenderReportBuilder::new().build())
///     .build();
///
/// // With custom interval
/// let chain = Registry::new()
///     .with(SenderReportBuilder::new().with_interval(Duration::from_millis(500)).build())
///     .build();
///
/// // With use_latest_packet enabled
/// let chain = Registry::new()
///     .with(SenderReportBuilder::new().with_use_latest_packet().build())
///     .build();
/// ```
pub struct SenderReportBuilder<P> {
    /// Interval between sender reports.
    interval: Duration,
    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,
    _phantom: PhantomData<P>,
}

impl<P> Default for SenderReportBuilder<P> {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            use_latest_packet: false,
            _phantom: PhantomData,
        }
    }
}

impl<P> SenderReportBuilder<P> {
    /// Create a new builder with default settings.
    ///
    /// Default interval is 1 second.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom interval between sender reports.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use rtc_interceptor::SenderReportBuilder;
    ///
    /// let builder = SenderReportBuilder::new()
    ///     .with_interval(Duration::from_millis(500));
    /// ```
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Enable always using the latest packet for timestamp tracking,
    /// even if it appears to be out-of-order based on sequence numbers.
    ///
    /// By default (disabled), only in-order packets update the RTP↔NTP
    /// timestamp correlation. This prevents out-of-order packets from
    /// corrupting the timestamp mapping.
    ///
    /// Enable this option when:
    /// - Packets are guaranteed to arrive in order
    /// - The application reorders packets before the interceptor
    /// - You want the sender report to always reflect the most recent packet
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rtc_interceptor::SenderReportBuilder;
    ///
    /// let builder = SenderReportBuilder::new()
    ///     .with_use_latest_packet();
    /// ```
    pub fn with_use_latest_packet(mut self) -> Self {
        self.use_latest_packet = true;
        self
    }

    /// Create a builder function for use with Registry.
    ///
    /// This returns a closure that can be passed to `Registry::with()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rtc_interceptor::{Registry, SenderReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(SenderReportBuilder::new().build());
    /// ```
    pub fn build(self) -> impl FnOnce(P) -> SenderReportInterceptor<P> {
        move |inner| SenderReportInterceptor::new(inner, self.interval, self.use_latest_packet)
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
/// use rtc_interceptor::{Registry, SenderReportBuilder};
///
/// let chain = Registry::new()
///     .with(SenderReportBuilder::new().build())
///     .build();
/// ```
pub struct SenderReportInterceptor<P> {
    inner: P,

    interval: Duration,
    eto: Instant,

    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,

    streams: HashMap<u32, SenderStream>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> SenderReportInterceptor<P> {
    /// Create a new SenderReportInterceptor.
    fn new(inner: P, interval: Duration, use_latest_packet: bool) -> Self {
        Self {
            inner,

            interval,
            eto: Instant::now(),

            use_latest_packet,

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
        // First drain generated RTCP reports
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
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
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let stream = SenderStream::new(info.ssrc, info.clock_rate, self.use_latest_packet);
        self.streams.insert(info.ssrc, stream);

        self.inner.bind_local_stream(info);
    }
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);

        self.inner.unbind_local_stream(info);
    }
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        self.inner.bind_remote_stream(info);
    }
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
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
        chain.handle_read(pkt).unwrap();
        assert!(chain.poll_read().is_none());

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

    #[test]
    fn test_use_latest_packet_option() {
        // Build with use_latest_packet enabled
        let chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_use_latest_packet()
                    .build(),
            )
            .build();

        assert!(chain.use_latest_packet);

        // Build without use_latest_packet (default)
        let chain_default = Registry::new()
            .with(SenderReportBuilder::default().build())
            .build();

        assert!(!chain_default.use_latest_packet);
    }

    #[test]
    fn test_use_latest_packet_combined_options() {
        // Test combining multiple options
        let chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_millis(250))
                    .with_use_latest_packet()
                    .build(),
            )
            .build();

        assert_eq!(chain.interval, Duration::from_millis(250));
        assert!(chain.use_latest_packet);
    }

    #[test]
    fn test_sender_report_generation_on_timeout() {
        // Port of pion's TestSenderInterceptor - tests full timeout/report cycle
        // No ticker mocking needed - sans-I/O pattern lets us control time directly
        let mut chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        // Bind a local stream
        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        let base_time = Instant::now();

        // Send some RTP packets through the write path
        for i in 0..5u16 {
            let pkt = TaggedPacket {
                now: base_time,
                transport: Default::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: 123456,
                        sequence_number: i,
                        timestamp: i as u32 * 3000,
                        ..Default::default()
                    },
                    payload: vec![0u8; 100].into(),
                    ..Default::default()
                }),
            };
            chain.handle_write(pkt).unwrap();
            // Drain the write queue
            chain.poll_write();
        }

        // First timeout triggers report generation (eto was set at construction)
        chain.handle_timeout(base_time).unwrap();

        // Drain any reports from initial timeout
        while chain.poll_write().is_some() {}

        // Advance time past the interval
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // Now a sender report should be generated
        let report = chain.poll_write();
        assert!(report.is_some());

        if let Some(tagged) = report {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                assert_eq!(rtcp_packets.len(), 1);
                let sr = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .expect("Expected SenderReport");
                assert_eq!(sr.ssrc, 123456);
                assert_eq!(sr.packet_count, 5);
                assert_eq!(sr.octet_count, 500);
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_sender_report_multiple_streams() {
        // Test that multiple streams each generate their own sender reports
        let mut chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        // Bind two local streams
        let info1 = StreamInfo {
            ssrc: 111111,
            clock_rate: 90000,
            ..Default::default()
        };
        let info2 = StreamInfo {
            ssrc: 222222,
            clock_rate: 48000,
            ..Default::default()
        };
        chain.bind_local_stream(&info1);
        chain.bind_local_stream(&info2);

        let base_time = Instant::now();

        // Send packets on stream 1
        for i in 0..3u16 {
            let pkt = TaggedPacket {
                now: base_time,
                transport: Default::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: 111111,
                        sequence_number: i,
                        timestamp: i as u32 * 3000,
                        ..Default::default()
                    },
                    payload: vec![0u8; 50].into(),
                    ..Default::default()
                }),
            };
            chain.handle_write(pkt).unwrap();
            chain.poll_write();
        }

        // Send packets on stream 2
        for i in 0..7u16 {
            let pkt = TaggedPacket {
                now: base_time,
                transport: Default::default(),
                message: Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: 222222,
                        sequence_number: i,
                        timestamp: i as u32 * 960,
                        ..Default::default()
                    },
                    payload: vec![0u8; 200].into(),
                    ..Default::default()
                }),
            };
            chain.handle_write(pkt).unwrap();
            chain.poll_write();
        }

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // Should get two sender reports
        let mut ssrcs = vec![];
        let mut packet_counts = vec![];
        let mut octet_counts = vec![];

        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                for rtcp_pkt in rtcp_packets {
                    if let Some(sr) = rtcp_pkt
                        .as_any()
                        .downcast_ref::<rtcp::sender_report::SenderReport>()
                    {
                        ssrcs.push(sr.ssrc);
                        packet_counts.push(sr.packet_count);
                        octet_counts.push(sr.octet_count);
                    }
                }
            }
        }

        assert_eq!(ssrcs.len(), 2);
        assert!(ssrcs.contains(&111111));
        assert!(ssrcs.contains(&222222));

        // Find stream 1's report
        let idx1 = ssrcs.iter().position(|&s| s == 111111).unwrap();
        assert_eq!(packet_counts[idx1], 3);
        assert_eq!(octet_counts[idx1], 150);

        // Find stream 2's report
        let idx2 = ssrcs.iter().position(|&s| s == 222222).unwrap();
        assert_eq!(packet_counts[idx2], 7);
        assert_eq!(octet_counts[idx2], 1400);
    }

    #[test]
    fn test_sender_report_unbind_stream() {
        // Test that unbinding a stream stops generating reports for it
        let mut chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        let base_time = Instant::now();

        // Send some packets
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 0,
                    timestamp: 0,
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(),
                ..Default::default()
            }),
        };
        chain.handle_write(pkt).unwrap();
        chain.poll_write();

        // Unbind the stream
        chain.unbind_local_stream(&info);

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // No report should be generated (stream was unbound)
        assert!(chain.poll_write().is_none());
    }

    #[test]
    fn test_poll_timeout_returns_earliest() {
        // Test that poll_timeout returns the earliest timeout
        let mut chain = Registry::new()
            .with(
                SenderReportBuilder::default()
                    .with_interval(Duration::from_secs(5))
                    .build(),
            )
            .build();

        // The interceptor should return its own eto
        let timeout = chain.poll_timeout();
        assert!(timeout.is_some());
    }
}
