//! Receiver Report Interceptor - Generates RTCP Receiver Reports.

use crate::report::receiver_stream::ReceiverStream;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket};
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Builder for the ReceiverReportInterceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, ReceiverReportBuilder};
/// use std::time::Duration;
///
/// // With default interval (1 second)
/// let chain = Registry::new()
///     .with(ReceiverReportBuilder::new().build())
///     .build();
///
/// // With custom interval
/// let chain = Registry::new()
///     .with(ReceiverReportBuilder::new().with_interval(Duration::from_millis(500)).build())
///     .build();
/// ```
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
    /// Create a new builder with default settings.
    ///
    /// Default interval is 1 second.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom interval between receiver reports.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use rtc_interceptor::ReceiverReportBuilder;
    ///
    /// let builder = ReceiverReportBuilder::new()
    ///     .with_interval(Duration::from_millis(500));
    /// ```
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Create a builder function for use with Registry.
    ///
    /// This returns a closure that can be passed to `Registry::with()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rtc_interceptor::{Registry, ReceiverReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(ReceiverReportBuilder::new().build());
    /// ```
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
/// use rtc_interceptor::{Registry, ReceiverReportBuilder};
///
/// let chain = Registry::new()
///     .with(ReceiverReportBuilder::new().build())
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
        if let Packet::Rtcp(rtcp_packets) = &msg.message {
            for rtcp_packet in rtcp_packets {
                if let Some(sr) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    && let Some(stream) = self.streams.get_mut(&sr.ssrc)
                {
                    stream.process_sender_report(msg.now, sr);
                }
            }
        } else if let Packet::Rtp(rtp_packet) = &msg.message
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.process_rtp(msg.now, rtp_packet);
        }

        self.inner.handle_read(msg)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.inner.poll_read()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
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

impl<P: Interceptor> Interceptor for ReceiverReportInterceptor<P> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        self.inner.bind_local_stream(info);
    }
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.inner.unbind_local_stream(info);
    }
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let stream = ReceiverStream::new(info.ssrc, info.clock_rate);
        self.streams.insert(info.ssrc, stream);

        self.inner.bind_remote_stream(info);
    }
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
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
        use crate::report::sender::SenderReportBuilder;

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

    #[test]
    fn test_receiver_report_generation_on_timeout() {
        // Port of pion's TestReceiverInterceptor - tests full timeout/report cycle
        // No ticker mocking needed - sans-I/O pattern lets us control time directly
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        // Bind a remote stream
        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive some RTP packets through the read path
        for i in 0..10u16 {
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
                    ..Default::default()
                }),
            };
            chain.handle_read(pkt).unwrap();
            chain.poll_read();
        }

        // First timeout triggers report generation (eto was set at construction)
        chain.handle_timeout(base_time).unwrap();

        // Drain any reports from initial timeout
        while chain.poll_write().is_some() {}

        // Advance time past the interval
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // Now a receiver report should be generated
        let report = chain.poll_write();
        assert!(report.is_some());

        if let Some(tagged) = report {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                assert_eq!(rtcp_packets.len(), 1);
                let rr = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .expect("Expected ReceiverReport");
                assert_eq!(rr.reports.len(), 1);
                assert_eq!(rr.reports[0].ssrc, 123456);
                assert_eq!(rr.reports[0].last_sequence_number, 9);
                assert_eq!(rr.reports[0].fraction_lost, 0);
                assert_eq!(rr.reports[0].total_lost, 0);
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_receiver_report_with_packet_loss() {
        // Test receiver report generation with packet loss
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive packet 1
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 1,
                    timestamp: 3000,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Skip packet 2, receive packet 3
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 3,
                    timestamp: 9000,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        let report = chain.poll_write();
        assert!(report.is_some());

        if let Some(tagged) = report {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                let rr = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .expect("Expected ReceiverReport");
                assert_eq!(rr.reports[0].last_sequence_number, 3);
                // 1 packet lost out of 3 total
                assert_eq!(rr.reports[0].total_lost, 1);
                // fraction_lost = 256 * 1 / 3 = 85
                assert_eq!(rr.reports[0].fraction_lost, (256u32 * 1 / 3) as u8);
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_receiver_report_with_sender_report() {
        // Test that receiver report includes DLSR after receiving sender report
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive an RTP packet first
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 1,
                    timestamp: 3000,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Receive a sender report
        let sr = rtcp::sender_report::SenderReport {
            ssrc: 123456,
            ntp_time: 0x1234_5678_0000_0000,
            rtp_time: 3000,
            packet_count: 100,
            octet_count: 10000,
            ..Default::default()
        };
        let sr_pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtcp(vec![Box::new(sr)]),
        };
        chain.handle_read(sr_pkt).unwrap();

        // Generate receiver report 1 second later
        let later_time = base_time + Duration::from_secs(1);
        chain.handle_timeout(later_time).unwrap();

        let report = chain.poll_write();
        assert!(report.is_some());

        if let Some(tagged) = report {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                let rr = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .expect("Expected ReceiverReport");
                // DLSR should be ~65536 (1 second in 1/65536 units)
                assert_eq!(rr.reports[0].delay, 65536);
                // LSR is middle 32 bits of NTP time
                assert_eq!(rr.reports[0].last_sender_report, 0x5678_0000);
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_receiver_report_multiple_streams() {
        // Test that multiple remote streams each generate their own reports
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

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
        chain.bind_remote_stream(&info1);
        chain.bind_remote_stream(&info2);

        let base_time = Instant::now();

        // Receive packets on stream 1
        for i in 0..5u16 {
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
                    ..Default::default()
                }),
            };
            chain.handle_read(pkt).unwrap();
            chain.poll_read();
        }

        // Receive packets on stream 2 with a gap (packet loss)
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 222222,
                    sequence_number: 0,
                    timestamp: 0,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 222222,
                    sequence_number: 5, // Skip 1-4
                    timestamp: 5 * 960,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // Collect all reports
        let mut ssrcs = vec![];
        let mut total_lost = vec![];

        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                for rtcp_pkt in rtcp_packets {
                    if let Some(rr) = rtcp_pkt
                        .as_any()
                        .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    {
                        for report in &rr.reports {
                            ssrcs.push(report.ssrc);
                            total_lost.push(report.total_lost);
                        }
                    }
                }
            }
        }

        assert_eq!(ssrcs.len(), 2);
        assert!(ssrcs.contains(&111111));
        assert!(ssrcs.contains(&222222));

        // Stream 1 should have no loss
        let idx1 = ssrcs.iter().position(|&s| s == 111111).unwrap();
        assert_eq!(total_lost[idx1], 0);

        // Stream 2 should have 4 lost packets (1-4)
        let idx2 = ssrcs.iter().position(|&s| s == 222222).unwrap();
        assert_eq!(total_lost[idx2], 4);
    }

    #[test]
    fn test_receiver_report_unbind_stream() {
        // Test that unbinding a remote stream stops generating reports for it
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive some packets
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
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Unbind the stream
        chain.unbind_remote_stream(&info);

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        // No report should be generated (stream was unbound)
        assert!(chain.poll_write().is_none());
    }

    #[test]
    fn test_receiver_report_sequence_wrap() {
        // Test sequence number wraparound handling
        let mut chain = Registry::new()
            .with(
                ReceiverReportBuilder::default()
                    .with_interval(Duration::from_secs(1))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 123456,
            clock_rate: 90000,
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive packet at 0xffff
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 0xffff,
                    timestamp: 0,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Wrap around to 0x00
        let pkt = TaggedPacket {
            now: base_time,
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc: 123456,
                    sequence_number: 0x00,
                    timestamp: 3000,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        chain.handle_read(pkt).unwrap();
        chain.poll_read();

        // Trigger timeout
        let later_time = base_time + Duration::from_secs(2);
        chain.handle_timeout(later_time).unwrap();

        let report = chain.poll_write();
        assert!(report.is_some());

        if let Some(tagged) = report {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                let rr = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .expect("Expected ReceiverReport");
                // Extended sequence number should show 1 cycle (1 << 16)
                assert_eq!(rr.reports[0].last_sequence_number, 1 << 16);
                assert_eq!(rr.reports[0].fraction_lost, 0);
                assert_eq!(rr.reports[0].total_lost, 0);
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }
}
