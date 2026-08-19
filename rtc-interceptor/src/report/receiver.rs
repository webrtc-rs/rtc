//! Receiver Report Interceptor - Generates RTCP Receiver Reports.

use super::receiver_stream::ReceiverStream;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the ReceiverReportInterceptor.
///
/// # Example
///
/// ```
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
pub struct ReceiverReportBuilder {
    /// Interval between receiver reports.
    interval: Duration,
}

impl Default for ReceiverReportBuilder {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
        }
    }
}

impl ReceiverReportBuilder {
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
    /// ```
    /// use rtc_interceptor::{ReceiverReportBuilder, Registry};
    /// use std::time::Duration;
    ///
    /// // The builder is generic over the next layer, so its type is pinned by `with`.
    /// let registry = Registry::new().with(
    ///     ReceiverReportBuilder::new()
    ///         .with_interval(Duration::from_millis(500))
    ///         .build(),
    /// );
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
    /// ```
    /// use rtc_interceptor::{Registry, ReceiverReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(ReceiverReportBuilder::new().build());
    /// ```
    pub fn build(self) -> ReceiverReportInterceptor {
        ReceiverReportInterceptor::new(self.interval)
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
/// ```
/// use rtc_interceptor::{Registry, ReceiverReportBuilder};
///
/// let chain = Registry::new()
///     .with(ReceiverReportBuilder::new().build())
///     .build();
/// ```
pub struct ReceiverReportInterceptor {
    interval: Duration,
    next_timeout: Option<Instant>,

    streams: HashMap<u32, ReceiverStream>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl ReceiverReportInterceptor {
    /// Create a new ReceiverReportInterceptor with default configuration.
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_timeout: None,

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

impl Protocol<TaggedPacket, TaggedPacket, ()> for ReceiverReportInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(rtcp_packets) = &msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(sr) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    && let Some(stream) = self.streams.get_mut(&sr.ssrc)
                {
                    stream.process_sender_report(msg.now, sr);
                }
            }
        } else if let Packet::Rtp(rtp_packet) = &msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.process_rtp(msg.now, rtp_packet);

            // Arm the report timer from the first packet's instant (see nack::generator).
            if self.next_timeout.is_none() {
                self.next_timeout = Some(msg.now + self.interval);
            }
        }

        self.read_queue.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain generated RTCP reports
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);

            for stream in self.streams.values_mut() {
                let rr = stream.generate_report(now);
                self.write_queue.push_back(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(rr)])),
                });
            }
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for ReceiverReportInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let stream = ReceiverStream::new(info.ssrc, info.clock_rate);
        self.streams.insert(info.ssrc, stream);
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
