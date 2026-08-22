//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

use super::sender_stream::SenderStream;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use rtcp::header::PacketType;
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the SenderReportInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
/// use std::time::Duration;
///
/// // With default interval (1 second)
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().build())
///     .build();
///
/// // With custom interval
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().with_interval(Duration::from_millis(500)).build())
///     .build();
///
/// // With use_latest_packet enabled
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().with_use_latest_packet().build())
///     .build();
/// ```
pub struct SenderReportBuilder {
    /// Interval between sender reports.
    interval: Duration,
    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,
}

impl Default for SenderReportBuilder {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            use_latest_packet: false,
        }
    }
}

impl SenderReportBuilder {
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
    /// ```
    /// use rtc_interceptor::{Registry, SenderReportBuilder, Slot};
    /// use std::time::Duration;
    ///
    /// let registry = Registry::new().with(
    ///     Slot::SenderReport,
    ///     SenderReportBuilder::new()
    ///         .with_interval(Duration::from_millis(500))
    ///         .build(),
    /// );
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
    /// ```
    /// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
    ///
    /// let registry =
    ///     Registry::new().with(Slot::SenderReport, SenderReportBuilder::new().with_use_latest_packet().build());
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
    /// ```
    /// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(Slot::SenderReport, SenderReportBuilder::new().build());
    /// ```
    pub fn build(self) -> SenderReportInterceptor {
        SenderReportInterceptor::new(self.interval, self.use_latest_packet)
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
/// ```
/// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().build())
///     .build();
/// ```
pub struct SenderReportInterceptor {
    interval: Duration,
    next_timeout: Option<Instant>,

    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,

    streams: HashMap<u32, SenderStream>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl SenderReportInterceptor {
    /// Create a new SenderReportInterceptor.
    fn new(interval: Duration, use_latest_packet: bool) -> Self {
        Self {
            interval,
            next_timeout: None,

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
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for SenderReportInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp_packet) = &msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.process_rtp(msg.now, rtp_packet);

            // Arm the report timer from the first packet's instant (see nack::generator).
            if self.next_timeout.is_none() {
                self.next_timeout = Some(msg.now + self.interval);
            }
        }

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
                if let Some(rr) = stream.generate_report(now) {
                    self.write_queue.push_back(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(rr)])),
                    });
                }
            }
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for SenderReportInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let stream = SenderStream::new(info.ssrc, info.clock_rate, self.use_latest_packet);
        self.streams.insert(info.ssrc, stream);
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
