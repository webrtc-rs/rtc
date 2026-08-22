//! TWCC Receiver Interceptor - tracks incoming packets and generates feedback.

use super::recorder::Recorder;
use super::stream_supports_twcc;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::Unmarshal;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Default interval for sending TWCC feedback.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Builder for the TwccReceiverInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, TwccReceiverBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::TwccReceiver, TwccReceiverBuilder::new()
///         .with_interval(Duration::from_millis(100))
///         .build())
///     .build();
/// ```
pub struct TwccReceiverBuilder {
    /// Interval between feedback reports.
    interval: Duration,
}

impl Default for TwccReceiverBuilder {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl TwccReceiverBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interval between feedback reports.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> TwccReceiverInterceptor {
        TwccReceiverInterceptor::new(self.interval)
    }
}

/// Per-stream state for the receiver.
struct RemoteStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
}

/// Interceptor that tracks incoming RTP packets and generates TWCC feedback.
///
/// This interceptor examines incoming RTP packets for transport-wide CC sequence
/// numbers and periodically generates TransportLayerCC feedback packets.
pub struct TwccReceiverInterceptor {
    /// Configuration
    interval: Duration,

    /// Start time for calculating arrival times.
    start_time: Option<Instant>,

    /// TWCC recorder for building feedback.
    recorder: Option<Recorder>,

    /// Remote stream state per SSRC.
    streams: HashMap<u32, RemoteStream>,

    /// Queue for feedback packets.
    write_queue: VecDeque<TaggedPacket>,

    /// Next timeout for sending feedback.
    next_timeout: Option<Instant>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl TwccReceiverInterceptor {
    fn new(interval: Duration) -> Self {
        Self {
            read_queue: VecDeque::new(),
            interval,
            start_time: None,
            recorder: None,
            streams: HashMap::new(),
            write_queue: VecDeque::new(),
            next_timeout: None,
        }
    }

    fn generate_feedback(&mut self, now: Instant) {
        let Some(recorder) = self.recorder.as_mut() else {
            return;
        };

        let packets = recorder.build_feedback_packet();
        for pkt in packets {
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![pkt])),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TwccReceiverInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Process incoming RTP packets with TWCC extension
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get(&rtp_packet.header.ssrc)
        {
            // Initialize recorder on first packet
            if self.recorder.is_none() {
                // Use a random sender SSRC for feedback
                self.recorder = Some(Recorder::new(rand::random()));
                self.start_time = Some(msg.now);
                self.next_timeout = Some(msg.now + self.interval);
            }

            // Extract transport CC sequence number
            if let Some(ext_data) = rtp_packet.header.get_extension(stream.hdr_ext_id)
                && let Ok(tcc) =
                    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                        &mut ext_data.as_ref(),
                    )
            {
                // Calculate arrival time in microseconds since start
                let arrival_time = self
                    .start_time
                    .map(|start| msg.now.duration_since(start).as_micros() as i64)
                    .unwrap_or(0);

                if let Some(recorder) = self.recorder.as_mut() {
                    recorder.record(rtp_packet.header.ssrc, tcc.transport_sequence, arrival_time);
                }
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
        // First drain feedback packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        // Check if we need to send feedback
        if let Some(timeout) = self.next_timeout
            && now >= timeout
        {
            self.generate_feedback(now);
            self.next_timeout = Some(now + self.interval);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for TwccReceiverInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(hdr_ext_id) = stream_supports_twcc(info) {
            // Don't track if ID is 0 (invalid)
            if hdr_ext_id != 0 {
                self.streams.insert(info.ssrc, RemoteStream { hdr_ext_id });
            }
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
