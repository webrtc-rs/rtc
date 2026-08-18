//! NACK Generator Interceptor - Generates NACK requests for missing packets.

use super::receive_log::ReceiveLog;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the NackGeneratorInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Registry, NackGeneratorBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(NackGeneratorBuilder::new()
///         .with_size(512)
///         .with_interval(Duration::from_millis(100))
///         .with_skip_last_n(2)
///         .build())
///     .build();
/// ```
pub struct NackGeneratorBuilder {
    /// Size of the receive log (must be power of 2: 64, 128, ..., 32768).
    size: u16,
    /// Interval between NACK generation cycles.
    interval: Duration,
    /// Number of most recent packets to skip when generating NACKs.
    skip_last_n: u16,
    /// Maximum number of NACKs to send per missing packet (0 = unlimited).
    max_nacks_per_packet: u16,
}

impl Default for NackGeneratorBuilder {
    fn default() -> Self {
        Self {
            size: 512,
            interval: Duration::from_millis(100),
            skip_last_n: 0,
            max_nacks_per_packet: 0,
        }
    }
}

impl NackGeneratorBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the receive log.
    ///
    /// Size must be a power of 2 between 64 and 32768 (inclusive).
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set the interval between NACK generation cycles.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the number of most recent packets to skip when generating NACKs.
    ///
    /// This helps avoid generating NACKs for packets that are simply delayed
    /// and haven't arrived yet.
    pub fn with_skip_last_n(mut self, skip_last_n: u16) -> Self {
        self.skip_last_n = skip_last_n;
        self
    }

    /// Set the maximum number of NACKs to send per missing packet.
    ///
    /// Set to 0 (default) for unlimited NACKs.
    pub fn with_max_nacks_per_packet(mut self, max: u16) -> Self {
        self.max_nacks_per_packet = max;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NackGeneratorInterceptor {
        NackGeneratorInterceptor::new(
            self.size,
            self.interval,
            self.skip_last_n,
            self.max_nacks_per_packet,
        )
    }
}

/// Interceptor that generates NACK requests for missing RTP packets.
///
/// This interceptor monitors incoming RTP packets on remote streams,
/// tracks which sequence numbers have been received, and periodically
/// generates RTCP TransportLayerNack packets for missing sequences.
pub struct NackGeneratorInterceptor {
    /// Configuration
    size: u16,
    interval: Duration,
    skip_last_n: u16,
    max_nacks_per_packet: u16,

    /// Next timeout for NACK generation
    next_timeout: Option<Instant>,

    /// Sender SSRC for NACK packets
    sender_ssrc: u32,

    /// Receive logs per remote stream SSRC
    receive_logs: HashMap<u32, ReceiveLog>,

    /// NACK count per (SSRC, sequence number) for max_nacks_per_packet limiting
    nack_counts: HashMap<u32, HashMap<u16, u16>>,

    /// Queue for outgoing NACK packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl NackGeneratorInterceptor {
    fn new(size: u16, interval: Duration, skip_last_n: u16, max_nacks_per_packet: u16) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            interval,
            skip_last_n,
            max_nacks_per_packet,
            next_timeout: None,
            sender_ssrc: rand::random(),
            receive_logs: HashMap::new(),
            nack_counts: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Generate NACKs for all streams with missing packets.
    fn generate_nacks(&mut self, now: Instant) {
        for (&ssrc, receive_log) in &self.receive_logs {
            let missing = receive_log.missing_seq_numbers(self.skip_last_n);
            if missing.is_empty() {
                // Clear nack counts for this SSRC if no missing packets
                self.nack_counts.remove(&ssrc);
                continue;
            }

            // Initialize nack counts for this SSRC if needed
            let nack_count = self.nack_counts.entry(ssrc).or_default();

            // Filter by max_nacks_per_packet if configured
            let filtered: Vec<u16> = if self.max_nacks_per_packet > 0 {
                missing
                    .iter()
                    .filter(|&&seq| {
                        let count = nack_count.entry(seq).or_insert(0);
                        if *count < self.max_nacks_per_packet {
                            *count += 1;
                            true
                        } else {
                            false
                        }
                    })
                    .copied()
                    .collect()
            } else {
                missing.clone()
            };

            if filtered.is_empty() {
                continue;
            }

            // Clean up nack counts for packets no longer missing
            nack_count.retain(|seq, _| missing.contains(seq));

            // Create NACK packet
            let nack = rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
                sender_ssrc: self.sender_ssrc,
                media_ssrc: ssrc,
                nacks: rtcp::transport_feedbacks::transport_layer_nack::nack_pairs_from_sequence_numbers(
                    &filtered,
                ),
            };

            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(nack)])),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackGeneratorInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Track incoming RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(receive_log) = self.receive_logs.get_mut(&rtp_packet.header.ssrc)
        {
            receive_log.add(rtp_packet.header.sequence_number);

            // Arm the NACK timer from the first tracked packet's instant. `None` means nothing is
            // scheduled, so the interceptor asks for no wake-up until a stream is actually flowing.
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
        // First drain generated NACK packets
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
            self.generate_nacks(now);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for NackGeneratorInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(receive_log) = ReceiveLog::new(self.size)
        {
            self.receive_logs.insert(info.ssrc, receive_log);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receive_logs.remove(&info.ssrc);
        self.nack_counts.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
