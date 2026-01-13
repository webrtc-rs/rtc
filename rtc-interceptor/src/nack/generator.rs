//! NACK Generator Interceptor - Generates NACK requests for missing packets.

use super::receive_log::ReceiveLog;
use super::stream_supports_nack;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Builder for the NackGeneratorInterceptor.
///
/// # Example
///
/// ```ignore
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
pub struct NackGeneratorBuilder<P> {
    /// Size of the receive log (must be power of 2: 64, 128, ..., 32768).
    size: u16,
    /// Interval between NACK generation cycles.
    interval: Duration,
    /// Number of most recent packets to skip when generating NACKs.
    skip_last_n: u16,
    /// Maximum number of NACKs to send per missing packet (0 = unlimited).
    max_nacks_per_packet: u16,
    _phantom: PhantomData<P>,
}

impl<P> Default for NackGeneratorBuilder<P> {
    fn default() -> Self {
        Self {
            size: 512,
            interval: Duration::from_millis(100),
            skip_last_n: 0,
            max_nacks_per_packet: 0,
            _phantom: PhantomData,
        }
    }
}

impl<P> NackGeneratorBuilder<P> {
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

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> NackGeneratorInterceptor<P> {
        move |inner| {
            NackGeneratorInterceptor::new(
                inner,
                self.size,
                self.interval,
                self.skip_last_n,
                self.max_nacks_per_packet,
            )
        }
    }
}

/// Interceptor that generates NACK requests for missing RTP packets.
///
/// This interceptor monitors incoming RTP packets on remote streams,
/// tracks which sequence numbers have been received, and periodically
/// generates RTCP TransportLayerNack packets for missing sequences.
#[derive(Interceptor)]
pub struct NackGeneratorInterceptor<P> {
    #[next]
    inner: P,

    /// Configuration
    size: u16,
    interval: Duration,
    skip_last_n: u16,
    max_nacks_per_packet: u16,

    /// Next timeout for NACK generation
    eto: Instant,

    /// Sender SSRC for NACK packets
    sender_ssrc: u32,

    /// Receive logs per remote stream SSRC
    receive_logs: HashMap<u32, ReceiveLog>,

    /// NACK count per (SSRC, sequence number) for max_nacks_per_packet limiting
    nack_counts: HashMap<u32, HashMap<u16, u16>>,

    /// Queue for outgoing NACK packets
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> NackGeneratorInterceptor<P> {
    fn new(
        inner: P,
        size: u16,
        interval: Duration,
        skip_last_n: u16,
        max_nacks_per_packet: u16,
    ) -> Self {
        Self {
            inner,
            size,
            interval,
            skip_last_n,
            max_nacks_per_packet,
            eto: Instant::now(),
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
                message: Packet::Rtcp(vec![Box::new(nack)]),
            });
        }
    }
}

#[interceptor]
impl<P: Interceptor> NackGeneratorInterceptor<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Track incoming RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message
            && let Some(receive_log) = self.receive_logs.get_mut(&rtp_packet.header.ssrc)
        {
            receive_log.add(rtp_packet.header.sequence_number);
        }

        self.inner.handle_read(msg)
    }

    #[overrides]
    fn poll_write(&mut self) -> Option<Self::Wout> {
        // First drain generated NACK packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        self.inner.poll_write()
    }

    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        if self.eto <= now {
            self.eto = now + self.interval;
            self.generate_nacks(now);
        }

        self.inner.handle_timeout(now)
    }

    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        if let Some(inner_eto) = self.inner.poll_timeout()
            && inner_eto < self.eto
        {
            return Some(inner_eto);
        }
        Some(self.eto)
    }

    #[overrides]
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(receive_log) = ReceiveLog::new(self.size)
        {
            self.receive_logs.insert(info.ssrc, receive_log);
        }
        self.inner.bind_remote_stream(info);
    }

    #[overrides]
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receive_logs.remove(&info.ssrc);
        self.nack_counts.remove(&info.ssrc);
        self.inner.unbind_remote_stream(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;
    use crate::stream_info::RTCPFeedback;
    use sansio::Protocol;

    fn make_rtp_packet(ssrc: u32, seq: u16) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number: seq,
                    ..Default::default()
                },
                ..Default::default()
            }),
        }
    }

    #[test]
    fn test_nack_generator_builder_defaults() {
        let chain = Registry::new()
            .with(NackGeneratorBuilder::default().build())
            .build();

        assert_eq!(chain.size, 512);
        assert_eq!(chain.interval, Duration::from_millis(100));
        assert_eq!(chain.skip_last_n, 0);
        assert_eq!(chain.max_nacks_per_packet, 0);
    }

    #[test]
    fn test_nack_generator_builder_custom() {
        let chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_size(1024)
                    .with_interval(Duration::from_millis(50))
                    .with_skip_last_n(3)
                    .with_max_nacks_per_packet(5)
                    .build(),
            )
            .build();

        assert_eq!(chain.size, 1024);
        assert_eq!(chain.interval, Duration::from_millis(50));
        assert_eq!(chain.skip_last_n, 3);
        assert_eq!(chain.max_nacks_per_packet, 5);
    }

    #[test]
    fn test_nack_generator_no_nack_without_binding() {
        let mut chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_interval(Duration::from_millis(100))
                    .build(),
            )
            .build();

        let now = Instant::now();

        // Receive packets without binding stream (no receive log)
        chain.handle_read(make_rtp_packet(12345, 0)).unwrap();
        chain.handle_read(make_rtp_packet(12345, 2)).unwrap(); // Gap at 1

        // Trigger timeout
        let later = now + Duration::from_millis(200);
        chain.handle_timeout(later).unwrap();

        // No NACK should be generated (stream not bound)
        assert!(chain.poll_write().is_none());
    }

    #[test]
    fn test_nack_generator_generates_nack() {
        let mut chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_size(64)
                    .with_interval(Duration::from_millis(100))
                    .build(),
            )
            .build();

        // Bind remote stream with NACK support
        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive packets with gap
        let mut pkt = make_rtp_packet(12345, 10);
        pkt.now = base_time;
        chain.handle_read(pkt).unwrap();

        let mut pkt = make_rtp_packet(12345, 12); // Gap at 11
        pkt.now = base_time;
        chain.handle_read(pkt).unwrap();

        chain.poll_read();

        // Trigger timeout
        let later = base_time + Duration::from_millis(200);
        chain.handle_timeout(later).unwrap();

        // Should generate NACK for seq 11
        let nack_pkt = chain.poll_write();
        assert!(nack_pkt.is_some());

        if let Some(tagged) = nack_pkt {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                assert_eq!(rtcp_packets.len(), 1);
                let nack = rtcp_packets[0]
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                    .expect("Expected TransportLayerNack");
                assert_eq!(nack.media_ssrc, 12345);
                assert!(!nack.nacks.is_empty());
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_nack_generator_skip_last_n() {
        let mut chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_size(64)
                    .with_interval(Duration::from_millis(100))
                    .with_skip_last_n(2)
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let base_time = Instant::now();

        // Receive: 10, 11, 12, 14, 16, 18 (gaps at 13, 15, 17)
        for seq in [10u16, 11, 12, 14, 16, 18] {
            let mut pkt = make_rtp_packet(12345, seq);
            pkt.now = base_time;
            chain.handle_read(pkt).unwrap();
        }

        // Trigger timeout
        let later = base_time + Duration::from_millis(200);
        chain.handle_timeout(later).unwrap();

        // With skip_last_n=2, should only NACK for 13, 15 (not 17)
        let nack_pkt = chain.poll_write();
        assert!(nack_pkt.is_some());

        if let Some(tagged) = nack_pkt
            && let Packet::Rtcp(rtcp_packets) = tagged.message
        {
            let nack = rtcp_packets[0]
                .as_any()
                .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                .expect("Expected TransportLayerNack");

            // Get all nacked sequence numbers
            let mut nacked_seqs = Vec::new();
            for nack_pair in &nack.nacks {
                nacked_seqs.push(nack_pair.packet_id);
                for i in 0..16 {
                    if nack_pair.lost_packets & (1 << i) != 0 {
                        nacked_seqs.push(nack_pair.packet_id.wrapping_add(i + 1));
                    }
                }
            }

            // Should contain 13, 15 but not 17
            assert!(nacked_seqs.contains(&13));
            assert!(nacked_seqs.contains(&15));
            assert!(!nacked_seqs.contains(&17));
        }
    }

    #[test]
    fn test_nack_generator_unbind_removes_stream() {
        let mut chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_size(64)
                    .with_interval(Duration::from_millis(100))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };

        chain.bind_remote_stream(&info);
        assert!(chain.receive_logs.contains_key(&12345));

        chain.unbind_remote_stream(&info);
        assert!(!chain.receive_logs.contains_key(&12345));
        assert!(!chain.nack_counts.contains_key(&12345));
    }

    #[test]
    fn test_nack_generator_no_nack_support() {
        let mut chain = Registry::new()
            .with(
                NackGeneratorBuilder::new()
                    .with_size(64)
                    .with_interval(Duration::from_millis(100))
                    .build(),
            )
            .build();

        // Bind stream without NACK support
        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![], // No NACK support
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        // Should not create receive log
        assert!(!chain.receive_logs.contains_key(&12345));
    }
}
