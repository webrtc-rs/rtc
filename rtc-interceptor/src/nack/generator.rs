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
/// use rtc_interceptor::{Slot, Registry, NackGeneratorBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::NackGenerator, NackGeneratorBuilder::new()
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

            // Filter by max_nacks_per_packet if configured. Unlimited, the missing list is the
            // feedback as it stands.
            let filtered: Vec<u16> = if self.max_nacks_per_packet > 0 {
                let nack_count = self.nack_counts.entry(ssrc).or_default();

                // Forget packets no longer missing — arrived late, or slid out of the log —
                // before counting, and whether or not this round goes on to send anything: a
                // round in which every missing packet has used up its allowance would otherwise
                // leave the stale counts for a later one. Membership comes from the receive log
                // in constant time; checking each count against the missing list was
                // O(counts × missing) on every round under loss.
                nack_count.retain(|&seq, _| receive_log.is_missing(seq, self.skip_last_n));

                missing
                    .into_iter()
                    .filter(|&seq| {
                        let count = nack_count.entry(seq).or_insert(0);
                        if *count < self.max_nacks_per_packet {
                            *count += 1;
                            true
                        } else {
                            false
                        }
                    })
                    .collect()
            } else {
                missing
            };

            if filtered.is_empty() {
                continue;
            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTCPFeedback;
    use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;

    const SSRC: u32 = 1;

    fn generator(max_nacks_per_packet: u16) -> NackGeneratorInterceptor {
        let mut generator = NackGeneratorBuilder::new()
            .with_interval(Duration::from_millis(10))
            .with_max_nacks_per_packet(max_nacks_per_packet)
            .build();
        generator.bind_remote_stream(&StreamInfo {
            ssrc: SSRC,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
        generator
    }

    fn receive(generator: &mut NackGeneratorInterceptor, seq: u16, now: Instant) {
        generator
            .handle_read(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: SSRC,
                        sequence_number: seq,
                        ..Default::default()
                    },
                    ..Default::default()
                })),
            })
            .unwrap();
        while generator.poll_read().is_some() {}
    }

    /// Runs one NACK round at `now` and returns the sequence numbers it asked for.
    fn round(generator: &mut NackGeneratorInterceptor, now: Instant) -> Vec<u16> {
        generator.handle_timeout(now).unwrap();
        let mut nacked = vec![];
        while let Some(packet) = generator.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
                for rtcp_packet in rtcp_packets {
                    if let Some(nack) = rtcp_packet.as_any().downcast_ref::<TransportLayerNack>() {
                        nacked.extend(nack.nacks.iter().flat_map(|pair| pair.packet_list()));
                    }
                }
            }
        }
        nacked
    }

    /// A packet that arrives late must stop being counted, even in a round that sends nothing
    /// because every packet still missing has used up its allowance.
    #[test]
    fn retry_counts_are_released_when_no_nack_is_sent() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut generator = generator(1);
        for seq in [0, 1, 3, 4, 6] {
            receive(&mut generator, seq, t0);
        }

        assert_eq!(round(&mut generator, at(10)), vec![2, 5]);
        assert!(
            round(&mut generator, at(20)).is_empty(),
            "allowance used up"
        );

        receive(&mut generator, 2, at(25));
        assert!(
            round(&mut generator, at(30)).is_empty(),
            "5 is still used up"
        );
        assert_eq!(
            generator.nack_counts[&SSRC]
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![5],
            "the count for 2 must go once 2 has arrived"
        );
    }

    /// The limit counts per packet: a packet that goes missing later gets its full allowance.
    #[test]
    fn retry_limit_applies_per_packet() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut generator = generator(2);
        for seq in [0, 2] {
            receive(&mut generator, seq, t0);
        }

        assert_eq!(round(&mut generator, at(10)), vec![1]);
        receive(&mut generator, 4, at(15));
        assert_eq!(round(&mut generator, at(20)), vec![1, 3]);
        assert_eq!(round(&mut generator, at(30)), vec![3]);
        assert!(round(&mut generator, at(40)).is_empty());
    }

    /// Unlimited retries keep no counts and ask for every missing packet every round.
    #[test]
    fn unlimited_retries_keep_no_counts() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut generator = generator(0);
        for seq in [0, 2, 5] {
            receive(&mut generator, seq, t0);
        }

        for tick in 1..=3 {
            assert_eq!(round(&mut generator, at(tick * 10)), vec![1, 3, 4]);
        }
        assert!(generator.nack_counts.is_empty());
    }
}
