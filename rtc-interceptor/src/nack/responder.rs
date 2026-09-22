//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::send_buffer::{HistoryLimits, SendBuffer};
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Default for how long a sent packet stays retransmittable: [`NackResponderBuilder::with_max_age`].
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(3);

/// Builder for the NackResponderInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, NackResponderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::NackResponder, NackResponderBuilder::new()
///         .with_size(1024)
///         .with_max_bytes(1 << 20)
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    /// Retransmission history limits beyond the packet count.
    limits: HistoryLimits,
}

impl Default for NackResponderBuilder {
    fn default() -> Self {
        Self {
            size: 1024,
            limits: HistoryLimits {
                max_bytes: usize::MAX,
                max_age: Some(DEFAULT_MAX_AGE),
            },
        }
    }
}

impl NackResponderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the send buffer.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Larger buffers can retransmit older packets but use more memory.
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Bound each stream's history by the payload bytes it keeps alive, as well as by packet
    /// count. Unbounded by default, so the packet count alone applies.
    ///
    /// RTP payloads are shared, so the history copies nothing — but it holds each payload's
    /// allocation for as long as the packet is kept. When the limit is exceeded the oldest
    /// packets are dropped first. The most recent packet is always kept.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.limits.max_bytes = max_bytes;
        self
    }

    /// How long a sent packet stays available for retransmission. Default: 3 seconds.
    ///
    /// A retransmission is only useful while the receiver is still waiting for the packet, a
    /// few round trips at most; past that it arrives too late to be played. The limit also
    /// releases a stream's history once it stops sending, rather than holding up to `size`
    /// packets for as long as the stream stays bound. Size it to the longest recovery window
    /// worth supporting — several times the round-trip time. `None` keeps packets until the
    /// packet count or byte limit displaces them.
    pub fn with_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.limits.max_age = max_age;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NackResponderInterceptor {
        NackResponderInterceptor::new(self.size, self.limits)
    }
}

/// Per-stream state for the responder.
struct LocalStream {
    /// Buffer of sent packets for retransmission.
    send_buffer: SendBuffer,
    /// RTX SSRC for RFC4588 retransmission (if configured).
    ssrc_rtx: Option<u32>,
    /// RTX payload type for RFC4588 retransmission (if configured).
    payload_type_rtx: Option<u8>,
    /// Sequence number counter for RTX packets.
    rtx_sequence_number: u16,
}

/// Interceptor that responds to NACK requests by retransmitting packets.
///
/// This interceptor buffers outgoing RTP packets on local streams and
/// retransmits them when RTCP TransportLayerNack packets are received.
pub struct NackResponderInterceptor {
    /// Configuration
    size: u16,
    limits: HistoryLimits,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl NackResponderInterceptor {
    fn new(size: u16, limits: HistoryLimits) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            limits,
            streams: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Handle a NACK request by queuing retransmissions.
    ///
    /// Retransmits in the order the request lists them: pair by pair, each pair's base packet
    /// first and then the packets its bitmask names, ascending (wrapping).
    fn handle_nack(
        &mut self,
        now: Instant,
        nack: &rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack,
    ) {
        let Some(stream) = self.streams.get_mut(&nack.media_ssrc) else {
            return;
        };

        // Each pair's iterator finds its set bits with `trailing_zeros` rather than testing all
        // 16 positions. The stream and the write queue are separate fields, so the sequence
        // numbers go straight to the send-buffer lookup without being collected first.
        for seq in nack.nacks.iter().flat_map(|&pair| pair) {
            let Some(original_packet) = stream.send_buffer.get(seq, now) else {
                continue;
            };

            let packet = if let (Some(ssrc_rtx), Some(pt_rtx)) =
                (stream.ssrc_rtx, stream.payload_type_rtx)
            {
                // RFC4588: Create RTX packet
                // - Use RTX SSRC and payload type
                // - Prepend original sequence number (2 bytes big-endian) to payload
                // - Use separate RTX sequence number counter
                let original_seq = original_packet.header.sequence_number;
                let mut rtx_payload = Vec::with_capacity(2 + original_packet.payload.len());
                rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
                rtx_payload.extend_from_slice(&original_packet.payload);

                let rtx_seq = stream.rtx_sequence_number;
                stream.rtx_sequence_number = stream.rtx_sequence_number.wrapping_add(1);

                rtp::Packet {
                    header: rtp::header::Header {
                        // Not left to `..Default::default()`: the default
                        // header is version 0, and receivers discard
                        // version != 2 before examining anything else, so a
                        // defaulted RTX packet is dropped on arrival and the
                        // NACKed gap never repairs.
                        version: 2,
                        ssrc: ssrc_rtx,
                        payload_type: pt_rtx,
                        sequence_number: rtx_seq,
                        timestamp: original_packet.header.timestamp,
                        marker: original_packet.header.marker,
                        ..Default::default()
                    },
                    payload: rtx_payload.into(),
                }
            } else {
                // No RTX: retransmit original packet as-is
                original_packet.clone()
            };

            // Tagged so a send history downstream counts it as new bytes on the wire rather
            // than as the original transmission. A bandwidth estimator that cannot tell the two
            // apart under-counts exactly when the path is lossy — it sees fewer bytes than are
            // really being sent, infers headroom, and raises the target during loss.
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackResponderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Process NACK packets
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                {
                    self.handle_nack(msg.now, nack);
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
        // Buffer outgoing RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.send_buffer.add(rtp_packet.clone(), msg.now);
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain retransmitted packets
        self.write_queue.pop_front()
    }

    /// Releases the history of streams that have stopped sending. A stream still sending
    /// evicts aged packets as it adds new ones; this is for the one that went quiet.
    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        for stream in self.streams.values_mut() {
            if stream
                .send_buffer
                .expires_at()
                .is_some_and(|expires_at| expires_at <= now)
            {
                stream.send_buffer.expire(now);
            }
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.streams
            .values()
            .filter_map(|stream| stream.send_buffer.expires_at())
            .min()
    }
}

impl Interceptor for NackResponderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(send_buffer) = SendBuffer::with_limits(self.size, self.limits)
        {
            self.streams.insert(
                info.ssrc,
                LocalStream {
                    send_buffer,
                    ssrc_rtx: info.ssrc_rtx,
                    payload_type_rtx: info.payload_type_rtx,
                    rtx_sequence_number: 0,
                },
            );
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTCPFeedback;
    use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};

    const SSRC: u32 = 7;
    const RTX_SSRC: u32 = 8;

    /// The order `handle_nack` retransmitted in before it used `NackPair`'s iterator: all 16
    /// bitmask positions tested for each pair, after its base packet.
    fn reference_order(nack: &TransportLayerNack) -> Vec<u16> {
        let mut seqs = Vec::new();
        for nack_pair in &nack.nacks {
            seqs.push(nack_pair.packet_id);
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    seqs.push(nack_pair.packet_id.wrapping_add(i + 1));
                }
            }
        }
        seqs
    }

    fn responder(rtx: bool) -> NackResponderInterceptor {
        let mut responder = NackResponderBuilder::new()
            .with_size(512)
            .with_max_age(None)
            .build();
        responder.bind_local_stream(&StreamInfo {
            ssrc: SSRC,
            ssrc_rtx: rtx.then_some(RTX_SSRC),
            payload_type_rtx: rtx.then_some(97),
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
        responder
    }

    /// Retransmissions come out in the order the per-position scan produced, with and without
    /// RTX: base packet first, bitmask packets ascending and wrapping past 65535, pairs in
    /// request order, repeats retransmitted again, and packets not in the history skipped.
    #[test]
    fn retransmission_order_matches_per_position_scan() {
        let mut rng = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let now = Instant::now();
        for rtx in [false, true] {
            let mut responder = responder(rtx);
            // 512 packets of history ending just past the wrap: 65_300 ..= 275.
            for i in 0..512u16 {
                let seq = 65_300u16.wrapping_add(i);
                responder
                    .handle_write(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                            header: rtp::header::Header {
                                version: 2,
                                ssrc: SSRC,
                                sequence_number: seq,
                                ..Default::default()
                            },
                            payload: seq.to_be_bytes().to_vec().into(),
                        })),
                    })
                    .unwrap();
            }
            while responder.poll_write().is_some() {}

            let mut rtx_seq = 0u16;
            for round in 0..200 {
                let nacks = (0..1 + next() % 6)
                    .map(|_| NackPair {
                        // Mostly inside the history, sometimes around its edges.
                        packet_id: 65_280u16.wrapping_add((next() % 560) as u16),
                        lost_packets: match round % 4 {
                            0 => next() as u16,
                            1 => u16::MAX,
                            2 => 1 << (next() % 16),
                            _ => 0,
                        },
                    })
                    .collect();
                let nack = TransportLayerNack {
                    sender_ssrc: 1,
                    media_ssrc: SSRC,
                    nacks,
                };
                let stream = &responder.streams[&SSRC];
                let expected: Vec<u16> = reference_order(&nack)
                    .into_iter()
                    .filter(|&seq| stream.send_buffer.get(seq, now).is_some())
                    .collect();

                responder
                    .handle_read(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(nack)])),
                    })
                    .unwrap();
                while responder.poll_read().is_some() {}

                let mut got = Vec::new();
                while let Some(sent) = responder.poll_write() {
                    let Packet::Rtp(packet) = &sent.message.packet else {
                        panic!("only retransmissions are queued");
                    };
                    if rtx {
                        assert_eq!(packet.header.ssrc, RTX_SSRC);
                        assert_eq!(packet.header.sequence_number, rtx_seq);
                        rtx_seq = rtx_seq.wrapping_add(1);
                        // RFC 4588: the original sequence number leads the payload, followed
                        // by the original payload, which is that number again.
                        assert_eq!(packet.payload[..2], packet.payload[2..]);
                    } else {
                        assert_eq!(packet.header.ssrc, SSRC);
                    }
                    got.push(u16::from_be_bytes([packet.payload[0], packet.payload[1]]));
                }
                assert_eq!(got, expected, "round {round}, rtx {rtx}");
            }
        }
    }
}
