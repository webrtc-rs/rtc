//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::send_buffer::SendBuffer;
use super::stream_supports_nack;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket};
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::Instant;

/// Builder for the NackResponderInterceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, NackResponderBuilder};
///
/// let chain = Registry::new()
///     .with(NackResponderBuilder::new()
///         .with_size(1024)
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder<P> {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    _phantom: PhantomData<P>,
}

impl<P> Default for NackResponderBuilder<P> {
    fn default() -> Self {
        Self {
            size: 1024,
            _phantom: PhantomData,
        }
    }
}

impl<P> NackResponderBuilder<P> {
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

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> NackResponderInterceptor<P> {
        move |inner| NackResponderInterceptor::new(inner, self.size)
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
pub struct NackResponderInterceptor<P> {
    inner: P,

    /// Configuration
    size: u16,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> NackResponderInterceptor<P> {
    fn new(inner: P, size: u16) -> Self {
        Self {
            inner,
            size,
            streams: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Handle a NACK request by queuing retransmissions.
    fn handle_nack(
        &mut self,
        now: Instant,
        nack: &rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack,
    ) {
        // Collect sequence numbers to retransmit
        let mut seqs_to_retransmit = Vec::new();

        for nack_pair in &nack.nacks {
            // Check the base packet ID
            seqs_to_retransmit.push(nack_pair.packet_id);

            // Check each bit in lost_packets bitmap
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    let seq = nack_pair.packet_id.wrapping_add(i + 1);
                    seqs_to_retransmit.push(seq);
                }
            }
        }

        let Some(stream) = self.streams.get_mut(&nack.media_ssrc) else {
            return;
        };

        // Queue retransmissions
        for seq in seqs_to_retransmit {
            let Some(original_packet) = stream.send_buffer.get(seq) else {
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
                let mut rtx_payload =
                    Vec::with_capacity(2 + original_packet.payload.len());
                rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
                rtx_payload.extend_from_slice(&original_packet.payload);

                let rtx_seq = stream.rtx_sequence_number;
                stream.rtx_sequence_number = stream.rtx_sequence_number.wrapping_add(1);

                rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: ssrc_rtx,
                        payload_type: pt_rtx,
                        sequence_number: rtx_seq,
                        timestamp: original_packet.header.timestamp,
                        marker: original_packet.header.marker,
                        ..Default::default()
                    },
                    payload: rtx_payload.into(),
                    ..Default::default()
                }
            } else {
                // No RTX: retransmit original packet as-is
                original_packet.clone()
            };

            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: Packet::Rtp(packet),
            });
        }
    }
}

impl<P: Interceptor> sansio::Protocol<TaggedPacket, TaggedPacket, ()>
    for NackResponderInterceptor<P>
{
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Process NACK packets
        if let Packet::Rtcp(ref rtcp_packets) = msg.message {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                {
                    self.handle_nack(msg.now, nack);
                }
            }
        }

        self.inner.handle_read(msg)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.inner.poll_read()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Buffer outgoing RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message {
            if let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc) {
                stream.send_buffer.add(rtp_packet.clone());
            }
        }

        self.inner.handle_write(msg)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        // First drain retransmitted packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        self.inner.poll_write()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.inner.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.inner.poll_timeout()
    }
}

impl<P: Interceptor> Interceptor for NackResponderInterceptor<P> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info) {
            if let Some(send_buffer) = SendBuffer::new(self.size) {
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
    use crate::stream_info::RTCPFeedback;
    use crate::Registry;
    use sansio::Protocol;

    fn make_rtp_packet(ssrc: u32, seq: u16, payload: &[u8]) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number: seq,
                    ..Default::default()
                },
                payload: payload.to_vec().into(),
                ..Default::default()
            }),
        }
    }

    fn make_nack_packet(
        sender_ssrc: u32,
        media_ssrc: u32,
        nacks: Vec<(u16, u16)>,
    ) -> TaggedPacket {
        let nack_pairs: Vec<rtcp::transport_feedbacks::transport_layer_nack::NackPair> = nacks
            .into_iter()
            .map(|(packet_id, lost_packets)| {
                rtcp::transport_feedbacks::transport_layer_nack::NackPair {
                    packet_id,
                    lost_packets,
                }
            })
            .collect();

        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: Packet::Rtcp(vec![Box::new(
                rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
                    sender_ssrc,
                    media_ssrc,
                    nacks: nack_pairs,
                },
            )]),
        }
    }

    #[test]
    fn test_nack_responder_builder_defaults() {
        let chain = Registry::new()
            .with(NackResponderBuilder::default().build())
            .build();

        assert_eq!(chain.size, 1024);
    }

    #[test]
    fn test_nack_responder_builder_custom() {
        let chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(2048).build())
            .build();

        assert_eq!(chain.size, 2048);
    }

    #[test]
    fn test_nack_responder_retransmits_packet() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
            .build();

        // Bind local stream with NACK support
        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        let now = Instant::now();

        // Send packets 10, 11, 12, 14, 15 (missing 13)
        for seq in [10u16, 11, 12, 14, 15] {
            let mut pkt = make_rtp_packet(12345, seq, &[seq as u8]);
            pkt.now = now;
            chain.handle_write(pkt).unwrap();
            chain.poll_write(); // Drain normal write
        }

        // Receive NACK for 11, 12, 13, 15
        // nack_pair: packet_id=11, lost_packets=0b1011 means 11, 12, 13, 15
        let mut nack = make_nack_packet(999, 12345, vec![(11, 0b1011)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();

        // Should retransmit 11, 12, 15 (13 was never sent)
        let mut retransmitted = Vec::new();
        while let Some(pkt) = chain.poll_write() {
            if let Packet::Rtp(rtp) = pkt.message {
                retransmitted.push(rtp.header.sequence_number);
            }
        }

        assert!(retransmitted.contains(&11));
        assert!(retransmitted.contains(&12));
        assert!(!retransmitted.contains(&13)); // Never sent
        assert!(retransmitted.contains(&15));
    }

    #[test]
    fn test_nack_responder_no_retransmit_without_binding() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
            .build();

        let now = Instant::now();

        // Send packets without binding stream (no buffer)
        for seq in [10u16, 11, 12] {
            let mut pkt = make_rtp_packet(12345, seq, &[seq as u8]);
            pkt.now = now;
            chain.handle_write(pkt).unwrap();
            chain.poll_write();
        }

        // Receive NACK
        let mut nack = make_nack_packet(999, 12345, vec![(11, 0)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();

        // No retransmissions (stream not bound)
        assert!(chain.poll_write().is_none());
    }

    #[test]
    fn test_nack_responder_no_retransmit_expired_packet() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
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
        chain.bind_local_stream(&info);

        let now = Instant::now();

        // Send packets 0-15 (buffer size is 8, so 0-7 will be pushed out)
        for seq in 0..16u16 {
            let mut pkt = make_rtp_packet(12345, seq, &[seq as u8]);
            pkt.now = now;
            chain.handle_write(pkt).unwrap();
            chain.poll_write();
        }

        // Request retransmit of seq 0 (should be expired from buffer)
        let mut nack = make_nack_packet(999, 12345, vec![(0, 0)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();

        // No retransmission (packet too old)
        assert!(chain.poll_write().is_none());

        // But seq 10 should still be available
        let mut nack = make_nack_packet(999, 12345, vec![(10, 0)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();

        let pkt = chain.poll_write();
        assert!(pkt.is_some());
        if let Some(tagged) = pkt {
            if let Packet::Rtp(rtp) = tagged.message {
                assert_eq!(rtp.header.sequence_number, 10);
            }
        }
    }

    #[test]
    fn test_nack_responder_unbind_removes_stream() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
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

        chain.bind_local_stream(&info);
        assert!(chain.streams.contains_key(&12345));

        chain.unbind_local_stream(&info);
        assert!(!chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_nack_responder_no_nack_support() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
            .build();

        // Bind stream without NACK support
        let info = StreamInfo {
            ssrc: 12345,
            clock_rate: 90000,
            rtcp_feedback: vec![], // No NACK support
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        // Should not create send buffer
        assert!(!chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_nack_responder_passthrough() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
            .build();

        let now = Instant::now();

        // RTP packets should pass through
        let mut pkt = make_rtp_packet(12345, 1, &[1]);
        pkt.now = now;
        chain.handle_write(pkt).unwrap();
        let out = chain.poll_write();
        assert!(out.is_some());

        // RTCP packets should pass through to read
        let mut nack = make_nack_packet(999, 12345, vec![(1, 0)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();
        let out = chain.poll_read();
        assert!(out.is_some());
    }

    #[test]
    fn test_nack_responder_rfc4588_rtx() {
        let mut chain = Registry::new()
            .with(NackResponderBuilder::new().with_size(8).build())
            .build();

        // Bind local stream with NACK support AND RTX configured
        let info = StreamInfo {
            ssrc: 1,
            ssrc_rtx: Some(2),       // RTX SSRC
            payload_type: 96,
            payload_type_rtx: Some(97), // RTX payload type
            clock_rate: 90000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        let now = Instant::now();

        // Send packets 10, 11, 12, 14, 15 (missing 13)
        for seq in [10u16, 11, 12, 14, 15] {
            let mut pkt = make_rtp_packet(1, seq, &[seq as u8]);
            pkt.now = now;
            chain.handle_write(pkt).unwrap();
            chain.poll_write(); // Drain normal write
        }

        // Receive NACK for 11, 12, 13, 15
        // nack_pair: packet_id=11, lost_packets=0b1011 means 11, 12, 13, 15
        let mut nack = make_nack_packet(999, 1, vec![(11, 0b1011)]);
        nack.now = now;
        chain.handle_read(nack).unwrap();

        // Should retransmit 11, 12, 15 (13 was never sent) using RTX format
        let mut rtx_seq = 0u16;
        for expected_original_seq in [11u16, 12, 15] {
            let pkt = chain.poll_write();
            assert!(pkt.is_some(), "Expected RTX packet for seq {}", expected_original_seq);

            if let Some(tagged) = pkt {
                if let Packet::Rtp(rtp) = tagged.message {
                    // Verify RTX SSRC
                    assert_eq!(rtp.header.ssrc, 2, "RTX packet should use RTX SSRC");
                    // Verify RTX payload type
                    assert_eq!(rtp.header.payload_type, 97, "RTX packet should use RTX payload type");
                    // Verify RTX sequence number (increments separately)
                    assert_eq!(rtp.header.sequence_number, rtx_seq, "RTX seq should be {}", rtx_seq);
                    rtx_seq += 1;

                    // Verify payload: first 2 bytes should be original sequence number (big-endian)
                    assert!(rtp.payload.len() >= 2, "RTX payload should have at least 2 bytes");
                    let original_seq_from_payload =
                        u16::from_be_bytes([rtp.payload[0], rtp.payload[1]]);
                    assert_eq!(
                        original_seq_from_payload, expected_original_seq,
                        "RTX payload should contain original seq"
                    );

                    // Verify original payload follows
                    assert_eq!(
                        rtp.payload[2..],
                        [expected_original_seq as u8],
                        "Original payload should follow seq number"
                    );
                } else {
                    panic!("Expected RTP packet");
                }
            }
        }

        // No more packets
        assert!(chain.poll_write().is_none());
    }
}
