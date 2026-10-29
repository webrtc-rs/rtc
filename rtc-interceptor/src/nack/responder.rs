//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::send_buffer::SendBuffer;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Decides which local streams this responder buffers, on top of the NACK feedback check.
/// pion's `ResponderStreamsFilter`.
pub type ResponderStreamsFilter = Box<dyn Fn(&StreamInfo) -> bool + Send + Sync>;

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
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    /// Extra per-stream gate, applied on top of the NACK feedback check.
    streams_filter: Option<ResponderStreamsFilter>,
}

impl Default for NackResponderBuilder {
    fn default() -> Self {
        Self {
            size: 1024,
            streams_filter: None,
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

    /// Restrict which local streams are buffered, on top of the NACK feedback check.
    ///
    /// pion's `ResponderStreamsFilter`: the predicate returns `true` for streams whose packets
    /// should be kept for retransmission. Without one, every stream negotiating `nack`
    /// feedback is buffered.
    pub fn with_streams_filter(mut self, filter: ResponderStreamsFilter) -> Self {
        self.streams_filter = Some(filter);
        self
    }

    /// Build the interceptor, rejecting a buffer size that could never retransmit anything.
    ///
    /// pion fails construction with `ErrInvalidSize`; the infallible [`Self::build`] keeps its
    /// historic shape and instead yields an interceptor that buffers nothing, so callers that
    /// prefer a loud mistake use this.
    pub fn try_build(self) -> Result<NackResponderInterceptor, Error> {
        if !super::send_buffer::is_valid_size(self.size) {
            return Err(Error::ErrNackInvalidSize);
        }
        Ok(self.build())
    }

    /// Build the interceptor.
    ///
    /// A size the send buffer cannot hold (not a power of two in range) yields an interceptor
    /// that buffers nothing; [`Self::try_build`] turns the same configuration into an error
    /// instead.
    pub fn build(self) -> NackResponderInterceptor {
        NackResponderInterceptor::new(self.size, self.streams_filter)
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
    /// Extra per-stream gate from the builder, applied with the NACK feedback check.
    streams_filter: Option<ResponderStreamsFilter>,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl NackResponderInterceptor {
    fn new(size: u16, streams_filter: Option<ResponderStreamsFilter>) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            streams_filter,
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

                // pion strips padding from the RTX copy: the P-bit comes off, and in the legacy
                // style — padding declared only by the P-bit, its count in the last payload
                // byte — that many bytes are trimmed from the end. A declared `padding_size`
                // already keeps the padding octets out of the payload, so only the flag needs
                // clearing (the fresh header below does).
                let mut trimmed = original_packet.payload.clone();
                if original_packet.header.padding
                    && original_packet.header.padding_size == 0
                    && !trimmed.is_empty()
                {
                    let padding_length = trimmed[trimmed.len() - 1] as usize;
                    // An overflowing count was never buffered on an RTX stream (see
                    // `handle_write`), so this cannot over-trim; it is checked again so the
                    // trimming arithmetic stays honest whatever future refactor does.
                    if padding_length <= trimmed.len() {
                        let keep = trimmed.len() - padding_length;
                        trimmed.truncate(keep);
                    }
                }

                let mut rtx_payload = Vec::with_capacity(2 + trimmed.len());
                rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
                rtx_payload.extend_from_slice(&trimmed);

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
            // A padded packet whose legacy padding count overflows the payload cannot become an
            // RTX copy. pion's packet factory rejects it at buffer time (`errPaddingOverflow`)
            // and the write itself still succeeds, so it is simply never retransmitted. pion's
            // check runs two bytes further into the OSN-prefixed copy and over-trims there, a
            // bug not worth copying.
            let malformed_rtx_padding = stream.ssrc_rtx.is_some()
                && stream.payload_type_rtx.is_some()
                && rtp_packet.header.padding
                && rtp_packet.header.padding_size == 0
                && !rtp_packet.payload.is_empty()
                && rtp_packet.payload[rtp_packet.payload.len() - 1] as usize
                    > rtp_packet.payload.len();

            if !malformed_rtx_padding {
                stream.send_buffer.add(rtp_packet.clone());
            }
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain retransmitted packets
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for NackResponderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let passes_filter = self
            .streams_filter
            .as_ref()
            .is_none_or(|filter| filter(info));
        if passes_filter
            && stream_supports_nack(info)
            && let Some(send_buffer) = SendBuffer::new(self.size)
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
