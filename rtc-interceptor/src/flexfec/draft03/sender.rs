//! Send-side FlexFEC draft-03: protects outgoing media with repair packets.

use super::encoder::FlexFec03Encoder;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Media packets gathered before a repair block is produced.
pub const DEFAULT_NUM_MEDIA_PACKETS: u32 = 5;

/// Repair packets produced per block.
pub const DEFAULT_NUM_FEC_PACKETS: u32 = 2;

/// Builder for [`FlexFec03SendInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{FlexFec03SendBuilder, Registry};
///
/// let chain = Registry::new()
///     .with(FlexFec03SendBuilder::new().with_num_fec_packets(1).build())
///     .build();
/// ```
pub struct FlexFec03SendBuilder {
    num_media_packets: u32,
    num_fec_packets: u32,
}

impl Default for FlexFec03SendBuilder {
    fn default() -> Self {
        Self {
            num_media_packets: DEFAULT_NUM_MEDIA_PACKETS,
            num_fec_packets: DEFAULT_NUM_FEC_PACKETS,
        }
    }
}

impl FlexFec03SendBuilder {
    /// Create a builder with the default block shape.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many media packets one repair block protects.
    ///
    /// Larger blocks cost less bandwidth per protected packet and recover later, since the block
    /// is only sent once it is full.
    pub fn with_num_media_packets(mut self, num_media_packets: u32) -> Self {
        self.num_media_packets = num_media_packets;
        self
    }

    /// How many repair packets each block produces.
    ///
    /// This is what the block can survive: *n* repair packets recover up to *n* losses, spread
    /// across the block by the interleaving.
    pub fn with_num_fec_packets(mut self, num_fec_packets: u32) -> Self {
        self.num_fec_packets = num_fec_packets;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> FlexFec03SendInterceptor {
        FlexFec03SendInterceptor::new(self.num_media_packets, self.num_fec_packets)
    }
}

/// One protected media stream.
struct ProtectedStream {
    encoder: FlexFec03Encoder,
    /// Media packets awaiting a full block.
    block: Vec<rtp::Packet>,
}

/// Produces FlexFEC draft-03 repair packets for outgoing media.
///
/// Binds only when the stream carries both a FEC SSRC and a FEC payload type: a repair stream
/// needs its own SSRC to send on and its own payload type to be recognised by, and half an
/// association is not usable. Those come from the negotiated `a=ssrc-group:FEC-FR`.
pub struct FlexFec03SendInterceptor {
    num_media_packets: u32,
    num_fec_packets: u32,
    /// Keyed by the **media** SSRC being protected.
    streams: HashMap<u32, ProtectedStream>,
    /// Repair packets the encoder produced, waiting to join the belt.
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl FlexFec03SendInterceptor {
    fn new(num_media_packets: u32, num_fec_packets: u32) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            num_media_packets: num_media_packets.max(1),
            num_fec_packets,
            streams: HashMap::new(),
        }
    }

    /// The media SSRCs currently being protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams.keys().copied()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for FlexFec03SendInterceptor {
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
        let Packet::Rtp(rtp_packet) = &msg.message.packet else {
            self.write_queue.push_back(msg);
            return Ok(());
        };

        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        let Some(stream) = self.streams.get_mut(&ssrc) else {
            self.write_queue.push_back(msg);
            return Ok(());
        };

        stream.block.push(rtp_packet.clone());
        let repair_packets = if stream.block.len() as u32 >= self.num_media_packets {
            let repair = stream.encoder.encode(&stream.block, self.num_fec_packets);
            // Cleared either way: a block the encoder refused — a gap, or one longer than the
            // masks describe — must not be retried packet by packet as more arrive.
            stream.block.clear();
            repair
        } else {
            Vec::new()
        };

        // The media packet goes out first; the repair packets protect what has already left.
        self.write_queue.push_back(msg);

        for packet in repair_packets {
            // Queued for `poll_write`, which puts them back on the belt: a repair packet is a real
            // outgoing RTP packet and still needs every interceptor ahead — a transport-wide sequence
            // number, the pacer, and a place in the send history congestion control reads.
            self.write_queue.push_back(TaggedPacket {
                now,
                transport,
                message: AttributedPacket::new(Packet::Rtp(packet)),
            });
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for FlexFec03SendInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        // The gate FEC-PRE-01 exists to open. Both halves or neither: an SSRC with no payload
        // type has nothing to mark its packets with, and a payload type with no SSRC has nowhere
        // to send them.
        if let (Some(ssrc_fec), Some(payload_type_fec)) = (info.ssrc_fec, info.payload_type_fec) {
            self.streams.insert(
                info.ssrc,
                ProtectedStream {
                    encoder: FlexFec03Encoder::new(payload_type_fec, ssrc_fec),
                    block: Vec::new(),
                },
            );
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        // Any partly-filled block goes with it: those packets have already been sent unprotected,
        // and a repair packet for a stream that has stopped has nothing left to repair.
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
