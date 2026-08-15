//! Send-side FlexFEC draft-03: protects outgoing media with repair packets.

use super::encoder::FlexFec03Encoder;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::error::Error;
use std::collections::HashMap;
use std::marker::PhantomData;

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
pub struct FlexFec03SendBuilder<P> {
    num_media_packets: u32,
    num_fec_packets: u32,
    _phantom: PhantomData<P>,
}

impl<P> Default for FlexFec03SendBuilder<P> {
    fn default() -> Self {
        Self {
            num_media_packets: DEFAULT_NUM_MEDIA_PACKETS,
            num_fec_packets: DEFAULT_NUM_FEC_PACKETS,
            _phantom: PhantomData,
        }
    }
}

impl<P> FlexFec03SendBuilder<P> {
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

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> FlexFec03SendInterceptor<P> {
        move |inner| {
            FlexFec03SendInterceptor::new(inner, self.num_media_packets, self.num_fec_packets)
        }
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
#[derive(Interceptor)]
pub struct FlexFec03SendInterceptor<P> {
    #[next]
    inner: P,
    num_media_packets: u32,
    num_fec_packets: u32,
    /// Keyed by the **media** SSRC being protected.
    streams: HashMap<u32, ProtectedStream>,
}

impl<P> FlexFec03SendInterceptor<P> {
    fn new(inner: P, num_media_packets: u32, num_fec_packets: u32) -> Self {
        Self {
            inner,
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

#[interceptor]
impl<P: Interceptor> FlexFec03SendInterceptor<P> {
    #[overrides]
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
        self.inner.bind_local_stream(info);
    }

    #[overrides]
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        // Any partly-filled block goes with it: those packets have already been sent unprotected,
        // and a repair packet for a stream that has stopped has nothing left to repair.
        self.streams.remove(&info.ssrc);
        self.inner.unbind_local_stream(info);
    }

    #[overrides]
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &msg.message else {
            return self.inner.handle_write(msg);
        };

        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        let Some(stream) = self.streams.get_mut(&ssrc) else {
            return self.inner.handle_write(msg);
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
        self.inner.handle_write(msg)?;

        for packet in repair_packets {
            // Re-injected rather than queued locally (chain contract rule 2): a repair packet is
            // a real outgoing RTP packet and still needs the layers below — a transport-wide
            // sequence number, and a place in the send history congestion control reads.
            self.inner.handle_write(TaggedPacket {
                now,
                transport,
                message: Packet::Rtp(packet),
            })?;
        }

        Ok(())
    }
}
