//! Receive-side FlexFEC draft-03: recovers lost media and keeps repair packets off the wire.
//!
//! # No upstream counterpart
//!
//! `pion/interceptor` has a full draft-03 decoder that nothing constructs: `ConfigureFlexFEC03`
//! registers only the encoder, and `newFECDecoder` appears outside its own tests nowhere. So this
//! interceptor is new work, and the decisions it makes are ones upstream never had to:
//!
//! - **Repair packets are consumed, not forwarded.** They are not media; the application must
//!   never see them, and neither should the interceptors below, which would treat their sequence
//!   numbers as a media stream's and report gaps that do not exist.
//! - **Recovered packets re-enter through `inner`.** A recovered packet has to look to every
//!   layer below exactly like one that arrived normally.
//! - **Memory is bounded** by the decoder's own retention limits; a receive path that keeps every
//!   packet it has ever seen in case a repair packet turns up later is a leak.

use super::decoder::FlexFec03Decoder;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Builder for [`FlexFec03ReceiveInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{FlexFec03ReceiveBuilder, Registry};
///
/// let chain = Registry::new()
///     .with(FlexFec03ReceiveBuilder::new().build())
///     .build();
/// ```
#[derive(Default)]
pub struct FlexFec03ReceiveBuilder {}

impl FlexFec03ReceiveBuilder {
    /// Create a builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the interceptor.
    pub fn build(self) -> FlexFec03ReceiveInterceptor {
        FlexFec03ReceiveInterceptor::new()
    }
}

/// Recovers media lost from streams protected by FlexFEC draft-03.
///
/// Belongs **early on the read path**, close to the wire: a recovered packet must be
/// indistinguishable from one that arrived, so recovery has to happen before anything after it
/// inspects sequence numbers — the NACK generator should not ask for a packet FEC is about to
/// rebuild, and the jitter buffer should order the recovered packet along with the rest.
pub struct FlexFec03ReceiveInterceptor {
    /// Decoders keyed by the media SSRC they protect.
    decoders: HashMap<u32, FlexFec03Decoder>,
    /// Repair SSRC to the media SSRC it repairs, so a repair packet finds its decoder.
    repair_to_media: HashMap<u32, u32>,
    /// Inbound packets ready for the next interceptor: what passed through, plus anything the
    /// decoder reconstructed.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl FlexFec03ReceiveInterceptor {
    fn new() -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            decoders: HashMap::new(),
            repair_to_media: HashMap::new(),
        }
    }

    /// The media SSRCs currently protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.decoders.keys().copied()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for FlexFec03ReceiveInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &msg.message.packet else {
            self.read_queue.push_back(msg);
            return Ok(());
        };

        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        // A repair packet: hand it to the decoder and swallow it. Passing it on would put a
        // non-media stream in front of every interceptor ahead.
        if let Some(&media_ssrc) = self.repair_to_media.get(&ssrc) {
            let recovered = match self.decoders.get_mut(&media_ssrc) {
                Some(decoder) => decoder.decode(rtp_packet.clone()),
                None => Vec::new(),
            };
            self.queue_recovered(now, transport, recovered);
            return Ok(());
        }

        // A protected media packet: the decoder needs it in order to recover its neighbours, and
        // it carries on as usual.
        let recovered = match self.decoders.get_mut(&ssrc) {
            Some(decoder) => decoder.decode(rtp_packet.clone()),
            None => {
                self.read_queue.push_back(msg);
                return Ok(());
            }
        };

        // The live packet arrived first, so it goes first; anything it made recoverable follows.
        // Their order relative to each other is the jitter buffer's problem, not this one's.
        self.read_queue.push_back(msg);
        self.queue_recovered(now, transport, recovered);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for FlexFec03ReceiveInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        // Both halves, as everywhere else: without the repair SSRC there is nothing to route, and
        // without the payload type the association was never negotiated.
        if let (Some(ssrc_fec), Some(_)) = (info.ssrc_fec, info.payload_type_fec) {
            self.decoders
                .insert(info.ssrc, FlexFec03Decoder::new(ssrc_fec, info.ssrc));
            self.repair_to_media.insert(ssrc_fec, info.ssrc);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.decoders.remove(&info.ssrc);
        self.repair_to_media.retain(|_, media| *media != info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

impl FlexFec03ReceiveInterceptor {
    /// Hold recovered packets for `poll_read`, which puts them back on the belt.
    ///
    /// They then traverse every interceptor ahead exactly as a packet that arrived normally does — which
    /// is the point of recovery, and which the nested design achieved by re-injecting through
    /// `inner` by hand.
    fn queue_recovered(
        &mut self,
        now: std::time::Instant,
        transport: shared::TransportContext,
        recovered: Vec<rtp::Packet>,
    ) {
        for packet in recovered {
            let mut message = AttributedPacket::new(Packet::Rtp(packet));
            // Says how it got here: it was never on the wire in this form, so anything measuring
            // the network — arrival times, loss — can tell it apart from a packet that was.
            message.add(Attribute::RecoveredByFec);
            self.read_queue.push_back(TaggedPacket {
                now,
                transport,
                message,
            });
        }
    }
}
