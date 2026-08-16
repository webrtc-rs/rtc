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
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::error::Error;
use std::collections::HashMap;
use std::marker::PhantomData;

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
pub struct FlexFec03ReceiveBuilder<P> {
    _phantom: PhantomData<P>,
}

impl<P> Default for FlexFec03ReceiveBuilder<P> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<P> FlexFec03ReceiveBuilder<P> {
    /// Create a builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> FlexFec03ReceiveInterceptor<P> {
        move |inner| FlexFec03ReceiveInterceptor::new(inner)
    }
}

/// Recovers media lost from streams protected by FlexFEC draft-03.
///
/// Belongs **outermost on the read path**: a recovered packet must be indistinguishable from one
/// that arrived, so recovery has to happen before anything below inspects sequence numbers — the
/// NACK generator should not ask for a packet FEC is about to rebuild, and the jitter buffer
/// should order the recovered packet along with the rest.
#[derive(Interceptor)]
pub struct FlexFec03ReceiveInterceptor<P> {
    #[next]
    inner: P,
    /// Decoders keyed by the media SSRC they protect.
    decoders: HashMap<u32, FlexFec03Decoder>,
    /// Repair SSRC to the media SSRC it repairs, so a repair packet finds its decoder.
    repair_to_media: HashMap<u32, u32>,
}

impl<P> FlexFec03ReceiveInterceptor<P> {
    fn new(inner: P) -> Self {
        Self {
            inner,
            decoders: HashMap::new(),
            repair_to_media: HashMap::new(),
        }
    }

    /// The media SSRCs currently protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.decoders.keys().copied()
    }
}

#[interceptor]
impl<P: Interceptor> FlexFec03ReceiveInterceptor<P> {
    #[overrides]
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        // Both halves, as everywhere else: without the repair SSRC there is nothing to route, and
        // without the payload type the association was never negotiated.
        if let (Some(ssrc_fec), Some(_)) = (info.ssrc_fec, info.payload_type_fec) {
            self.decoders
                .insert(info.ssrc, FlexFec03Decoder::new(ssrc_fec, info.ssrc));
            self.repair_to_media.insert(ssrc_fec, info.ssrc);
        }
        self.inner.bind_remote_stream(info);
    }

    #[overrides]
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.decoders.remove(&info.ssrc);
        self.repair_to_media.retain(|_, media| *media != info.ssrc);
        self.inner.unbind_remote_stream(info);
    }

    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &msg.message else {
            return self.inner.handle_read(msg);
        };

        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        // A repair packet: hand it to the decoder and stop here. Forwarding it would put a
        // non-media stream in front of every interceptor below.
        if let Some(&media_ssrc) = self.repair_to_media.get(&ssrc) {
            let recovered = match self.decoders.get_mut(&media_ssrc) {
                Some(decoder) => decoder.decode(rtp_packet.clone()),
                None => Vec::new(),
            };
            return self.forward_recovered(now, transport, recovered);
        }

        // A protected media packet: the decoder needs it in order to recover its neighbours, and
        // it carries on downstream as usual.
        let recovered = match self.decoders.get_mut(&ssrc) {
            Some(decoder) => decoder.decode(rtp_packet.clone()),
            None => return self.inner.handle_read(msg),
        };

        // The live packet arrived first, so it goes first; anything it made recoverable follows.
        // Their order relative to each other is the jitter buffer's problem, not this one's.
        self.inner.handle_read(msg)?;
        self.forward_recovered(now, transport, recovered)
    }
}

impl<P: Interceptor> FlexFec03ReceiveInterceptor<P> {
    /// Re-inject recovered packets through `inner` (chain contract rule 2).
    ///
    /// Not a local `poll_read` queue: a recovered packet is a media packet the layers below have
    /// never seen, and they all have work to do on it.
    fn forward_recovered(
        &mut self,
        now: std::time::Instant,
        transport: shared::TransportContext,
        recovered: Vec<rtp::Packet>,
    ) -> Result<(), Error> {
        for packet in recovered {
            self.inner.handle_read(TaggedPacket {
                now,
                transport,
                message: Packet::Rtp(packet),
            })?;
        }
        Ok(())
    }
}
