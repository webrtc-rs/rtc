use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use interceptor::{Interceptor, Packet, TaggedPacket};
use log::{debug, trace};
use shared::error::{Error, Result};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct InterceptorHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    ctx: &'a mut InterceptorHandlerContext,
    interceptor: &'a mut I,
}

impl<'a, I> InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    pub(crate) fn new(ctx: &'a mut InterceptorHandlerContext, interceptor: &'a mut I) -> Self {
        InterceptorHandler { ctx, interceptor }
    }

    pub(crate) fn name(&self) -> &'static str {
        "InterceptorHandler"
    }
}

impl<'a, I> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = &msg.message {
            self.interceptor.handle_read(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.clone(),
                // RTP packet use Bytes which is zero-copy,
                // RTCP packet may have clone overhead.
                // TODO: Future optimization: If RTCP becomes a bottleneck, wrap it in Arc (minor change)
            })?;

            if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(_))) = &msg.message {
                // RTCP message read must end here. If any rtcp packet needs to be forwarded to PeerConnection,
                // just add a new interceptor to forward it.
                debug!("interceptor terminates Rtcp {:?}", msg.transport.peer_addr);
                return Ok(());
            }
        }

        debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
        self.ctx.read_outs.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        while let Some(packet) = self.interceptor.poll_read() {
            self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                now: packet.now,
                transport: packet.transport,
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message)),
            });
        }

        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = &msg.message {
            self.interceptor.handle_write(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.clone(),
                // RTP packet use Bytes which is zero-copy,
                // RTCP packet may have clone overhead.
                // TODO: Future optimization: If RTCP becomes a bottleneck, wrap it in Arc (minor change)
            })?;
        }

        debug!("interceptor write {:?}", msg.transport.peer_addr);
        self.ctx.write_outs.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        while let Some(packet) = self.interceptor.poll_write() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: packet.now,
                transport: packet.transport,
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message)),
            });
            trace!("interceptor write {:?}", packet.transport.peer_addr);
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        // self.interceptor.handle_event(());

        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        // self.interceptor.poll_event(());

        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.interceptor.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.interceptor.poll_timeout()
    }

    fn close(&mut self) -> Result<()> {
        self.interceptor.close()
    }
}
