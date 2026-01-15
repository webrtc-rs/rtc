use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};

use interceptor::Packet;
use log::debug;
use shared::error::{Error, Result};
use shared::marshal::{Marshal, Unmarshal};
use shared::util::is_rtcp;
use srtp::context::Context;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SrtpHandlerContext {
    pub(crate) local_srtp_context: Option<Context>,
    pub(crate) remote_srtp_context: Option<Context>,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// SrtpHandler implements SRTP/RTP/RTCP Protocols handling
pub(crate) struct SrtpHandler<'a> {
    ctx: &'a mut SrtpHandlerContext,
}

impl<'a> SrtpHandler<'a> {
    pub(crate) fn new(ctx: &'a mut SrtpHandlerContext) -> Self {
        SrtpHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "SrtpHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for SrtpHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Rtp(RTPMessage::Raw(message)) = msg.message {
            debug!("srtp read {:?}", msg.transport.peer_addr);

            #[allow(clippy::collapsible_else_if)]
            if is_rtcp(&message) {
                if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                    let mut decrypted = context.decrypt_rtcp(&message)?;
                    let rtcp_packets = rtcp::packet::unmarshal(&mut decrypted)?;
                    if rtcp_packets.is_empty() {
                        return Err(Error::Other("empty rtcp_packets".to_string()));
                    }

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(
                            rtcp_packets,
                        ))),
                    });
                } else {
                    return Err(Error::Other(format!(
                        "remote_srtp_context is not set yet for rtcp_packet {:?}",
                        msg.transport.peer_addr
                    )));
                }
            } else {
                if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                    let mut decrypted = context.decrypt_rtp(&message)?;
                    let rtp_packet = rtp::Packet::unmarshal(&mut decrypted)?;

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(
                            rtp_packet,
                        ))),
                    });
                } else {
                    return Err(Error::Other(format!(
                        "remote_srtp_context is not set yet for rtp_packet {:?}",
                        msg.transport.peer_addr
                    )));
                }
            }
        } else {
            debug!("bypass srtp read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Rtp(message) = msg.message {
            debug!("srtp write {:?}", msg.transport.peer_addr);

            let encrypted = match message {
                RTPMessage::Packet(Packet::Rtcp(rtcp_packets)) => {
                    if rtcp_packets.is_empty() {
                        return Err(Error::Other("empty rtcp_packets".to_string()));
                    };

                    if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                        let packet = rtcp::packet::marshal(&rtcp_packets)?;
                        context.encrypt_rtcp(&packet)?
                    } else {
                        return Err(Error::Other(format!(
                            "local_srp_context is not set yet for rtcp_packet {:?}",
                            msg.transport.peer_addr
                        )));
                    }
                }
                RTPMessage::Packet(Packet::Rtp(rtp_message)) => {
                    if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                        let packet = rtp_message.marshal()?;
                        context.encrypt_rtp(&packet)?
                    } else {
                        return Err(Error::Other(format!(
                            "local_srtp_context is not set yet for rtp_packet {:?}",
                            msg.transport.peer_addr
                        )));
                    }
                }
                RTPMessage::Raw(raw_packet) => {
                    // Bypass
                    debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
                    raw_packet
                }
                RTPMessage::TrackPacket(_) => {
                    return Err(Error::Other(
                        "application level track message should never reach here".to_string(),
                    ));
                }
            };

            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(encrypted)),
            });
        } else {
            // Bypass
            debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, mut evt: RTCEventInternal) -> Result<()> {
        if let RTCEventInternal::DTLSHandshakeComplete(local_srtp_context, remote_srtp_context) =
            &mut evt
        {
            debug!("srtp recv dtls handshake complete");

            self.ctx.local_srtp_context = local_srtp_context.take();
            self.ctx.remote_srtp_context = remote_srtp_context.take()
        }

        self.ctx.event_outs.push_back(evt);

        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
