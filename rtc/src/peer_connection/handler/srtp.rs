use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};

use bytes::BytesMut;
use log::{debug, error};
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

            let mut try_read = || -> Result<RTCMessageInternal> {
                #[allow(clippy::collapsible_else_if)]
                if is_rtcp(&message) {
                    if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                        let mut decrypted = context.decrypt_rtcp(&message)?;
                        let rtcp_packets = rtcp::packet::unmarshal(&mut decrypted)?;
                        if rtcp_packets.is_empty() {
                            return Err(Error::Other("empty rtcp_packets".to_string()));
                        }

                        Ok(RTCMessageInternal::Rtp(RTPMessage::Rtcp(rtcp_packets)))
                    } else {
                        Err(Error::Other(format!(
                            "remote_srtp_context is not set yet for {:?}",
                            msg.transport.peer_addr
                        )))
                    }
                } else {
                    if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                        let mut decrypted = context.decrypt_rtp(&message)?;
                        let rtp_packet = rtp::Packet::unmarshal(&mut decrypted)?;

                        Ok(RTCMessageInternal::Rtp(RTPMessage::Rtp(rtp_packet)))
                    } else {
                        Err(Error::Other(format!(
                            "remote_srtp_context is not set yet for {:?}",
                            msg.transport.peer_addr
                        )))
                    }
                }
            };

            match try_read() {
                Ok(message) => {
                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message,
                    });
                }
                Err(err) => {
                    error!("try_read got error {}", err);
                    return Err(err);
                }
            };
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

            let try_write = || -> Result<BytesMut> {
                match message {
                    RTPMessage::Rtcp(rtcp_packets) => {
                        if rtcp_packets.is_empty() {
                            return Err(Error::Other("empty rtcp_packets".to_string()));
                        };

                        if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                            let packet = rtcp::packet::marshal(&rtcp_packets)?;
                            context.encrypt_rtcp(&packet)
                        } else {
                            Err(Error::Other(format!(
                                "local_srtp_context is not set yet for {:?}",
                                msg.transport.peer_addr
                            )))
                        }
                    }
                    RTPMessage::Rtp(rtp_message) => {
                        if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                            let packet = rtp_message.marshal()?;
                            context.encrypt_rtp(&packet)
                        } else {
                            Err(Error::Other(format!(
                                "local_srtp_context is not set yet for {:?}",
                                msg.transport.peer_addr
                            )))
                        }
                    }
                    RTPMessage::Raw(raw_packet) => {
                        // Bypass
                        debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
                        Ok(raw_packet)
                    }
                    RTPMessage::Track(_) => Err(Error::Other(
                        "application level track message should never reach here".to_string(),
                    )),
                }
            };

            match try_write() {
                Ok(encrypted) => {
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Rtp(RTPMessage::Raw(encrypted)),
                    });
                }
                Err(err) => {
                    error!("try_write with error {}", err);
                    return Err(err);
                }
            }
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
        if let RTCEventInternal::DTLSHandshakeComplete(_, local_srtp_context, remote_srtp_context) =
            &mut evt
        {
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
