use super::message::{RTCEventInternal, RTCMessage, RTPMessage, TaggedRTCMessage};
use crate::transport::dtls::role::DTLSRole;
use crate::transport::TransportStates;
use bytes::BytesMut;
use log::{debug, error};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, Unmarshal};
use shared::util::is_rtcp;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SrtpHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// SrtpHandler implements SRTP/RTP/RTCP Protocols handling
pub(crate) struct SrtpHandler<'a> {
    transport_states: &'a mut TransportStates,
    ctx: &'a mut SrtpHandlerContext,
}

impl<'a> SrtpHandler<'a> {
    pub(crate) fn new(
        transport_states: &'a mut TransportStates,
        ctx: &'a mut SrtpHandlerContext,
    ) -> Self {
        SrtpHandler {
            transport_states,
            ctx,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "SrtpHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal>
    for SrtpHandler<'a>
{
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Rtp(RTPMessage::Raw(message)) = msg.message {
            debug!("srtp read {:?}", msg.transport.peer_addr);

            let mut try_read = || -> Result<RTCMessage> {
                let four_tuple = (&msg.transport).into();
                let transport = self
                    .transport_states
                    .find_transport_mut(&four_tuple)
                    .ok_or(Error::ErrTransportNoExisted)?;

                if is_rtcp(&message) {
                    let mut remote_context = transport.remote_srtp_context();
                    if let Some(context) = remote_context.as_mut() {
                        let mut decrypted = context.decrypt_rtcp(&message)?;
                        let rtcp_packets = rtcp::packet::unmarshal(&mut decrypted)?;
                        if rtcp_packets.is_empty() {
                            return Err(Error::Other("empty rtcp_packets".to_string()));
                        }

                        Ok(RTCMessage::Rtp(RTPMessage::Rtcp(rtcp_packets)))
                    } else {
                        Err(Error::Other(format!(
                            "remote_srtp_context is not set yet for four_tuple {:?}",
                            four_tuple
                        )))
                    }
                } else {
                    let mut remote_context = transport.remote_srtp_context();
                    if let Some(context) = remote_context.as_mut() {
                        let mut decrypted = context.decrypt_rtp(&message)?;
                        let rtp_packet = rtp::Packet::unmarshal(&mut decrypted)?;

                        Ok(RTCMessage::Rtp(RTPMessage::Rtp(rtp_packet)))
                    } else {
                        Err(Error::Other(format!(
                            "remote_srtp_context is not set yet for four_tuple {:?}",
                            four_tuple
                        )))
                    }
                }
            };

            match try_read() {
                Ok(message) => {
                    self.ctx.read_outs.push_back(TaggedRTCMessage {
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

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Rtp(message) = msg.message {
            debug!("srtp write {:?}", msg.transport.peer_addr);

            let try_write = || -> Result<BytesMut> {
                let four_tuple = (&msg.transport).into();
                let transport = self
                    .transport_states
                    .find_transport_mut(&four_tuple)
                    .ok_or(Error::ErrTransportNoExisted)?;

                match message {
                    RTPMessage::Rtcp(rtcp_packets) => {
                        if rtcp_packets.is_empty() {
                            return Err(Error::Other("empty rtcp_packets".to_string()));
                        };

                        let mut local_context = transport.local_srtp_context();
                        if let Some(context) = local_context.as_mut() {
                            let packet = rtcp::packet::marshal(&rtcp_packets)?;
                            context.encrypt_rtcp(&packet)
                        } else {
                            Err(Error::Other(format!(
                                "local_srtp_context is not set yet for four_tuple {:?}",
                                four_tuple
                            )))
                        }
                    }
                    RTPMessage::Rtp(rtp_message) => {
                        let mut local_context = transport.local_srtp_context();
                        if let Some(context) = local_context.as_mut() {
                            let packet = rtp_message.marshal()?;
                            context.encrypt_rtp(&packet)
                        } else {
                            Err(Error::Other(format!(
                                "local_srtp_context is not set yet for four_tuple {:?}",
                                four_tuple
                            )))
                        }
                    }
                    RTPMessage::Raw(raw_packet) => {
                        // Bypass
                        debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
                        Ok(raw_packet)
                    }
                }
            };

            match try_write() {
                Ok(encrypted) => {
                    self.ctx.write_outs.push_back(TaggedRTCMessage {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessage::Rtp(RTPMessage::Raw(encrypted)),
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

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        //TODO: should DTLSHandshakeComplete be terminated at SRTP handler?
        if let RTCEventInternal::DTLSHandshakeComplete(local, remote) = &evt {
            //TODO:
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
