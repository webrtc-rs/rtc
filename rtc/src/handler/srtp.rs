use super::message::{RTCMessage, RTPMessage, TaggedRTCMessage};
use log::debug;
use shared::error::{Error, Result};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SrtpHandlerContext {
    //server_states: Rc<RefCell<ServerStates>>,
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
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

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, ()> for SrtpHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Rtp(RTPMessage::Raw(_message)) = msg.message {
            debug!("srtp read {:?}", msg.transport.peer_addr);
            /*TODO:
            let try_read = || -> Result<RTCMessage> {
                let four_tuple = (&msg.transport).into();
                let mut server_states = self.server_states.borrow_mut();
                let transport = server_states.get_mut_transport(&four_tuple)?;

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
            };*/
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
        if let RTCMessage::Rtp(_message) = msg.message {
            debug!("srtp write {:?}", msg.transport.peer_addr);
            /*todo:
            let try_write = || -> Result<BytesMut> {
                let four_tuple = (&msg.transport).into();
                let mut server_states = self.server_states.borrow_mut();
                let transport = server_states.get_mut_transport(&four_tuple)?;

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
            }*/
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

    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
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
