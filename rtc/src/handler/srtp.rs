use super::message::{RTCMessage, RTPMessage, TaggedRTCMessage};
use log::debug;
use shared::{Context, Handler};

/// SrtpHandler implements SRTP/RTP/RTCP Protocols handling
pub struct SrtpHandler {
    //server_states: Rc<RefCell<ServerStates>>,
}

impl SrtpHandler {
    pub fn new(/*server_states: Rc<RefCell<ServerStates>>*/) -> Self {
        SrtpHandler { /*server_states*/ }
    }
}

impl Handler for SrtpHandler {
    type Rin = TaggedRTCMessage;
    type Rout = Self::Rin;
    type Win = TaggedRTCMessage;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "SrtpHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
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
                    msg.message = message;
                    ctx.fire_handle_read(msg);
                }
                Err(err) => {
                    error!("try_read got error {}", err);
                    ctx.fire_handle_error(Box::new(err))
                }
            };*/
        } else {
            debug!("bypass srtp read {:?}", msg.transport.peer_addr);
            ctx.fire_handle_read(msg);
        }
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
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
                        msg.message = RTCMessage::Rtp(RTPMessage::Raw(encrypted));
                        Some(msg)
                    }
                    Err(err) => {
                        error!("try_write with error {}", err);
                        ctx.fire_handle_error(Box::new(err));
                        None
                    }
                }*/
                None
            } else {
                // Bypass
                debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
                Some(msg)
            }
        } else {
            None
        }
    }
}
