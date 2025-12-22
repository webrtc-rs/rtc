use super::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCEvent, RTCMessage, RTPMessage,
    STUNMessage, TaggedRTCMessage,
};
use crate::data_channel::event::RTCDataChannelEvent;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::transport::{CandidatePair, Transport, TransportStates};
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::TransportContext;
use std::collections::VecDeque;
use std::time::Instant;
use stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_NETWORK_COST, ATTR_PRIORITY, ATTR_USERNAME,
    ATTR_USE_CANDIDATE,
};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{Setter, TransactionId, BINDING_SUCCESS};
use stun::textattrs::TextAttribute;
use stun::xoraddr::XorMappedAddress;

#[derive(Default)]
pub(crate) struct EndpointHandlerContext {
    pub(crate) dtls_handshake_config: ::dtls::config::HandshakeConfig,
    pub(crate) sctp_endpoint_config: ::sctp::EndpointConfig,
    pub(crate) sctp_server_config: ::sctp::ServerConfig,

    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,
}

/// EndpointHandler implements DataChannel/Media Endpoint handling
/// The transmits queue is now stored in RTCPeerConnection and passed by reference
pub(crate) struct EndpointHandler<'a> {
    transport_states: &'a mut TransportStates,
    ctx: &'a mut EndpointHandlerContext,
}

impl<'a> EndpointHandler<'a> {
    pub(crate) fn new(
        transport_states: &'a mut TransportStates,
        ctx: &'a mut EndpointHandlerContext,
    ) -> Self {
        EndpointHandler {
            transport_states,
            ctx,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "EndpointHandler"
    }
}

// Implement Protocol trait for message processing
impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEvent> for EndpointHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        match msg.message {
            RTCMessage::Stun(STUNMessage::Stun(message)) => {
                self.handle_stun_message(msg.now, msg.transport, message)
            }
            RTCMessage::Dtls(DTLSMessage::DataChannel(message)) => {
                self.handle_dtls_message(msg.now, msg.transport, message)
            }
            RTCMessage::Rtp(RTPMessage::Rtp(message)) => {
                self.handle_rtp_message(msg.now, msg.transport, message)
            }
            RTCMessage::Rtp(RTPMessage::Rtcp(message)) => {
                self.handle_rtcp_message(msg.now, msg.transport, message)
            }
            _ => {
                warn!("drop unsupported message from {}", msg.transport.peer_addr);
                Ok(())
            }
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        self.ctx.write_outs.push_back(TaggedRTCMessage {
            now: Instant::now(),
            transport: TransportContext::default(), //TODO: rewrite transport context
            message: msg.message,
        });
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: RTCEvent) -> Result<()> {
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

impl<'a> EndpointHandler<'a> {
    fn handle_stun_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        mut request: stun::message::Message,
    ) -> Result<()> {
        let candidate_pair = match self.check_stun_message(&mut request)? {
            Some(candidate_pair) => candidate_pair,
            None => {
                self.ctx.write_outs.push_back(
                    EndpointHandler::create_server_reflective_address_message_event(
                        now,
                        transport_context,
                        request.transaction_id,
                    )?,
                );
                return Ok(());
            }
        };

        let password = candidate_pair.get_local_parameters().password.clone();

        self.add_transport(&request, candidate_pair, &transport_context)?;

        let mut response = stun::message::Message::new();

        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(request.transaction_id),
            Box::new(XorMappedAddress {
                ip: transport_context.peer_addr.ip(),
                port: transport_context.peer_addr.port(),
            }),
        ])?;
        let integrity = MessageIntegrity::new_short_term_integrity(password);
        integrity.add_to(&mut response)?;
        FINGERPRINT.add_to(&mut response)?;

        debug!(
            "handle_stun_message response type {} with ip {} and port {} sent",
            response.typ,
            transport_context.peer_addr.ip(),
            transport_context.peer_addr.port()
        );

        self.ctx.write_outs.push_back(TaggedRTCMessage {
            now,
            transport: transport_context,
            message: RTCMessage::Stun(STUNMessage::Stun(response)),
        });

        Ok(())
    }

    fn handle_dtls_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        message: ApplicationMessage,
    ) -> Result<()> {
        match message.data_channel_event {
            DataChannelEvent::Open => self.handle_datachannel_open(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
            DataChannelEvent::Message(is_string, data) => self.handle_datachannel_message(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
                is_string,
                data,
            ),
            DataChannelEvent::Close => self.handle_datachannel_close(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
        }
    }

    fn handle_rtp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _rtp_packet: rtp::packet::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

        Ok(())
    }

    fn handle_rtcp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _rtcp_packets: Vec<Box<dyn rtcp::packet::Packet>>,
    ) -> Result<()> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);

        Ok(())
    }

    fn check_stun_message(
        &self,
        request: &mut stun::message::Message,
    ) -> Result<Option<CandidatePair>> {
        match TextAttribute::get_from_as(request, ATTR_USERNAME) {
            Ok(username) => {
                if !request.contains(ATTR_PRIORITY) {
                    return Err(Error::Other(
                        "invalid STUN message without ATTR_PRIORITY".to_string(),
                    ));
                }

                if request.contains(ATTR_ICE_CONTROLLING) {
                    if request.contains(ATTR_ICE_CONTROLLED) {
                        return Err(Error::Other("invalid STUN message with both ATTR_ICE_CONTROLLING and ATTR_ICE_CONTROLLED".to_string()));
                    }
                } else if request.contains(ATTR_ICE_CONTROLLED) {
                    if request.contains(ATTR_USE_CANDIDATE) {
                        return Err(Error::Other("invalid STUN message with both ATTR_USE_CANDIDATE and ATTR_ICE_CONTROLLED".to_string()));
                    }
                } else {
                    return Err(Error::Other(
                        "invalid STUN message without ATTR_ICE_CONTROLLING or ATTR_ICE_CONTROLLED"
                            .to_string(),
                    ));
                }

                if let Some(candidate_pair) =
                    self.transport_states.find_candidate_pair(&username.text)
                {
                    let password = candidate_pair.get_local_parameters().password.clone();
                    let integrity = MessageIntegrity::new_short_term_integrity(password);
                    integrity.check(request)?;
                    Ok(Some(candidate_pair.clone()))
                } else {
                    Err(Error::Other("username not found".to_string()))
                }
            }
            Err(_) => {
                if request.contains(ATTR_ICE_CONTROLLED)
                    || request.contains(ATTR_ICE_CONTROLLING)
                    || request.contains(ATTR_NETWORK_COST)
                    || request.contains(ATTR_PRIORITY)
                    || request.contains(ATTR_USE_CANDIDATE)
                {
                    Err(Error::Other("unexpected attribute".to_string()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn create_server_reflective_address_message_event(
        now: Instant,
        transport_context: TransportContext,
        transaction_id: TransactionId,
    ) -> Result<TaggedRTCMessage> {
        let mut response = stun::message::Message::new();
        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(transaction_id),
            Box::new(XorMappedAddress {
                ip: transport_context.peer_addr.ip(),
                port: transport_context.peer_addr.port(),
            }),
        ])?;

        debug!(
            "create_server_reflective_address_message_event response type {} sent",
            response.typ
        );

        Ok(TaggedRTCMessage {
            now,
            transport: transport_context,
            message: RTCMessage::Stun(STUNMessage::Stun(response)),
        })
    }

    fn add_transport(
        &mut self,
        request: &stun::message::Message,
        candidate_pair: CandidatePair,
        transport_context: &TransportContext,
    ) -> Result<bool> {
        let four_tuple = transport_context.into();
        let has_transport = self.transport_states.has_transport(&four_tuple);

        if !request.contains(ATTR_USE_CANDIDATE) || has_transport {
            return Ok(false);
        }

        let transport = Transport::new(
            four_tuple,
            transport_context.transport_protocol,
            candidate_pair,
            &self.ctx.dtls_handshake_config,
            &self.ctx.sctp_endpoint_config,
            &self.ctx.sctp_server_config,
        );

        self.transport_states.add_transport(four_tuple, transport);

        Ok(true)
    }

    fn handle_datachannel_open(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<()> {
        debug!("data channel is open for {:?}", transport_context);

        let four_tuple = transport_context.into();
        let transport = self
            .transport_states
            .find_transport_mut(&four_tuple)
            .ok_or(Error::ErrTransportNoExisted)?;
        transport.set_association_handle(association_handle);

        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnOpen(stream_id),
            ));

        Ok(())
    }

    fn handle_datachannel_close(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _association_handle: usize,
        stream_id: u16,
    ) -> Result<()> {
        debug!("data channel is close for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnClose(stream_id),
            ));

        Ok(())
    }

    fn handle_datachannel_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _association_handle: usize,
        stream_id: u16,
        is_string: bool,
        data: BytesMut,
    ) -> Result<()> {
        debug!("data channel recv message for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnMessage(
                    stream_id,
                    RTCDataChannelMessage { is_string, data },
                ),
            ));

        Ok(())
    }
}
