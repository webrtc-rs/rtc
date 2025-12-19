use super::message::{RTCMessage, STUNMessage, TaggedRTCMessage};
use crate::transport::{CandidatePair, Transport, TransportStates};
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::{Context, Handler, TransportContext};
use std::collections::VecDeque;
use std::sync::Arc;
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

/// EndpointHandler implements Data/Media Endpoint handling
pub struct EndpointHandler {
    dtls_handshake_config: Arc<::dtls::config::HandshakeConfig>,
    sctp_endpoint_config: Arc<::sctp::EndpointConfig>,
    sctp_server_config: Arc<::sctp::ServerConfig>,
    transport_states: Arc<TransportStates>,
    transmits: VecDeque<TaggedRTCMessage>,
}

impl EndpointHandler {
    pub fn new(
        dtls_handshake_config: Arc<::dtls::config::HandshakeConfig>,
        sctp_endpoint_config: Arc<::sctp::EndpointConfig>,
        sctp_server_config: Arc<::sctp::ServerConfig>,
        transport_states: Arc<TransportStates>,
    ) -> Self {
        EndpointHandler {
            dtls_handshake_config,
            sctp_endpoint_config,
            sctp_server_config,
            transport_states,
            transmits: VecDeque::new(),
        }
    }
}

impl Handler for EndpointHandler {
    type Rin = TaggedRTCMessage;
    type Rout = Self::Rin;
    type Win = TaggedRTCMessage;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "EndpointHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
        let try_read = || -> Result<Vec<TaggedRTCMessage>> {
            match msg.message {
                RTCMessage::Stun(STUNMessage::Stun(message)) => {
                    self.handle_stun_message(msg.now, msg.transport, message)
                }
                /*
                RTCMessage::Dtls(DTLSMessage::DataChannel(message)) => EndpointHandler::handle_dtls_message(
                    &mut server_states,
                    msg.now,
                    msg.transport,
                    message,
                ),
                RTCMessage::Rtp(RTPMessage::Rtp(message)) => EndpointHandler::handle_rtp_message(
                    &mut server_states,
                    msg.now,
                    msg.transport,
                    message,
                ),
                RTCMessage::Rtp(RTPMessage::Rtcp(message)) => EndpointHandler::handle_rtcp_message(
                    &mut server_states,
                    msg.now,
                    msg.transport,
                    message,
                ),*/
                _ => {
                    warn!("drop unsupported message from {}", msg.transport.peer_addr);
                    Ok(vec![])
                }
            }
        };

        match try_read() {
            Ok(messages) => {
                for message in messages {
                    self.transmits.push_back(message);
                }
            }
            Err(err) => {
                warn!("try_read got error {}", err);
                ctx.fire_handle_error(Box::new(err));
            }
        }
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
            self.transmits.push_back(msg);
        }
        self.transmits.pop_front()
    }
}

impl EndpointHandler {
    fn check_stun_message(
        &self,
        request: &mut stun::message::Message,
    ) -> Result<Option<Arc<CandidatePair>>> {
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

    fn handle_stun_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        mut request: stun::message::Message,
    ) -> Result<Vec<TaggedRTCMessage>> {
        let candidate_pair = match self.check_stun_message(&mut request)? {
            Some(candidate) => candidate,
            None => {
                return EndpointHandler::create_server_reflective_address_message_event(
                    now,
                    transport_context,
                    request.transaction_id,
                );
            }
        };

        self.add_transport(&request, &candidate_pair, &transport_context)?;

        let mut response = stun::message::Message::new();

        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(request.transaction_id),
            Box::new(XorMappedAddress {
                ip: transport_context.peer_addr.ip(),
                port: transport_context.peer_addr.port(),
            }),
        ])?;
        let integrity = MessageIntegrity::new_short_term_integrity(
            candidate_pair.get_local_parameters().password.clone(),
        );
        integrity.add_to(&mut response)?;
        FINGERPRINT.add_to(&mut response)?;

        debug!(
            "handle_stun_message response type {} with ip {} and port {} sent",
            response.typ,
            transport_context.peer_addr.ip(),
            transport_context.peer_addr.port()
        );

        Ok(vec![TaggedRTCMessage {
            now,
            transport: transport_context,
            message: RTCMessage::Stun(STUNMessage::Stun(response)),
        }])
    }
    /*
    fn handle_dtls_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        message: ApplicationMessage,
    ) -> Result<Vec<TaggedRTCMessage>> {
        match message.data_channel_event {
            DataChannelEvent::Open => EndpointHandler::handle_datachannel_open(
                server_states,
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
            DataChannelEvent::Message(payload) => EndpointHandler::handle_datachannel_message(
                server_states,
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
                payload,
            ),
            DataChannelEvent::Close => EndpointHandler::handle_datachannel_close(
                server_states,
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
        }
    }

    fn handle_datachannel_open(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<Vec<TaggedRTCMessage>> {
        let four_tuple = (&transport_context).into();
        let (session_id, endpoint_id) = server_states
            .find_endpoint(&four_tuple)
            .ok_or(Error::ErrClientTransportNotSet)?;

        let session = server_states
            .get_mut_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {}",
                session_id
            )))?;

        let mut new_transceivers = vec![];
        let endpoints = session.get_endpoints();
        for (&other_endpoint_id, other_endpoint) in endpoints.iter() {
            if other_endpoint_id != endpoint_id {
                let other_transceivers = other_endpoint.get_transceivers();
                for (other_mid_value, other_transceiver) in other_transceivers.iter() {
                    if other_transceiver.direction == RTCRtpTransceiverDirection::Recvonly {
                        let mut transceiver = other_transceiver.clone();
                        transceiver.mid = format!("{}-{}", other_endpoint_id, other_mid_value);
                        transceiver.direction = RTCRtpTransceiverDirection::Sendonly;
                        new_transceivers.push(transceiver);
                    }
                }
            }
        }

        let endpoint = session
            .get_mut_endpoint(&endpoint_id)
            .ok_or(Error::Other(format!(
                "can't find endpoint id {}",
                endpoint_id
            )))?;

        let transports = endpoint.get_mut_transports();
        let transport = transports.get_mut(&four_tuple).ok_or(Error::Other(format!(
            "can't find transport for endpoint id {} with {:?}",
            endpoint_id, four_tuple
        )))?;
        transport.set_association_handle_and_stream_id(association_handle, stream_id);
        info!(
            "{}/{}: data channel is ready for {:?}",
            session_id,
            endpoint_id,
            transport.four_tuple()
        );
        endpoint.set_renegotiation_needed(!new_transceivers.is_empty());

        let (mids, transceivers) = endpoint.get_mut_mids_and_transceivers();
        for transceiver in new_transceivers {
            mids.push(transceiver.mid.clone());
            transceivers.insert(transceiver.mid.clone(), transceiver);
        }

        if endpoint.is_renegotiation_needed() {
            Ok(vec![EndpointHandler::create_offer_message_event(
                server_states,
                now,
                transport_context,
                association_handle,
                stream_id,
            )?])
        } else {
            Ok(vec![])
        }
    }

    fn handle_datachannel_close(
        _server_states: &mut ServerStates,
        _now: Instant,
        _transport_context: TransportContext,
        _association_handle: usize,
        _stream_id: u16,
    ) -> Result<Vec<TaggedRTCMessage>> {
        //TODO: handle datachannel close event!
        // clean up resources, like sctp_association, endpoint, etc.
        Ok(vec![])
    }

    fn handle_datachannel_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        association_handle: usize,
        stream_id: u16,
        payload: BytesMut,
    ) -> Result<Vec<TaggedRTCMessage>> {
        let request_sdp_str = String::from_utf8(payload.to_vec())?;
        let request_sdp = serde_json::from_str::<RTCSessionDescription>(&request_sdp_str)
            .map_err(|err| Error::Other(err.to_string()))?;

        let four_tuple = (&transport_context).into();
        let (session_id, endpoint_id) = server_states
            .find_endpoint(&four_tuple)
            .ok_or(Error::ErrClientTransportNotSet)?;

        match request_sdp.sdp_type {
            RTCSdpType::Offer => {
                let answer = server_states.accept_offer(
                    session_id,
                    endpoint_id,
                    Some(four_tuple),
                    request_sdp,
                )?;
                let answer_str =
                    serde_json::to_string(&answer).map_err(|err| Error::Other(err.to_string()))?;

                let peers = EndpointHandler::get_other_datachannel_transport_contexts(
                    server_states,
                    &transport_context,
                )?;
                let mut messages = Vec::with_capacity(peers.len() + 1);

                messages.push(TaggedRTCMessage {
                    now,
                    transport: transport_context,
                    message: RTCMessage::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                        association_handle,
                        stream_id,
                        data_channel_event: DataChannelEvent::Message(BytesMut::from(
                            answer_str.as_str(),
                        )),
                    })),
                });

                // trigger other endpoints' create_offer()
                for (
                    other_transport_context,
                    association_handle,
                    stream_id,
                    is_renegotiation_needed,
                ) in peers
                {
                    if is_renegotiation_needed {
                        messages.push(EndpointHandler::create_offer_message_event(
                            server_states,
                            now,
                            other_transport_context,
                            association_handle,
                            stream_id,
                        )?);
                    }
                }

                Ok(messages)
            }
            RTCSdpType::Answer => {
                server_states.accept_answer(session_id, endpoint_id, four_tuple, request_sdp)?;
                Ok(vec![])
            }
            _ => Err(Error::Other(format!(
                "Unsupported SDP type {}",
                request_sdp.sdp_type
            ))),
        }
    }

    fn handle_rtp_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        rtp_packet: rtp::packet::Packet,
    ) -> Result<Vec<TaggedRTCMessage>> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);
        server_states
            .get_mut_transport(&(&transport_context).into())?
            .keep_alive();

        //TODO: Selective Forwarding RTP Packets
        let peers =
            EndpointHandler::get_other_media_transport_contexts(server_states, &transport_context)?;

        let mut outgoing_messages = Vec::with_capacity(peers.len());
        for transport in peers {
            outgoing_messages.push(TaggedRTCMessage {
                now,
                transport,
                message: RTCMessage::Rtp(RTPMessage::Rtp(rtp_packet.clone())),
            });
        }

        Ok(outgoing_messages)
    }

    fn handle_rtcp_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        rtcp_packets: Vec<Box<dyn rtcp::packet::Packet>>,
    ) -> Result<Vec<TaggedRTCMessage>> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);
        server_states
            .get_mut_transport(&(&transport_context).into())?
            .keep_alive();

        //TODO: Selective Forwarding RTCP Packets
        let peers =
            EndpointHandler::get_other_media_transport_contexts(server_states, &transport_context)?;

        let mut outgoing_messages = Vec::with_capacity(peers.len());
        for transport in peers {
            outgoing_messages.push(TaggedRTCMessage {
                now,
                transport,
                message: RTCMessage::Rtp(RTPMessage::Rtcp(rtcp_packets.clone())),
            });
        }

        Ok(outgoing_messages)
    }



    fn get_other_datachannel_transport_contexts(
        server_states: &mut ServerStates,
        transport_context: &TransportContext,
    ) -> Result<Vec<(TransportContext, usize, u16, bool)>> {
        let four_tuple = transport_context.into();
        let (session_id, endpoint_id) = server_states
            .find_endpoint(&four_tuple)
            .ok_or(Error::ErrClientTransportNotSet)?;
        let session = server_states
            .get_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {}",
                session_id
            )))?;

        let mut peers = vec![];
        let endpoints = session.get_endpoints();
        for (&other_endpoint_id, other_endpoint) in endpoints.iter() {
            if other_endpoint_id != endpoint_id {
                let transports = other_endpoint.get_transports();
                for (other_four_tuple, other_transport) in transports.iter() {
                    if let (Some(association_handle), Some(stream_id)) =
                        other_transport.association_handle_and_stream_id()
                    {
                        peers.push((
                            TransportContext {
                                local_addr: other_four_tuple.local_addr,
                                peer_addr: other_four_tuple.peer_addr,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: transport_context.ecn,
                            },
                            association_handle,
                            stream_id,
                            other_endpoint.is_renegotiation_needed(),
                        ));
                    } else {
                        // data channel is not ready yet for other_endpoint_id's other_four_tuple.
                        // this transport just joins, but data channel is still setup
                        trace!(
                            "{}/{}'s data channel is not ready yet for {:?} since it is still setup",
                            session_id,
                            other_endpoint_id,
                            other_four_tuple,
                        );
                    }
                }
            }
        }
        Ok(peers)
    }

    fn get_other_media_transport_contexts(
        server_states: &mut ServerStates,
        transport_context: &TransportContext,
    ) -> Result<Vec<TransportContext>> {
        let four_tuple = transport_context.into();
        let (session_id, endpoint_id) = server_states
            .find_endpoint(&four_tuple)
            .ok_or(Error::ErrClientTransportNotSet)?;
        let session = server_states
            .get_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {}",
                session_id
            )))?;

        let mut peers = vec![];
        let endpoints = session.get_endpoints();
        for (&other_endpoint_id, other_endpoint) in endpoints.iter() {
            if other_endpoint_id != endpoint_id {
                let transports = other_endpoint.get_transports();
                for (other_four_tuple, other_transport) in transports.iter() {
                    if other_transport.is_local_srtp_context_ready() {
                        peers.push(TransportContext {
                            local_addr: other_four_tuple.local_addr,
                            peer_addr: other_four_tuple.peer_addr,
                            transport_protocol: TransportProtocol::UDP,
                            ecn: transport_context.ecn,
                        });
                    } else {
                        // local_srtp_context is not ready yet for other_endpoint_id's other_four_tuple.
                        // this transport just joins, but local_srtp_context is still setup
                        trace!(
                            "{}/{}'s local_srtp_context is not ready yet for {:?} since it is still setup",
                            session_id,
                            other_endpoint_id,
                            other_four_tuple,
                        );
                    }
                }
            }
        }
        Ok(peers)
    }*/

    fn create_server_reflective_address_message_event(
        now: Instant,
        transport_context: TransportContext,
        transaction_id: TransactionId,
    ) -> Result<Vec<TaggedRTCMessage>> {
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

        Ok(vec![TaggedRTCMessage {
            now,
            transport: transport_context,
            message: RTCMessage::Stun(STUNMessage::Stun(response)),
        }])
    }

    fn add_transport(
        &mut self,
        request: &stun::message::Message,
        candidate_pair: &Arc<CandidatePair>,
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
            candidate_pair.clone(),
            self.dtls_handshake_config.clone(),
            self.sctp_endpoint_config.clone(),
            self.sctp_server_config.clone(),
        );

        self.transport_states.add_transport(four_tuple, transport);

        Ok(true)
    }

    /*
    fn create_offer_message_event(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<TaggedRTCMessage> {
        let four_tuple = (&transport_context).into();
        let (session_id, endpoint_id) = server_states
            .find_endpoint(&four_tuple)
            .ok_or(Error::ErrClientTransportNotSet)?;
        let session = server_states
            .get_mut_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {}",
                session_id
            )))?;

        let endpoint = session
            .get_mut_endpoint(&endpoint_id)
            .ok_or(Error::Other(format!(
                "can't find endpoint id {}",
                endpoint_id
            )))?;
        endpoint.set_renegotiation_needed(false); //clean renegotiation_needed flag

        let remote_description = endpoint
            .remote_description()
            .ok_or(Error::Other("remote_description is not set".to_string()))?
            .clone();

        let local_conn_cred = {
            let transports = endpoint.get_mut_transports();
            let transport = transports.get_mut(&four_tuple).ok_or(Error::Other(format!(
                "can't find transport for endpoint id {} with {:?}",
                endpoint_id, four_tuple
            )))?;
            transport.candidate().local_connection_credentials().clone()
        };

        let offer = session.create_offer(
            endpoint_id,
            &remote_description,
            &local_conn_cred.ice_params,
        )?;
        session.set_local_description(endpoint_id, &offer)?;

        let offer_str =
            serde_json::to_string(&offer).map_err(|err| Error::Other(err.to_string()))?;

        Ok(TaggedRTCMessage {
            now,
            transport: transport_context,
            message: RTCMessage::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                association_handle,
                stream_id,
                data_channel_event: DataChannelEvent::Message(BytesMut::from(offer_str.as_str())),
            })),
        })
    }*/
}
