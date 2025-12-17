use crate::description::{
    rtp_transceiver_direction::RTCRtpTransceiverDirection, sdp_type::RTCSdpType,
    RTCSessionDescription,
};
use crate::endpoint::candidate::Candidate;
use crate::messages::{
    ApplicationMessage, DTLSMessageEvent, DataChannelEvent, MessageEvent, RTPMessageEvent,
    STUNMessageEvent, TaggedMessageEvent,
};
use crate::state::server_states::ServerStates;
use bytes::BytesMut;
use log::{debug, info, trace, warn};
use shared::error::{Error, Result};
use shared::{Context, Handler, TransportContext, TransportProtocol};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::{Add, Sub};
use std::rc::Rc;
use std::time::Duration;
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

/// GatewayHandler implements Data/Media Selective Forward handling
pub struct GatewayHandler {
    server_states: Rc<RefCell<ServerStates>>,
    transmits: VecDeque<TaggedMessageEvent>,
    next_timeout: Instant,
    idle_timeout: Duration,
}

impl GatewayHandler {
    pub fn new(server_states: Rc<RefCell<ServerStates>>) -> Self {
        let idle_timeout = server_states.borrow().server_config().idle_timeout;

        GatewayHandler {
            server_states,
            transmits: VecDeque::new(),
            next_timeout: Instant::now().add(idle_timeout),
            idle_timeout,
        }
    }
}

impl Handler for GatewayHandler {
    type Rin = TaggedMessageEvent;
    type Rout = Self::Rin;
    type Win = TaggedMessageEvent;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "GatewayHandler"
    }

    fn transport_inactive(&mut self, _ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>) {
        let server_states = self.server_states.borrow();
        let sessions = server_states.get_sessions();
        let mut endpoint_count = 0;
        for session in sessions.values() {
            endpoint_count += session.get_endpoints().len();
        }
        info!(
            "Still Active Sessions {}, Endpoints {}/{}, Candidates {} on {}",
            sessions.len(),
            endpoint_count,
            server_states.get_endpoints().len(),
            server_states.get_candidates().len(),
            server_states.local_addr()
        );
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
        let try_read = || -> Result<Vec<TaggedMessageEvent>> {
            let mut server_states = self.server_states.borrow_mut();
            match msg.message {
                MessageEvent::Stun(STUNMessageEvent::Stun(message)) => {
                    GatewayHandler::handle_stun_message(
                        &mut server_states,
                        msg.now,
                        msg.transport,
                        message,
                    )
                }
                MessageEvent::Dtls(DTLSMessageEvent::DataChannel(message)) => {
                    GatewayHandler::handle_dtls_message(
                        &mut server_states,
                        msg.now,
                        msg.transport,
                        message,
                    )
                }
                MessageEvent::Rtp(RTPMessageEvent::Rtp(message)) => {
                    GatewayHandler::handle_rtp_message(
                        &mut server_states,
                        msg.now,
                        msg.transport,
                        message,
                    )
                }
                MessageEvent::Rtp(RTPMessageEvent::Rtcp(message)) => {
                    GatewayHandler::handle_rtcp_message(
                        &mut server_states,
                        msg.now,
                        msg.transport,
                        message,
                    )
                }
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

    fn handle_timeout(
        &mut self,
        _ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        now: Instant,
    ) {
        // terminate timeout here, no more ctx.fire_handle_timeout(now);
        if self.next_timeout <= now {
            let mut four_tuples = vec![];
            let mut server_states = self.server_states.borrow_mut();
            for session in server_states.get_mut_sessions().values_mut() {
                for endpoint in session.get_mut_endpoints().values_mut() {
                    for transport in endpoint.get_mut_transports().values_mut() {
                        if transport.last_activity() <= now.sub(self.idle_timeout) {
                            four_tuples.push(*transport.four_tuple());
                        }
                    }
                }
            }
            for four_tuple in four_tuples {
                server_states.remove_transport(four_tuple);
            }

            self.next_timeout = self.next_timeout.add(self.idle_timeout);
        }
    }

    fn poll_timeout(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        eto: &mut Instant,
    ) {
        if self.next_timeout < *eto {
            *eto = self.next_timeout;
        }
        ctx.fire_poll_timeout(eto);
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

impl GatewayHandler {
    fn handle_stun_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        mut request: stun::message::Message,
    ) -> Result<Vec<TaggedMessageEvent>> {
        let candidate = match GatewayHandler::check_stun_message(server_states, &mut request)? {
            Some(candidate) => candidate,
            None => {
                return GatewayHandler::create_server_reflective_address_message_event(
                    now,
                    transport_context,
                    request.transaction_id,
                );
            }
        };

        GatewayHandler::add_endpoint(server_states, &request, &candidate, &transport_context)?;

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
            candidate.get_local_parameters().password.clone(),
        );
        integrity.add_to(&mut response)?;
        FINGERPRINT.add_to(&mut response)?;

        debug!(
            "handle_stun_message response type {} with ip {} and port {} sent",
            response.typ,
            transport_context.peer_addr.ip(),
            transport_context.peer_addr.port()
        );

        Ok(vec![TaggedMessageEvent {
            now,
            transport: transport_context,
            message: MessageEvent::Stun(STUNMessageEvent::Stun(response)),
        }])
    }

    fn handle_dtls_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        message: ApplicationMessage,
    ) -> Result<Vec<TaggedMessageEvent>> {
        match message.data_channel_event {
            DataChannelEvent::Open => GatewayHandler::handle_datachannel_open(
                server_states,
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
            DataChannelEvent::Message(payload) => GatewayHandler::handle_datachannel_message(
                server_states,
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
                payload,
            ),
            DataChannelEvent::Close => GatewayHandler::handle_datachannel_close(
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
    ) -> Result<Vec<TaggedMessageEvent>> {
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
            Ok(vec![GatewayHandler::create_offer_message_event(
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
    ) -> Result<Vec<TaggedMessageEvent>> {
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
    ) -> Result<Vec<TaggedMessageEvent>> {
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

                let peers = GatewayHandler::get_other_datachannel_transport_contexts(
                    server_states,
                    &transport_context,
                )?;
                let mut messages = Vec::with_capacity(peers.len() + 1);

                messages.push(TaggedMessageEvent {
                    now,
                    transport: transport_context,
                    message: MessageEvent::Dtls(DTLSMessageEvent::DataChannel(
                        ApplicationMessage {
                            association_handle,
                            stream_id,
                            data_channel_event: DataChannelEvent::Message(BytesMut::from(
                                answer_str.as_str(),
                            )),
                        },
                    )),
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
                        messages.push(GatewayHandler::create_offer_message_event(
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
    ) -> Result<Vec<TaggedMessageEvent>> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);
        server_states
            .get_mut_transport(&(&transport_context).into())?
            .keep_alive();

        //TODO: Selective Forwarding RTP Packets
        let peers =
            GatewayHandler::get_other_media_transport_contexts(server_states, &transport_context)?;

        let mut outgoing_messages = Vec::with_capacity(peers.len());
        for transport in peers {
            outgoing_messages.push(TaggedMessageEvent {
                now,
                transport,
                message: MessageEvent::Rtp(RTPMessageEvent::Rtp(rtp_packet.clone())),
            });
        }

        Ok(outgoing_messages)
    }

    fn handle_rtcp_message(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        rtcp_packets: Vec<Box<dyn rtcp::packet::Packet>>,
    ) -> Result<Vec<TaggedMessageEvent>> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);
        server_states
            .get_mut_transport(&(&transport_context).into())?
            .keep_alive();

        //TODO: Selective Forwarding RTCP Packets
        let peers =
            GatewayHandler::get_other_media_transport_contexts(server_states, &transport_context)?;

        let mut outgoing_messages = Vec::with_capacity(peers.len());
        for transport in peers {
            outgoing_messages.push(TaggedMessageEvent {
                now,
                transport,
                message: MessageEvent::Rtp(RTPMessageEvent::Rtcp(rtcp_packets.clone())),
            });
        }

        Ok(outgoing_messages)
    }

    fn check_stun_message(
        server_states: &ServerStates,
        request: &mut stun::message::Message,
    ) -> Result<Option<Rc<Candidate>>> {
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

                if let Some(candidate) = server_states.find_candidate(&username.text) {
                    let password = candidate.get_local_parameters().password.clone();
                    let integrity = MessageIntegrity::new_short_term_integrity(password);
                    integrity.check(request)?;
                    Ok(Some(candidate.clone()))
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
    }

    fn create_server_reflective_address_message_event(
        now: Instant,
        transport_context: TransportContext,
        transaction_id: TransactionId,
    ) -> Result<Vec<TaggedMessageEvent>> {
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

        Ok(vec![TaggedMessageEvent {
            now,
            transport: transport_context,
            message: MessageEvent::Stun(STUNMessageEvent::Stun(response)),
        }])
    }

    fn add_endpoint(
        server_states: &mut ServerStates,
        request: &stun::message::Message,
        candidate: &Rc<Candidate>,
        transport_context: &TransportContext,
    ) -> Result<bool> {
        let mut is_new_endpoint = false;

        let session_id = candidate.session_id();
        let session = server_states
            .get_mut_session(&session_id)
            .ok_or(Error::Other(format!("session {} not found", session_id)))?;

        let endpoint_id = candidate.endpoint_id();
        let endpoint = session.get_endpoint(&endpoint_id);
        let four_tuple = transport_context.into();
        let has_transport = if let Some(endpoint) = &endpoint {
            endpoint.has_transport(&four_tuple)
        } else {
            is_new_endpoint = true;
            false
        };

        if !request.contains(ATTR_USE_CANDIDATE) || has_transport {
            return Ok(is_new_endpoint);
        }

        let is_new_endpoint = session.add_endpoint(candidate, transport_context)?;

        server_states.add_endpoint(four_tuple, session_id, endpoint_id);

        Ok(is_new_endpoint)
    }

    fn create_offer_message_event(
        server_states: &mut ServerStates,
        now: Instant,
        transport_context: TransportContext,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<TaggedMessageEvent> {
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

        Ok(TaggedMessageEvent {
            now,
            transport: transport_context,
            message: MessageEvent::Dtls(DTLSMessageEvent::DataChannel(ApplicationMessage {
                association_handle,
                stream_id,
                data_channel_event: DataChannelEvent::Message(BytesMut::from(offer_str.as_str())),
            })),
        })
    }
}
