use super::*;
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCPeerConnectionIceEvent};
use crate::peer_connection::sdp::{
    MediaSection, PopulateSdpParams, get_by_mid, get_peer_direction, get_rids, have_data_channel,
    is_ext_map_allow_mixed_set, rtp_extensions_from_media_description, track_details_from_sdp,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::{PayloadType, RTCRtpTransceiverId};
use crate::statistics::accumulator::IceCandidateAccumulator;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;
use std::collections::HashSet;

impl<I> RTCPeerConnection<I>
where
    I: Interceptor,
{
    pub(super) fn new(
        mut configuration: RTCConfiguration,
        media_engine: MediaEngine,
        setting_engine: SettingEngine,
        interceptor: I,
    ) -> Result<Self> {
        configuration.validate()?;

        let mut candidate_types = vec![];
        if setting_engine.candidates.ice_lite {
            candidate_types.push(ice::candidate::CandidateType::Host);
        } else if configuration.ice_transport_policy == RTCIceTransportPolicy::Relay {
            candidate_types.push(ice::candidate::CandidateType::Relay);
        }

        let mut validated_servers = vec![];
        if !configuration.ice_servers.is_empty() {
            for server in &configuration.ice_servers {
                let url = server.urls()?;
                validated_servers.extend(url);
            }
        }

        let network_types = if setting_engine.candidates.ice_network_types.is_empty() {
            ice::network_type::supported_network_types()
        } else {
            setting_engine.candidates.ice_network_types.clone()
        };

        let agent_config = AgentConfig {
            lite: setting_engine.candidates.ice_lite,
            urls: validated_servers,
            disconnected_timeout: setting_engine.timeout.ice_disconnected_timeout,
            failed_timeout: setting_engine.timeout.ice_failed_timeout,
            keepalive_interval: setting_engine.timeout.ice_keepalive_interval,
            candidate_types,
            network_types,
            host_acceptance_min_wait: setting_engine.timeout.ice_host_acceptance_min_wait,
            srflx_acceptance_min_wait: setting_engine.timeout.ice_srflx_acceptance_min_wait,
            prflx_acceptance_min_wait: setting_engine.timeout.ice_prflx_acceptance_min_wait,
            relay_acceptance_min_wait: setting_engine.timeout.ice_relay_acceptance_min_wait,
            multicast_dns_mode: setting_engine.multicast_dns.mode,
            multicast_dns_local_name: setting_engine.multicast_dns.local_name.clone(),
            multicast_dns_local_ip: setting_engine.multicast_dns.local_ip,
            multicast_dns_query_timeout: setting_engine.multicast_dns.timeout,
            local_ufrag: setting_engine.candidates.username_fragment.clone(),
            local_pwd: setting_engine.candidates.password.clone(),

            ..Default::default()
        };

        // Create the ICE transport
        let ice_transport = RTCIceTransport::new(agent_config)?;

        // Create the DTLS transport
        let certificates = configuration.certificates.drain(..).collect();
        let dtls_transport = RTCDtlsTransport::new(
            certificates,
            setting_engine.answering_dtls_role,
            setting_engine.srtp_protection_profiles.clone(),
            setting_engine.allow_insecure_verification_algorithm,
            setting_engine.replay_protection,
        )?;

        // Create the SCTP transport
        let sctp_transport = RTCSctpTransport::new(setting_engine.sctp_max_message_size);

        // Create Pipeline Context
        let ice_handler_context = IceHandlerContext::new(ice_transport);
        let dtls_handler_context = DtlsHandlerContext::new(dtls_transport);
        let sctp_handler_context = SctpHandlerContext::new(sctp_transport);

        let pipeline_context = PipelineContext {
            ice_handler_context,
            dtls_handler_context,
            sctp_handler_context,

            ..Default::default()
        };

        Ok(Self {
            configuration,
            media_engine,
            setting_engine,
            interceptor,
            local_description: None,
            current_local_description: None,
            pending_local_description: None,
            remote_description: None,
            current_remote_description: None,
            pending_remote_description: None,
            signaling_state: RTCSignalingState::Stable,
            peer_connection_state: RTCPeerConnectionState::New,
            can_trickle_ice_candidates: None,
            pipeline_context,
            data_channels: HashMap::new(),
            rtp_transceivers: Vec::new(),
            greater_mid: -1,
            sdp_origin: Origin::default(),
            last_offer: String::new(),
            last_answer: String::new(),
            ice_restart_requested: None,
            negotiation_needed_state: NegotiationNeededState::Empty,
            is_negotiation_ongoing: false,
        })
    }

    /// generate_unmatched_sdp generates an SDP that doesn't take remote state into account
    /// This is used for the initial call for CreateOffer
    pub(super) fn generate_unmatched_sdp(&mut self) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false);

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.ice_transport().get_local_candidates()?;

        let mut media_sections = vec![];

        for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
            if let Some(sender) = t.sender_mut() {
                sender.set_negotiated();
            }

            if let Some(mid) = t.mid().clone() {
                media_sections.push(MediaSection {
                    mid,
                    transceiver_index: i,
                    ..Default::default()
                });
            }
        }

        if !self.data_channels.is_empty() {
            media_sections.push(MediaSection {
                mid: format!("{}", media_sections.len()),
                transceiver_index: usize::MAX,
                data: true,
                ..Default::default()
            });
        }

        let dtls_fingerprints = if let Some(cert) = self.dtls_transport().certificates.first() {
            cert.get_fingerprints()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed: true,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group: None,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            ignore_rid_pause_for_recv: false,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
        };
        RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )
    }

    /// generate_matched_sdp generates a SDP and takes the remote state into account
    /// this is used everytime we have a remote_description
    pub(super) fn generate_matched_sdp(
        &mut self,
        include_unmatched: bool,
        connection_role: ConnectionRole,
        ignore_rid_pause_for_recv: bool,
    ) -> Result<SessionDescription> {
        let mut d = SessionDescription::new_jsep_session_description(false);
        d = d.with_value_attribute(ATTR_KEY_MSID_SEMANTIC.to_owned(), "WMS *".to_owned());

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.ice_transport().get_local_candidates()?;

        let mut media_sections = vec![];
        let mut already_have_application_media_section = false;
        let is_extmap_allow_mixed = is_ext_map_allow_mixed_set(self.remote_description.as_ref());

        // Extract media descriptions to avoid borrowing conflicts
        let media_descriptions = self
            .remote_description()
            .as_ref()
            .and_then(|r| r.parsed.as_ref())
            .map(|parsed| parsed.media_descriptions.clone());

        if let Some(media_descriptions) = media_descriptions {
            for media in &media_descriptions {
                if let Some(mid_value) = get_mid_value(media) {
                    if mid_value.is_empty() {
                        return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                    }

                    if media.media_name.media == MEDIA_SECTION_APPLICATION {
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: usize::MAX,
                            data: true,
                            ..Default::default()
                        });
                        already_have_application_media_section = true;
                        continue;
                    }

                    let kind = RtpCodecKind::from(media.media_name.media.as_str());
                    let direction = get_peer_direction(media);
                    if kind == RtpCodecKind::Unspecified
                        || direction == RTCRtpTransceiverDirection::Unspecified
                    {
                        continue;
                    }

                    if let Some(i) =
                        RTCPeerConnection::find_by_mid(mid_value, &self.rtp_transceivers)
                    {
                        if let Some(sender) = self.rtp_transceivers[i].sender_mut() {
                            sender.set_negotiated();
                        }

                        let extensions = rtp_extensions_from_media_description(media)?;
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: i,
                            match_extensions: extensions,
                            rid_map: get_rids(media),
                            ..Default::default()
                        });
                    } else {
                        return Err(Error::ErrPeerConnTransceiverMidNil);
                    }
                }
            }
        }

        // If we are offering also include unmatched local transceivers
        let match_bundle_group = if include_unmatched {
            for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
                if let Some(sender) = t.sender_mut() {
                    sender.set_negotiated();
                }

                if let Some(mid) = t.mid().clone() {
                    media_sections.push(MediaSection {
                        mid,
                        transceiver_index: i,
                        ..Default::default()
                    });
                }
            }

            if !self.data_channels.is_empty() && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    mid: format!("{}", media_sections.len()),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                });
            }
            None
        } else {
            self.remote_description()
                .as_ref()
                .and_then(|d| d.parsed.as_ref())
                .and_then(|d| d.attribute(ATTR_KEY_GROUP))
                .map(ToOwned::to_owned)
                .or(Some(String::new()))
        };

        let dtls_fingerprints = if let Some(cert) = self.dtls_transport().certificates.first() {
            cert.get_fingerprints()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed,
            connection_role,
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            ignore_rid_pause_for_recv,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
        };
        RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )
    }

    // 4.4.1.6 Set the SessionDescription
    pub(super) fn set_description(
        &mut self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
    ) -> Result<()> {
        if sd.sdp_type == RTCSdpType::Unspecified {
            return Err(Error::ErrPeerConnSDPTypeInvalidValue);
        }

        let next_state = {
            let cur = self.signaling_state;
            let new_sdpdoes_not_match_offer = Error::ErrSDPDoesNotMatchOffer;
            let new_sdpdoes_not_match_answer = Error::ErrSDPDoesNotMatchAnswer;

            match op {
                StateChangeOp::SetLocal => {
                    match sd.sdp_type {
                        // stable->SetLocal(offer)->have-local-offer
                        RTCSdpType::Offer => {
                            if sd.sdp != self.last_offer {
                                Err(new_sdpdoes_not_match_offer)
                            } else {
                                let next_state = check_next_signaling_state(
                                    cur,
                                    RTCSignalingState::HaveLocalOffer,
                                    StateChangeOp::SetLocal,
                                    sd.sdp_type,
                                );
                                if next_state.is_ok() {
                                    self.pending_local_description = Some(sd.clone());
                                }
                                next_state
                            }
                        }
                        // have-remote-offer->SetLocal(answer)->stable
                        // have-local-pranswer->SetLocal(answer)->stable
                        RTCSdpType::Answer => {
                            if sd.sdp != self.last_answer {
                                Err(new_sdpdoes_not_match_answer)
                            } else {
                                let next_state = check_next_signaling_state(
                                    cur,
                                    RTCSignalingState::Stable,
                                    StateChangeOp::SetLocal,
                                    sd.sdp_type,
                                );
                                if next_state.is_ok() {
                                    let pending_remote_description =
                                        self.pending_remote_description.take();
                                    let _pending_local_description =
                                        self.pending_local_description.take();

                                    self.current_local_description = Some(sd.clone());
                                    self.current_remote_description = pending_remote_description;
                                }
                                next_state
                            }
                        }
                        RTCSdpType::Rollback => {
                            let next_state = check_next_signaling_state(
                                cur,
                                RTCSignalingState::Stable,
                                StateChangeOp::SetLocal,
                                sd.sdp_type,
                            );
                            if next_state.is_ok() {
                                self.pending_local_description = None;
                            }
                            next_state
                        }
                        // have-remote-offer->SetLocal(pranswer)->have-local-pranswer
                        RTCSdpType::Pranswer => {
                            if sd.sdp != self.last_answer {
                                Err(new_sdpdoes_not_match_answer)
                            } else {
                                let next_state = check_next_signaling_state(
                                    cur,
                                    RTCSignalingState::HaveLocalPranswer,
                                    StateChangeOp::SetLocal,
                                    sd.sdp_type,
                                );
                                if next_state.is_ok() {
                                    self.pending_local_description = Some(sd.clone());
                                }
                                next_state
                            }
                        }
                        _ => Err(Error::ErrPeerConnStateChangeInvalid),
                    }
                }
                StateChangeOp::SetRemote => {
                    match sd.sdp_type {
                        // stable->SetRemote(offer)->have-remote-offer
                        RTCSdpType::Offer => {
                            let next_state = check_next_signaling_state(
                                cur,
                                RTCSignalingState::HaveRemoteOffer,
                                StateChangeOp::SetRemote,
                                sd.sdp_type,
                            );
                            if next_state.is_ok() {
                                self.pending_remote_description = Some(sd.clone());
                            }
                            next_state
                        }
                        // have-local-offer->SetRemote(answer)->stable
                        // have-remote-pranswer->SetRemote(answer)->stable
                        RTCSdpType::Answer => {
                            let next_state = check_next_signaling_state(
                                cur,
                                RTCSignalingState::Stable,
                                StateChangeOp::SetRemote,
                                sd.sdp_type,
                            );
                            if next_state.is_ok() {
                                let pending_local_description =
                                    self.pending_local_description.take();

                                let _pending_remote_description =
                                    self.pending_remote_description.take();

                                self.current_remote_description = Some(sd.clone());
                                self.current_local_description = pending_local_description;
                            }
                            next_state
                        }
                        RTCSdpType::Rollback => {
                            let next_state = check_next_signaling_state(
                                cur,
                                RTCSignalingState::Stable,
                                StateChangeOp::SetRemote,
                                sd.sdp_type,
                            );
                            if next_state.is_ok() {
                                self.pending_remote_description = None;
                            }
                            next_state
                        }
                        // have-local-offer->SetRemote(pranswer)->have-remote-pranswer
                        RTCSdpType::Pranswer => {
                            let next_state = check_next_signaling_state(
                                cur,
                                RTCSignalingState::HaveRemotePranswer,
                                StateChangeOp::SetRemote,
                                sd.sdp_type,
                            );
                            if next_state.is_ok() {
                                self.pending_remote_description = Some(sd.clone());
                            }
                            next_state
                        }
                        _ => Err(Error::ErrPeerConnStateChangeInvalid),
                    }
                } //_ => Err(Error::ErrPeerConnStateChangeUnhandled.into()),
            }
        };

        match next_state {
            Ok(next_state) => {
                self.signaling_state = next_state;
                if self.signaling_state == RTCSignalingState::Stable {
                    self.is_negotiation_ongoing = false;
                    self.trigger_negotiation_needed();
                }
                self.do_signaling_state_change(next_state);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn do_signaling_state_change(&mut self, new_state: RTCSignalingState) {
        log::info!("signaling state changed to {new_state}");
        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(new_state),
        );
    }

    pub(crate) fn ice_transport(&self) -> &RTCIceTransport {
        &self.pipeline_context.ice_handler_context.ice_transport
    }

    pub(crate) fn ice_transport_mut(&mut self) -> &mut RTCIceTransport {
        &mut self.pipeline_context.ice_handler_context.ice_transport
    }

    pub(crate) fn dtls_transport(&self) -> &RTCDtlsTransport {
        &self.pipeline_context.dtls_handler_context.dtls_transport
    }

    pub(crate) fn dtls_transport_mut(&mut self) -> &mut RTCDtlsTransport {
        &mut self.pipeline_context.dtls_handler_context.dtls_transport
    }

    pub(crate) fn sctp_transport(&self) -> &RTCSctpTransport {
        &self.pipeline_context.sctp_handler_context.sctp_transport
    }

    pub(crate) fn sctp_transport_mut(&mut self) -> &mut RTCSctpTransport {
        &mut self.pipeline_context.sctp_handler_context.sctp_transport
    }

    /// add_rtp_transceiver appends t into rtp_transceivers
    /// and fires onNegotiationNeeded;
    /// caller of this method should hold `self.mu` lock
    pub(super) fn add_rtp_transceiver(&mut self, t: RTCRtpTransceiver<I>) -> RTCRtpTransceiverId {
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
        self.rtp_transceivers.len() - 1
    }

    fn start_rtp_senders(&mut self) -> Result<()> {
        // Collect SSRCs, kinds, mids, rids, encoding indices, rtx_ssrc, and transceiver_id for outbound stream accumulators
        // We do this in two phases to avoid borrow conflicts
        #[allow(clippy::type_complexity)]
        let mut outbound_streams_to_create: Vec<(
            u32,
            RtpCodecKind,
            String,
            String,
            u32,
            Option<u32>,
            RTCRtpTransceiverId,
        )> = Vec::new();

        for (transceiver_id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            // Get kind and mid before mutable borrow of sender
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();

            if let Some(sender) = transceiver.sender_mut()
                && sender.is_negotiated()
                && !sender.has_sent()
                && !sender.track().codings().is_empty()
            {
                // Collect SSRCs for stats accumulator creation
                for (encoding_index, coding) in sender.track().codings().iter().enumerate() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        let rid = coding.rtp_coding_parameters.rid.clone();
                        let rtx_ssrc = coding
                            .rtp_coding_parameters
                            .rtx
                            .as_ref()
                            .map(|rtx| rtx.ssrc);
                        outbound_streams_to_create.push((
                            ssrc,
                            kind,
                            mid.clone(),
                            rid,
                            encoding_index as u32,
                            rtx_ssrc,
                            transceiver_id,
                        ));
                    }
                }

                sender.interceptor_local_streams_op(
                    &self.media_engine,
                    &mut self.interceptor,
                    true,
                );

                sender.set_sent();
            }
        }

        // Create outbound stream accumulators
        for (ssrc, kind, mid, rid, encoding_index, rtx_ssrc, transceiver_id) in
            outbound_streams_to_create
        {
            self.pipeline_context
                .stats
                .get_or_create_outbound_rtp_streams(
                    ssrc,
                    kind,
                    &mid,
                    &rid,
                    encoding_index,
                    rtx_ssrc,
                    transceiver_id,
                );
        }

        Ok(())
    }

    pub(super) fn start_rtp(&mut self, remote_desc: RTCSessionDescription) -> Result<()> {
        self.start_rtp_senders()?;

        let incoming_tracks = if let Some(parsed) = &remote_desc.parsed {
            track_details_from_sdp(parsed)
        } else {
            vec![]
        };

        let only_one_rtp_transceiver = self.rtp_transceivers.len() == 1;

        for incoming_track in incoming_tracks.into_iter() {
            if let Some(transceiver) = self.rtp_transceivers.iter_mut().find(|transceiver| {
                transceiver.mid().as_ref() == Some(&incoming_track.mid)
                    && incoming_track.kind == transceiver.kind()
                    && transceiver.direction().has_recv()
            }) && let Some(receiver) = transceiver.receiver_mut()
            {
                let mut receive_codings = vec![];
                if !incoming_track.rids.is_empty() {
                    // for incoming_track with rids, defer adding track until received the first RTP
                    // packet with rtp header extension with "urn:ietf:params:rtp-hdrext:sdes:mid" and
                    // "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", so that endpoint handler can
                    // map the unknown ssrc to m= line. Here, we should add a track but with 0 ssrc.
                    // The reason is to provide stream_id and track_id information for later usage
                    // when received the first RTP packet. So, it is placeholder here.
                    let mut codings = vec![];
                    for rid in incoming_track.rids {
                        let rtp_coding_parameters = RTCRtpCodingParameters {
                            rid,
                            ssrc: None, // Defer receiver's track's ssrc until received the first RTP packet with mid/rid header extension in endpoint handler
                            rtx: None,
                            fec: None,
                        };
                        receive_codings.push(rtp_coding_parameters.clone());
                        codings.push(RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(),
                            ..Default::default()
                        })
                    }

                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id.clone(),
                        incoming_track.track_id.clone(),
                        format!("remote-{}-{}", incoming_track.kind, math_rand_alpha(16)), //TODO:// Label
                        incoming_track.kind,
                        codings,
                    ));
                } else if let Some(ssrc) = incoming_track.ssrc {
                    let rtp_coding_parameters = RTCRtpCodingParameters {
                        rid: "".to_string(),
                        ssrc: Some(ssrc),
                        rtx: incoming_track
                            .rtx_ssrc
                            .map(|rtx_ssrc| RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                        fec: incoming_track
                            .fec_ssrc
                            .map(|fec_ssrc| RTCRtpFecParameters { ssrc: fec_ssrc }),
                    };

                    receive_codings.push(rtp_coding_parameters.clone());

                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        format!("remote-{}-{}", incoming_track.kind, math_rand_alpha(16)), //TODO:// Label
                        incoming_track.kind,
                        vec![RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(), // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                            ..Default::default()
                        }],
                    ));

                    receiver.interceptor_remote_streams_op(
                        &self.media_engine,
                        &mut self.interceptor,
                        true,
                    );
                } else if only_one_rtp_transceiver {
                    // If the remote SDP has only one media rtp transceiver, the ssrc doesn't have to be explicitly declared
                    // here, we should add a track but with 0 ssrc. The reason is to provide stream_id and track_id information for later usage
                    // when received the first RTP packet. So, it is placeholder here.
                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        format!("remote-{}-{}", incoming_track.kind, math_rand_alpha(16)), //TODO:// Label
                        incoming_track.kind,
                        vec![], // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                    ));
                } else {
                    return Err(Error::ErrRTPReceiverForSSRCTrackStreamNotFound);
                }

                receiver.set_coding_parameters(receive_codings);
            }
        }

        Ok(())
    }

    /// Update the PeerConnectionState given the state of relevant transports
    /// <https://www.w3.org/TR/webrtc/#rtcpeerconnectionstate-enum>
    pub(crate) fn update_connection_state(&mut self, is_closed: bool) {
        let connection_state =
            // The RTCPeerConnection object's [[IsClosed]] slot is true.
            if is_closed {
                RTCPeerConnectionState::Closed
            } else if self.ice_transport().ice_connection_state == RTCIceConnectionState::Failed || self.dtls_transport().state == RTCDtlsTransportState::Failed {
                // Any of the RTCIceTransports or RTCDtlsTransports are in a "failed" state.
                RTCPeerConnectionState::Failed
            } else if self.ice_transport().ice_connection_state == RTCIceConnectionState::Disconnected {
                // Any of the RTCIceTransports or RTCDtlsTransports are in the "disconnected"
                // state and none of them are in the "failed" or "connecting" or "checking" state.
                RTCPeerConnectionState::Disconnected
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::New || self.ice_transport().ice_connection_state == RTCIceConnectionState::Closed) &&
                (self.dtls_transport().state == RTCDtlsTransportState::New || self.dtls_transport().state == RTCDtlsTransportState::Closed) {
                // None of the previous states apply and all RTCIceTransports are in the "new" or "closed" state,
                // and all RTCDtlsTransports are in the "new" or "closed" state, or there are no transports.
                RTCPeerConnectionState::New
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::New || self.ice_transport().ice_connection_state == RTCIceConnectionState::Checking) ||
                (self.dtls_transport().state == RTCDtlsTransportState::New || self.dtls_transport().state == RTCDtlsTransportState::Connecting) {
                // None of the previous states apply and any RTCIceTransport is in the "new" or "checking" state or
                // any RTCDtlsTransport is in the "new" or "connecting" state.
                RTCPeerConnectionState::Connecting
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::Connected || self.ice_transport().ice_connection_state == RTCIceConnectionState::Completed || self.ice_transport().ice_connection_state == RTCIceConnectionState::Closed) &&
                (self.dtls_transport().state == RTCDtlsTransportState::Connected || self.dtls_transport().state == RTCDtlsTransportState::Closed) {
                // All RTCIceTransports and RTCDtlsTransports are in the "connected", "completed" or "closed"
                // state and all RTCDtlsTransports are in the "connected" or "closed" state.
                RTCPeerConnectionState::Connected
            } else {
                RTCPeerConnectionState::New
            };

        if self.peer_connection_state == connection_state {
            return;
        }

        log::info!("peer connection state changed: {connection_state}");
        self.peer_connection_state = connection_state;

        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(connection_state),
        );
    }

    pub(crate) fn generate_data_channel_id(&self) -> Result<RTCDataChannelId> {
        let mut id = 0u16;
        if self.dtls_transport().role() != RTCDtlsRole::Client {
            id += 1;
        }

        // Create map of ids so we can compare without double-looping each time.
        let ids: HashSet<RTCDataChannelId> = self.data_channels.keys().cloned().collect();
        let max = self.sctp_transport().max_channels();
        while id < max - 1 {
            if ids.contains(&id) {
                id += 2;
            } else {
                return Ok(id);
            }
        }

        Err(Error::ErrMaxDataChannelID)
    }

    /// Helper to trigger a negotiation needed.
    pub(super) fn trigger_negotiation_needed(&mut self) {
        if !self.do_negotiation_needed() {
            return;
        }
        let _ = self.negotiation_needed_op();
    }

    fn do_negotiation_needed(&mut self) -> bool {
        // https://w3c.github.io/webrtc-pc/#updating-the-negotiation-needed-flag
        // non-canon step 1
        if self.negotiation_needed_state == NegotiationNeededState::Run {
            self.negotiation_needed_state = NegotiationNeededState::Queue;
            false
        } else if self.negotiation_needed_state == NegotiationNeededState::Queue {
            false
        } else {
            self.negotiation_needed_state = NegotiationNeededState::Run;
            true
        }
    }

    fn negotiation_needed_op(&mut self) -> bool {
        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // Step 2.1
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return false;
        }
        // non-canon step 2.2
        // no need to check ops

        // non-canon, run again if there was a request
        // starting defer(after_do_negotiation_needed(params).await);

        // Step 2.3
        if self.signaling_state != RTCSignalingState::Stable {
            return self.after_negotiation_needed_op();
        }

        // Step 2.4
        if !self.check_negotiation_needed() {
            self.is_negotiation_ongoing = false;
            return self.after_negotiation_needed_op();
        }

        // Step 2.5
        if self.is_negotiation_ongoing {
            return self.after_negotiation_needed_op();
        }

        // Step 2.6
        // set negotiation is in middle of ongoing
        self.is_negotiation_ongoing = true;

        // Step 2.7
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnNegotiationNeededEvent);

        //TODO: do we need this call with new event-based handling?
        self.after_negotiation_needed_op()
    }

    fn after_negotiation_needed_op(&mut self) -> bool {
        let old_negotiation_needed_state = self.negotiation_needed_state;

        self.negotiation_needed_state = NegotiationNeededState::Empty;

        if old_negotiation_needed_state == NegotiationNeededState::Queue {
            self.do_negotiation_needed()
        } else {
            false
        }
    }

    fn check_negotiation_needed(&self) -> bool {
        // To check if negotiation is needed for connection, perform the following checks:
        // Skip 1, 2 steps
        // Step 3

        if let Some(local_desc) = &self.current_local_description {
            let len_data_channel = self.data_channels.len();

            if len_data_channel != 0 && have_data_channel(local_desc).is_none() {
                return true;
            }

            for transceiver in &self.rtp_transceivers {
                // https://www.w3.org/TR/webrtc/#dfn-update-the-negotiation-needed-flag
                // Step 5.1
                // if t.stopping && !t.stopped {
                // 	return true
                // }
                let m = transceiver
                    .mid()
                    .as_ref()
                    .and_then(|mid| get_by_mid(mid.as_str(), local_desc));
                // Step 5.2
                if m.is_none() {
                    return true;
                }

                if let Some(m) = m {
                    // Step 5.3.1
                    if transceiver.direction().has_send() {
                        if let Some(sender) = transceiver.sender() {
                            let dmsid = match m.attribute(ATTR_KEY_MSID).and_then(|o| o) {
                                Some(msid) => msid,
                                None => return true, // doesn't contain a single a=msid line
                            };

                            let track = sender.track();
                            if dmsid.split_whitespace().next()
                                != Some(&format!("{} {}", track.stream_id(), track.track_id()))
                            {
                                return true;
                            }
                        } else {
                            return true;
                        }
                    }
                    match local_desc.sdp_type {
                        RTCSdpType::Offer => {
                            // Step 5.3.2
                            if let Some(remote_desc) = &self.current_remote_description {
                                if let Some(rm) = transceiver
                                    .mid()
                                    .as_ref()
                                    .and_then(|mid| get_by_mid(mid.as_str(), remote_desc))
                                {
                                    if get_peer_direction(m) != transceiver.direction()
                                        && get_peer_direction(rm)
                                            != transceiver.direction().reverse()
                                    {
                                        return true;
                                    }
                                } else {
                                    return true;
                                }
                            }
                        }
                        RTCSdpType::Answer => {
                            if m.attribute(transceiver.direction().to_string().as_str())
                                .is_none()
                            {
                                return true;
                            }
                        }
                        _ => {}
                    };
                }

                // Step 5.4
            }
            // Step 6
            false
        } else {
            true
        }
    }

    pub(super) fn new_transceiver_from_track(
        &self,
        track: MediaStreamTrack,
        mut init: RTCRtpTransceiverInit,
    ) -> Result<RTCRtpTransceiver<I>> {
        if init.direction == RTCRtpTransceiverDirection::Unspecified {
            Err(Error::ErrPeerConnAddTransceiverFromTrackSupport)
        } else {
            if init.send_encodings.is_empty() {
                init.send_encodings = self.send_encodings_from_track(&track);
            }
            Ok(RTCRtpTransceiver::new(track.kind(), Some(track), init))
        }
    }

    pub(super) fn send_encodings_from_track(
        &self,
        track: &MediaStreamTrack,
    ) -> Vec<RTCRtpEncodingParameters> {
        let (is_rtx_enabled, is_fec_enabled) = (
            self.media_engine
                .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
            self.media_engine
                .is_fec_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
        );

        track
            .codings()
            .iter()
            .map(|coding| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: coding.rtp_coding_parameters.rid.to_owned(),
                    ssrc: coding.rtp_coding_parameters.ssrc.to_owned(),
                    rtx: if is_rtx_enabled {
                        Some(RTCRtpRtxParameters {
                            ssrc: rand::random::<u32>(),
                        })
                    } else {
                        None
                    },
                    fec: if is_fec_enabled {
                        Some(RTCRtpFecParameters {
                            ssrc: rand::random::<u32>(),
                        })
                    } else {
                        None
                    },
                },
                codec: coding.codec.clone(),
                ..Default::default()
            })
            .collect()
    }

    pub(crate) fn stats(&self) -> &RTCStatsAccumulator {
        &self.pipeline_context.stats
    }

    pub(crate) fn stats_mut(&mut self) -> &mut RTCStatsAccumulator {
        &mut self.pipeline_context.stats
    }

    /// Updates stats after ICE restart with the new credentials from the agent.
    pub(super) fn ice_restart(&mut self) -> Result<()> {
        let (local_ufrag, local_pwd, keep_local_candidates) = (
            self.setting_engine.candidates.username_fragment.clone(),
            self.setting_engine.candidates.password.clone(),
            !self
                .setting_engine
                .candidates
                .discard_local_candidates_during_ice_restart,
        );
        self.ice_transport_mut()
            .restart(local_ufrag, local_pwd, keep_local_candidates)?;

        // Update stats with new ICE credentials after restart
        if let Ok(params) = self.ice_transport().get_local_parameters() {
            self.pipeline_context
                .stats
                .transport
                .ice_local_username_fragment = params.username_fragment;
        }

        Ok(())
    }

    pub(super) fn start_transports(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
        remote_dtls_parameters: DTLSParameters,
    ) -> Result<()> {
        // Update ICE role (may change after ICE restart if peer roles swap)
        self.pipeline_context.stats.transport.ice_role = local_ice_role;

        // Start the ice transport
        self.ice_transport_mut()
            .start(local_ice_role, remote_ice_parameters)?;

        // Start the dtls transport
        self.dtls_transport_mut()
            .start(local_ice_role, remote_dtls_parameters)?;

        self.update_connection_state(false);

        Ok(())
    }

    /// Converts an RTCIceCandidate to an IceCandidateAccumulator for stats collection.
    ///
    /// # Arguments
    ///
    /// * `candidate` - The ICE candidate to convert.
    /// * `username_fragment` - The ICE username fragment.
    /// * `url` - Optional STUN/TURN server URL. Per W3C spec, this should only be
    ///   provided for local candidates of type "srflx" or "relay".
    pub(super) fn candidate_to_accumulator(
        &self,
        candidate: &RTCIceCandidate,
        username_fragment: &str,
        url: Option<&str>,
    ) -> IceCandidateAccumulator {
        // Per W3C spec, URL is only valid for local srflx/relay candidates
        let url_for_stats = match candidate.typ {
            RTCIceCandidateType::Srflx | RTCIceCandidateType::Relay => {
                url.map(|s| s.to_string()).unwrap_or_default()
            }
            _ => String::new(),
        };

        IceCandidateAccumulator {
            transport_id: self.pipeline_context.stats.transport.transport_id.clone(),
            address: if candidate.address.is_empty() {
                None
            } else {
                Some(candidate.address.clone())
            },
            port: candidate.port,
            protocol: candidate.protocol.to_string(),
            candidate_type: candidate.typ,
            priority: (candidate.priority >> 16) as u16, // Take high 16 bits for stats priority
            url: url_for_stats,
            relay_protocol: candidate.relay_protocol,
            foundation: candidate.foundation.clone(),
            related_address: candidate.related_address.clone(),
            related_port: candidate.related_port,
            username_fragment: username_fragment.to_string(),
            tcp_type: candidate.tcp_type,
        }
    }

    pub(super) fn add_ice_remote_candidate(&mut self, candidate_value: &str) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;

        // Register remote candidate with stats accumulator
        // Per W3C spec, URL must NOT be present for remote candidates
        let rtc_candidate: RTCIceCandidate = (&candidate).into();
        let candidate_id = format!("RTCRemoteIceCandidate_{}", rtc_candidate.id);
        let (ufrag, _) = self.ice_transport().get_remote_user_credentials();
        let accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, None);
        self.stats_mut()
            .register_remote_candidate(candidate_id, accumulator);

        self.ice_transport_mut().add_remote_candidate(candidate)?;
        Ok(())
    }

    pub(super) fn add_ice_local_candidate(
        &mut self,
        candidate_value: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;

        // Register local candidate with stats accumulator
        let rtc_candidate: RTCIceCandidate = (&candidate).into();
        let candidate_id = format!("RTCLocalIceCandidate_{}", rtc_candidate.id);
        let (ufrag, _) = self.ice_transport().get_local_user_credentials();
        let accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, url);
        self.stats_mut()
            .register_local_candidate(candidate_id, accumulator);

        self.ice_transport_mut().add_local_candidate(candidate)?;

        // Emit OnIceCandidateEvent
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnIceCandidateEvent(
                RTCPeerConnectionIceEvent {
                    candidate: rtc_candidate,
                    url: url.unwrap_or_default().to_string(),
                },
            ));

        Ok(())
    }

    /// Update STUN transaction stats from the ICE agent to the stats accumulator.
    ///
    /// This is called automatically by `get_stats()` to ensure ICE candidate pair
    /// statistics (RTT, requests/responses sent/received) are up to date.
    pub(super) fn update_ice_agent_stats(&mut self) {
        if let Some((local, remote)) = self
            .pipeline_context
            .ice_handler_context
            .ice_transport
            .agent
            .get_selected_candidate_pair()
        {
            let pair_id = format!("RTCIceCandidatePair_{}_{}", local.id(), remote.id());

            // Get candidate pair stats from the ice agent
            for cp_stats in self
                .pipeline_context
                .ice_handler_context
                .ice_transport
                .agent
                .get_candidate_pairs_stats()
            {
                let ice_pair_id = format!(
                    "RTCIceCandidatePair_{}_{}",
                    cp_stats.local_candidate_id, cp_stats.remote_candidate_id
                );
                if ice_pair_id == pair_id {
                    // Sync STUN stats from ice agent to RTC accumulator
                    self.pipeline_context.stats.update_ice_agent_stats(
                        local.id(),
                        remote.id(),
                        &cp_stats,
                    );
                    break;
                }
            }
        }
    }

    /// Update codec stats from transceivers to the stats accumulator.
    ///
    /// This is called automatically by `get_stats()` to ensure codec statistics
    /// are registered for all active RTP streams. Per W3C spec, codecs are only
    /// exposed when referenced by an RTP stream.
    pub(super) fn update_codec_stats(&mut self) {
        // Collect codec info from transceivers to avoid borrow conflicts
        let mut inbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();
        let mut outbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();

        for transceiver in &self.rtp_transceivers {
            // Process receivers (inbound streams)
            if let Some(receiver) = transceiver.receiver() {
                let codec_prefs = receiver.get_codec_preferences();
                let track = receiver.track();

                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        // Find the codec for this encoding
                        if let Some(codec) = track.get_codec_by_ssrc(ssrc)
                            && !codec.mime_type.is_empty()
                                // Find matching payload type from codec preferences
                                && let Some(codec_params) = codec_prefs.iter().find(|cp| {
                                    cp.rtp_codec.mime_type == codec.mime_type
                                        && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                            || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                                })
                        {
                            inbound_codecs.push((ssrc, codec.clone(), codec_params.payload_type));
                        }
                    }
                }
            }

            // Process senders (outbound streams)
            if let Some(sender) = transceiver.sender()
                && sender.has_sent()
            {
                let track = sender.track();
                let send_codecs = sender.get_send_codecs();
                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        let codec = &coding.codec;
                        if !codec.mime_type.is_empty() {
                            // Find matching payload type from send codecs
                            if let Some(codec_params) = send_codecs.iter().find(|cp| {
                                cp.rtp_codec.mime_type == codec.mime_type
                                    && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                        || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                            }) {
                                outbound_codecs.push((
                                    ssrc,
                                    codec.clone(),
                                    codec_params.payload_type,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Register inbound codecs
        for (ssrc, codec, payload_type) in inbound_codecs {
            self.pipeline_context
                .stats
                .register_inbound_codec(ssrc, &codec, payload_type);
        }

        // Register outbound codecs
        for (ssrc, codec, payload_type) in outbound_codecs {
            self.pipeline_context
                .stats
                .register_outbound_codec(ssrc, &codec, payload_type);
        }

        // Clean up unreferenced codecs
        self.pipeline_context.stats.cleanup_unreferenced_codecs();
    }
}
