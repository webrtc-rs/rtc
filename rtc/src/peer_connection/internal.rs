use super::*;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::sdp::{
    get_by_mid, get_peer_direction, get_rids, populate_sdp, MediaSection, PopulateSdpParams,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;
use std::collections::HashSet;

impl RTCPeerConnection {
    /// generate_unmatched_sdp generates an SDP that doesn't take remote state into account
    /// This is used for the initial call for CreateOffer
    pub(super) fn generate_unmatched_sdp(&mut self) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false);

        let ice_params = self.ice_transport().get_local_parameters()?;

        let candidates = self.ice_transport().get_local_candidates()?;

        let mut media_sections = vec![];

        for t in &mut self.rtp_transceivers {
            if t.stopped || t.mid.is_none() {
                // An "m=" section is generated for each
                // RtpTransceiver that has been added to the PeerConnection, excluding
                // any stopped RtpTransceivers;
                continue;
            }

            if let Some(mid) = t.mid.as_ref() {
                t.sender.set_negotiated();
                media_sections.push(MediaSection {
                    id: mid.to_string(),
                    //TODO: transceivers: vec![t],
                    ..Default::default()
                });
            }
        }

        if !self.data_channels.is_empty() {
            media_sections.push(MediaSection {
                id: format!("{}", media_sections.len()),
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
            media_description_fingerprint: self
                .configuration
                .setting_engine
                .sdp_media_level_fingerprints,
            is_ice_lite: self.configuration.setting_engine.candidates.ice_lite,
            extmap_allow_mixed: true,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group: None,
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            //&self.media_engine,
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
    ) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false);

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.ice_transport().get_local_candidates()?;

        let mut media_sections = vec![];
        let mut already_have_application_media_section = false;
        let mut extmap_allow_mixed = false;

        // Extract media descriptions to avoid borrowing conflicts
        let media_descriptions_and_extmap_allow_mixed = self
            .remote_description()
            .as_ref()
            .and_then(|r| r.parsed.as_ref())
            .map(|parsed| {
                (
                    parsed.media_descriptions.clone(),
                    parsed.has_attribute(ATTR_KEY_EXTMAP_ALLOW_MIXED),
                )
            });

        if let Some((media_descriptions, parsed_extmap_allow_mixed)) =
            media_descriptions_and_extmap_allow_mixed
        {
            extmap_allow_mixed = parsed_extmap_allow_mixed;

            for media in &media_descriptions {
                if let Some(mid_value) = get_mid_value(media) {
                    if mid_value.is_empty() {
                        return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                    }

                    if media.media_name.media == MEDIA_SECTION_APPLICATION {
                        media_sections.push(MediaSection {
                            id: mid_value.to_owned(),
                            data: true,
                            ..Default::default()
                        });
                        already_have_application_media_section = true;
                        continue;
                    }

                    let kind = RTPCodecType::from(media.media_name.media.as_str());
                    let direction = get_peer_direction(media);
                    if kind == RTPCodecType::Unspecified
                        || direction == RTCRtpTransceiverDirection::Unspecified
                    {
                        continue;
                    }

                    let extmap_allow_mixed = media.has_attribute(ATTR_KEY_EXTMAP_ALLOW_MIXED);

                    if let Some(t) = find_by_mid(mid_value, &mut self.rtp_transceivers) {
                        t.sender.set_negotiated();
                        //TODO: let media_transceivers = vec![t];

                        // NB: The below could use `then_some`, but with our current MSRV
                        // it's not possible to actually do this. The clippy version that
                        // ships with 1.64.0 complains about this so we disable it for now.
                        #[allow(clippy::unnecessary_lazy_evaluations)]
                        media_sections.push(MediaSection {
                            id: mid_value.to_owned(),
                            //TODO: transceivers: media_transceivers,
                            rid_map: get_rids(media),
                            offered_direction: (!include_unmatched).then(|| direction),
                            extmap_allow_mixed,
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
            for t in &mut self.rtp_transceivers {
                if let Some(mid) = t.mid.as_ref() {
                    t.sender.set_negotiated();
                    media_sections.push(MediaSection {
                        id: mid.to_string(),
                        //TODO:transceivers: vec![Arc::clone(t)],
                        ..Default::default()
                    });
                }
            }

            if !self.data_channels.is_empty() && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    id: format!("{}", media_sections.len()),
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
            media_description_fingerprint: self
                .configuration
                .setting_engine
                .sdp_media_level_fingerprints,
            is_ice_lite: self.configuration.setting_engine.candidates.ice_lite,
            extmap_allow_mixed,
            connection_role,
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group,
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            //&self.media_engine,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )
    }

    pub(super) fn has_local_description_changed(&self, desc: &RTCSessionDescription) -> bool {
        for t in &self.rtp_transceivers {
            let m = match t
                .mid
                .as_ref()
                .and_then(|mid| get_by_mid(mid.as_str(), desc))
            {
                Some(m) => m,
                None => return true,
            };

            if get_peer_direction(m) != t.direction {
                return true;
            }
        }
        false
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
                    self.is_negotiation_needed = false;
                    self.trigger_negotiation_needed();
                }
                self.do_signaling_state_change(next_state);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Helper to trigger a negotiation needed.
    pub(super) fn trigger_negotiation_needed(&mut self) {
        self.do_negotiation_needed();
    }

    pub(super) fn make_negotiation_needed_trigger(&mut self) {
        self.do_negotiation_needed();
    }

    fn do_negotiation_needed_inner(&mut self) -> bool {
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

    fn do_negotiation_needed(&mut self) {
        if !self.do_negotiation_needed_inner() {
            return;
        }
        let _ = self.negotiation_needed_op();
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
    pub(super) fn add_rtp_transceiver(&mut self, t: RTCRtpTransceiver) {
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
    }

    /// start_rtp_senders starts all outbound RTP streams
    pub(crate) fn start_rtp_senders(&mut self) -> Result<()> {
        /*TODO: let current_transceivers = self.internal.rtp_transceivers.lock().await;
        for transceiver in &*current_transceivers {
            let sender = transceiver.sender().await;
            if !sender.track_encodings.lock().await.is_empty()
                && sender.is_negotiated()
                && !sender.has_sent()
            {
                sender.send(&sender.get_parameters().await).await?;
            }
        }*/

        Ok(())
    }

    pub(crate) fn start_rtp(
        &mut self,
        _is_renegotiation: bool,
        _remote_desc: RTCSessionDescription,
    ) -> Result<()> {
        /*
        let mut track_details = if let Some(parsed) = &remote_desc.parsed {
            track_details_from_sdp(parsed, false)
        } else {
            vec![]
        };

        let current_transceivers = {
            let current_transceivers = self.rtp_transceivers.lock().await;
            current_transceivers.clone()
        };

        if !is_renegotiation {
            self.undeclared_media_processor();
        } else {
            for t in &current_transceivers {
                let receiver = t.receiver().await;
                let tracks = receiver.tracks().await;
                if tracks.is_empty() {
                    continue;
                }

                let mut receiver_needs_stopped = false;

                for t in tracks {
                    if !t.rid().is_empty() {
                        if let Some(details) =
                            track_details_for_rid(&track_details, SmolStr::from(t.rid()))
                        {
                            t.set_id(details.id.clone());
                            t.set_stream_id(details.stream_id.clone());
                            continue;
                        }
                    } else if t.ssrc() != 0 {
                        if let Some(details) = track_details_for_ssrc(&track_details, t.ssrc()) {
                            t.set_id(details.id.clone());
                            t.set_stream_id(details.stream_id.clone());
                            continue;
                        }
                    }

                    receiver_needs_stopped = true;
                }

                if !receiver_needs_stopped {
                    continue;
                }

                log::info!("Stopping receiver {receiver:?}");
                if let Err(err) = receiver.stop().await {
                    log::warn!("Failed to stop RtpReceiver: {err}");
                    continue;
                }

                let interceptor = self
                    .interceptor
                    .upgrade()
                    .ok_or(Error::ErrInterceptorNotBind)?;

                let receiver = Arc::new(RTCRtpReceiver::new(
                    self.setting_engine.get_receive_mtu(),
                    receiver.kind(),
                    Arc::clone(&self.dtls_transport),
                    Arc::clone(&self.media_engine),
                    interceptor,
                ));
                t.set_receiver(receiver).await;
            }
        }

        self.start_rtp_receivers(&mut track_details, &current_transceivers, is_renegotiation)
            .await?;
        if let Some(parsed_remote) = &remote_desc.parsed {
            let current_local_desc = self.current_local_description.lock().await;
            if let Some(parsed_local) = current_local_desc
                .as_ref()
                .and_then(|desc| desc.parsed.as_ref())
            {
                if let Some(remote_port) = get_application_media_section_sctp_port(parsed_remote) {
                    if let Some(local_port) = get_application_media_section_sctp_port(parsed_local)
                    {
                        // TODO: Reuse the MediaDescription retrieved when looking for the message size.
                        let max_message_size =
                            get_application_media_section_max_message_size(parsed_remote)
                                .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
                        self.start_sctp(
                            local_port,
                            remote_port,
                            SCTPTransportCapabilities { max_message_size },
                        )
                        .await;
                    }
                }
            }
        }*/

        Ok(())
    }

    fn negotiation_needed_op(&mut self) -> Result<()> {
        /*
        // Don't run NegotiatedNeeded checks if on_negotiation_needed is not set
        let handler = &*params.on_negotiation_needed_handler.load();
        if handler.is_none() {
            return false;
        }

        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // Step 2.1
        if params.is_closed.load(Ordering::SeqCst) {
            return false;
        }
        // non-canon step 2.2
        if !params.ops.is_empty().await {
            //enqueue negotiation_needed_op again by return true
            return true;
        }

        // non-canon, run again if there was a request
        // starting defer(after_do_negotiation_needed(params).await);

        // Step 2.3
        if params.signaling_state.load(Ordering::SeqCst) != RTCSignalingState::Stable as u8 {
            return RTCPeerConnection::after_negotiation_needed_op(params).await;
        }

        // Step 2.4
        if !RTCPeerConnection::check_negotiation_needed(&params.check_negotiation_needed_params)
            .await
        {
            params.is_negotiation_needed.store(false, Ordering::SeqCst);
            return RTCPeerConnection::after_negotiation_needed_op(params).await;
        }

        // Step 2.5
        if params.is_negotiation_needed.load(Ordering::SeqCst) {
            return RTCPeerConnection::after_negotiation_needed_op(params).await;
        }

        // Step 2.6
        params.is_negotiation_needed.store(true, Ordering::SeqCst);

        // Step 2.7
        if let Some(handler) = handler {
            let mut f = handler.lock().await;
            f().await;
        }

        RTCPeerConnection::after_negotiation_needed_op(params).await

         */
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
        if self.dtls_transport().role() != DTLSRole::Client {
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
}
