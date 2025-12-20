use super::*;
use crate::handler::message::TaggedRTCEvent;
use crate::peer_connection::sdp::{
    get_by_mid, get_peer_direction, get_rids, populate_sdp, MediaSection, PopulateSdpParams,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;

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
            ice_gathering_state: self.ice_gathering_state,
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
            ice_gathering_state: self.ice_gathering_state,
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
        let _ = self.ops_enqueue_start(TaggedRTCEvent::DoNegotiationNeeded);
    }

    pub(super) fn do_signaling_state_change(&mut self, new_state: RTCSignalingState) {
        log::info!("signaling state changed to {new_state}");
        self.events
            .push_back(RTCPeerConnectionEvent::OnSignalingStateChangeEvent(
                new_state,
            ));
    }

    /// add_rtp_transceiver appends t into rtp_transceivers
    /// and fires onNegotiationNeeded;
    /// caller of this method should hold `self.mu` lock
    pub(super) fn add_rtp_transceiver(&mut self, t: RTCRtpTransceiver) {
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
    }

    pub(super) fn ops_enqueue_start(&mut self, event: TaggedRTCEvent) -> Result<()> {
        let mut intermediate_eouts = VecDeque::new();
        intermediate_eouts.append(&mut self.pipeline_context.event_outs);

        let mut endpoint_handler = self.get_endpoint_handler();
        while let Some(evt) = intermediate_eouts.pop_front() {
            endpoint_handler.handle_event(evt)?;
        }
        endpoint_handler.handle_event(event)
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
}
