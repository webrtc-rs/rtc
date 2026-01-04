use super::*;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::sdp::{
    MediaSection, PopulateSdpParams, get_by_mid, get_peer_direction, get_rids, have_data_channel,
    is_ext_map_allow_mixed_set, populate_sdp, rtp_extensions_from_media_description,
    track_details_from_sdp,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use ::sdp::MediaDescription;
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
            media_description_fingerprint: self
                .configuration
                .setting_engine
                .sdp_media_level_fingerprints,
            is_ice_lite: self.configuration.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed: true,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group: None,
            sctp_max_message_size: self
                .configuration
                .setting_engine
                .sctp_max_message_size
                .as_usize(),
            ignore_rid_pause_for_recv: false,
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            &self.configuration.media_engine,
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

                    if let Some(i) = find_by_mid(mid_value, &self.rtp_transceivers) {
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
            media_description_fingerprint: self
                .configuration
                .setting_engine
                .sdp_media_level_fingerprints,
            is_ice_lite: self.configuration.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed,
            connection_role,
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            match_bundle_group,
            sctp_max_message_size: self
                .configuration
                .setting_engine
                .sctp_max_message_size
                .as_usize(),
            ignore_rid_pause_for_recv,
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            &self.configuration.media_engine,
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
    pub(super) fn add_rtp_transceiver(&mut self, t: RTCRtpTransceiver) -> RTCRtpTransceiverId {
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
        self.rtp_transceivers.len() - 1
    }

    pub(super) fn start_rtp(&mut self, remote_desc: RTCSessionDescription) -> Result<()> {
        let incoming_tracks = if let Some(parsed) = &remote_desc.parsed {
            track_details_from_sdp(parsed)
        } else {
            vec![]
        };

        for incoming_track in incoming_tracks.into_iter() {
            if let Some(transceiver) = self.rtp_transceivers.iter_mut().find(|transceiver| {
                transceiver.mid().as_ref() == Some(&incoming_track.mid)
                    && incoming_track.kind == transceiver.kind()
                    && transceiver.direction().has_recv()
            }) && let Some(receiver) = transceiver.receiver_mut()
            {
                let mut receive_codings = vec![];
                if !incoming_track.rids.is_empty() {
                    //TODO: handle simulcast rid without ssrc in RTCPeerConnection's start_rtp for incoming_track handling #8
                    for rid in incoming_track.rids {
                        receive_codings.push(RTCRtpCodingParameters {
                            rid,
                            ssrc: incoming_track.ssrc,
                            rtx: incoming_track
                                .rtx_ssrc
                                .map(|rtx_ssrc| RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                            ..Default::default()
                        });
                    }
                } else if let Some(ssrc) = incoming_track.ssrc {
                    if receiver.track(&incoming_track.track_id).is_none() {
                        receiver.add_track(MediaStreamTrack::new(
                            incoming_track.stream_id,
                            incoming_track.track_id,
                            format!("remote-{}-{}", incoming_track.kind, math_rand_alpha(16)), //TODO:// Label
                            incoming_track.kind,
                            None,
                            ssrc,
                            RTCRtpCodec::default(), // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                        ));
                    }

                    receive_codings.push(RTCRtpCodingParameters {
                        rid: "".to_string(),
                        ssrc: Some(ssrc),
                        rtx: incoming_track
                            .rtx_ssrc
                            .map(|rtx_ssrc| RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                        fec: incoming_track
                            .fec_ssrc
                            .map(|fec_ssrc| RTCRtpFecParameters { ssrc: fec_ssrc }),
                    });
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
    ) -> Result<RTCRtpTransceiver> {
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
            self.configuration
                .media_engine
                .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
            self.configuration
                .media_engine
                .is_fec_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
        );

        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: track.rid().unwrap_or_default().into(),
                ssrc: Some(track.ssrc()),
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
            codec: track.codec().clone(),
            ..Default::default()
        }]
    }

    pub(super) fn set_rtp_transceiver_current_direction(
        &mut self,
        media_descriptions: &[MediaDescription],
        we_offer: bool,
    ) -> Result<()> {
        for media in media_descriptions {
            let mid_value = match get_mid_value(media) {
                Some(mid) if !mid.is_empty() => mid,
                _ => return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue),
            };

            if media.media_name.media == MEDIA_SECTION_APPLICATION {
                continue;
            }

            let i = match find_by_mid(mid_value, &self.rtp_transceivers) {
                Some(i) => i,
                None => return Err(Error::ErrPeerConnTransceiverMidNil),
            };

            let kind = RtpCodecKind::from(media.media_name.media.as_str());
            let mut direction = get_peer_direction(media);
            if kind == RtpCodecKind::Unspecified
                || direction == RTCRtpTransceiverDirection::Unspecified
            {
                continue;
            }

            // reverse direction if it was a remote answer
            if we_offer {
                if direction == RTCRtpTransceiverDirection::Sendonly {
                    direction = RTCRtpTransceiverDirection::Recvonly;
                } else if direction == RTCRtpTransceiverDirection::Recvonly {
                    direction = RTCRtpTransceiverDirection::Sendonly;
                }
            }

            // If a transceiver is created by applying a remote description that has recvonly transceiver,
            // it will have no sender. In this case, the transceiver's current direction is set to inactive so
            // that the transceiver can be reused by next AddTrack.
            if !we_offer
                && direction == RTCRtpTransceiverDirection::Sendonly
                && self.rtp_transceivers[i].sender().is_none()
            {
                direction = RTCRtpTransceiverDirection::Inactive;
            }

            self.rtp_transceivers[i].set_current_direction(direction);
        }

        Ok(())
    }
}
