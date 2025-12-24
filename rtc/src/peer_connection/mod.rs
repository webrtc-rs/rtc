pub mod certificate;
pub mod event;
mod internal;
pub mod sdp;
pub mod state;

use crate::configuration::setting_engine::SctpMaxMessageSize;
use crate::configuration::{
    offer_answer_options::{RTCAnswerOptions, RTCOfferOptions},
    RTCConfiguration,
};
use crate::data_channel::init::RTCDataChannelInit;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::{internal::RTCDataChannelInternal, RTCDataChannel, RTCDataChannelId};
use crate::handler::dtls::DtlsHandlerContext;
use crate::handler::ice::IceHandlerContext;
use crate::handler::sctp::SctpHandlerContext;
use crate::handler::PipelineContext;
use crate::media::rtp_codec::RTPCodecType;
use crate::media::rtp_receiver::RTCRtpReceiver;
use crate::media::rtp_sender::RTCRtpSender;
use crate::media::rtp_transceiver::{find_by_mid, satisfy_type_and_direction, RTCRtpTransceiver};
use crate::media::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::sdp::{
    extract_fingerprint, extract_ice_details, get_application_media_section_max_message_size,
    get_application_media_section_sctp_port, get_mid_value, get_peer_direction, is_lite_set,
    sdp_type::RTCSdpType, update_sdp_origin,
};
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::{
    NegotiationNeededState, RTCPeerConnectionState,
};
use crate::peer_connection::state::signaling_state::{RTCSignalingState, StateChangeOp};
use crate::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::transport::dtls::parameters::DTLSParameters;
use crate::transport::dtls::role::{DTLSRole, DEFAULT_DTLS_ROLE_ANSWER, DEFAULT_DTLS_ROLE_OFFER};
use crate::transport::dtls::RTCDtlsTransport;
use crate::transport::ice::candidate::RTCIceCandidateInit;
use crate::transport::ice::parameters::RTCIceParameters;
use crate::transport::ice::role::RTCIceRole;
use crate::transport::ice::RTCIceTransport;
use crate::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::transport::sctp::RTCSctpTransport;
use ::sdp::description::session::Origin;
use ::sdp::util::ConnectionRole;
use ice::candidate::{unmarshal_candidate, Candidate};
use sdp::MEDIA_SECTION_APPLICATION;
use shared::error::{Error, Result};
use std::collections::{HashMap, VecDeque};

/// PeerConnection represents a WebRTC connection that establishes a
/// peer-to-peer communications with another PeerConnection instance in a
/// browser, or to another endpoint implementing the required protocols.
#[derive(Default)]
pub struct RTCPeerConnection {
    //////////////////////////////////////////////////
    // PeerConnection WebRTC Spec Interface Definition
    //////////////////////////////////////////////////
    configuration: RTCConfiguration,

    local_description: Option<RTCSessionDescription>,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    remote_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,

    signaling_state: RTCSignalingState,
    ice_gathering_state: RTCIceGatheringState,
    ice_connection_state: RTCIceConnectionState,
    peer_connection_state: RTCPeerConnectionState,
    can_trickle_ice_candidates: bool,

    events: VecDeque<RTCPeerConnectionEvent>,

    //////////////////////////////////////////////////
    // PeerConnection Internal State Machine
    //////////////////////////////////////////////////
    pub(crate) pipeline_context: PipelineContext,
    pub(crate) data_channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,
    pub(super) rtp_transceivers: Vec<RTCRtpTransceiver>,

    greater_mid: usize,
    sdp_origin: Origin,
    last_offer: String,
    last_answer: String,

    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_needed: bool,
}

impl RTCPeerConnection {
    /// creates a PeerConnection with RTCConfiguration
    pub fn new(mut configuration: RTCConfiguration) -> Result<Self> {
        configuration.validate()?;

        // Create the ICE transport
        let ice_transport = RTCIceTransport::new(
            configuration
                .setting_engine
                .candidates
                .username_fragment
                .clone(),
            configuration.setting_engine.candidates.password.clone(),
        )?;

        // Create the DTLS transport
        let certificates = configuration.certificates.drain(..).collect();
        let dtls_transport = RTCDtlsTransport::new(
            certificates,
            configuration.setting_engine.answering_dtls_role,
            configuration
                .setting_engine
                .srtp_protection_profiles
                .clone(),
            configuration
                .setting_engine
                .allow_insecure_verification_algorithm,
            configuration.setting_engine.replay_protection.dtls,
        )?;

        // Create the SCTP transport
        let sctp_transport =
            RTCSctpTransport::new(configuration.setting_engine.sctp_max_message_size);

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
            pipeline_context,
            ..Default::default()
        })
    }

    /// create_offer starts the PeerConnection and generates the localDescription
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createoffer>
    pub fn create_offer(
        &mut self,
        options: Option<RTCOfferOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        if let Some(options) = options {
            if options.ice_restart {
                self.restart_ice()?;
            }
        }

        // This may be necessary to recompute if, for example, createOffer was called when only an
        // audio RTCRtpTransceiver was added to connection, but while performing the in-parallel
        // steps to create an offer, a video RTCRtpTransceiver was added, requiring additional
        // inspection of video system resources.
        let mut count = 0;
        let mut offer;

        loop {
            // include unmatched local transceivers
            // update the greater mid if the remote description provides a greater one
            if let Some(d) = self.current_remote_description.as_ref() {
                if let Some(parsed) = &d.parsed {
                    for media in &parsed.media_descriptions {
                        if let Some(mid) = get_mid_value(media) {
                            if mid.is_empty() {
                                continue;
                            }
                            let numeric_mid = match mid.parse::<usize>() {
                                Ok(n) => n,
                                Err(_) => continue,
                            };
                            if numeric_mid > self.greater_mid {
                                self.greater_mid = numeric_mid + 1;
                            }
                        }
                    }
                    if parsed.media_descriptions.len() > self.greater_mid {
                        self.greater_mid = parsed.media_descriptions.len() + 1;
                    }
                }
            }

            for t in &mut self.rtp_transceivers {
                if t.mid.is_some() {
                    continue;
                }

                t.mid = Some(format!("{}", self.greater_mid));
                self.greater_mid += 1;
            }

            let mut d = if self.current_remote_description.is_none() {
                self.generate_unmatched_sdp()?
            } else {
                self.generate_matched_sdp(
                    true, /*includeUnmatched */
                    DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
                )?
            };

            update_sdp_origin(&mut self.sdp_origin, &mut d);

            let sdp = d.marshal();

            offer = RTCSessionDescription {
                sdp_type: RTCSdpType::Offer,
                sdp,
                parsed: Some(d),
            };

            // Verify local media hasn't changed during offer
            // generation. Recompute if necessary
            if !self.has_local_description_changed(&offer) {
                break;
            }
            count += 1;
            if count >= 128 {
                return Err(Error::ErrExcessiveRetries);
            }
        }

        self.last_offer.clone_from(&offer.sdp);

        Ok(offer)
    }

    /// create_answer starts the PeerConnection and generates the localDescription
    pub fn create_answer(
        &mut self,
        _options: Option<RTCAnswerOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.remote_description().is_none() {
            return Err(Error::ErrNoRemoteDescription);
        }

        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        if self.signaling_state != RTCSignalingState::HaveRemoteOffer
            && self.signaling_state != RTCSignalingState::HaveLocalPranswer
        {
            return Err(Error::ErrIncorrectSignalingState);
        }

        let mut connection_role = self
            .configuration
            .setting_engine
            .answering_dtls_role
            .to_connection_role();
        if connection_role == ConnectionRole::Unspecified {
            connection_role = DEFAULT_DTLS_ROLE_ANSWER.to_connection_role();

            if let Some(remote_description) = self.remote_description() {
                if let Some(parsed) = remote_description.parsed.as_ref() {
                    if is_lite_set(parsed) && !self.configuration.setting_engine.candidates.ice_lite
                    {
                        connection_role = DTLSRole::Server.to_connection_role();
                    }
                }
            }
        }

        let mut d = self.generate_matched_sdp(false /*includeUnmatched */, connection_role)?;
        update_sdp_origin(&mut self.sdp_origin, &mut d);

        let sdp = d.marshal();

        let answer = RTCSessionDescription {
            sdp_type: RTCSdpType::Answer,
            sdp,
            parsed: Some(d),
        };

        self.last_answer.clone_from(&answer.sdp);

        Ok(answer)
    }

    /// set_local_description sets the SessionDescription of the local peer
    pub fn set_local_description(
        &mut self,
        mut local_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let is_renegotiation = self.current_local_description.is_some();

        // JSEP 5.4
        if local_description.sdp.is_empty() {
            match local_description.sdp_type {
                RTCSdpType::Answer | RTCSdpType::Pranswer => {
                    local_description.sdp.clone_from(&self.last_answer);
                }
                RTCSdpType::Offer => {
                    local_description.sdp.clone_from(&self.last_offer);
                }
                _ => return Err(Error::ErrPeerConnSDPTypeInvalidValueSetLocalDescription),
            }
        }

        local_description.parsed = Some(local_description.unmarshal()?);
        self.set_description(&local_description, StateChangeOp::SetLocal)?;

        let we_answer = local_description.sdp_type == RTCSdpType::Answer;
        if we_answer {
            if let Some(parsed_local_description) = &local_description.parsed {
                // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                // Section 4.4.1.5
                for media in &parsed_local_description.media_descriptions {
                    if media.media_name.media == MEDIA_SECTION_APPLICATION {
                        continue;
                    }

                    let kind = RTPCodecType::from(media.media_name.media.as_str());
                    let direction = get_peer_direction(media);
                    if kind == RTPCodecType::Unspecified
                        || direction == RTCRtpTransceiverDirection::Unspecified
                    {
                        continue;
                    }

                    let mid_value = match get_mid_value(media) {
                        Some(mid) if !mid.is_empty() => mid,
                        _ => continue,
                    };

                    let t = match find_by_mid(mid_value, &mut self.rtp_transceivers) {
                        Some(t) => t,
                        None => continue,
                    };
                    let previous_direction = t.current_direction;
                    // 4.9.1.7.3 applying a local answer or pranswer
                    // Set transceiver.[[CurrentDirection]] and transceiver.[[FiredDirection]] to direction.
                    t.set_current_direction(direction);
                    t.process_new_current_direction(previous_direction)?;
                }

                if let Some(remote_description) = self.remote_description().cloned() {
                    if let Some(parsed_remote_description) = remote_description.parsed.as_ref() {
                        if let Some(remote_port) =
                            get_application_media_section_sctp_port(parsed_remote_description)
                        {
                            if let Some(local_port) =
                                get_application_media_section_sctp_port(parsed_local_description)
                            {
                                let max_message_size =
                                    get_application_media_section_max_message_size(
                                        parsed_remote_description,
                                    )
                                    .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
                                let dtls_role = self.dtls_transport().role();

                                self.sctp_transport_mut().start(
                                    dtls_role,
                                    SCTPTransportCapabilities { max_message_size },
                                    local_port,
                                    remote_port,
                                )?;
                            }
                        }
                    }

                    self.start_rtp_senders()?;
                    self.start_rtp(is_renegotiation, remote_description)?;
                }
            }
        }

        Ok(())
    }

    /// local_description returns PendingLocalDescription if it is not null and
    /// otherwise it returns CurrentLocalDescription. This property is used to
    /// determine if set_local_description has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-localdescription>
    pub fn local_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_local_description.is_some() {
            self.pending_local_description.as_ref()
        } else {
            self.current_local_description.as_ref()
        }
    }

    /// set_remote_description sets the SessionDescription of the remote peer
    pub fn set_remote_description(
        &mut self,
        mut remote_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let is_renegotiation = self.current_remote_description.is_some();

        remote_description.parsed = Some(remote_description.unmarshal()?);
        self.set_description(&remote_description, StateChangeOp::SetRemote)?;

        if let Some(parsed_remote_description) = &remote_description.parsed {
            self.configuration
                .media_engine
                .update_from_remote_description(parsed_remote_description)?;

            let we_offer = remote_description.sdp_type == RTCSdpType::Answer;

            // Extract media descriptions to avoid borrowing conflicts
            let media_descriptions = self
                .remote_description()
                .as_ref()
                .and_then(|r| r.parsed.as_ref())
                .map(|parsed| parsed.media_descriptions.clone());

            if let Some(media_descriptions) = media_descriptions {
                if !we_offer {
                    for media in &media_descriptions {
                        let mid_value = match get_mid_value(media) {
                            Some(m) => {
                                if m.is_empty() {
                                    return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                                } else {
                                    m
                                }
                            }
                            None => continue,
                        };

                        if media.media_name.media == MEDIA_SECTION_APPLICATION {
                            continue;
                        }

                        let kind = RTPCodecType::from(media.media_name.media.as_str());
                        let direction = get_peer_direction(media);
                        if kind == RTPCodecType::Unspecified
                            || direction == RTCRtpTransceiverDirection::Unspecified
                        {
                            continue;
                        }

                        let t = if let Some(t) = find_by_mid(mid_value, &mut self.rtp_transceivers)
                        {
                            Some(t)
                        } else {
                            satisfy_type_and_direction(kind, direction, &mut self.rtp_transceivers)
                        };

                        if let Some(t) = t {
                            if t.mid.is_none() {
                                t.mid = Some(mid_value.to_string());
                            }
                        } else {
                            let local_direction =
                                if direction == RTCRtpTransceiverDirection::Recvonly {
                                    RTCRtpTransceiverDirection::Sendonly
                                } else {
                                    RTCRtpTransceiverDirection::Recvonly
                                };

                            let receive_mtu = self.configuration.setting_engine.get_receive_mtu();
                            let enable_sender_rtx =
                                self.configuration.setting_engine.enable_sender_rtx;

                            let receiver = RTCRtpReceiver::new(receive_mtu, kind);

                            let sender =
                                RTCRtpSender::new(kind, false, receive_mtu, enable_sender_rtx);

                            let mut t = RTCRtpTransceiver::new(
                                receiver,
                                sender,
                                local_direction,
                                kind,
                                vec![],
                            );

                            if t.mid.is_none() {
                                t.mid = Some(mid_value.to_string());
                            }

                            self.add_rtp_transceiver(t);
                        }
                    }
                } else {
                    // we_offer
                    // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                    // 4.5.9.2
                    // This is an answer from the remote.
                    for media in &media_descriptions {
                        let mid_value = match get_mid_value(media) {
                            Some(m) => {
                                if m.is_empty() {
                                    return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                                } else {
                                    m
                                }
                            }
                            None => continue,
                        };

                        if media.media_name.media == MEDIA_SECTION_APPLICATION {
                            continue;
                        }
                        let kind = RTPCodecType::from(media.media_name.media.as_str());
                        let direction = get_peer_direction(media);
                        if kind == RTPCodecType::Unspecified
                            || direction == RTCRtpTransceiverDirection::Unspecified
                        {
                            continue;
                        }

                        if let Some(t) = find_by_mid(mid_value, &mut self.rtp_transceivers) {
                            let previous_direction = t.current_direction;

                            // 4.5.9.2.9
                            // Let direction be an RTCRtpTransceiverDirection value representing the direction
                            // from the media description, but with the send and receive directions reversed to
                            // represent this peer's point of view. If the media description is rejected,
                            // set direction to "inactive".
                            let reversed_direction = direction.reverse();

                            // 4.5.9.2.13.2
                            // Set transceiver.[[CurrentDirection]] and transceiver.[[Direction]]s to direction.
                            t.set_current_direction(reversed_direction);
                            // TODO: According to the specification we should set
                            // transceiver.[[Direction]] here, however libWebrtc doesn't do this.
                            // NOTE: After raising this it seems like the specification might
                            // change to remove the setting of transceiver.[[Direction]].
                            // See https://github.com/w3c/webrtc-pc/issues/2751#issuecomment-1185901962
                            // t.set_direction_internal(reversed_direction);
                            t.process_new_current_direction(previous_direction)?;
                        }
                    }
                }
            }

            let (remote_ufrag, remote_pwd, candidates) =
                extract_ice_details(parsed_remote_description)?;

            if is_renegotiation
                && self
                    .ice_transport()
                    .have_remote_credentials_change(&remote_ufrag, &remote_pwd)
            {
                // An ICE Restart only happens implicitly for a set_remote_description of type offer
                let (local_ufrag, local_pwd, keep_local_candidates) = (
                    self.configuration
                        .setting_engine
                        .candidates
                        .username_fragment
                        .clone(),
                    self.configuration
                        .setting_engine
                        .candidates
                        .password
                        .clone(),
                    self.configuration
                        .setting_engine
                        .candidates
                        .keep_local_candidates_during_ice_restart,
                );
                if !we_offer {
                    self.ice_transport_mut().restart(
                        local_ufrag,
                        local_pwd,
                        keep_local_candidates,
                    )?;
                }

                self.ice_transport_mut()
                    .set_remote_credentials(remote_ufrag.clone(), remote_pwd.clone())?;
            }

            for candidate in candidates {
                self.ice_transport_mut().add_remote_candidate(candidate)?;
            }

            if !is_renegotiation {
                let remote_is_lite = is_lite_set(parsed_remote_description);

                let (remote_fingerprint, remote_fingerprint_hash) =
                    extract_fingerprint(parsed_remote_description)?;

                // If one of the agents is lite and the other one is not, the lite agent must be the controlling agent.
                // If both or neither agents are lite the offering agent is controlling.
                // RFC 8445 S6.1.1
                let local_ice_role = if (we_offer
                    && remote_is_lite == self.configuration.setting_engine.candidates.ice_lite)
                    || (remote_is_lite && !self.configuration.setting_engine.candidates.ice_lite)
                {
                    RTCIceRole::Controlling
                } else {
                    RTCIceRole::Controlled
                };

                let remote_dtls_role = DTLSRole::from(parsed_remote_description);
                log::trace!(
                    "start_transports: local_ice_role={local_ice_role}, remote_dtls_role={remote_dtls_role}"
                );
                // Start the ice transport
                self.ice_transport_mut().start(
                    local_ice_role,
                    RTCIceParameters {
                        username_fragment: remote_ufrag,
                        password: remote_pwd,
                        ice_lite: remote_is_lite,
                    },
                )?;

                // Start the dtls transport
                self.dtls_transport_mut().start(
                    local_ice_role,
                    DTLSParameters {
                        role: remote_dtls_role,
                        fingerprints: vec![RTCDtlsFingerprint {
                            algorithm: remote_fingerprint_hash,
                            value: remote_fingerprint,
                        }],
                    },
                )?;
            }

            if we_offer {
                if let Some(parsed_local_description) = self
                    .current_local_description
                    .as_ref()
                    .and_then(|desc| desc.parsed.as_ref())
                {
                    if let Some(remote_port) =
                        get_application_media_section_sctp_port(parsed_remote_description)
                    {
                        if let Some(local_port) =
                            get_application_media_section_sctp_port(parsed_local_description)
                        {
                            let max_message_size = get_application_media_section_max_message_size(
                                parsed_remote_description,
                            )
                            .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
                            let dtls_role = self.dtls_transport().role();

                            self.sctp_transport_mut().start(
                                dtls_role,
                                SCTPTransportCapabilities { max_message_size },
                                local_port,
                                remote_port,
                            )?;
                        }
                    }
                }

                self.start_rtp_senders()?;
                self.start_rtp(is_renegotiation, remote_description)?;
            }
        }

        Ok(())
    }

    /// remote_description returns pending_remote_description if it is not null and
    /// otherwise it returns current_remote_description. This property is used to
    /// determine if setRemoteDescription has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-remotedescription>
    pub fn remote_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_remote_description.is_some() {
            self.pending_remote_description.as_ref()
        } else {
            self.current_remote_description.as_ref()
        }
    }

    /// add_remote_candidate accepts a remote ICE candidate string and adds it
    /// to the existing set of remote candidates.
    pub fn add_remote_candidate(&mut self, remote_candidate: RTCIceCandidateInit) -> Result<()> {
        if self.remote_description().is_none() {
            return Err(Error::ErrNoRemoteDescription);
        }

        let candidate_value = match remote_candidate.candidate.strip_prefix("candidate:") {
            Some(s) => s,
            None => remote_candidate.candidate.as_str(),
        };

        if !candidate_value.is_empty() {
            let candidate: Candidate = unmarshal_candidate(candidate_value)?;

            self.ice_transport_mut().add_remote_candidate(candidate)?;
        }

        Ok(())
    }

    /// add_local_candidate accepts an ICE candidate string and adds it
    /// to the existing set of candidates.
    pub fn add_local_candidate(&mut self, local_candidate: RTCIceCandidateInit) -> Result<()> {
        let candidate_value = match local_candidate.candidate.strip_prefix("candidate:") {
            Some(s) => s,
            None => local_candidate.candidate.as_str(),
        };

        if !candidate_value.is_empty() {
            let candidate: Candidate = unmarshal_candidate(candidate_value)?;

            self.ice_transport_mut().add_local_candidate(candidate)?;
        }

        Ok(())
    }

    /// restart_ice restart ICE and triggers negotiation needed
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-restartice>
    pub fn restart_ice(&mut self) -> Result<()> {
        let (local_ufrag, local_pwd, keep_local_candidates) = (
            self.configuration
                .setting_engine
                .candidates
                .username_fragment
                .clone(),
            self.configuration
                .setting_engine
                .candidates
                .password
                .clone(),
            self.configuration
                .setting_engine
                .candidates
                .keep_local_candidates_during_ice_restart,
        );
        self.ice_transport_mut()
            .restart(local_ufrag, local_pwd, keep_local_candidates)?;
        self.trigger_negotiation_needed();
        Ok(())
    }

    /// get_configuration returns a Configuration object representing the current
    /// configuration of this PeerConnection object. The returned object is a
    /// copy and direct mutation on it will not take effect until set_configuration
    /// has been called with Configuration passed as its only argument.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getconfiguration>
    pub fn get_configuration(&self) -> &RTCConfiguration {
        &self.configuration
    }

    /// set_configuration updates the configuration of this PeerConnection object.
    pub fn set_configuration(&mut self, configuration: RTCConfiguration) -> Result<()> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setconfiguration (step #2)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #3)
        if !configuration.peer_identity.is_empty() {
            if configuration.peer_identity != self.configuration.peer_identity {
                return Err(Error::ErrModifyingPeerIdentity);
            }
            self.configuration.peer_identity = configuration.peer_identity;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #4)
        if !configuration.certificates.is_empty() {
            if configuration.certificates.len() != self.configuration.certificates.len() {
                return Err(Error::ErrModifyingCertificates);
            }

            self.configuration.certificates = configuration.certificates;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #5)

        if configuration.bundle_policy != self.configuration.bundle_policy {
            return Err(Error::ErrModifyingBundlePolicy);
        }
        self.configuration.bundle_policy = configuration.bundle_policy;

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #6)
        if configuration.rtcp_mux_policy != self.configuration.rtcp_mux_policy {
            return Err(Error::ErrModifyingRTCPMuxPolicy);
        }
        self.configuration.rtcp_mux_policy = configuration.rtcp_mux_policy;

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #7)
        if configuration.ice_candidate_pool_size != 0 {
            if self.configuration.ice_candidate_pool_size != configuration.ice_candidate_pool_size
                && self.local_description().is_some()
            {
                return Err(Error::ErrModifyingICECandidatePoolSize);
            }
            self.configuration.ice_candidate_pool_size = configuration.ice_candidate_pool_size;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #8)

        self.configuration.ice_transport_policy = configuration.ice_transport_policy;

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #11)
        if !configuration.ice_servers.is_empty() {
            // https://www.w3.org/TR/webrtc/#set-the-configuration (step #11.3)
            for server in &configuration.ice_servers {
                server.validate()?;
            }
            self.configuration.ice_servers = configuration.ice_servers
        }

        Ok(())
    }

    /// create_data_channel creates a new DataChannel object with the given label
    /// and optional DataChannelInit used to configure properties of the
    /// underlying channel such as data reliability.
    pub fn create_data_channel(
        &mut self,
        label: &str,
        options: Option<RTCDataChannelInit>,
    ) -> Result<RTCDataChannel<'_>> {
        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #2)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let mut params = DataChannelParameters {
            label: label.to_owned(),
            ..Default::default()
        };

        let mut id = {
            let mut id = rand::random::<u16>();
            while self.data_channels.contains_key(&id) {
                id = rand::random::<u16>();
            }
            id
        };

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #19)
        if let Some(options) = options {
            // Ordered indicates if data is allowed to be delivered out of order. The
            // default value of true, guarantees that data will be delivered in order.
            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #9)
            params.ordered = options.ordered;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #7)
            params.max_packet_life_time = Some(options.max_packet_life_time);

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #8)
            params.max_retransmits = Some(options.max_retransmits);

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #10)
            params.protocol = options.protocol;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #11)
            if params.protocol.len() > 65535 {
                return Err(Error::ErrProtocolTooLarge);
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #12)
            params.negotiated = options.negotiated;

            if let Some(negotiated_id) = &params.negotiated {
                id = *negotiated_id;
            }
        }

        let data_channel = RTCDataChannelInternal::new(
            params,
            //TODO: &self.configuration.setting_engine,
        );

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #16)
        if data_channel.max_packet_lifetime.is_some() && data_channel.max_retransmits.is_some() {
            return Err(Error::ErrRetransmitsOrPacketLifeTime);
        }

        self.data_channels.insert(id, data_channel);

        Ok(RTCDataChannel {
            id,
            peer_connection: self,
        })
    }

    pub fn data_channel(&mut self, id: RTCDataChannelId) -> Option<RTCDataChannel<'_>> {
        if self.data_channels.contains_key(&id) {
            Some(RTCDataChannel {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }
}
