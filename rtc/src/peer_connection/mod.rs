pub mod certificate;
pub mod configuration;
pub mod event;
pub(crate) mod handler;
mod internal;
pub mod message;
pub mod sdp;
pub mod state;
pub mod transport;

use crate::data_channel::init::RTCDataChannelInit;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::{RTCDataChannel, RTCDataChannelId, internal::RTCDataChannelInternal};
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::configuration::{
    RTCConfiguration,
    offer_answer_options::{RTCAnswerOptions, RTCOfferOptions},
};
use crate::peer_connection::handler::PipelineContext;
use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::sctp::SctpHandlerContext;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::sdp::{
    extract_fingerprint, extract_ice_details, get_application_media_section_max_message_size,
    get_application_media_section_sctp_port, get_mid_value, get_peer_direction, is_lite_set,
    sdp_type::RTCSdpType, update_sdp_origin,
};
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::peer_connection_state::{
    NegotiationNeededState, RTCPeerConnectionState,
};
use crate::peer_connection::state::signaling_state::{RTCSignalingState, StateChangeOp};
use crate::peer_connection::transport::dtls::RTCDtlsTransport;
use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::dtls::parameters::DTLSParameters;
use crate::peer_connection::transport::dtls::role::{
    DEFAULT_DTLS_ROLE_ANSWER, DEFAULT_DTLS_ROLE_OFFER, RTCDtlsRole,
};
use crate::peer_connection::transport::ice::RTCIceTransport;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidateInit;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::sctp::RTCSctpTransport;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::rtp_transceiver::rtp_sender::internal::RTCRtpSenderInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, encoding_parameters_fuzzy_search,
};
use crate::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiver, RTCRtpTransceiverId,
    RTCRtpTransceiverInit, find_by_mid, satisfy_type_and_direction,
};
use ::sdp::description::session::Origin;
use ::sdp::util::ConnectionRole;
use ice::candidate::{Candidate, unmarshal_candidate};
use sdp::MEDIA_SECTION_APPLICATION;
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;
use std::collections::HashMap;

/// The `RTCPeerConnection` interface represents a WebRTC connection between the local computer
/// and a remote peer. It provides methods to connect to a remote peer, maintain and monitor
/// the connection, and close the connection once it's no longer needed.
///
/// This is a sans-I/O implementation following the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/).
///
/// # Examples
///
/// ```no_run
/// use rtc::peer_connection::RTCPeerConnection;
/// use rtc::peer_connection::configuration::RTCConfiguration;
///
/// let config = RTCConfiguration::default();
/// let mut pc = RTCPeerConnection::new(config)?;
/// # Ok::<(), rtc::shared::error::Error>(())
/// ```
#[derive(Default)]
pub struct RTCPeerConnection {
    //////////////////////////////////////////////////
    // PeerConnection WebRTC Spec Interface Definition
    //////////////////////////////////////////////////
    pub(crate) configuration: RTCConfiguration,

    local_description: Option<RTCSessionDescription>,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    remote_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,

    pub(crate) signaling_state: RTCSignalingState,
    pub(crate) peer_connection_state: RTCPeerConnectionState,
    can_trickle_ice_candidates: bool,

    //////////////////////////////////////////////////
    // PeerConnection Internal State Machine
    //////////////////////////////////////////////////
    pub(crate) pipeline_context: PipelineContext,
    pub(crate) data_channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,
    pub(super) rtp_transceivers: Vec<RTCRtpTransceiver>,

    greater_mid: isize,
    sdp_origin: Origin,
    last_offer: String,
    last_answer: String,

    ice_restart_requested: Option<RTCOfferOptions>,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_ongoing: bool,
}

impl RTCPeerConnection {
    /// Creates a new `RTCPeerConnection` with the specified configuration.
    ///
    /// This constructor creates the necessary transport layers (ICE, DTLS, SCTP) and
    /// initializes the peer connection state machine.
    ///
    /// # Arguments
    ///
    /// * `configuration` - The configuration for the peer connection, including ICE servers,
    ///   certificates, and various settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or if transport initialization fails.
    ///
    /// # Specification
    ///
    /// See [RTCPeerConnection constructor](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-constructor)
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
            configuration.setting_engine.replay_protection,
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
            greater_mid: -1,
            ..Default::default()
        })
    }

    /// Creates an SDP offer to start a new WebRTC connection to a remote peer.
    ///
    /// The offer includes information about the attached media tracks, codecs and options supported
    /// by the browser, and ICE candidates gathered by the ICE agent. This offer can be sent to a
    /// remote peer over a signaling channel to establish a connection.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the offer, such as whether to restart ICE.
    ///
    /// # Returns
    ///
    /// Returns an `RTCSessionDescription` containing the SDP offer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - There's an error generating the SDP
    ///
    /// # Specification
    ///
    /// See [createOffer](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createoffer)
    pub fn create_offer(
        &mut self,
        mut options: Option<RTCOfferOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let is_ice_restart_requested = self
            .ice_restart_requested
            .take()
            .is_some_and(|options| options.ice_restart)
            || options.take().is_some_and(|options| options.ice_restart);

        if is_ice_restart_requested {
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
                !self
                    .configuration
                    .setting_engine
                    .candidates
                    .discard_local_candidates_during_ice_restart,
            );
            self.ice_transport_mut()
                .restart(local_ufrag, local_pwd, keep_local_candidates)?;
        }

        // include unmatched local transceivers
        // update the greater mid if the remote description provides a greater one
        if let Some(d) = self.current_remote_description.as_ref()
            && let Some(parsed) = &d.parsed
        {
            for media in &parsed.media_descriptions {
                if let Some(mid) = get_mid_value(media) {
                    if mid.is_empty() {
                        continue;
                    }
                    let numeric_mid = match mid.parse::<isize>() {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if numeric_mid > self.greater_mid {
                        self.greater_mid = numeric_mid;
                    }
                }
            }
            for transceiver in &mut self.rtp_transceivers {
                if let Some(mid) = transceiver.mid()
                    && !mid.is_empty()
                {
                    if let Ok(numeric_mid) = mid.parse::<isize>()
                        && numeric_mid > self.greater_mid
                    {
                        self.greater_mid = numeric_mid;
                    }

                    continue;
                }

                self.greater_mid += 1;
                transceiver.set_mid(format!("{}", self.greater_mid))?;
            }
        }

        let mut d = if self.current_remote_description.is_none() {
            self.generate_unmatched_sdp()?
        } else {
            self.generate_matched_sdp(
                true, /*includeUnmatched */
                DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
                false,
            )?
        };

        update_sdp_origin(&mut self.sdp_origin, &mut d);

        let sdp = d.marshal();

        let offer = RTCSessionDescription {
            sdp_type: RTCSdpType::Offer,
            sdp,
            parsed: Some(d),
        };

        self.last_offer.clone_from(&offer.sdp);

        Ok(offer)
    }

    /// Creates an SDP answer in response to an offer received from a remote peer.
    ///
    /// The answer includes information about any media already attached to the session,
    /// codecs and options supported by the browser, and ICE candidates gathered by the ICE agent.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the answer (currently unused).
    ///
    /// # Returns
    ///
    /// Returns an `RTCSessionDescription` containing the SDP answer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No remote description has been set
    /// - The peer connection is closed
    /// - The signaling state is not `have-remote-offer` or `have-local-pranswer`
    ///
    /// # Specification
    ///
    /// See [createAnswer](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createanswer)
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

            if let Some(remote_description) = self.remote_description()
                && let Some(parsed) = remote_description.parsed.as_ref()
                && is_lite_set(parsed)
                && !self.configuration.setting_engine.candidates.ice_lite
            {
                connection_role = RTCDtlsRole::Server.to_connection_role();
            }
        }

        let mut d = self.generate_matched_sdp(
            false, /*includeUnmatched */
            connection_role,
            self.configuration.setting_engine.ignore_rid_pause_for_recv,
        )?;

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

    /// Sets the local description as part of the offer/answer negotiation.
    ///
    /// This changes the local description associated with the connection. If the `sdp` field
    /// is empty, an implicit description will be created based on the type.
    ///
    /// # Arguments
    ///
    /// * `local_description` - The local session description to set.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - The SDP type is invalid
    /// - The SDP cannot be parsed
    ///
    /// # Specification
    ///
    /// See [setLocalDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setlocaldescription)
    pub fn set_local_description(
        &mut self,
        mut local_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

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
        if we_answer && let Some(parsed_local_description) = &local_description.parsed {
            // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
            // Section 4.4.1.5
            self.set_rtp_transceiver_current_direction(
                &parsed_local_description.media_descriptions,
                false,
            )?;

            if let Some(remote_description) = self.remote_description().cloned()
                && let Some(parsed_remote_description) = remote_description.parsed.as_ref()
            {
                if let Some(remote_port) =
                    get_application_media_section_sctp_port(parsed_remote_description)
                    && let Some(local_port) =
                        get_application_media_section_sctp_port(parsed_local_description)
                {
                    let max_message_size =
                        get_application_media_section_max_message_size(parsed_remote_description)
                            .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
                    let dtls_role = self.dtls_transport().role();

                    self.sctp_transport_mut().start(
                        dtls_role,
                        SCTPTransportCapabilities { max_message_size },
                        local_port,
                        remote_port,
                    )?;
                }

                self.start_rtp(remote_description)?;
            }
        }

        Ok(())
    }

    /// Returns the local session description.
    ///
    /// Returns `pending_local_description` if it is not null, otherwise returns
    /// `current_local_description`. This property is used to determine if
    /// `set_local_description` has already been called.
    ///
    /// # Specification
    ///
    /// See [localDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-localdescription)
    pub fn local_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_local_description.is_some() {
            self.pending_local_description.as_ref()
        } else {
            self.current_local_description.as_ref()
        }
    }

    /// Sets the remote description as part of the offer/answer negotiation.
    ///
    /// This changes the remote description associated with the connection. This description
    /// specifies the properties of the remote end of the connection, including the media format.
    ///
    /// # Arguments
    ///
    /// * `remote_description` - The remote session description to set.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - The SDP cannot be parsed
    /// - The media engine fails to update from the remote description
    ///
    /// # Specification
    ///
    /// See [setRemoteDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setremotedescription)
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

            // Disable RTX/FEC on RTPSenders if the remote didn't support it
            for transceiver in &mut self.rtp_transceivers {
                if let Some(sender) = transceiver.sender_mut() {
                    let (is_rtx_enabled, is_fec_enabled) = (
                        self.configuration
                            .media_engine
                            .is_rtx_enabled(sender.kind(), RTCRtpTransceiverDirection::Sendonly),
                        self.configuration
                            .media_engine
                            .is_fec_enabled(sender.kind(), RTCRtpTransceiverDirection::Sendonly),
                    );
                    sender.configure_rtx_and_fec(is_rtx_enabled, is_fec_enabled);
                }
            }

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
                            Some(m) if !m.is_empty() => m,
                            _ => return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue),
                        };

                        if media.media_name.media == MEDIA_SECTION_APPLICATION {
                            continue;
                        }

                        let kind = RtpCodecKind::from(media.media_name.media.as_str());
                        let direction = get_peer_direction(media);
                        if kind == RtpCodecKind::Unspecified
                            || direction == RTCRtpTransceiverDirection::Unspecified
                        {
                            continue;
                        }

                        let transceiver = if let Some(i) =
                            find_by_mid(mid_value, &self.rtp_transceivers)
                        {
                            if direction == RTCRtpTransceiverDirection::Inactive {
                                self.rtp_transceivers[i].stop();
                            }
                            Some(&mut self.rtp_transceivers[i])
                        } else {
                            satisfy_type_and_direction(kind, direction, &mut self.rtp_transceivers)
                        };

                        if let Some(transceiver) = transceiver {
                            if direction == RTCRtpTransceiverDirection::Recvonly {
                                if transceiver.direction() == RTCRtpTransceiverDirection::Sendrecv {
                                    transceiver.set_direction(RTCRtpTransceiverDirection::Sendonly);
                                } else if transceiver.direction()
                                    == RTCRtpTransceiverDirection::Recvonly
                                {
                                    transceiver.set_direction(RTCRtpTransceiverDirection::Inactive);
                                }
                            } else if direction == RTCRtpTransceiverDirection::Sendrecv {
                                if transceiver.direction() == RTCRtpTransceiverDirection::Sendonly {
                                    transceiver.set_direction(RTCRtpTransceiverDirection::Sendrecv);
                                } else if transceiver.direction()
                                    == RTCRtpTransceiverDirection::Inactive
                                {
                                    transceiver.set_direction(RTCRtpTransceiverDirection::Recvonly);
                                }
                            } else if direction == RTCRtpTransceiverDirection::Sendonly
                                && transceiver.direction() == RTCRtpTransceiverDirection::Inactive
                            {
                                transceiver.set_direction(RTCRtpTransceiverDirection::Recvonly);
                            }

                            transceiver.set_codec_preferences_from_remote_description(
                                media,
                                &self.configuration.media_engine,
                            )?;

                            if transceiver.mid().is_none() {
                                transceiver.set_mid(mid_value.to_string())?;
                            }
                        } else {
                            let local_direction =
                                if direction == RTCRtpTransceiverDirection::Recvonly {
                                    RTCRtpTransceiverDirection::Sendonly
                                } else {
                                    RTCRtpTransceiverDirection::Recvonly
                                };

                            let mut transceiver = RTCRtpTransceiver::new(
                                kind,
                                None,
                                RTCRtpTransceiverInit {
                                    direction: local_direction,
                                    streams: vec![],
                                    send_encodings: vec![],
                                },
                            );

                            transceiver.set_codec_preferences_from_remote_description(
                                media,
                                &self.configuration.media_engine,
                            )?;

                            if transceiver.mid().is_none() {
                                transceiver.set_mid(mid_value.to_string())?;
                            }

                            self.add_rtp_transceiver(transceiver);
                        }
                    }
                } else {
                    // we_offer
                    // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                    // 4.5.9.2
                    // This is an answer from the remote.
                    self.set_rtp_transceiver_current_direction(&media_descriptions, true)?;
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

                if !we_offer {
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
                        !self
                            .configuration
                            .setting_engine
                            .candidates
                            .discard_local_candidates_during_ice_restart,
                    );
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

                let remote_dtls_role = RTCDtlsRole::from(parsed_remote_description);
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

                self.update_connection_state(false);
            }

            if we_offer
                && let Some(parsed_local_description) = self
                    .current_local_description
                    .as_ref()
                    .and_then(|desc| desc.parsed.as_ref())
            {
                if let Some(remote_port) =
                    get_application_media_section_sctp_port(parsed_remote_description)
                    && let Some(local_port) =
                        get_application_media_section_sctp_port(parsed_local_description)
                {
                    let max_message_size =
                        get_application_media_section_max_message_size(parsed_remote_description)
                            .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
                    let dtls_role = self.dtls_transport().role();

                    self.sctp_transport_mut().start(
                        dtls_role,
                        SCTPTransportCapabilities { max_message_size },
                        local_port,
                        remote_port,
                    )?;
                }

                self.start_rtp(remote_description)?;
            }
        }

        Ok(())
    }

    /// Returns the remote session description.
    ///
    /// Returns `pending_remote_description` if it is not null, otherwise returns
    /// `current_remote_description`. This property is used to determine if
    /// `set_remote_description` has already been called.
    ///
    /// # Specification
    ///
    /// See [remoteDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-remotedescription)
    pub fn remote_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_remote_description.is_some() {
            self.pending_remote_description.as_ref()
        } else {
            self.current_remote_description.as_ref()
        }
    }

    /// Adds a remote ICE candidate to the peer connection.
    ///
    /// This method provides a remote candidate to the ICE agent. When the remote peer
    /// gathers ICE candidates and sends them over the signaling channel, this method
    /// should be called to add each candidate.
    ///
    /// # Arguments
    ///
    /// * `remote_candidate` - The ICE candidate initialization data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No remote description has been set
    /// - The candidate string is invalid
    ///
    /// # Specification
    ///
    /// See [addIceCandidate](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addicecandidate)
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

    /// Adds a local ICE candidate to the peer connection.
    ///
    /// This method adds a locally gathered ICE candidate. In a typical implementation,
    /// local candidates are generated by the ICE agent and passed to this method.
    ///
    /// # Arguments
    ///
    /// * `local_candidate` - The ICE candidate initialization data.
    ///
    /// # Errors
    ///
    /// Returns an error if the candidate string is invalid.
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

    /// Tells the peer connection that ICE should be restarted.
    ///
    /// This method causes the next call to `create_offer` to generate an offer that
    /// will restart ICE. This is useful when network conditions change or the connection
    /// fails.
    ///
    /// # Specification
    ///
    /// See [restartIce](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-restartice)
    pub fn restart_ice(&mut self) {
        self.ice_restart_requested = Some(RTCOfferOptions { ice_restart: true });
    }

    /// Returns the current configuration of this peer connection.
    ///
    /// The returned reference is to the current configuration. To modify the configuration,
    /// use `set_configuration`.
    ///
    /// # Specification
    ///
    /// See [getConfiguration](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getconfiguration)
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

        let mut id = self.generate_data_channel_id()?;

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #19)
        if let Some(options) = options {
            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #16)
            if options.max_packet_life_time.is_some() && options.max_retransmits.is_some() {
                return Err(Error::ErrRetransmitsOrPacketLifeTime);
            }

            // Ordered indicates if data is allowed to be delivered out of order. The
            // default value of true, guarantees that data will be delivered in order.
            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #9)
            params.ordered = options.ordered;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #7)
            params.max_packet_life_time = options.max_packet_life_time;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #8)
            params.max_retransmits = options.max_retransmits;

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

        let data_channel = RTCDataChannelInternal::new(id, params);

        self.data_channels.insert(id, data_channel);

        self.trigger_negotiation_needed();

        Ok(RTCDataChannel {
            id,
            peer_connection: self,
        })
    }

    /// Returns an iterator over the `RTCRtpSender` objects.
    ///
    /// The `RTCRtpSender` objects represent the media streams that are being sent
    /// to the remote peer.
    ///
    /// # Specification
    ///
    /// See [getSenders](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getsenders)
    pub fn get_senders(&self) -> impl Iterator<Item = RTCRtpSenderId> + use<'_> {
        self.rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, transceiver)| transceiver.direction().has_send())
            .map(|(id, _)| RTCRtpSenderId(id))
    }

    /// Returns an iterator over the `RTCRtpReceiver` objects.
    ///
    /// The `RTCRtpReceiver` objects represent the media streams that are being received
    /// from the remote peer.
    ///
    /// # Specification
    ///
    /// See [getReceivers](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getreceivers)
    pub fn get_receivers(&self) -> impl Iterator<Item = RTCRtpReceiverId> + use<'_> {
        self.rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, transceiver)| transceiver.direction().has_recv())
            .map(|(id, _)| RTCRtpReceiverId(id))
    }

    /// Returns an iterator over the `RTCRtpTransceiver` objects.
    ///
    /// The `RTCRtpTransceiver` objects represent the combination of an `RTCRtpSender`
    /// and an `RTCRtpReceiver` that share a common mid.
    ///
    /// # Specification
    ///
    /// See [getTransceivers](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-gettransceivers)
    pub fn get_transceivers(&self) -> impl Iterator<Item = RTCRtpTransceiverId> {
        0..self.rtp_transceivers.len()
    }

    /// Adds a media track to the peer connection.
    ///
    /// This method adds a track to the connection, either by finding an existing transceiver
    /// that can be reused, or by creating a new transceiver. The track represents media
    /// (audio or video) that will be sent to the remote peer.
    ///
    /// # Arguments
    ///
    /// * `track` - The media stream track to add.
    ///
    /// # Returns
    ///
    /// Returns the ID of the `RTCRtpSender` that will send this track.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer connection is closed.
    ///
    /// # Specification
    ///
    /// See [addTrack](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtrack)
    pub fn add_track(&mut self, track: MediaStreamTrack) -> Result<RTCRtpSenderId> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let send_encodings = self.send_encodings_from_track(&track);
        for (id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            if !transceiver.stopped()
                && transceiver.kind() == track.kind()
                && transceiver.sender().is_none()
            {
                let mut sender =
                    RTCRtpSenderInternal::new(track.kind(), track, vec![], send_encodings);

                sender.set_codec_preferences(transceiver.get_codec_preferences().to_vec());

                transceiver.sender_mut().replace(sender);

                transceiver.set_direction(RTCRtpTransceiverDirection::from_send_recv(
                    true,
                    transceiver.direction().has_recv(),
                ));

                self.trigger_negotiation_needed();
                return Ok(RTCRtpSenderId(id));
            }
        }

        let transceiver = self.new_transceiver_from_track(
            track,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings,
            },
        )?;
        Ok(RTCRtpSenderId(self.add_rtp_transceiver(transceiver)))
    }

    /// Removes a track from the peer connection.
    ///
    /// This method stops an `RTCRtpSender` from sending media and marks its transceiver
    /// as no longer sending. This will trigger renegotiation.
    ///
    /// # Arguments
    ///
    /// * `sender_id` - The ID of the `RTCRtpSender` to remove.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - The sender ID is invalid
    ///
    /// # Specification
    ///
    /// See [removeTrack](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-removetrack)
    pub fn remove_track(&mut self, sender_id: RTCRtpSenderId) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        if sender_id.0 >= self.rtp_transceivers.len() {
            return Err(Error::ErrRTPSenderNotExisted);
        }

        // This also happens in `set_sending_track` but we need to make sure we do this
        // before we call sender.stop to avoid a race condition when removing tracks and
        // generating offers.
        let has_recv = self.rtp_transceivers[sender_id.0].direction().has_recv();
        self.rtp_transceivers[sender_id.0]
            .set_direction(RTCRtpTransceiverDirection::from_send_recv(false, has_recv));

        if let Some(sender) = self.rtp_transceivers[sender_id.0].sender_mut()
            && sender.stop().is_ok()
        {
            self.trigger_negotiation_needed();
        }

        self.rtp_transceivers[sender_id.0].sender_mut().take();

        Ok(())
    }

    /// Creates a new `RTCRtpTransceiver` and adds it to the set of transceivers.
    ///
    /// This method creates a transceiver associated with the given track, which can be
    /// configured to send, receive, or both.
    ///
    /// # Arguments
    ///
    /// * `track` - The media stream track to associate with the transceiver.
    /// * `init` - Optional initialization parameters for the transceiver.
    ///
    /// # Returns
    ///
    /// Returns the ID of the created transceiver.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer connection is closed.
    ///
    /// # Specification
    ///
    /// See [addTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtransceiver)
    pub fn add_transceiver_from_track(
        &mut self,
        track: MediaStreamTrack,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<RTCRtpTransceiverId> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        if let Some(init) = init.as_ref()
            && !init.direction.has_send()
        {
            return Err(Error::ErrInvalidDirection);
        }

        let transceiver = self.new_transceiver_from_track(
            track,
            if let Some(init) = init {
                init
            } else {
                RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendrecv,
                    streams: vec![],
                    send_encodings: vec![],
                }
            },
        )?;

        Ok(self.add_rtp_transceiver(transceiver))
    }

    /// add_transceiver_from_kind Create a new RtpTransceiver and adds it to the set of transceivers.
    pub fn add_transceiver_from_kind(
        &mut self,
        kind: RtpCodecKind,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<RTCRtpTransceiverId> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let (direction, streams, send_encodings) = if let Some(init) = init {
            if init.direction.has_send() && init.send_encodings.is_empty() {
                return Err(Error::ErrInvalidDirection);
            }

            (init.direction, init.streams, init.send_encodings)
        } else {
            (RTCRtpTransceiverDirection::Recvonly, vec![], vec![])
        };

        let transceiver = match direction {
            RTCRtpTransceiverDirection::Sendonly | RTCRtpTransceiverDirection::Sendrecv => {
                let codecs = self.configuration.media_engine.get_codecs_by_kind(kind);
                let (encoding, code_match_result) =
                    encoding_parameters_fuzzy_search(&send_encodings, &codecs);
                if code_match_result != CodecMatch::None {
                    if encoding.rtp_coding_parameters.rid.is_empty()
                        && encoding.rtp_coding_parameters.ssrc.is_none()
                    {
                        return Err(Error::ErrRTPSenderNoBaseEncoding);
                    }

                    let track = MediaStreamTrack::new(
                        math_rand_alpha(16), // MediaStreamId
                        math_rand_alpha(16), // MediaStreamTrackId
                        math_rand_alpha(16), // Label
                        kind,
                        if encoding.rtp_coding_parameters.rid.is_empty() {
                            None
                        } else {
                            Some(encoding.rtp_coding_parameters.rid)
                        },
                        if let Some(ssrc) = encoding.rtp_coding_parameters.ssrc {
                            ssrc
                        } else {
                            rand::random::<u32>()
                        },
                        encoding.codec,
                    );
                    self.new_transceiver_from_track(
                        track,
                        RTCRtpTransceiverInit {
                            direction,
                            streams,
                            send_encodings,
                        },
                    )?
                } else {
                    return Err(Error::ErrRTPSenderNoBaseEncoding);
                }
            }
            RTCRtpTransceiverDirection::Recvonly => RTCRtpTransceiver::new(
                kind,
                None,
                RTCRtpTransceiverInit {
                    direction,
                    streams: vec![],
                    send_encodings: vec![],
                },
            ),
            _ => return Err(Error::ErrPeerConnAddTransceiverFromKindSupport),
        };

        Ok(self.add_rtp_transceiver(transceiver))
    }

    /// data_channel provides the access to RTCDataChannel object with the given id
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

    /// rtp_sender provides the access to RTCRtpSender object with the given id
    pub fn rtp_sender(&mut self, id: RTCRtpSenderId) -> Option<RTCRtpSender<'_>> {
        if id.0 < self.rtp_transceivers.len() {
            Some(RTCRtpSender {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// rtp_receiver provides the access to RTCRtpReceiver object with the given id
    pub fn rtp_receiver(&mut self, id: RTCRtpReceiverId) -> Option<RTCRtpReceiver<'_>> {
        if id.0 < self.rtp_transceivers.len() {
            Some(RTCRtpReceiver {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }
}
