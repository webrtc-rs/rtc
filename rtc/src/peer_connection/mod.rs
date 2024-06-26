/*TODO:#[cfg(test)]
pub(crate) mod peer_connection_test;
*/
pub mod certificate;
pub mod configuration;
pub mod offer_answer_options;
/*
pub(crate) mod operation;
mod peer_connection_internal;
*/
pub mod peer_connection_state;
pub mod policy;
pub mod sdp;
pub mod signaling_state;

use ::sdp::description::session::{Origin, ATTR_KEY_ICELITE};
use rcgen::KeyPair;
use shared::error::{Error, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
/*
use ::ice::candidate::candidate_base::unmarshal_candidate;
use ::ice::candidate::Candidate;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use interceptor::{stats, Attributes, Interceptor, RTCPWriter};
use peer_connection_internal::*;*/
use ::sdp::util::ConnectionRole;
use ::sdp::SessionDescription;
use ice::candidate::unmarshal_candidate;
use rand::{thread_rng, Rng};
//use srtp::stream::Stream;

use crate::api::media_engine::MediaEngine;
use crate::api::setting_engine::SettingEngine;
use crate::api::API;
use crate::data_channel::data_channel_init::RTCDataChannelInit;
use crate::data_channel::data_channel_parameters::DataChannelParameters;
use crate::data_channel::RTCDataChannel;
use crate::handler::demuxer::Demuxer;
/*
use crate::transports::data_channel::data_channel_init::RTCDataChannelInit;
use crate::transports::data_channel::data_channel_parameters::DataChannelParameters;
use crate::transports::data_channel::data_channel_state::RTCDataChannelState;
use crate::transports::data_channel::RTCDataChannel;
use crate::transports::dtls_transport::dtls_fingerprint::RTCDtlsFingerprint;
use crate::transports::dtls_transport::dtls_parameters::DTLSParameters;
*/
use crate::transport::dtls_transport::dtls_role::{
    DTLSRole, DEFAULT_DTLS_ROLE_ANSWER, DEFAULT_DTLS_ROLE_OFFER,
};
/*use crate::transports::dtls_transport::dtls_transport_state::RTCDtlsTransportState;
use shared::error::{flatten_errs, Error, Result};
//use crate::transports::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};*/
use crate::transport::ice_transport::ice_connection_state::RTCIceConnectionState;
/*use crate::transports::ice_transport::ice_gatherer::{
    OnGatheringCompleteHdlrFn, OnICEGathererStateChangeHdlrFn, OnLocalCandidateHdlrFn,
    RTCIceGatherOptions, RTCIceGatherer,
};
use crate::transports::ice_transport::ice_gatherer_state::RTCIceGathererState;
use crate::transports::ice_transport::ice_gathering_state::RTCIceGatheringState;
use crate::transports::ice_transport::ice_parameters::RTCIceParameters;
use crate::transports::ice_transport::ice_role::RTCIceRole;
use crate::transports::ice_transport::ice_transport_state::RTCIceTransportState;
*/
use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::configuration::RTCConfiguration;
use crate::peer_connection::offer_answer_options::{RTCAnswerOptions, RTCOfferOptions};
//use crate::peer_connection::offer_answer_options::{RTCAnswerOptions, RTCOfferOptions};
//use crate::peer_connection::operation::{Operation, Operations};
use crate::peer_connection::peer_connection_state::{
    NegotiationNeededState, RTCPeerConnectionState,
};
use crate::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use crate::peer_connection::sdp::sdp_type::RTCSdpType;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::sdp::{
    extract_fingerprint, extract_ice_details, get_mid_value, get_peer_direction, get_rids,
    update_sdp_origin, MediaSection, PopulateSdpParams,
};
use crate::peer_connection::sdp::{populate_local_candidates, populate_sdp};
//use crate::peer_connection::sdp::*;
use crate::peer_connection::signaling_state::{
    check_next_signaling_state, RTCSignalingState, StateChangeOp,
};
use crate::rtp_transceiver::rtp_codec::RTPCodecType;
use crate::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::{find_by_mid, satisfy_type_and_direction, Mid, RTCRtpTransceiver};
//use crate::rtp_transceiver::rtp_codec::RTPCodecType;
//use crate::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use crate::transport::dtls_transport::RTCDtlsTransport;
use crate::transport::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use crate::transport::ice_transport::ice_gatherer_state::RTCIceGathererState;
use crate::transport::ice_transport::ice_gathering_state::RTCIceGatheringState;
use crate::transport::ice_transport::ice_role::RTCIceRole;
use crate::transport::ice_transport::{
    ice_gatherer::{RTCIceGatherOptions, RTCIceGatherer},
    RTCIceTransport,
};
use crate::transport::sctp_transport::sctp_transport_state::RTCSctpTransportState;
use crate::transport::sctp_transport::RTCSctpTransport;

//use crate::transport::sctp_transport::RTCSctpTransport;
/*use crate::rtp_transceiver::rtp_codec::{RTCRtpHeaderExtensionCapability, RTPCodecType};
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::{
    find_by_mid, handle_unknown_rtp_packet, satisfy_type_and_direction, RTCRtpTransceiver,
    RTCRtpTransceiverInit, SSRC,
};
use crate::transports::sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities;
use crate::transports::sctp_transport::sctp_transport_state::RTCSctpTransportState;
use crate::transports::sctp_transport::RTCSctpTransport;
use crate::stats::StatsReport;
use crate::track::track_local::TrackLocal;
use crate::track::track_remote::TrackRemote;
*/
/// SIMULCAST_PROBE_COUNT is the amount of RTP Packets
/// that handleUndeclaredSSRC will read and try to dispatch from
/// mid and rid values
pub(crate) const SIMULCAST_PROBE_COUNT: usize = 10;

/// SIMULCAST_MAX_PROBE_ROUTINES is how many active routines can be used to probe
/// If the total amount of incoming SSRCes exceeds this new requests will be ignored
pub(crate) const SIMULCAST_MAX_PROBE_ROUTINES: u64 = 25;

pub(crate) const MEDIA_SECTION_APPLICATION: &str = "application";

const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
pub fn math_rand_alpha(n: usize) -> String {
    let mut rng = thread_rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.gen_range(0..RUNES_ALPHA.len());
            RUNES_ALPHA[idx] as char
        })
        .collect();

    rand_string
}

pub enum PeerConnectionEvent {
    // Peer-to-peer connections
    OnNegotiationNeeded,
    OnIceCandidate,
    OnIceCandidateError,
    OnSignalingStateChange(RTCSignalingState),
    OnIceConnectionStateChange(RTCIceConnectionState),
    OnIceGatheringStateChane,
    OnPeerConnectionStateChange(RTCPeerConnectionState),
    // RTP Media API
    OnTrack,
    // Peer-to-peer Data API
    OnDataChannel,
}

/*
#[derive(Clone)]
struct StartTransportsParams {
    ice_transport: RTCIceTransport,
    dtls_transport: Arc<RTCDtlsTransport>,
    on_peer_connection_state_change_handler: Arc<Mutex<Option<OnPeerConnectionStateChangeHdlrFn>>>,
    is_closed: Arc<AtomicBool>,
    peer_connection_state: Arc<AtomicU8>,
    ice_connection_state: Arc<AtomicU8>,
}

#[derive(Clone)]
struct CheckNegotiationNeededParams {
    sctp_transport: Arc<RTCSctpTransport>,
    rtp_transceivers: Arc<Mutex<Vec<Arc<RTCRtpTransceiver>>>>,
    current_local_description: Arc<Mutex<Option<RTCSessionDescription>>>,
    current_remote_description: Arc<Mutex<Option<RTCSessionDescription>>>,
}*/

#[derive(Clone)]
struct NegotiationNeededParams {
    is_closed: bool,
    //TODO:ops: Arc<Operations>,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_needed: bool,
    signaling_state: RTCSignalingState,
    //TODO:check_negotiation_needed_params: CheckNegotiationNeededParams,
}
/// PeerConnection represents a WebRTC connection that establishes a
/// peer-to-peer communications with another PeerConnection instance in a
/// browser, or to another endpoint implementing the required protocols.
pub struct RTCPeerConnection {
    pub(super) sdp_origin: Origin,
    pub(crate) configuration: RTCConfiguration,
    pub(super) is_closed: bool,
    pub(super) is_negotiation_needed: bool,
    pub(super) negotiation_needed_state: NegotiationNeededState,
    pub(super) last_offer: String,
    pub(super) last_answer: String,
    pub(super) signaling_state: RTCSignalingState,
    pub(super) peer_connection_state: RTCPeerConnectionState,
    pub(super) ice_connection_state: RTCIceConnectionState,
    pub(super) current_local_description: Option<RTCSessionDescription>,
    pub(super) current_remote_description: Option<RTCSessionDescription>,
    pub(super) pending_local_description: Option<RTCSessionDescription>,
    pub(super) pending_remote_description: Option<RTCSessionDescription>,

    pub(super) demuxer: Demuxer,
    pub(super) ice_transport: RTCIceTransport,
    pub(super) dtls_transport: RTCDtlsTransport,
    pub(super) sctp_transport: RTCSctpTransport,
    /// ops is an operations queue which will ensure the enqueued actions are
    /// executed in order. It is used for asynchronously, but serially processing
    /// remote and local descriptions
    //TODO:pub(crate) ops: Arc<Operations>,
    pub(super) rtp_transceivers: Vec<RTCRtpTransceiver>,
    /*pub(super) ice_gatherer: Arc<RTCIceGatherer>,
    interceptor_rtcp_writer: Arc<dyn RTCPWriter + Send + Sync>,
    interceptor: Arc<dyn Interceptor + Send + Sync>,
    pub(super) interceptor: Weak<dyn Interceptor + Send + Sync>,
    stats_interceptor: Arc<stats::StatsInterceptor>,*/
    pub(crate) stats_id: String,
    /// a value containing the last known greater mid value
    /// we internally generate mids as numbers. Needed since JSEP
    /// requires that when reusing a media section a new unique mid
    /// should be defined (see JSEP 3.4.1).
    pub(super) greater_mid: isize,
    /// A reference to the associated API state used by this connection
    pub(super) setting_engine: Arc<SettingEngine>,
    pub(crate) media_engine: MediaEngine,

    pub(crate) events: VecDeque<PeerConnectionEvent>,
}

impl std::fmt::Debug for RTCPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RTCPeerConnection")
            .field("stats_id", &self.stats_id)
            .field("signaling_state", &self.signaling_state)
            .field("ice_connection_state", &self.ice_connection_state)
            .finish()
    }
}

impl std::fmt::Display for RTCPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(RTCPeerConnection {})", self.stats_id)
    }
}

impl RTCPeerConnection {
    /// creates a PeerConnection with the default codecs and
    /// interceptors.  See register_default_codecs and register_default_interceptors.
    ///
    /// If you wish to customize the set of available codecs or the set of
    /// active interceptors, create a MediaEngine and call api.new_peer_connection
    /// instead of this function.
    pub(crate) fn new(api: &API, mut configuration: RTCConfiguration) -> Result<Self> {
        RTCPeerConnection::init_configuration(&mut configuration)?;

        // Create the demuxer
        let demuxer = Demuxer::new();

        // Create the ICE transport
        let ice_gatherer = Self::new_ice_gatherer(
            RTCIceGatherOptions {
                ice_servers: configuration.get_ice_servers(),
                ice_gather_policy: configuration.ice_transport_policy,
            },
            &api.setting_engine,
        )?;
        let ice_transport = Self::new_ice_transport(ice_gatherer);

        // Create the DTLS transport
        let certificates = configuration.certificates.drain(..).collect();
        let dtls_transport = Self::new_dtls_transport(certificates, &api.setting_engine)?;

        // Create the SCTP transport
        let sctp_transport = Self::new_sctp_transport(&api.setting_engine)?;

        // <https://w3c.github.io/webrtc-pc/#constructor> (Step #2)
        // Some variables defined explicitly despite their implicit zero values to
        // allow better readability to understand what is happening.
        Ok(RTCPeerConnection {
            sdp_origin: Default::default(),
            stats_id: format!(
                "PeerConnection-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),

            configuration,

            is_closed: false,
            greater_mid: -1,

            negotiation_needed_state: NegotiationNeededState::Empty,
            last_offer: "".to_string(),
            last_answer: "".to_string(),
            signaling_state: RTCSignalingState::Stable,
            ice_connection_state: RTCIceConnectionState::New,
            current_local_description: None,
            current_remote_description: None,
            pending_local_description: None,
            pending_remote_description: None,
            peer_connection_state: RTCPeerConnectionState::New,

            setting_engine: api.setting_engine.clone(),
            media_engine: api.media_engine.clone(),
            is_negotiation_needed: false,

            events: Default::default(),

            demuxer,
            ice_transport,
            dtls_transport,
            sctp_transport,
            rtp_transceivers: vec![],
        })
    }

    /// init_configuration defines validation of the specified Configuration and
    /// its assignment to the internal configuration variable. This function differs
    /// from its set_configuration counterpart because most of the checks do not
    /// include verification statements related to the existing state. Thus the
    /// function describes only minor verification of some the struct variables.
    fn init_configuration(configuration: &mut RTCConfiguration) -> Result<()> {
        let sanitized_ice_servers = configuration.get_ice_servers();
        if !sanitized_ice_servers.is_empty() {
            for server in &sanitized_ice_servers {
                server.validate()?;
            }
        }

        // TODO: <https://www.w3.org/TR/webrtc/#constructor> (step #2):
        // Let connection have a [[DocumentOrigin]] internal slot,
        // initialized to the relevant settings object's origin.

        // <https://www.w3.org/TR/webrtc/#constructor> (step #5)
        if !configuration.certificates.is_empty() {
            // If the value of certificate.expires is less than the current time,
            // throw an InvalidAccessError.
            let now = SystemTime::now();
            for cert in &configuration.certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }

            //TODO: If certificate.[[Origin]] is not same origin with connection.[[DocumentOrigin]],
            // throw an InvalidAccessError.
        } else {
            // (step #6) Else, generate one or more new RTCCertificate instances with this RTCPeerConnection
            // instance and store them. This MAY happen asynchronously and the value of certificates
            // remains undefined for the subsequent steps. As noted in Section 4.3.2.3 of [RFC8826],
            // WebRTC utilizes self-signed rather than Public Key Infrastructure (PKI) certificates,
            // so that the expiration check is to ensure that keys are not used indefinitely and
            // additional certificate checks are unnecessary.
            let kp = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = RTCCertificate::from_key_pair(kp)?;
            configuration.certificates = vec![cert];
        };

        Ok(())
    }

    fn do_negotiation_needed_inner(params: &mut NegotiationNeededParams) -> bool {
        // https://w3c.github.io/webrtc-pc/#updating-the-negotiation-needed-flag
        // non-canon step 1

        if params.negotiation_needed_state == NegotiationNeededState::Run {
            params.negotiation_needed_state = NegotiationNeededState::Queue;
            false
        } else if params.negotiation_needed_state == NegotiationNeededState::Queue {
            false
        } else {
            params.negotiation_needed_state = NegotiationNeededState::Run;
            true
        }
    }

    /*
    /// do_negotiation_needed enqueues negotiation_needed_op if necessary
    /// caller of this method should hold `pc.mu` lock
    fn do_negotiation_needed(mut params: NegotiationNeededParams) {
        if !RTCPeerConnection::do_negotiation_needed_inner(&mut params) {
            return;
        }

        let params2 = params.clone();
        let _ = params
            .ops
            .enqueue(Operation::new(
                move || {
                    let params3 = params2.clone();
                    Box::pin(async move { RTCPeerConnection::negotiation_needed_op(params3).await })
                },
                "do_negotiation_needed",
            ));
    }


    async fn after_negotiation_needed_op(params: NegotiationNeededParams) -> bool {
        let old_negotiation_needed_state = params.negotiation_needed_state.load(Ordering::SeqCst);

        params
            .negotiation_needed_state
            .store(NegotiationNeededState::Empty as u8, Ordering::SeqCst);

        if old_negotiation_needed_state == NegotiationNeededState::Queue as u8 {
            RTCPeerConnection::do_negotiation_needed_inner(&params)
        } else {
            false
        }
    }

    async fn negotiation_needed_op(params: NegotiationNeededParams) -> bool {
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
    }

    async fn check_negotiation_needed(params: &CheckNegotiationNeededParams) -> bool {
        // To check if negotiation is needed for connection, perform the following checks:
        // Skip 1, 2 steps
        // Step 3
        let current_local_description = {
            let current_local_description = params.current_local_description.lock().await;
            current_local_description.clone()
        };
        let current_remote_description = {
            let current_remote_description = params.current_remote_description.lock().await;
            current_remote_description.clone()
        };

        if let Some(local_desc) = &current_local_description {
            let len_data_channel = {
                let data_channels = params.sctp_transport.data_channels.lock().await;
                data_channels.len()
            };

            if len_data_channel != 0 && have_data_channel(local_desc).is_none() {
                return true;
            }

            let transceivers = params.rtp_transceivers.lock().await;
            for t in &*transceivers {
                // https://www.w3.org/TR/webrtc/#dfn-update-the-negotiation-needed-flag
                // Step 5.1
                // if t.stopping && !t.stopped {
                // 	return true
                // }
                let mid = t.mid();
                let m = mid
                    .as_ref()
                    .and_then(|mid| get_by_mid(mid.as_str(), local_desc));
                // Step 5.2
                if !t.stopped.load(Ordering::SeqCst) {
                    if m.is_none() {
                        return true;
                    }

                    if let Some(m) = m {
                        // Step 5.3.1
                        if t.direction().has_send() {
                            let dmsid = match m.attribute(ATTR_KEY_MSID).and_then(|o| o) {
                                Some(m) => m,
                                None => return true, // doesn't contain a single a=msid line
                            };

                            let sender = t.sender().await;
                            // (...)or the number of MSIDs from the a=msid lines in this m= section,
                            // or the MSID values themselves, differ from what is in
                            // transceiver.sender.[[AssociatedMediaStreamIds]], return true.

                            // TODO: This check should be robuster by storing all streams in the
                            // local description so we can compare all of them. For no we only
                            // consider the first one.

                            let stream_ids = sender.associated_media_stream_ids();
                            // Different number of lines, 1 vs 0
                            if stream_ids.is_empty() {
                                return true;
                            }

                            // different stream id
                            if dmsid.split_whitespace().next() != Some(&stream_ids[0]) {
                                return true;
                            }
                        }
                        match local_desc.sdp_type {
                            RTCSdpType::Offer => {
                                // Step 5.3.2
                                if let Some(remote_desc) = &current_remote_description {
                                    if let Some(rm) = t
                                        .mid()
                                        .and_then(|mid| get_by_mid(mid.as_str(), remote_desc))
                                    {
                                        if get_peer_direction(m) != t.direction()
                                            && get_peer_direction(rm) != t.direction().reverse()
                                        {
                                            return true;
                                        }
                                    } else {
                                        return true;
                                    }
                                }
                            }
                            RTCSdpType::Answer => {
                                let remote_desc = match &current_remote_description {
                                    Some(d) => d,
                                    None => return true,
                                };
                                let offered_direction = match t
                                    .mid()
                                    .and_then(|mid| get_by_mid(mid.as_str(), remote_desc))
                                {
                                    Some(d) => {
                                        let dir = get_peer_direction(d);
                                        if dir == RTCRtpTransceiverDirection::Unspecified {
                                            RTCRtpTransceiverDirection::Inactive
                                        } else {
                                            dir
                                        }
                                    }
                                    None => RTCRtpTransceiverDirection::Inactive,
                                };

                                let current_direction = get_peer_direction(m);
                                // Step 5.3.3
                                if current_direction
                                    != t.direction().intersect(offered_direction.reverse())
                                {
                                    return true;
                                }
                            }
                            _ => {}
                        };
                    }
                }
                // Step 5.4
                if t.stopped.load(Ordering::SeqCst) {
                    let search_mid = match t.mid() {
                        Some(mid) => mid,
                        None => return false,
                    };

                    if let Some(remote_desc) = &*params.current_remote_description.lock().await {
                        return get_by_mid(search_mid.as_str(), local_desc).is_some()
                            || get_by_mid(search_mid.as_str(), remote_desc).is_some();
                    }
                }
            }
            // Step 6
            false
        } else {
            true
        }
    }


    fn do_track(
        on_track_handler: Arc<ArcSwapOption<Mutex<OnTrackHdlrFn>>>,
        track: Arc<TrackRemote>,
        receiver: Arc<RTCRtpReceiver>,
        transceiver: Arc<RTCRtpTransceiver>,
    ) {
        log::debug!("got new track: {:?}", track);

        tokio::spawn(async move {
            if let Some(handler) = &*on_track_handler.load() {
                let mut f = handler.lock().await;
                f(track, receiver, transceiver).await;
            } else {
                log::warn!("on_track unset, unable to handle incoming media streams");
            }
        });
    }*/

    /// 4.4.1.3 Update the connection state
    fn update_peer_connection_state_change(&mut self, new_state: RTCPeerConnectionState) {
        self.peer_connection_state = new_state;
        self.events
            .push_back(PeerConnectionEvent::OnPeerConnectionStateChange(new_state));
    }

    fn update_signaling_state_change(&mut self, new_state: RTCSignalingState) {
        self.signaling_state = new_state;
        self.events
            .push_back(PeerConnectionEvent::OnSignalingStateChange(new_state));
    }

    fn update_ice_connection_state_change(&mut self, new_state: RTCIceConnectionState) {
        self.ice_connection_state = new_state;
        self.events
            .push_back(PeerConnectionEvent::OnIceConnectionStateChange(new_state));
    }

    /*TODO: // set_configuration updates the configuration of this PeerConnection object.
    pub async fn set_configuration(&mut self, configuration: Configuration) -> Result<()> {
        //nolint:gocognit
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setconfiguration (step #2)
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Err(Error::ErrConnectionClosed.into());
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #4)
        if !configuration.certificates.is_empty() {
            if configuration.certificates.len() != self.configuration.certificates.len() {
                return Err(Error::ErrModifyingCertificates.into());
            }

            self.configuration.certificates = configuration.certificates;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #5)
        if configuration.bundle_policy != BundlePolicy::Unspecified {
            if configuration.bundle_policy != self.configuration.bundle_policy {
                return Err(Error::ErrModifyingBundlePolicy.into());
            }
            self.configuration.bundle_policy = configuration.bundle_policy;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #6)
        if configuration.rtcp_mux_policy != RTCPMuxPolicy::Unspecified {
            if configuration.rtcp_mux_policy != self.configuration.rtcp_mux_policy {
                return Err(Error::ErrModifyingRTCPMuxPolicy.into());
            }
            self.configuration.rtcp_mux_policy = configuration.rtcp_mux_policy;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #7)
        if configuration.ice_candidate_pool_size != 0 {
            if self.configuration.ice_candidate_pool_size != configuration.ice_candidate_pool_size
                && self.local_description().await.is_some()
            {
                return Err(Error::ErrModifyingICECandidatePoolSize.into());
            }
            self.configuration.ice_candidate_pool_size = configuration.ice_candidate_pool_size;
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #8)
        if configuration.ice_transport_policy != ICETransportPolicy::Unspecified {
            self.configuration.ice_transport_policy = configuration.ice_transport_policy
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration (step #11)
        if !configuration.ice_servers.is_empty() {
            // https://www.w3.org/TR/webrtc/#set-the-configuration (step #11.3)
            for server in &configuration.ice_servers {
                server.validate()?;
            }
            self.configuration.ice_servers = configuration.ice_servers
        }
        Ok(())
    }*/

    /// get_configuration returns a Configuration object representing the current
    /// configuration of this PeerConnection object. The returned object is a
    /// copy and direct mutation on it will not take affect until set_configuration
    /// has been called with Configuration passed as its only argument.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getconfiguration>
    pub fn get_configuration(&self) -> &RTCConfiguration {
        &self.configuration
    }

    pub fn get_stats_id(&self) -> &str {
        self.stats_id.as_str()
    }

    pub(crate) fn new_ice_gatherer(
        opts: RTCIceGatherOptions,
        setting_engine: &Arc<SettingEngine>,
    ) -> Result<RTCIceGatherer> {
        let mut candidate_types = vec![];
        if setting_engine.candidates.ice_lite {
            candidate_types.push(ice::candidate::CandidateType::Host);
        } else if opts.ice_gather_policy == RTCIceTransportPolicy::Relay {
            candidate_types.push(ice::candidate::CandidateType::Relay);
        }

        let mut validated_servers = vec![];
        if !opts.ice_servers.is_empty() {
            for server in &opts.ice_servers {
                let url = server.urls()?;
                validated_servers.extend(url);
            }
        }

        let ice_agent_config = ice::AgentConfig {
            lite: setting_engine.candidates.ice_lite,
            urls: validated_servers.clone(),
            disconnected_timeout: setting_engine.timeout.ice_disconnected_timeout,
            failed_timeout: setting_engine.timeout.ice_failed_timeout,
            keepalive_interval: setting_engine.timeout.ice_keepalive_interval,
            candidate_types,
            host_acceptance_min_wait: setting_engine.timeout.ice_host_acceptance_min_wait,
            srflx_acceptance_min_wait: setting_engine.timeout.ice_srflx_acceptance_min_wait,
            prflx_acceptance_min_wait: setting_engine.timeout.ice_prflx_acceptance_min_wait,
            relay_acceptance_min_wait: setting_engine.timeout.ice_relay_acceptance_min_wait,
            local_ufrag: setting_engine.candidates.username_fragment.clone(),
            local_pwd: setting_engine.candidates.password.clone(),
            ..Default::default()
        };

        // Create the ICE transport
        let ice_agent = ice::Agent::new(Arc::new(ice_agent_config))?;

        Ok(RTCIceGatherer::new(
            ice_agent,
            validated_servers,
            opts.ice_gather_policy,
            Arc::clone(setting_engine),
        ))
    }

    pub(crate) fn new_ice_transport(ice_gatherer: RTCIceGatherer) -> RTCIceTransport {
        RTCIceTransport::new(ice_gatherer)
    }

    pub(crate) fn new_dtls_transport(
        mut certificates: Vec<RTCCertificate>,
        setting_engine: &Arc<SettingEngine>,
    ) -> Result<RTCDtlsTransport> {
        if !certificates.is_empty() {
            let now = SystemTime::now();
            for cert in &certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }
        } else {
            let kp = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = RTCCertificate::from_key_pair(kp)?;
            certificates = vec![cert];
        };

        Ok(RTCDtlsTransport::new(
            certificates,
            Arc::clone(setting_engine),
        ))
    }

    pub(crate) fn new_sctp_transport(
        setting_engine: &Arc<SettingEngine>,
    ) -> Result<RTCSctpTransport> {
        Ok(RTCSctpTransport::new(Arc::clone(setting_engine)))
    }

    /// create_offer starts the PeerConnection and generates the localDescription
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createoffer>
    pub fn create_offer(
        &mut self,
        options: Option<RTCOfferOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        }

        if let Some(options) = options {
            if options.ice_restart {
                self.ice_transport.restart()?;
            }
        }

        // include unmatched local transceivers
        // update the greater mid if the remote description provides a greater one
        if let Some(d) = &self.current_remote_description {
            if let Some(parsed) = &d.parsed {
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
            }
        }

        for t in &mut self.rtp_transceivers {
            if t.mid().is_some() {
                continue;
            }

            if let Some(gen) = &self.setting_engine.mid_generator {
                let current_greatest = self.greater_mid;
                let mid = (gen)(current_greatest);

                // If it's possible to parse the returned mid as numeric, we will update the greater_mid field.
                if let Ok(numeric_mid) = mid.parse::<isize>() {
                    if numeric_mid > self.greater_mid {
                        self.greater_mid = numeric_mid;
                    }
                }

                t.set_mid(mid)?;
            } else {
                self.greater_mid += 1;
                t.set_mid(format!("{}", self.greater_mid))?;
            }
        }

        let current_remote_description_is_none = self.current_remote_description.is_none();

        let mut d = if current_remote_description_is_none {
            self.generate_unmatched_sdp()?
        } else {
            self.generate_matched_sdp(
                true, /*includeUnmatched */
                DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
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

    /// create_answer starts the PeerConnection and generates the localDescription
    pub fn create_answer(
        &mut self,
        _options: Option<RTCAnswerOptions>,
    ) -> Result<RTCSessionDescription> {
        let remote_description = if let Some(desc) = self.remote_description().cloned() {
            desc
        } else {
            return Err(Error::ErrNoRemoteDescription);
        };

        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        } else if self.signaling_state() != RTCSignalingState::HaveRemoteOffer
            && self.signaling_state() != RTCSignalingState::HaveLocalPranswer
        {
            return Err(Error::ErrIncorrectSignalingState);
        }

        let mut connection_role = self.setting_engine.answering_dtls_role.to_connection_role();
        if connection_role == ConnectionRole::Unspecified {
            connection_role = DEFAULT_DTLS_ROLE_ANSWER.to_connection_role();
            if let Some(parsed) = remote_description.parsed {
                if Self::is_lite_set(&parsed) && !self.setting_engine.candidates.ice_lite {
                    connection_role = DTLSRole::Server.to_connection_role();
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

    /*
    /// Update the PeerConnectionState given the state of relevant transports
    /// <https://www.w3.org/TR/webrtc/#rtcpeerconnectionstate-enum>
    async fn update_connection_state(
        on_peer_connection_state_change_handler: &Arc<
            ArcSwapOption<Mutex<OnPeerConnectionStateChangeHdlrFn>>,
        >,
        is_closed: &Arc<AtomicBool>,
        peer_connection_state: &Arc<AtomicU8>,
        ice_connection_state: RTCIceConnectionState,
        dtls_transport_state: RTCDtlsTransportState,
    ) {
        let connection_state =
            // The RTCPeerConnection object's [[IsClosed]] slot is true.
            if is_closed.load(Ordering::SeqCst) {
                RTCPeerConnectionState::Closed
            } else if ice_connection_state == RTCIceConnectionState::Failed || dtls_transport_state == RTCDtlsTransportState::Failed {
                // Any of the RTCIceTransports or RTCDtlsTransports are in a "failed" state.
                RTCPeerConnectionState::Failed
            } else if ice_connection_state == RTCIceConnectionState::Disconnected {
                // Any of the RTCIceTransports or RTCDtlsTransports are in the "disconnected"
                // state and none of them are in the "failed" or "connecting" or "checking" state.
                RTCPeerConnectionState::Disconnected
            } else if ice_connection_state == RTCIceConnectionState::Connected && dtls_transport_state == RTCDtlsTransportState::Connected {
                // All RTCIceTransports and RTCDtlsTransports are in the "connected", "completed" or "closed"
                // state and at least one of them is in the "connected" or "completed" state.
                RTCPeerConnectionState::Connected
            } else if ice_connection_state == RTCIceConnectionState::Checking && dtls_transport_state == RTCDtlsTransportState::Connecting {
                //  Any of the RTCIceTransports or RTCDtlsTransports are in the "connecting" or
                // "checking" state and none of them is in the "failed" state.
                RTCPeerConnectionState::Connecting
            } else {
                RTCPeerConnectionState::New
            };

        if peer_connection_state.load(Ordering::SeqCst) == connection_state as u8 {
            return;
        }

        log::info!("peer connection state changed: {}", connection_state);
        peer_connection_state.store(connection_state as u8, Ordering::SeqCst);

        RTCPeerConnection::update_peer_connection_state_change(
            on_peer_connection_state_change_handler,
            connection_state,
        )
        .await;
    }
    */

    // Helper to trigger a negotiation needed.
    fn trigger_negotiation_needed(&self) {
        //TODO: RTCPeerConnection::do_negotiation_needed(self.create_negotiation_needed_params());
    }

    /// Creates the parameters needed to trigger a negotiation needed.
    fn create_negotiation_needed_params(&self) -> NegotiationNeededParams {
        NegotiationNeededParams {
            //TODO: on_negotiation_needed_handler: Arc::clone(&self.on_negotiation_needed_handler),
            is_closed: self.is_closed,
            //todo: ops: Arc::clone(&self.ops),
            negotiation_needed_state: self.negotiation_needed_state,
            is_negotiation_needed: self.is_negotiation_needed,
            signaling_state: self.signaling_state,
            /*check_negotiation_needed_params: CheckNegotiationNeededParams {
                sctp_transport: Arc::clone(&self.sctp_transport),
                rtp_transceivers: Arc::clone(&self.rtp_transceivers),
                current_local_description: Arc::clone(&self.current_local_description),
                current_remote_description: Arc::clone(&self.current_remote_description),
            },*/
        }
    }

    /*fn make_negotiation_needed_trigger(
        &self,
    ) -> impl Fn() -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> + Send + Sync {
        let params = self.create_negotiation_needed_params();
        move || {
            let params = params.clone();
            Box::pin(async move {
                let params = params.clone();
                RTCPeerConnection::do_negotiation_needed(params).await;
            })
        }
    }*/

    // 4.4.1.6 Set the SessionDescription
    pub(crate) fn set_description(
        &mut self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
    ) -> Result<()> {
        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        } else if sd.sdp_type == RTCSdpType::Unspecified {
            return Err(Error::ErrPeerConnSDPTypeInvalidValue);
        }

        let next_state = {
            let cur = self.signaling_state();
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
                if self.signaling_state() == RTCSignalingState::Stable {
                    self.is_negotiation_needed = false;
                    self.trigger_negotiation_needed();
                }
                self.update_signaling_state_change(next_state);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// set_local_description sets the SessionDescription of the local peer
    pub fn set_local_description(&mut self, mut desc: RTCSessionDescription) -> Result<()> {
        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        }

        let _have_local_description = self.current_local_description.is_some();

        // JSEP 5.4
        if desc.sdp.is_empty() {
            match desc.sdp_type {
                RTCSdpType::Answer | RTCSdpType::Pranswer => {
                    desc.sdp.clone_from(&self.last_answer);
                }
                RTCSdpType::Offer => {
                    desc.sdp.clone_from(&self.last_offer);
                }
                _ => return Err(Error::ErrPeerConnSDPTypeInvalidValueSetLocalDescription),
            }
        }

        desc.parsed = Some(desc.unmarshal()?);
        self.set_description(&desc, StateChangeOp::SetLocal)?;

        let we_answer = desc.sdp_type == RTCSdpType::Answer;
        let remote_description = self.remote_description().cloned();
        if we_answer {
            if let Some(parsed) = desc.parsed {
                // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                // Section 4.4.1.5
                for media in &parsed.media_descriptions {
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
                        Some((_, t)) => t,
                        None => continue,
                    };
                    let previous_direction = t.current_direction();
                    // 4.9.1.7.3 applying a local answer or pranswer
                    // Set transceiver.[[CurrentDirection]] and transceiver.[[FiredDirection]] to direction.

                    // TODO: Also set FiredDirection here.
                    t.set_current_direction(direction);
                    t.process_new_current_direction(previous_direction)?;
                }
            }

            if let Some(_remote_desc) = remote_description {
                //TODO: self.start_rtp_senders().await?;

                /*TODO: let pci = Arc::clone(&self.internal);
                let remote_desc = Arc::new(remote_desc);
                self.internal
                    .ops
                    .enqueue(Operation::new(
                        move || {
                            let pc = Arc::clone(&pci);
                            let rd = Arc::clone(&remote_desc);
                            Box::pin(async move {
                                let _ = pc.start_rtp(have_local_description, rd).await;
                                false
                            })
                        },
                        "set_local_description",
                    ))
                    .await?;*/
            }
        }

        if self.ice_transport.gatherer.state() == RTCIceGathererState::New {
            self.ice_transport.gatherer.gather()
        } else {
            Ok(())
        }
    }

    /// local_description returns PendingLocalDescription if it is not null and
    /// otherwise it returns CurrentLocalDescription. This property is used to
    /// determine if set_local_description has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-localdescription>
    pub fn local_description(&self) -> Option<RTCSessionDescription> {
        if let Some(pending_local_description) = self.pending_local_description() {
            return Some(pending_local_description);
        }
        self.current_local_description()
    }

    pub fn is_lite_set(desc: &SessionDescription) -> bool {
        for a in &desc.attributes {
            if a.key.trim() == ATTR_KEY_ICELITE {
                return true;
            }
        }
        false
    }

    /// set_remote_description sets the SessionDescription of the remote peer
    pub fn set_remote_description(&mut self, mut desc: RTCSessionDescription) -> Result<()> {
        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        }

        let is_renegotiation = self.current_remote_description.is_some();

        desc.parsed = Some(desc.unmarshal()?);
        self.set_description(&desc, StateChangeOp::SetRemote)?;

        if let Some(parsed) = &desc.parsed {
            self.media_engine.update_from_remote_description(parsed)?;

            let remote_description = self.remote_description().cloned();
            let we_offer = desc.sdp_type == RTCSdpType::Answer;

            if !we_offer {
                if let Some(parsed) = remote_description.as_ref().and_then(|r| r.parsed.as_ref()) {
                    for media in &parsed.media_descriptions {
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

                        let t = if let Some((_, t)) =
                            find_by_mid(mid_value, &mut self.rtp_transceivers)
                        {
                            Some(t)
                        } else if let Some(i) =
                            satisfy_type_and_direction(kind, direction, &self.rtp_transceivers)
                        {
                            Some(&mut self.rtp_transceivers[i])
                        } else {
                            None
                        };

                        if let Some(t) = t {
                            if t.mid().is_none() {
                                t.set_mid(mid_value.to_string())?;
                            }
                        } else {
                            let _local_direction =
                                if direction == RTCRtpTransceiverDirection::Recvonly {
                                    RTCRtpTransceiverDirection::Sendonly
                                } else {
                                    RTCRtpTransceiverDirection::Recvonly
                                };

                            let _receive_mtu = self.setting_engine.get_receive_mtu();

                            /*TODO:
                            let receiver = Arc::new(RTCRtpReceiver::new(
                                receive_mtu,
                                kind,
                                Arc::clone(&self.internal.dtls_transport),
                                Arc::clone(&self.internal.media_engine),
                                Arc::clone(&self.interceptor),
                            ));

                            let sender = Arc::new(
                                RTCRtpSender::new(
                                    receive_mtu,
                                    None,
                                    Arc::clone(&self.internal.dtls_transport),
                                    Arc::clone(&self.internal.media_engine),
                                    Arc::clone(&self.interceptor),
                                    false,
                                )
                                .await,
                            );

                            let t = RTCRtpTransceiver::new(
                                receiver,
                                sender,
                                local_direction,
                                kind,
                                vec![],
                                Arc::clone(&self.internal.media_engine),
                                Some(Box::new(self.internal.make_negotiation_needed_trigger())),
                            )
                            .await;

                            self.internal.add_rtp_transceiver(Arc::clone(&t)).await;

                            if t.mid().is_none() {
                                t.set_mid(mid_value.to_string())?;
                            }*/
                        }
                    }
                }
            }

            if we_offer {
                // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                // 4.5.9.2
                // This is an answer from the remote.
                if let Some(parsed) = remote_description.as_ref().and_then(|r| r.parsed.as_ref()) {
                    for media in &parsed.media_descriptions {
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

                        if let Some((_, t)) = find_by_mid(mid_value, &mut self.rtp_transceivers) {
                            let previous_direction = t.current_direction();

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

            let (remote_ufrag, remote_pwd, candidates) = extract_ice_details(parsed)?;

            if is_renegotiation
                && self
                    .ice_transport
                    .have_remote_credentials_change(&remote_ufrag, &remote_pwd)
            {
                // An ICE Restart only happens implicitly for a set_remote_description of type offer
                if !we_offer {
                    self.ice_transport.restart()?;
                }

                self.ice_transport
                    .set_remote_credentials(remote_ufrag.clone(), remote_pwd.clone())?;
            }

            for candidate in candidates {
                self.ice_transport.add_remote_candidate(Some(candidate))?;
            }

            if is_renegotiation {
                if we_offer {
                    /*TODO: self.start_rtp_senders().await?;

                    let pci = Arc::clone(&self.internal);
                    let remote_desc = Arc::new(desc);
                    self.internal
                        .ops
                        .enqueue(Operation::new(
                            move || {
                                let pc = Arc::clone(&pci);
                                let rd = Arc::clone(&remote_desc);
                                Box::pin(async move {
                                    let _ = pc.start_rtp(true, rd).await;
                                    false
                                })
                            },
                            "set_remote_description renegotiation",
                        ))
                        .await?;*/
                }
                return Ok(());
            }

            let remote_is_lite = Self::is_lite_set(parsed);

            let (_fingerprint, _fingerprint_hash) = extract_fingerprint(parsed)?;

            // If one of the agents is lite and the other one is not, the lite agent must be the controlling agent.
            // If both or neither agents are lite the offering agent is controlling.
            // RFC 8445 S6.1.1
            let _ice_role = if (we_offer
                && remote_is_lite == self.setting_engine.candidates.ice_lite)
                || (remote_is_lite && !self.setting_engine.candidates.ice_lite)
            {
                RTCIceRole::Controlling
            } else {
                RTCIceRole::Controlled
            };

            // Start the networking in a new routine since it will block until
            // the connection is actually established.
            if we_offer {
                //TODO: self.start_rtp_senders()?;
            }

            //log::trace!("start_transports: parsed={:?}", parsed);

            /*TODO: let pci = Arc::clone(&self.internal);
            let dtls_role = DTLSRole::from(parsed);
            let remote_desc = Arc::new(desc);
            self.internal
                .ops
                .enqueue(Operation::new(
                    move || {
                        let pc = Arc::clone(&pci);
                        let rd = Arc::clone(&remote_desc);
                        let ru = remote_ufrag.clone();
                        let rp = remote_pwd.clone();
                        let fp = fingerprint.clone();
                        let fp_hash = fingerprint_hash.clone();
                        Box::pin(async move {
                            log::trace!(
                                "start_transports: ice_role={}, dtls_role={}",
                                ice_role,
                                dtls_role,
                            );
                            pc.start_transports(ice_role, dtls_role, ru, rp, fp, fp_hash)
                                .await;

                            if we_offer {
                                let _ = pc.start_rtp(false, rd).await;
                            }
                            false
                        })
                    },
                    "set_remote_description",
                ))
                .await?;*/
        }

        Ok(())
    }

    /*
    /// start_rtp_senders starts all outbound RTP streams
    pub(crate) async fn start_rtp_senders(&self) -> Result<()> {
        let current_transceivers = self.internal.rtp_transceivers.lock().await;
        for transceiver in &*current_transceivers {
            let sender = transceiver.sender().await;
            if sender.is_negotiated() && !sender.has_sent() {
                sender.send(&sender.get_parameters().await).await?;
            }
        }

        Ok(())
    }
    */

    /// add_ice_candidate accepts an ICE candidate string and adds it
    /// to the existing set of candidates.
    pub fn add_ice_candidate(&mut self, candidate: RTCIceCandidateInit) -> Result<()> {
        if self.remote_description().is_none() {
            return Err(Error::ErrNoRemoteDescription);
        }

        let candidate_value = match candidate.candidate.strip_prefix("candidate:") {
            Some(s) => s,
            None => candidate.candidate.as_str(),
        };

        let ice_candidate = if !candidate_value.is_empty() {
            let candidate = unmarshal_candidate(candidate_value)?;

            Some(RTCIceCandidate::from(&candidate))
        } else {
            None
        };

        self.ice_transport.add_remote_candidate(ice_candidate)
    }

    /// ice_connection_state returns the ICE connection state of the
    /// PeerConnection instance.
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.ice_connection_state
    }

    /*
    /// get_senders returns the RTPSender that are currently attached to this PeerConnection
    pub async fn get_senders(&self) -> Vec<Arc<RTCRtpSender>> {
        let mut senders = vec![];
        let rtp_transceivers = self.internal.rtp_transceivers.lock().await;
        for transceiver in &*rtp_transceivers {
            let sender = transceiver.sender().await;
            senders.push(sender);
        }
        senders
    }

    /// get_receivers returns the RTPReceivers that are currently attached to this PeerConnection
    pub async fn get_receivers(&self) -> Vec<Arc<RTCRtpReceiver>> {
        let mut receivers = vec![];
        let rtp_transceivers = self.internal.rtp_transceivers.lock().await;
        for transceiver in &*rtp_transceivers {
            receivers.push(transceiver.receiver().await);
        }
        receivers
    }

    /// get_transceivers returns the RtpTransceiver that are currently attached to this PeerConnection
    pub async fn get_transceivers(&self) -> Vec<Arc<RTCRtpTransceiver>> {
        let rtp_transceivers = self.internal.rtp_transceivers.lock().await;
        rtp_transceivers.clone()
    }

    /// add_track adds a Track to the PeerConnection
    pub async fn add_track(
        &self,
        track: Arc<dyn TrackLocal + Send + Sync>,
    ) -> Result<Arc<RTCRtpSender>> {
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Err(Error::ErrConnectionClosed);
        }

        {
            let rtp_transceivers = self.internal.rtp_transceivers.lock().await;
            for t in &*rtp_transceivers {
                if !t.stopped.load(Ordering::SeqCst)
                    && t.kind == track.kind()
                    && track.id() == t.sender().await.id
                {
                    let sender = t.sender().await;
                    if sender.track().await.is_none() {
                        if let Err(err) = sender.replace_track(Some(track)).await {
                            let _ = sender.stop().await;
                            return Err(err);
                        }

                        t.set_direction_internal(RTCRtpTransceiverDirection::from_send_recv(
                            true,
                            t.direction().has_recv(),
                        ));

                        self.internal.trigger_negotiation_needed().await;
                        return Ok(sender);
                    }
                }
            }
        }

        let transceiver = self
            .internal
            .new_transceiver_from_track(RTCRtpTransceiverDirection::Sendrecv, track)
            .await?;
        self.internal
            .add_rtp_transceiver(Arc::clone(&transceiver))
            .await;

        Ok(transceiver.sender().await)
    }

    /// remove_track removes a Track from the PeerConnection
    pub async fn remove_track(&self, sender: &Arc<RTCRtpSender>) -> Result<()> {
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Err(Error::ErrConnectionClosed);
        }

        let mut transceiver = None;
        {
            let rtp_transceivers = self.internal.rtp_transceivers.lock().await;
            for t in &*rtp_transceivers {
                if t.sender().await.id == sender.id {
                    if sender.track().await.is_none() {
                        return Ok(());
                    }
                    transceiver = Some(t.clone());
                    break;
                }
            }
        }

        let t = transceiver.ok_or(Error::ErrSenderNotCreatedByConnection)?;

        // This also happens in `set_sending_track` but we need to make sure we do this
        // before we call sender.stop to avoid a race condition when removing tracks and
        // generating offers.
        t.set_direction_internal(RTCRtpTransceiverDirection::from_send_recv(
            false,
            t.direction().has_recv(),
        ));
        // Stop the sender
        let sender_result = sender.stop().await;
        // This also updates direction
        let sending_track_result = t.set_sending_track(None).await;

        if sender_result.is_ok() && sending_track_result.is_ok() {
            self.internal.trigger_negotiation_needed().await;
        }
        Ok(())
    }

    /// add_transceiver_from_kind Create a new RtpTransceiver and adds it to the set of transceivers.
    pub async fn add_transceiver_from_kind(
        &self,
        kind: RTPCodecType,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<Arc<RTCRtpTransceiver>> {
        self.internal.add_transceiver_from_kind(kind, init).await
    }

    /// add_transceiver_from_track Create a new RtpTransceiver(SendRecv or SendOnly) and add it to the set of transceivers.
    pub async fn add_transceiver_from_track(
        &self,
        track: Arc<dyn TrackLocal + Send + Sync>,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<Arc<RTCRtpTransceiver>> {
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Err(Error::ErrConnectionClosed);
        }

        let direction = init
            .map(|init| init.direction)
            .unwrap_or(RTCRtpTransceiverDirection::Sendrecv);

        let t = self
            .internal
            .new_transceiver_from_track(direction, track)
            .await?;

        self.internal.add_rtp_transceiver(Arc::clone(&t)).await;

        Ok(t)
    }
    */
    /// create_data_channel creates a new DataChannel object with the given label
    /// and optional DataChannelInit used to configure properties of the
    /// underlying channel such as data reliability.
    pub fn create_data_channel(
        &mut self,
        label: &str,
        options: Option<RTCDataChannelInit>,
    ) -> Result<()> {
        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #2)
        if self.is_closed {
            return Err(Error::ErrConnectionClosed);
        }

        if self.sctp_transport.data_channels.contains_key(label) {
            return Err(Error::ErrDataChannelExist);
        }

        let mut params = DataChannelParameters {
            label: label.to_owned(),
            ordered: true,
            ..Default::default()
        };

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #19)
        if let Some(options) = options {
            // Ordered indicates if data is allowed to be delivered out of order. The
            // default value of true, guarantees that data will be delivered in order.
            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #9)
            if let Some(ordered) = options.ordered {
                params.ordered = ordered;
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #7)
            if let Some(max_packet_life_time) = options.max_packet_life_time {
                params.max_packet_life_time = max_packet_life_time;
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #8)
            if let Some(max_retransmits) = options.max_retransmits {
                params.max_retransmits = max_retransmits;
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #10)
            if let Some(protocol) = options.protocol {
                params.protocol = protocol;
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #11)
            if params.protocol.len() > 65535 {
                return Err(Error::ErrProtocolTooLarge);
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #12)
            params.negotiated = options.negotiated;
        }

        let d = RTCDataChannel::new(params, Arc::clone(&self.setting_engine));

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #16)
        if d.max_packet_lifetime != 0 && d.max_retransmits != 0 {
            return Err(Error::ErrRetransmitsOrPacketLifeTime);
        }

        self.sctp_transport
            .data_channels
            .insert(label.to_string(), d);
        self.sctp_transport.data_channels_requested += 1;

        // If SCTP already connected open all the channels
        if self.sctp_transport.state() == RTCSctpTransportState::Connected {
            //TODO: d.open(Arc::clone(&self.sctp_transport))?;
        }

        self.trigger_negotiation_needed();

        Ok(())
    }
    /*
    /// set_identity_provider is used to configure an identity provider to generate identity assertions
    pub fn set_identity_provider(&self, _provider: &str) -> Result<()> {
        Err(Error::ErrPeerConnSetIdentityProviderNotImplemented)
    }

    /// write_rtcp sends a user provided RTCP packet to the connected peer. If no peer is connected the
    /// packet is discarded. It also runs any configured interceptors.
    pub async fn write_rtcp(
        &self,
        pkts: &[Box<dyn rtcp::packet::Packet + Send + Sync>],
    ) -> Result<usize> {
        let a = Attributes::new();
        Ok(self.interceptor_rtcp_writer.write(pkts, &a).await?)
    }

    /// close ends the PeerConnection
    pub async fn close(&self) -> Result<()> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #2)
        self.internal.is_closed.store(true, Ordering::SeqCst);

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.internal
            .signaling_state
            .store(RTCSignalingState::Closed as u8, Ordering::SeqCst);

        // Try closing everything and collect the errors
        // Shutdown strategy:
        // 1. All Conn close by closing their underlying Conn.
        // 2. A Mux stops this chain. It won't close the underlying
        //    Conn if one of the endpoints is closed down. To
        //    continue the chain the Mux has to be closed.
        let mut close_errs = vec![];

        if let Err(err) = self.interceptor.close().await {
            close_errs.push(Error::new(format!("interceptor: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #4)
        {
            let mut rtp_transceivers = self.internal.rtp_transceivers.lock().await;
            for t in &*rtp_transceivers {
                if let Err(err) = t.stop().await {
                    close_errs.push(Error::new(format!("rtp_transceivers: {err}")));
                }
            }
            rtp_transceivers.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #5)
        {
            let mut data_channels = self.internal.sctp_transport.data_channels.lock().await;
            for d in &*data_channels {
                if let Err(err) = d.close().await {
                    close_errs.push(Error::new(format!("data_channels: {err}")));
                }
            }
            data_channels.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #6)
        if let Err(err) = self.internal.sctp_transport.stop().await {
            close_errs.push(Error::new(format!("sctp_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #7)
        if let Err(err) = self.internal.dtls_transport.stop().await {
            close_errs.push(Error::new(format!("dtls_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #8, #9, #10)
        if let Err(err) = self.internal.ice_transport.stop().await {
            close_errs.push(Error::new(format!("dtls_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #11)
        RTCPeerConnection::update_connection_state(
            &self.internal.on_peer_connection_state_change_handler,
            &self.internal.is_closed,
            &self.internal.peer_connection_state,
            self.ice_connection_state(),
            self.internal.dtls_transport.state(),
        )
        .await;

        if let Err(err) = self.internal.ops.close().await {
            close_errs.push(Error::new(format!("ops: {err}")));
        }

        flatten_errs(close_errs)
    }
    */
    /// CurrentLocalDescription represents the local description that was
    /// successfully negotiated the last time the PeerConnection transitioned
    /// into the stable state plus any local candidates that have been generated
    /// by the ICEAgent since the offer or answer was created.
    pub fn current_local_description(&self) -> Option<RTCSessionDescription> {
        let local_description = self.current_local_description.clone();
        let ice_gathering_state = self.ice_gathering_state();

        populate_local_candidates(
            local_description.as_ref(),
            &self.ice_transport.gatherer,
            ice_gathering_state,
        )
    }

    /// PendingLocalDescription represents a local description that is in the
    /// process of being negotiated plus any local candidates that have been
    /// generated by the ICEAgent since the offer or answer was created. If the
    /// PeerConnection is in the stable state, the value is null.
    pub fn pending_local_description(&self) -> Option<RTCSessionDescription> {
        let local_description = self.pending_local_description.clone();
        let ice_gathering_state = self.ice_gathering_state();

        populate_local_candidates(
            local_description.as_ref(),
            &self.ice_transport.gatherer,
            ice_gathering_state,
        )
    }

    /// current_remote_description represents the last remote description that was
    /// successfully negotiated the last time the PeerConnection transitioned
    /// into the stable state plus any remote candidates that have been supplied
    /// via add_icecandidate() since the offer or answer was created.
    pub fn current_remote_description(&self) -> Option<RTCSessionDescription> {
        self.current_remote_description.clone()
    }

    /// pending_remote_description represents a remote description that is in the
    /// process of being negotiated, complete with any remote candidates that
    /// have been supplied via add_icecandidate() since the offer or answer was
    /// created. If the PeerConnection is in the stable state, the value is
    /// null.
    pub fn pending_remote_description(&self) -> Option<RTCSessionDescription> {
        self.pending_remote_description.clone()
    }

    /// signaling_state attribute returns the signaling state of the
    /// PeerConnection instance.
    pub fn signaling_state(&self) -> RTCSignalingState {
        self.signaling_state
    }

    /// connection_state attribute returns the connection state of the
    /// PeerConnection instance.
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer_connection_state
    }

    /*
    pub async fn get_stats(&self) -> StatsReport {
        self.internal
            .get_stats(self.get_stats_id().to_owned())
            .await
            .into()
    }

    /// sctp returns the SCTPTransport for this PeerConnection
    ///
    /// The SCTP transport over which SCTP data is sent and received. If SCTP has not been negotiated, the value is nil.
    /// <https://www.w3.org/TR/webrtc/#attributes-15>
    pub fn sctp(&self) -> Arc<RTCSctpTransport> {
        Arc::clone(&self.internal.sctp_transport)
    }

    /// gathering_complete_promise is a Pion specific helper function that returns a channel that is closed when gathering is complete.
    /// This function may be helpful in cases where you are unable to trickle your ICE Candidates.
    ///
    /// It is better to not use this function, and instead trickle candidates. If you use this function you will see longer connection startup times.
    /// When the call is connected you will see no impact however.
    pub async fn gathering_complete_promise(&self) -> mpsc::Receiver<()> {
        let (gathering_complete_tx, gathering_complete_rx) = mpsc::channel(1);

        // It's possible to miss the GatherComplete event since setGatherCompleteHandler is an atomic operation and the
        // promise might have been created after the gathering is finished. Therefore, we need to check if the ICE gathering
        // state has changed to complete so that we don't block the caller forever.
        let done = Arc::new(Mutex::new(Some(gathering_complete_tx)));
        let done2 = Arc::clone(&done);
        self.internal.set_gather_complete_handler(Box::new(move || {
            log::trace!("setGatherCompleteHandler");
            let done3 = Arc::clone(&done2);
            Box::pin(async move {
                let mut d = done3.lock().await;
                d.take();
            })
        }));

        if self.ice_gathering_state() == RTCIceGatheringState::Complete {
            log::trace!("ICEGatheringState::Complete");
            let mut d = done.lock().await;
            d.take();
        }

        gathering_complete_rx
    }

    /// Returns the internal [`RTCDtlsTransport`].
    pub fn dtls_transport(&self) -> Arc<RTCDtlsTransport> {
        Arc::clone(&self.internal.dtls_transport)
    }

    /// Adds the specified [`RTCRtpTransceiver`] to this [`RTCPeerConnection`].
    pub async fn add_transceiver(&self, t: Arc<RTCRtpTransceiver>) {
        self.internal.add_rtp_transceiver(t).await
    }*/

    /// remote_description returns pending_remote_description if it is not null and
    /// otherwise it returns current_remote_description. This property is used to
    /// determine if setRemoteDescription has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-remotedescription>
    fn remote_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_remote_description.is_some() {
            self.pending_remote_description.as_ref()
        } else {
            self.current_remote_description.as_ref()
        }
    }

    /// ice gathering_state attribute returns the ICE gathering state of the
    /// PeerConnection instance.
    pub fn ice_gathering_state(&self) -> RTCIceGatheringState {
        match self.ice_transport.gatherer.state() {
            RTCIceGathererState::New => RTCIceGatheringState::New,
            RTCIceGathererState::Gathering => RTCIceGatheringState::Gathering,
            _ => RTCIceGatheringState::Complete,
        }
    }

    /// generate_unmatched_sdp generates an SDP that doesn't take remote state into account
    /// This is used for the initial call for CreateOffer
    pub(super) fn generate_unmatched_sdp(&mut self) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false /*use_identity*/);

        let ice_params = self.ice_transport.gatherer.get_local_parameters()?;

        let candidates = self.ice_transport.gatherer.get_local_candidates();

        let mut media_sections = vec![];
        let mut mid2index: HashMap<Mid, usize> = HashMap::new();

        for (index, t) in self.rtp_transceivers.iter_mut().enumerate() {
            if t.stopped {
                // An "m=" section is generated for each
                // RtpTransceiver that has been added to the PeerConnection, excluding
                // any stopped RtpTransceivers;
                continue;
            }

            if let Some(mid) = t.mid().cloned() {
                // TODO: This is dubious because of rollbacks.
                t.sender_mut().set_negotiated();
                media_sections.push(MediaSection {
                    id: mid.clone(),
                    //TODO: transceivers: vec![Arc::clone(t)],
                    ..Default::default()
                });
                mid2index.insert(mid, index);
            } else {
                return Err(Error::ErrPeerConnTransceiverMidNil);
            }
        }

        if self.sctp_transport.data_channels_requested != 0 {
            media_sections.push(MediaSection {
                id: format!("{}", media_sections.len()),
                data: true,
                ..Default::default()
            });
        }

        let dtls_fingerprints = if let Some(cert) = self.dtls_transport.certificates.first() {
            cert.get_fingerprints()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_icelite: self.setting_engine.candidates.ice_lite,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_gathering_state(),
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            &mut self.media_engine,
            &candidates,
            &ice_params,
            &media_sections,
            params,
            &mut self.rtp_transceivers,
            &mid2index,
        )
    }

    /// generate_matched_sdp generates a SDP and takes the remote state into account
    /// this is used everytime we have a remote_description
    pub(super) fn generate_matched_sdp(
        &mut self,
        include_unmatched: bool,
        connection_role: ConnectionRole,
    ) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false /*use_identity*/);

        let ice_params = self.ice_transport.gatherer.get_local_parameters()?;
        let candidates = self.ice_transport.gatherer.get_local_candidates();

        let mut media_sections = vec![];
        let mut already_have_application_media_section = false;
        let mut matched: HashSet<Mid> = HashSet::new();
        let mut mid2index: HashMap<Mid, usize> = HashMap::new();
        if let Some(remote_description) = self.remote_description().cloned() {
            if let Some(parsed) = &remote_description.parsed {
                for media in &parsed.media_descriptions {
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

                        if let Some((index, t)) = find_by_mid(mid_value, &mut self.rtp_transceivers)
                        {
                            t.sender_mut().set_negotiated();

                            // NB: The below could use `then_some`, but with our current MSRV
                            // it's not possible to actually do this. The clippy version that
                            // ships with 1.64.0 complains about this so we disable it for now.
                            #[allow(clippy::unnecessary_lazy_evaluations)]
                            media_sections.push(MediaSection {
                                id: mid_value.to_owned(),
                                //TODO: transceivers: media_transceivers,
                                rid_map: get_rids(media),
                                offered_direction: (!include_unmatched).then(|| direction),
                                ..Default::default()
                            });
                            matched.insert(mid_value.to_string());
                            mid2index.insert(mid_value.to_string(), index);
                        } else {
                            return Err(Error::ErrPeerConnTransceiverMidNil);
                        }
                    }
                }
            }
        }

        // If we are offering also include unmatched local transceivers
        if include_unmatched {
            for (index, t) in self.rtp_transceivers.iter_mut().enumerate() {
                if let Some(mid) = t.mid().cloned() {
                    if !matched.contains(&mid) {
                        t.sender_mut().set_negotiated();
                        media_sections.push(MediaSection {
                            id: mid.clone(),
                            //TODO: transceivers: vec![Arc::clone(t)],
                            ..Default::default()
                        });
                        mid2index.insert(mid, index);
                    }
                }
            }

            if self.sctp_transport.data_channels_requested != 0
                && !already_have_application_media_section
            {
                media_sections.push(MediaSection {
                    id: format!("{}", media_sections.len()),
                    data: true,
                    ..Default::default()
                });
            }
        }

        let dtls_fingerprints = if let Some(cert) = self.dtls_transport.certificates.first() {
            cert.get_fingerprints()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_icelite: self.setting_engine.candidates.ice_lite,
            connection_role,
            ice_gathering_state: self.ice_gathering_state(),
        };
        populate_sdp(
            d,
            &dtls_fingerprints,
            &mut self.media_engine,
            &candidates,
            &ice_params,
            &media_sections,
            params,
            &mut self.rtp_transceivers,
            &mid2index,
        )
    }
}
