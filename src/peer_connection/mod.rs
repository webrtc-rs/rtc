//! Peer-to-peer connections
//!
//! This module implements the `RTCPeerConnection` interface as defined in the
//! [W3C WebRTC specification](https://w3c.github.io/webrtc-pc/). It provides
//! the core functionality for establishing peer-to-peer connections, negotiating
//! media capabilities, and managing data channels.
//!
//! # Overview
//!
//! `RTCPeerConnection` is the central interface in WebRTC. It handles:
//!
//! - **Signaling**: Creating and exchanging SDP offers/answers
//! - **ICE**: Gathering candidates and establishing connectivity
//! - **Media**: Managing audio/video tracks and transceivers
//! - **Data**: Creating and managing data channels
//! - **Security**: DTLS encryption for all communication
//!
//! # Architecture
//!
//! This is a **sans-I/O** implementation, meaning it separates protocol logic
//! from I/O operations. The application is responsible for:
//!
//! - Transmitting/receiving network packets
//! - Managing the event loop
//! - Handling signaling channel communication
//!
//! ## Sans-I/O Benefits
//!
//! - **Flexibility**: Works with any I/O runtime (tokio, async-std, blocking, etc.)
//! - **Testability**: Protocol logic can be tested without network I/O
//! - **Control**: Application has full control over threading and scheduling
//!
//! # Connection Establishment
//!
//! The typical WebRTC connection flow:
//!
//! ```text
//! Peer A (Offerer)              Signaling Server              Peer B (Answerer)
//! ════════════════              ════════════════              ═══════════════════
//!      │                               │                               │
//!      │ 1. create_offer()             │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 2. set_local_description()    │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 3. send offer (via signaling) │                               │
//!      │──────────────────────────────>│──────────────────────────────>│
//!      │                               │                               │
//!      │                               │  4. set_remote_description()  │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │                               │       5. create_answer()      │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │                               │  6. set_local_description()   │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │ 7. receive answer             │<──────────────────────────────│
//!      │<──────────────────────────────┤                               │
//!      │                               │                               │
//!      │ 8. set_remote_description()   │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 9. ICE candidates exchanged   │                               │
//!      │<─────────────────────────────────────────────────────────────>│
//!      │                               │                               │
//!      │ 10. Media/data flows directly │                               │
//!      │<═════════════════════════════════════════════════════════════>│
//! ```
//!
//! # Examples
//!
//! ## Creating a Peer Connection
//!
//! ```
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create with default configuration
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating an Offer (Initiating Peer)
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add media track or data channel first
//! // pc.add_track(audio_track)?;
//!
//! // Create offer
//! let offer = pc.create_offer(None)?;
//!
//! // Set as local description
//! pc.set_local_description(Instant::now(), offer.clone())?;
//!
//! // Send offer.sdp to remote peer via signaling channel
//! // signaling_channel.send(offer.sdp)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Answering an Offer (Responding Peer)
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::sdp::RTCSessionDescription;
//!
//! # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Receive offer from remote peer
//! let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
//!
//! // Set as remote description
//! pc.set_remote_description(Instant::now(), offer)?;
//!
//! // Create answer
//! let answer = pc.create_answer(None)?;
//!
//! // Set as local description
//! pc.set_local_description(Instant::now(), answer.clone())?;
//!
//! // Send answer.sdp to remote peer via signaling channel
//! // signaling_channel.send(answer.sdp)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Adding Media Tracks
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::media_stream::MediaStreamTrack;
//! use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//!
//! # fn example(audio_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add an audio track
//! let sender_id = pc.add_track(audio_track)?;
//!
//! // Or add a transceiver for receiving
//! let transceiver_id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating Data Channels
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::data_channel::RTCDataChannelInit;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Create a reliable, ordered data channel
//! let init = RTCDataChannelInit {
//!     ordered: true,
//!     max_retransmits: None,
//!     ..Default::default()
//! };
//!
//! let channel_id = pc.create_data_channel("my-channel", Some(init))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## ICE Candidate Exchange
//!
//! ```no_run
//! use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
//! use rtc::peer_connection::transport::RTCIceCandidateInit;
//!
//! # fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
//! // When local candidates are gathered, send to remote peer
//! // (In sans-I/O, you'd poll for events to get candidates)
//!
//! // When receiving remote candidate from signaling channel
//! let remote_candidate = RTCIceCandidateInit {
//!     candidate: "candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host".to_string(),
//!     ..Default::default()
//! };
//!
//! pc.add_remote_candidate(remote_candidate)?;
//! # Ok(())
//! # }
//! ```
//!
//! # State Management
//!
//! The peer connection maintains several state machines:
//!
//! - **Signaling State**: SDP negotiation progress (stable, have-local-offer, etc.)
//! - **ICE Connection State**: Network connectivity status
//! - **ICE Gathering State**: Candidate gathering progress
//! - **Connection State**: Overall connection health
//!
//! Monitor these states through the event system (sans-I/O polling).
//!
//! # Thread Safety
//!
//! `RTCPeerConnection` is **not** thread-safe. The application must ensure
//! exclusive access or use appropriate synchronization primitives.
//!
//! # Specifications
//!
//! - [W3C WebRTC 1.0] - Main specification
//! - [RFC 8829] - JSEP: JavaScript Session Establishment Protocol
//! - [RFC 8866] - SDP: Session Description Protocol
//! - [RFC 8445] - ICE: Interactive Connectivity Establishment
//! - [RFC 8831] - WebRTC Data Channels
//!
//! [W3C WebRTC 1.0]: https://w3c.github.io/webrtc-pc/
//! [RFC 8829]: https://datatracker.ietf.org/doc/html/rfc8829
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831

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
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::{RTCDataChannel, RTCDataChannelId, internal::RTCDataChannelInternal};
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::setting_engine::{SctpMaxMessageSize, SettingEngine};
use crate::peer_connection::configuration::{
    RTCConfiguration, RTCIceTransportPolicy,
    offer_answer_options::{RTCAnswerOptions, RTCOfferOptions},
};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::handler::PipelineContext;
use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::sctp::SctpHandlerContext;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::sdp::{
    extract_fingerprint, extract_ice_details, get_application_media,
    get_application_media_section_max_message_size, get_application_media_section_sctp_port,
    get_mid_value, get_peer_direction, has_ice_trickle_option, is_lite_set, sdp_type::RTCSdpType,
    update_sdp_origin,
};
use crate::peer_connection::state::RTCIceGatheringState;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::peer_connection_state::{
    NegotiationNeededState, RTCPeerConnectionState,
};
use crate::peer_connection::state::signaling_state::{RTCSignalingState, StateChangeOp};
use crate::peer_connection::transport::RTCSctpTransport;
use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
use crate::peer_connection::transport::dtls::role::{
    DEFAULT_DTLS_ROLE_ANSWER, DEFAULT_DTLS_ROLE_OFFER, RTCDtlsRole,
};
use crate::peer_connection::transport::dtls::{DtlsTransport, RTCDtlsTransportConfig};
use crate::peer_connection::transport::ice::IceTransport;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidateInit;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::sctp::SctpTransport;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::rtp_transceiver::rtp_sender::internal::RTCRtpSenderInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, codec_parameters_fuzzy_search,
};
use crate::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiver, RTCRtpTransceiverId,
    RTCRtpTransceiverInit, internal::RTCRtpTransceiverInternal,
};
use crate::statistics::StatsSelector;
use crate::statistics::accumulator::RTCStatsAccumulator;
use crate::statistics::report::RTCStatsReport;
use ::sdp::description::session::Origin;
use ::sdp::util::ConnectionRole;
use ice::AgentConfig;
use ice::candidate::{Candidate, unmarshal_candidate};
use interceptor::{Interceptor, Registry};
use sdp::MEDIA_SECTION_APPLICATION;
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;
use std::collections::HashMap;
use std::time::Instant;

/// Builder for creating RTCPeerConnection instances.
///
/// This builder provides a fluent API for configuring peer connections with:
/// - ICE servers (STUN/TURN) via [`RTCConfiguration`]
/// - Media codecs and RTP extensions via [`MediaEngine`]
/// - Low-level transport settings via [`SettingEngine`]
/// - RTP/RTCP interceptors for NACK, TWCC, and RTCP reports
///
/// # Examples
///
/// ## Basic peer connection
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With ICE servers
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_configuration(
///         RTCConfigurationBuilder::new()
///             .with_ice_servers(vec![RTCIceServer {
///                 urls: vec!["stun:stun.l.google.com:19302".to_string()],
///                 ..Default::default()
///             }])
///             .build()
///     )
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With custom media engine
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// media_engine.register_default_codecs()?;
///
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With interceptors
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtc::interceptor::Registry;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
///
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .with_interceptor_registry(registry)
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct RTCPeerConnectionBuilder {
    configuration: RTCConfiguration,
    media_engine: MediaEngine,
    setting_engine: SettingEngine,
    interceptor_registry: Registry,
}

impl RTCPeerConnectionBuilder {
    /// Creates a new RTCPeerConnectionBuilder with default configuration.
    ///
    /// The default builder includes:
    /// - Empty ICE server list
    /// - Default MediaEngine (no codecs registered)
    /// - Default SettingEngine (standard timeouts and limits)
    /// - NoopInterceptor (no RTP/RTCP processing)
    ///
    /// Use `with_*` methods to customize configuration before calling `build()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
}

impl RTCPeerConnectionBuilder {
    /// Sets the RTCConfiguration for the peer connection.
    ///
    /// The configuration includes ICE servers, transport policies, bundle policies,
    /// RTCP mux policies, and certificates.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_ice_servers(vec![RTCIceServer {
    ///         urls: vec!["stun:stun.l.google.com:19302".to_string()],
    ///         ..Default::default()
    ///     }])
    ///     .build();
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_configuration(config)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_configuration(mut self, configuration: RTCConfiguration) -> Self {
        self.configuration = configuration;
        self
    }

    /// Sets the MediaEngine for the peer connection.
    ///
    /// The media engine configures codecs and RTP header extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// media_engine.register_default_codecs()?;
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_media_engine(media_engine)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_media_engine(mut self, media_engine: MediaEngine) -> Self {
        self.media_engine = media_engine;
        self
    }

    /// Sets the SettingEngine for the peer connection.
    ///
    /// The setting engine configures low-level transport parameters including
    /// timeouts, buffer sizes, ICE settings, and SCTP parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_timeouts(
    ///         Some(Duration::from_secs(30)),
    ///         Some(Duration::from_secs(60)),
    ///         Some(Duration::from_millis(100)),
    ///     )
    ///     .build();
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_setting_engine(setting_engine)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_setting_engine(mut self, setting_engine: SettingEngine) -> Self {
        self.setting_engine = setting_engine;
        self
    }

    /// Configures the peer connection with an interceptor registry.
    ///
    /// Interceptors process RTP/RTCP packets as they flow through the pipeline,
    /// enabling features like:
    /// - NACK (Negative Acknowledgment) for packet loss recovery
    /// - TWCC (Transport-Wide Congestion Control) for bandwidth estimation
    /// - RTCP Reports for quality statistics
    ///
    /// This method replaces the builder's interceptor type — `NoopInterceptor` by default —
    /// with the registry's, so it returns a `RTCPeerConnectionBuilder<P>` rather than
    /// `Self`. Every other builder setting is carried over, and the remaining setters are
    /// available on the returned builder, so this does not have to be the last call before
    /// `build()`; it is simply the only one that changes the builder's type.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The interceptor type produced by the registry
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    /// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
    /// use rtc::interceptor::Registry;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// let registry = Registry::new();
    /// let registry = register_default_interceptors(registry, &mut media_engine)?;
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_media_engine(media_engine)
    ///     .with_interceptor_registry(registry)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # One connection type, whatever the chain
    ///
    /// A chain is a flat list of interceptors, so the connection has one concrete type whatever
    /// the list contains. That is what lets a non-generic struct own one, or two connections with
    /// *different* chains share a collection:
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::interceptor::Registry;
    /// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    /// use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
    ///
    /// struct Session {
    ///     peer_connection: RTCPeerConnection, // no type parameter
    /// }
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    ///
    /// let session = Session {
    ///     peer_connection: RTCPeerConnectionBuilder::new()
    ///         .with_media_engine(media_engine)
    ///         .with_interceptor_registry(registry)
    ///         .build(Instant::now())?,
    /// };
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The registry is assembled into the chain by [`build`](RTCPeerConnectionBuilder::build),
    /// so it stays a list — inspectable, extendable — right up until the connection is made.
    pub fn with_interceptor_registry(mut self, interceptor_registry: Registry) -> Self {
        self.interceptor_registry = interceptor_registry;
        self
    }

    /// Builds the RTCPeerConnection with the configured settings.
    ///
    /// This method validates the configuration and creates a new peer connection.
    /// If validation fails (e.g., expired certificates, invalid ICE servers),
    /// an error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificates have expired
    /// - ICE server URLs are invalid
    /// - Other validation checks fail
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, now: Instant) -> Result<RTCPeerConnection> {
        RTCPeerConnection::new(
            now,
            self.configuration,
            self.media_engine,
            self.setting_engine,
            // The registry is a list until here; `build` freezes it into the chain.
            Box::new(self.interceptor_registry.build()),
        )
    }
}

/// The `RTCPeerConnection` interface represents a WebRTC connection between the local computer
/// and a remote peer. It provides methods to connect to a remote peer, maintain and monitor
/// the connection, and close the connection once it's no longer needed.
///
/// This is a sans-I/O implementation following the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/).
///
/// # Examples
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
pub struct RTCPeerConnection {
    //////////////////////////////////////////////////
    // PeerConnection WebRTC Spec Interface Definition
    //////////////////////////////////////////////////
    pub(crate) configuration: RTCConfiguration,
    pub(crate) media_engine: MediaEngine,
    pub(crate) setting_engine: SettingEngine,
    pub(crate) interceptor: Box<dyn Interceptor>,

    local_description: Option<RTCSessionDescription>,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    remote_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,

    pub(crate) signaling_state: RTCSignalingState,
    pub(crate) peer_connection_state: RTCPeerConnectionState,
    can_trickle_ice_candidates: Option<bool>,

    //////////////////////////////////////////////////
    // PeerConnection Internal State Machine
    //////////////////////////////////////////////////
    pub(crate) pipeline_context: PipelineContext,
    pub(crate) data_channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,
    pub(super) rtp_transceivers: Vec<RTCRtpTransceiverInternal>,

    greater_mid: isize,
    sdp_origin: Origin,
    last_offer: String,
    last_answer: String,

    ice_restart_requested: Option<RTCOfferOptions>,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_ongoing: bool,
}

impl RTCPeerConnection {
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

        // Staging, not restarting: the offer must advertise fresh ICE credentials, but JSEP
        // requires `createOffer` to be free of side effects, and inbound STUN is still being
        // validated against the current ufrag/pwd. `set_local_description` applies the restart.
        let is_ice_restart_requested = self
            .ice_restart_requested
            .take()
            .is_some_and(|options| options.ice_restart)
            || options.take().is_some_and(|options| options.ice_restart);

        if is_ice_restart_requested {
            self.stage_ice_restart()?;
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
            } else {
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
    /// Creates an SDP answer in response to an offer from a remote peer.
    ///
    /// This method must be called after `set_remote_description()` has been called
    /// with an offer. The answer describes which media formats and codecs this peer
    /// will accept and how the connection will be established.
    ///
    /// # Parameters
    ///
    /// - `options`: Optional answer configuration. Currently not used but reserved
    ///   for future extensions.
    ///
    /// # Returns
    ///
    /// Returns an `RTCSessionDescription` containing the SDP answer that should be
    /// set as the local description and sent to the remote peer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No remote description has been set (`ErrNoRemoteDescription`)
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The signaling state is incorrect (`ErrIncorrectSignalingState`)
    /// - SDP generation fails
    ///
    /// # Signaling State Requirements
    ///
    /// This method can only be called when the signaling state is:
    /// - `HaveRemoteOffer` - After receiving an initial offer
    /// - `HaveLocalPranswer` - After sending a provisional answer
    ///
    /// # Examples
    ///
    /// ## Basic Answer Flow
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    ///
    /// # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // 1. Receive and set remote offer
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // 2. Create answer
    /// let answer = pc.create_answer(None)?;
    ///
    /// // 3. Set as local description
    /// pc.set_local_description(Instant::now(), answer.clone())?;
    ///
    /// // 4. Send answer to remote peer
    /// // signaling_channel.send(answer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## With Media Tracks
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    /// use rtc::media_stream::MediaStreamTrack;
    ///
    /// # fn example(
    /// #     remote_offer_sdp: String,
    /// #     audio_track: MediaStreamTrack,
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Set remote offer
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // Add local track before creating answer
    /// pc.add_track(audio_track)?;
    ///
    /// // Create answer (will include the track)
    /// let answer = pc.create_answer(None)?;
    /// pc.set_local_description(Instant::now(), answer)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # DTLS Role Selection
    ///
    /// The answer automatically determines the appropriate DTLS role:
    /// - Uses `answering_dtls_role` from settings if configured
    /// - Defaults to `Client` (active) for lower latency
    /// - Uses `Server` (passive) if remote is ICE-Lite
    ///
    /// # Specifications
    ///
    /// - [W3C RTCPeerConnection.createAnswer]
    /// - [RFC 8829 Section 5.3] - Generating an Answer
    ///
    /// [W3C RTCPeerConnection.createAnswer]: https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createanswer
    /// [RFC 8829 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc8829#section-5.3
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

        let mut connection_role = self.setting_engine.answering_dtls_role.to_connection_role();
        if connection_role == ConnectionRole::Unspecified {
            connection_role = DEFAULT_DTLS_ROLE_ANSWER.to_connection_role();

            if let Some(remote_description) = self.remote_description()
                && let Some(parsed) = remote_description.parsed.as_ref()
                && is_lite_set(parsed)
                && !self.setting_engine.candidates.ice_lite
            {
                connection_role = RTCDtlsRole::Server.to_connection_role();
            }
        }

        let mut d = self.generate_matched_sdp(
            false, /*includeUnmatched */
            connection_role,
            self.setting_engine.ignore_rid_pause_for_recv,
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
    /// Sets the local description for this peer connection.
    ///
    /// This method applies a local SDP description (offer or answer) to the peer
    /// connection, updating the local media and transport configuration. It must be
    /// called after creating an offer or answer.
    ///
    /// # Parameters
    ///
    /// - `local_description`: The session description to set as the local description.
    ///   This should be an offer or answer created by `create_offer()` or `create_answer()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The SDP type is invalid for the current signaling state
    /// - SDP parsing fails
    /// - Transport configuration fails
    ///
    /// # Signaling State Transitions
    ///
    /// Setting the local description causes signaling state transitions:
    ///
    /// - **Offer**: `Stable` → `HaveLocalOffer`
    /// - **Answer**: `HaveRemoteOffer` → `Stable`
    /// - **Pranswer**: `HaveRemoteOffer` → `HaveLocalPranswer`
    ///
    /// # Examples
    ///
    /// ## Setting Local Offer
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Create offer
    /// let offer = pc.create_offer(None)?;
    ///
    /// // Set as local description
    /// pc.set_local_description(Instant::now(), offer.clone())?;
    ///
    /// // Now send offer.sdp to remote peer via signaling
    /// // signaling_channel.send(offer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Setting Local Answer
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    ///
    /// # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Set remote offer first
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // Create and set local answer
    /// let answer = pc.create_answer(None)?;
    /// pc.set_local_description(Instant::now(), answer.clone())?;
    ///
    /// // Send answer to remote peer
    /// // signaling_channel.send(answer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Empty SDP Handling (JSEP 5.4)
    ///
    /// If the SDP string is empty, the last offer or answer is reused:
    /// - For offers: Uses the last generated offer
    /// - For answers: Uses the last generated answer
    ///
    /// This allows re-applying descriptions without regenerating SDP.
    ///
    /// # Media and Transport Activation
    ///
    /// When setting a local answer:
    /// - RTP transceivers are activated
    /// - SCTP transport is started for data channels
    /// - Media can begin flowing
    ///
    /// # Specifications
    ///
    /// - [W3C RTCPeerConnection.setLocalDescription]
    /// - [RFC 8829 Section 5.4] - Setting the Session Description
    ///
    /// [W3C RTCPeerConnection.setLocalDescription]: https://w3c.github.io/webrtc-pc/#dom-peerconnection-setlocaldescription
    /// [RFC 8829 Section 5.4]: https://datatracker.ietf.org/doc/html/rfc8829#section-5.4
    pub fn set_local_description(
        &mut self,
        now: Instant,
        mut local_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // Apply an ICE restart staged by `create_offer`. A no-op if none was staged, so an offer
        // that was created and then discarded leaves the existing session untouched.
        if self.ice_transport().has_pending_restart() {
            self.apply_ice_restart(now)?;
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
                RTCSdpType::Rollback => {
                    // WebRTC spec: rollback SDP is ignored, empty is allowed
                }
                _ => return Err(Error::ErrPeerConnSDPTypeInvalidValueSetLocalDescription),
            }
        }

        // Parse SDP (skip for rollback as content is ignored per spec)
        if local_description.sdp_type != RTCSdpType::Rollback {
            local_description.parsed = Some(local_description.unmarshal()?);
        }
        self.set_description(&local_description, StateChangeOp::SetLocal)?;

        let we_answer = local_description.sdp_type == RTCSdpType::Answer;
        if we_answer && let Some(parsed_local_description) = &local_description.parsed {
            // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
            // Section 4.4.1.5
            for media in &parsed_local_description.media_descriptions {
                let mid_value = match get_mid_value(media) {
                    Some(mid) if !mid.is_empty() => mid,
                    _ => return Err(Error::ErrPeerConnLocalDescriptionWithoutMidValue),
                };

                if media.media_name.media == MEDIA_SECTION_APPLICATION {
                    continue;
                }

                let i = match RTCPeerConnection::find_by_mid(mid_value, &self.rtp_transceivers) {
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

                // If a transceiver is created by applying a remote description that has recvonly transceiver,
                // it will have no sender. In this case, the transceiver's current direction is set to inactive so
                // that the transceiver can be reused by next AddTrack.
                if direction == RTCRtpTransceiverDirection::Sendonly
                    && self.rtp_transceivers[i].sender().is_none()
                {
                    direction = RTCRtpTransceiverDirection::Inactive;
                }

                self.rtp_transceivers[i].set_current_direction(direction);
            }

            if let Some(remote_description) = self.remote_description().cloned()
                && let Some(parsed_remote_description) = remote_description.parsed.as_ref()
            {
                // only start sctp transport if application media has been negotiated
                if let (Some(local_application_media), Some(remote_application_media)) = (
                    get_application_media(parsed_local_description),
                    get_application_media(parsed_remote_description),
                ) {
                    let (dtls_role, remote_caps, local_sctp_port, remote_sctp_port) = (
                        self.dtls_transport().role(),
                        SCTPTransportCapabilities {
                            max_message_size: get_application_media_section_max_message_size(
                                remote_application_media,
                            )
                            .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE),
                        },
                        get_application_media_section_sctp_port(local_application_media)
                            .unwrap_or(5000),
                        get_application_media_section_sctp_port(remote_application_media)
                            .unwrap_or(5000),
                    );

                    // we_answer: we first call set_remote_description,
                    // then, we create_answer() and set_local_description() here
                    // Now we should have done SDP negotiation.
                    // Therefore, it is ready to start sctp and rtp.
                    self.sctp_transport_mut().start(
                        dtls_role,
                        remote_caps,
                        local_sctp_port,
                        remote_sctp_port,
                    )?;
                }
                self.start_rtp(remote_description)?;
            }
        }

        self.ice_transport_mut().ice_gathering_state = RTCIceGatheringState::Gathering;

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
    pub fn local_description(&self) -> Option<RTCSessionDescription> {
        if let Some(pending_local_description) = self.pending_local_description() {
            return Some(pending_local_description);
        }
        self.current_local_description()
    }

    /// Returns the current local description as last successfully negotiated since
    /// the last negotiation completed.
    ///
    /// This represents the local description from the last offer/answer exchange that was
    /// successfully applied, not including any offers currently being negotiated.
    ///
    /// Returns `None` if there is no current local description (e.g., before initial negotiation).
    ///
    /// # Specification
    ///
    /// See [currentLocalDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-currentlocaldescription)
    pub fn current_local_description(&self) -> Option<RTCSessionDescription> {
        self.populate_local_candidates(self.current_local_description.as_ref())
    }

    /// Returns the pending local description if it exists.
    ///
    /// This represents the local description from a call to `set_local_description()` whose
    /// corresponding remote description has not yet been applied. This is `None` if negotiation
    /// is not in progress or if a rollback has been performed.
    ///
    /// Returns `None` if there is no pending local description.
    ///
    /// # Specification
    ///
    /// See [pendingLocalDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-pendinglocaldescription)
    pub fn pending_local_description(&self) -> Option<RTCSessionDescription> {
        self.populate_local_candidates(self.pending_local_description.as_ref())
    }

    /// Returns whether the remote peer supports trickle ICE.
    ///
    /// This value is determined from the remote SDP description after `set_remote_description()`
    /// is called. It checks for "trickle" in the "ice-options" attribute per
    /// RFC 8838 and RFC 9429 section 4.1.17.
    ///
    /// Returns:
    /// - `None` if no remote description has been set yet (unknown)
    /// - `Some(true)` if the remote peer indicated trickle ICE support
    /// - `Some(false)` if the remote peer did not indicate support
    ///
    /// # Specification
    ///
    /// See [canTrickleIceCandidates](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-cantrickleicecandidates)
    pub fn can_trickle_ice_candidates(&self) -> Option<bool> {
        self.can_trickle_ice_candidates
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
        now: Instant,
        mut remote_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let is_renegotiation = self.current_remote_description.is_some();

        // Parse SDP (skip for rollback as content is ignored per spec)
        if remote_description.sdp_type != RTCSdpType::Rollback {
            remote_description.parsed = Some(remote_description.unmarshal()?);
        }
        self.set_description(&remote_description, StateChangeOp::SetRemote)?;

        if let Some(parsed_remote_description) = &remote_description.parsed {
            self.media_engine
                .update_from_remote_description(parsed_remote_description)?;

            // Detect trickle ICE support from remote SDP (RFC 8838/RFC 9429 section 4.1.17)
            // Check for "trickle" in space-separated "ice-options" attribute values
            let has_trickle_ice = has_ice_trickle_option(parsed_remote_description);

            match remote_description.sdp_type {
                RTCSdpType::Offer | RTCSdpType::Answer | RTCSdpType::Pranswer => {
                    self.can_trickle_ice_candidates = Some(has_trickle_ice);
                }
                _ => {
                    // Rollback or other types: reset to unknown
                    self.can_trickle_ice_candidates = None;
                }
            }

            // Disable RTX/FEC on RTPSenders if the remote didn't support it
            for transceiver in &mut self.rtp_transceivers {
                if let Some(sender) = transceiver.sender_mut() {
                    let (is_rtx_enabled, is_fec_enabled) = (
                        self.media_engine
                            .is_rtx_enabled(sender.kind(), RTCRtpTransceiverDirection::Sendonly),
                        self.media_engine
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
                            Some(mid) if !mid.is_empty() => mid,
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
                            RTCPeerConnection::find_by_mid(mid_value, &self.rtp_transceivers)
                        {
                            if direction == RTCRtpTransceiverDirection::Inactive {
                                self.rtp_transceivers[i]
                                    .stop(&self.media_engine, &mut self.interceptor)?;
                            }
                            Some(&mut self.rtp_transceivers[i])
                        } else {
                            RTCPeerConnection::satisfy_type_and_direction(
                                kind,
                                direction,
                                &mut self.rtp_transceivers,
                            )
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
                                &self.media_engine,
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

                            let mut transceiver = RTCRtpTransceiverInternal::new(
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
                                &self.media_engine,
                            )?;

                            if transceiver.mid().is_none() {
                                transceiver.set_mid(mid_value.to_string())?;
                            }

                            // Mark as implicitly created by a remote offer so that, if this offer
                            // is later rolled back, the transceiver is stopped and removed
                            // (RFC 8829, Section 5.7) — unless a track is attached via add_track.
                            transceiver.set_created_by_remote_description(true);

                            self.add_rtp_transceiver(transceiver);
                        }
                    }
                } else {
                    // we_offer
                    // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                    // 4.5.9.2
                    // This is an answer from the remote.
                    for media in &media_descriptions {
                        let mid_value = match get_mid_value(media) {
                            Some(mid) if !mid.is_empty() => mid,
                            _ => return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue),
                        };

                        if media.media_name.media == MEDIA_SECTION_APPLICATION {
                            continue;
                        }

                        let kind = RtpCodecKind::from(media.media_name.media.as_str());
                        let mut direction = get_peer_direction(media);
                        if kind == RtpCodecKind::Unspecified
                            || direction == RTCRtpTransceiverDirection::Unspecified
                        {
                            continue;
                        }

                        let transceiver = if let Some(i) =
                            RTCPeerConnection::find_by_mid(mid_value, &self.rtp_transceivers)
                        {
                            &mut self.rtp_transceivers[i]
                        } else {
                            return Err(Error::ErrPeerConnTransceiverMidNil);
                        };

                        // reverse direction if it was a remote answer
                        if direction == RTCRtpTransceiverDirection::Sendonly {
                            direction = RTCRtpTransceiverDirection::Recvonly;
                        } else if direction == RTCRtpTransceiverDirection::Recvonly {
                            direction = RTCRtpTransceiverDirection::Sendonly;
                        }

                        transceiver.set_current_direction(direction);

                        transceiver.set_codec_preferences_from_remote_description(
                            media,
                            &self.media_engine,
                        )?;
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

                if !we_offer {
                    // The answerer restarts in one step: it has `now`, and the answer it generates
                    // next must already carry the new local credentials.
                    self.stage_ice_restart()?;
                    self.apply_ice_restart(now)?;
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
                    && remote_is_lite == self.setting_engine.candidates.ice_lite)
                    || (remote_is_lite && !self.setting_engine.candidates.ice_lite)
                {
                    RTCIceRole::Controlling
                } else {
                    RTCIceRole::Controlled
                };

                let remote_dtls_role = RTCDtlsRole::from(parsed_remote_description);
                log::trace!(
                    "start_transports: local_ice_role={local_ice_role}, remote_dtls_role={remote_dtls_role}"
                );

                self.start_transports(
                    now,
                    local_ice_role,
                    RTCIceParameters {
                        username_fragment: remote_ufrag,
                        password: remote_pwd,
                        ice_lite: remote_is_lite,
                    },
                    RTCDtlsParameters {
                        role: remote_dtls_role,
                        fingerprints: vec![RTCDtlsFingerprint {
                            algorithm: remote_fingerprint_hash,
                            value: remote_fingerprint,
                        }],
                    },
                )?;
            }

            if we_offer
                && let Some(parsed_local_description) = self
                    .current_local_description
                    .as_ref()
                    .and_then(|desc| desc.parsed.as_ref())
            {
                // only start sctp transport if application media has been negotiated
                if let (Some(local_application_media), Some(remote_application_media)) = (
                    get_application_media(parsed_local_description),
                    get_application_media(parsed_remote_description),
                ) {
                    let (dtls_role, remote_caps, local_sctp_port, remote_sctp_port) = (
                        self.dtls_transport().role(),
                        SCTPTransportCapabilities {
                            max_message_size: get_application_media_section_max_message_size(
                                remote_application_media,
                            )
                            .unwrap_or(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE),
                        },
                        get_application_media_section_sctp_port(local_application_media)
                            .unwrap_or(5000),
                        get_application_media_section_sctp_port(remote_application_media)
                            .unwrap_or(5000),
                    );

                    // we_offer: we create_offer() and set_local_description() first
                    // then, after call set_remote_description here,
                    // Now we should have done SDP negotiation.
                    // Therefore, it is ready to start sctp and rtp.
                    self.sctp_transport_mut().start(
                        dtls_role,
                        remote_caps,
                        local_sctp_port,
                        remote_sctp_port,
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

    /// Returns the current remote description as last successfully negotiated since
    /// the last negotiation completed.
    ///
    /// This represents the remote description from the last offer/answer exchange that was
    /// successfully applied, not including any offers currently being negotiated.
    ///
    /// Returns `None` if there is no current remote description (e.g., before initial negotiation).
    ///
    /// # Specification
    ///
    /// See [currentRemoteDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-currentremotedescription)
    pub fn current_remote_description(&self) -> Option<&RTCSessionDescription> {
        self.current_remote_description.as_ref()
    }

    /// Returns the pending remote description if it exists.
    ///
    /// This represents the remote description from a call to `set_remote_description()` whose
    /// corresponding local description has not yet been applied. This is `None` if negotiation
    /// is not in progress or if a rollback has been performed.
    ///
    /// Returns `None` if there is no pending remote description.
    ///
    /// # Specification
    ///
    /// See [pendingRemoteDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-pendingremotedescription)
    pub fn pending_remote_description(&self) -> Option<&RTCSessionDescription> {
        self.pending_remote_description.as_ref()
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
            self.add_ice_remote_candidate(candidate_value)?;
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
    /// * `local_candidate` - The ICE candidate initialization data. For candidates of
    ///   type "srflx" (server reflexive) or "relay", the `url` field should contain
    ///   the STUN/TURN server URL used to gather the candidate.
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
            self.add_ice_local_candidate(candidate_value, local_candidate.url.as_deref())?;
        } else {
            self.ice_transport_mut().ice_gathering_state = RTCIceGatheringState::Complete;
            // Emit OnIceGatheringStateChangeEvent
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(
                    RTCIceGatheringState::Complete,
                ),
            );
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

        // `None` means "the dictionary defaults", which is what `RTCDataChannelInit::default()`
        // spells out. Taking that route rather than leaving `params` on its derived default
        // keeps a single definition of those defaults — notably `ordered`, which is `true`.
        let options = options.unwrap_or_default();

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

        let mut data_channel = RTCDataChannelInternal::new(id, params);

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #23)
        // Open the channel's data transport immediately when an SCTP association already exists.
        if let Some(handle) = self
            .sctp_transport()
            .sctp_associations
            .keys()
            .next()
            .copied()
            && data_channel.ready_state == RTCDataChannelState::Connecting
            && data_channel.data_channel.is_none()
        {
            data_channel.dial(handle.0)?;
        }

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
        let (track, send_encodings, codec_preferences) =
            self.normalize_sender_track(track, send_encodings)?;
        for (id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            if !transceiver.stopped()
                && transceiver.kind() == track.kind()
                && transceiver.sender().is_none()
            {
                let mut sender =
                    RTCRtpSenderInternal::new(track.kind(), track, vec![], send_encodings);

                if transceiver.get_codec_preferences().is_empty() && !codec_preferences.is_empty() {
                    transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
                }

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

        let mut transceiver = self.new_transceiver_from_track(
            track,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings,
            },
        )?;
        if !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }
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
            && sender
                .stop(&self.media_engine, &mut self.interceptor)
                .is_ok()
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

        let mut init = if let Some(init) = init {
            init
        } else {
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings: vec![],
            }
        };

        let send_encodings = if init.send_encodings.is_empty() {
            self.send_encodings_from_track(&track)
        } else {
            init.send_encodings.clone()
        };
        let (track, send_encodings, codec_preferences) =
            self.normalize_sender_track(track, send_encodings)?;
        init.send_encodings = send_encodings;

        let mut transceiver = self.new_transceiver_from_track(track, init)?;
        if !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }

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

        let init = if let Some(init) = init {
            if init.direction.has_send() && init.send_encodings.is_empty() {
                return Err(Error::ErrInvalidDirection);
            }

            init
        } else {
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            }
        };

        let transceiver = match init.direction {
            RTCRtpTransceiverDirection::Sendonly | RTCRtpTransceiverDirection::Sendrecv => {
                let mut init = init;
                let track = MediaStreamTrack::new(
                    math_rand_alpha(16), // MediaStreamId
                    math_rand_alpha(16), // MediaStreamTrackId
                    math_rand_alpha(16), // Label
                    kind,
                    init.send_encodings.clone(),
                );
                let (track, send_encodings, codec_preferences) =
                    self.normalize_sender_track(track, init.send_encodings)?;
                init.send_encodings = send_encodings;

                let mut transceiver = self.new_transceiver_from_track(track, init)?;
                if !codec_preferences.is_empty() {
                    transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
                }
                transceiver
            }
            RTCRtpTransceiverDirection::Recvonly => {
                RTCRtpTransceiverInternal::new(kind, None, init)
            }
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

    /// The SCTP transport over which data channels are carried.
    ///
    /// `None` until SCTP has been negotiated — that is, until a description establishing an
    /// SCTP association has been applied by both sides. A connection carrying only media never
    /// has one.
    ///
    /// This is the **only** transport accessor on `RTCPeerConnection`, matching the W3C
    /// interface, which exposes `sctp` and nothing else. The DTLS and ICE transports are
    /// reached by walking from here (or from a sender or receiver):
    ///
    /// ```text
    /// pc.sctp()?.transport().ice_transport()
    /// ```
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-sctp)
    pub fn sctp(&self) -> Option<RTCSctpTransport<'_>> {
        if self.sctp_transport().is_started {
            Some(RTCSctpTransport {
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// rtp_sender provides the access to RTCRtpSender object with the given id
    pub fn rtp_sender(&mut self, id: RTCRtpSenderId) -> Option<RTCRtpSender<'_>> {
        if id.0 < self.rtp_transceivers.len()
            && self.rtp_transceivers[id.0].direction().has_send()
            && self.rtp_transceivers[id.0].sender().is_some()
        {
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
        if id.0 < self.rtp_transceivers.len()
            && self.rtp_transceivers[id.0].direction().has_recv()
            && self.rtp_transceivers[id.0].receiver().is_some()
        {
            Some(RTCRtpReceiver {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// rtp_transceiver provides the access to RTCRtpTransceiver object with the given id
    pub fn rtp_transceiver(&mut self, id: RTCRtpTransceiverId) -> Option<RTCRtpTransceiver<'_>> {
        if id < self.rtp_transceivers.len() {
            Some(RTCRtpTransceiver {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// Returns a snapshot of accumulated statistics.
    ///
    /// This method creates an immutable snapshot of WebRTC statistics
    /// at the given timestamp. When `selector` is `StatsSelector::None`,
    /// the returned `RTCStatsReport` contains statistics for all aspects
    /// of the peer connection. When a sender or receiver is specified,
    /// only statistics relevant to that sender/receiver are included.
    ///
    /// # Statistics included by selector
    ///
    /// - `StatsSelector::None` - All statistics for the entire connection
    /// - `StatsSelector::Sender(id)` - Outbound RTP streams for the sender
    ///   and all referenced stats (transport, codec, remote inbound, etc.)
    /// - `StatsSelector::Receiver(id)` - Inbound RTP streams for the receiver
    ///   and all referenced stats (transport, codec, remote outbound, etc.)
    ///
    /// # Arguments
    ///
    /// * `now` - The timestamp to use for all stats in the report. This is
    ///   passed explicitly to support deterministic testing.
    /// * `selector` - Controls which statistics are included in the report.
    ///
    /// # Returns
    ///
    /// An `RTCStatsReport` containing snapshots of the selected statistics.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::statistics::StatsSelector;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Get all stats
    /// let report = pc.get_stats(Instant::now(), StatsSelector::None);
    ///
    /// // Access peer connection stats
    /// if let Some(pc_stats) = report.peer_connection() {
    ///     println!("Data channels opened: {}", pc_stats.data_channels_opened);
    /// }
    ///
    /// // Iterate over inbound RTP streams
    /// for stream in report.inbound_rtp_streams() {
    ///     println!("SSRC {}: {} packets received", stream.received_rtp_stream_stats.rtp_stream_stats.ssrc, stream.received_rtp_stream_stats.packets_received);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [getStats](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getstats) and
    /// [The stats selection algorithm](https://www.w3.org/TR/webrtc/#the-stats-selection-algorithm)
    pub fn get_stats(&mut self, now: Instant, selector: StatsSelector) -> RTCStatsReport {
        // Update ICE agent stats before taking snapshot
        self.update_ice_agent_stats(now);
        // Update codec stats from transceivers before taking snapshot
        self.update_codec_stats();
        self.pipeline_context
            .stats
            .snapshot_with_selector(now, selector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_channel::state::RTCDataChannelState;
    use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use crate::peer_connection::transport::RTCIceComponent;
    use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
    use sctp::AssociationHandle;

    #[test]
    fn with_sctp_receive_buffer_size_sets_and_clamps() {
        let setting_engine = SettingEngineBuilder::new()
            .with_sctp_max_receive_buffer_size(200_000)
            .build();

        let builder = RTCPeerConnectionBuilder::new().with_setting_engine(setting_engine);
        assert_eq!(
            builder.setting_engine.sctp_max_receive_buffer_size,
            Some(200_000)
        );

        // Values below the RFC 4960 §6 floor (1500 bytes), including 0, are clamped up so
        // they cannot break the SCTP handshake.
        for input in [0u32, 500, 1499] {
            let setting_engine = SettingEngineBuilder::new()
                .with_sctp_max_receive_buffer_size(input)
                .build();
            let builder = RTCPeerConnectionBuilder::new().with_setting_engine(setting_engine);
            assert_eq!(
                builder.setting_engine.sctp_max_receive_buffer_size,
                Some(1500),
                "input {input} should clamp up to the 1500-byte floor"
            );
        }
    }

    // The graph the spec exposes: `pc.sctp` is the only way in, and the rest is walked.
    #[test]
    fn sctp_is_none_until_sctp_is_negotiated() {
        let pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        assert!(
            pc.sctp().is_none(),
            "nothing has been negotiated, so there is no SCTP transport to expose"
        );
    }

    #[test]
    fn the_transport_graph_is_walkable_and_ids_identify() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        // `start()` is what negotiation calls once both descriptions carry an m=application
        // section; it is the predicate `sctp()` keys off.
        pc.sctp_transport_mut()
            .start(
                RTCDtlsRole::Client,
                crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");

        let sctp = pc.sctp().expect("SCTP is negotiated");
        let dtls = sctp.transport();
        let ice = dtls.ice_transport();

        // Three transports, three identities.
        assert_ne!(sctp.id(), dtls.id());
        assert_ne!(dtls.id(), ice.id());
        assert_ne!(sctp.id(), ice.id());

        // Ids are stored, not minted per call: walking twice yields the same identity.
        let dtls_again = pc.sctp().unwrap().transport();
        assert_eq!(dtls.id(), dtls_again.id());
        assert_eq!(ice.id(), dtls_again.ice_transport().id());

        // The default configuration caps messages at 64 KiB and the peer advertised no limit,
        // so the negotiated value is this endpoint's cap.
        assert_eq!(Some(65536), sctp.max_message_size());
        // No association yet, so no negotiated stream count.
        assert_eq!(None, sctp.max_channels());
        assert_eq!(RTCIceComponent::Rtp, ice.component());
    }

    // W3C types `maxMessageSize` `unrestricted double` so that an implementation with no limit
    // can report +Infinity. This one always has a limit — the working buffer is a real
    // allocation — so a configuration naming no limit resolves to the implementation ceiling,
    // and the value reported is the value enforced.
    #[test]
    fn max_message_size_with_no_configured_limit_reports_the_ceiling() {
        let setting_engine = SettingEngineBuilder::new()
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(0))
            .build();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(setting_engine)
            .build(Instant::now())
            .unwrap();
        pc.sctp_transport_mut()
            .start(
                RTCDtlsRole::Client,
                crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");

        assert_eq!(
            Some(SctpMaxMessageSize::MAX_MESSAGE_SIZE),
            pc.sctp().expect("negotiated").max_message_size()
        );
    }

    // `RTCRtpSender.transport` / `RTCRtpReceiver.transport` come from the per-object
    // `[[SenderTransport]]` / `[[ReceiverTransport]]` slots, filled when the transceiver is
    // associated by negotiation. Before that the spec reports null.
    #[test]
    fn sender_and_receiver_transport_are_none_until_the_transceiver_is_associated() {
        let mut pc = media_pc();
        // `add_track` creates a sendrecv transceiver, so this one has both a sender and a
        // receiver while still being unassociated.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        let sender_id = pc.add_track(track).expect("add track");
        let receiver_id = RTCRtpReceiverId::from(sender_id.0);

        assert!(pc.rtp_transceivers[sender_id.0].mid().is_none());
        assert!(
            pc.rtp_sender(sender_id)
                .expect("sender")
                .transport()
                .is_none(),
            "an unassociated sender has a null transport"
        );
        assert!(
            pc.rtp_receiver(receiver_id)
                .expect("receiver")
                .transport()
                .is_none(),
            "an unassociated receiver has a null transport"
        );

        // Applying a local offer associates the transceiver. This is the offerer's window: a mid
        // exists, but no answer has arrived so DTLS has not started — and a browser reports a
        // transport here, which is why the predicate is association rather than "DTLS is up".
        let offer = pc.create_offer(None).expect("create offer");
        pc.set_local_description(Instant::now(), offer)
            .expect("set local description");
        assert!(pc.rtp_transceivers[sender_id.0].mid().is_some());
        assert!(
            !pc.dtls_transport().is_started(),
            "no answer yet, so DTLS has not been brought up"
        );

        let sender_transport_id = pc
            .rtp_sender(sender_id)
            .expect("sender")
            .transport()
            .expect("an associated sender has a transport")
            .id();
        let receiver_transport_id = pc
            .rtp_receiver(receiver_id)
            .expect("receiver")
            .transport()
            .expect("an associated receiver has a transport")
            .id();

        // Under bundling both directions share one DTLS transport, as the spec says...
        assert_eq!(sender_transport_id, receiver_transport_id);
        // ...and it is the same transport the rest of the graph names.
        assert_eq!(sender_transport_id, pc.dtls_transport().id);
        // Its state is `New` until the handshake begins: a transport that exists but has not
        // connected, exactly as a browser reports in this window.
        assert_eq!(RTCDtlsTransportState::New, pc.dtls_transport().state());
    }

    // `with_discard_local_candidates_during_ice_restart` has to reach `apply_restart`, not just
    // land in the struct. Applying a restart with it set must empty the local candidates the
    // agent had gathered; with it unset they survive.
    //
    // This is the setting that makes a socket-rebinding ICE restart work (webrtc#868): retained
    // candidates name addresses nothing is bound to any more, so checks written for them go
    // nowhere and the restarted generation never leaves `Checking`.
    #[test]
    fn discard_local_candidates_during_ice_restart_reaches_apply_restart() {
        fn restart_with(discard: bool) -> usize {
            let setting_engine = SettingEngineBuilder::new()
                .with_discard_local_candidates_during_ice_restart(discard)
                .build();
            let mut pc = RTCPeerConnectionBuilder::new()
                .with_setting_engine(setting_engine)
                .build(Instant::now())
                .unwrap();

            // Gather one host candidate so there is something to keep or drop.
            pc.add_local_candidate(RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host".to_owned(),
                ..Default::default()
            })
            .expect("add local candidate");
            assert_eq!(
                1,
                pc.ice_transport().get_local_candidates().unwrap().len(),
                "precondition: the agent holds the gathered candidate"
            );

            pc.ice_transport_mut()
                .generate_restart_credentials(
                    "newufrag".to_owned(),
                    "newpasswordlongenough".to_owned(),
                )
                .expect("stage restart");
            pc.apply_ice_restart(Instant::now())
                .expect("apply ice restart");

            pc.ice_transport().get_local_candidates().unwrap().len()
        }

        assert_eq!(
            0,
            restart_with(true),
            "with discard enabled the stale generation's candidates are dropped"
        );
        assert_eq!(
            1,
            restart_with(false),
            "the default keeps them, which is the pre-existing behaviour"
        );
    }

    // Two connections must never report the same transport as each other's. This is the case a
    // per-connection counter or a small-integer scheme gets wrong.
    #[test]
    fn transports_of_two_peer_connections_are_never_equal() {
        let mut ids = vec![];
        for _ in 0..2 {
            let mut pc = RTCPeerConnectionBuilder::new()
                .build(Instant::now())
                .unwrap();
            pc.sctp_transport_mut()
                .start(
                    RTCDtlsRole::Client,
                    crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                        max_message_size: 0,
                    },
                    5000,
                    5000,
                )
                .expect("start");
            let sctp = pc.sctp().expect("SCTP is negotiated");
            ids.push((
                sctp.id(),
                sctp.transport().id(),
                sctp.transport().ice_transport().id(),
            ));
        }

        let (a_sctp, a_dtls, a_ice) = ids[0];
        let (b_sctp, b_dtls, b_ice) = ids[1];
        assert_ne!(a_sctp, b_sctp);
        assert_ne!(a_dtls, b_dtls);
        assert_ne!(a_ice, b_ice);
    }

    #[test]
    fn create_data_channel_dials_immediately_when_sctp_association_present() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();

        // Simulate an SCTP association so create_data_channel sees a transport
        // that is ready to open streams.
        pc.sctp_transport_mut()
            .sctp_associations
            .insert(AssociationHandle(0), sctp::Association::default());

        let _dc = pc.create_data_channel("test", None).unwrap();

        let internal = pc
            .data_channels
            .values()
            .next()
            .expect("data channel must be stored internally");
        assert!(internal.data_channel.is_some());
        assert_eq!(internal.ready_state, RTCDataChannelState::Open);
    }

    // ---- Rollback (RFC 8829, Section 5.7) ----

    use crate::peer_connection::configuration::media_engine::MediaEngine;
    use crate::rtp_transceiver::RTCRtpTransceiverInit;

    fn media_pc() -> RTCPeerConnection {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .build(Instant::now())
            .unwrap()
    }

    /// Builds an audio+video offer from a freshly-created peer connection.
    fn audio_video_offer() -> RTCSessionDescription {
        let mut offerer = media_pc();
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Audio,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        offerer.create_offer(None).unwrap()
    }

    fn rollback() -> RTCSessionDescription {
        RTCSessionDescription {
            sdp_type: RTCSdpType::Rollback,
            sdp: String::new(),
            parsed: None,
        }
    }

    #[test]
    fn set_remote_rollback_removes_transceivers_created_by_remote_offer() {
        let offer = audio_video_offer();

        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();

        // Applying the remote offer implicitly creates two transceivers, each associated
        // with an "m=" section.
        assert_eq!(pc.rtp_transceivers.len(), 2);
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        assert!(pc.rtp_transceivers.iter().all(|t| t.mid().is_some()));

        // Rolling back the offer must stop and remove those transceivers and return to stable.
        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert!(
            pc.rtp_transceivers.is_empty(),
            "transceivers created by a rolled-back remote offer must be removed"
        );
    }

    #[test]
    fn set_local_rollback_disassociates_but_keeps_app_created_transceivers() {
        // A locally-initiated offer: the transceivers are created by the application, so
        // rolling back the local offer via set_local_description must disassociate them
        // (clear their mids) but must NOT remove them. This exercises the same rollback
        // cleanup path as set_remote_description, per RFC 8829 Section 5.7.
        let mut pc = media_pc();
        pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            }),
        )
        .unwrap();

        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveLocalOffer);
        assert_eq!(pc.rtp_transceivers.len(), 1);
        assert!(pc.rtp_transceivers[0].mid().is_some());

        pc.set_local_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "application-created transceivers must not be removed by rollback"
        );
        assert!(
            pc.rtp_transceivers[0].mid().is_none(),
            "rolled-back transceiver must be disassociated from its m= section"
        );
    }

    #[test]
    fn rollback_keeps_transceiver_with_track_attached_via_add_track() {
        let offer = audio_video_offer();

        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 2);

        // Attach a local track. add_track reuses the sender-less audio transceiver that was
        // created by the remote offer, giving it a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();

        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        // The video transceiver (no track) is removed; the audio transceiver with the attached
        // track is kept but disassociated (mid cleared) so a future offer can re-add it.
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "transceiver with a track attached via add_track must not be removed"
        );
        let kept = &pc.rtp_transceivers[0];
        assert_eq!(kept.kind(), RtpCodecKind::Audio);
        assert!(kept.sender().is_some());
        assert!(
            kept.mid().is_none(),
            "kept transceiver must be disassociated from its m= section on rollback"
        );
    }

    #[test]
    fn rollback_keeps_transceiver_negotiated_by_a_previous_exchange() {
        // First, complete a full offer/answer so an incoming transceiver becomes part of the
        // stable state (its mid is recorded in the current remote description).
        let offer = audio_video_offer();
        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 2);
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        let negotiated_mids: Vec<_> = pc
            .rtp_transceivers
            .iter()
            .map(|t| t.mid().clone())
            .collect();
        assert!(negotiated_mids.iter().all(|m| m.is_some()));

        // Now a renegotiation arrives and is rolled back. The transceivers negotiated by the
        // FIRST exchange must survive with their mids intact — rollback only undoes the pending
        // (second) transaction, not committed state.
        let reoffer = audio_video_offer();
        pc.set_remote_description(Instant::now(), reoffer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);

        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert_eq!(
            pc.rtp_transceivers.len(),
            2,
            "previously-negotiated transceivers must not be removed by a renegotiation rollback"
        );
        let mids_after: Vec<_> = pc
            .rtp_transceivers
            .iter()
            .map(|t| t.mid().clone())
            .collect();
        assert_eq!(
            mids_after, negotiated_mids,
            "previously-negotiated transceivers must keep their mid across rollback"
        );
    }

    #[test]
    fn add_track_then_rollback_remote_offer_then_create_offer_includes_track() {
        // RFC 8829, Section 5.7: "an application may call addTrack, then call
        // setRemoteDescription with an offer, then roll back that offer, then call createOffer
        // and have an "m=" section for the added track appear in the generated offer."
        let mut pc = media_pc();

        // 1. addTrack — creates a local sendrecv audio transceiver with a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 1);

        // 2. setRemoteDescription with a remote (video-only) offer. This reuses no existing
        //    transceiver (different kind), so it creates a second, remote-originated one.
        let mut video_offerer = media_pc();
        video_offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        let remote_offer = video_offerer.create_offer(None).unwrap();
        pc.set_remote_description(Instant::now(), remote_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        // The audio transceiver (with our track) got associated with the offer's m= section.
        assert!(
            pc.rtp_transceivers
                .iter()
                .any(|t| t.kind() == RtpCodecKind::Audio && t.sender().is_some())
        );

        // 3. Roll back that offer.
        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);

        // The audio transceiver with the attached track must survive (disassociated), while the
        // remote-created video transceiver must be gone.
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "the add_track transceiver must survive rollback; the remote one must be removed"
        );
        let kept = &pc.rtp_transceivers[0];
        assert_eq!(kept.kind(), RtpCodecKind::Audio);
        assert!(kept.sender().is_some());
        assert!(kept.mid().is_none(), "must be disassociated after rollback");

        // 4. createOffer — an m= section for the added (audio) track must appear.
        let offer = pc.create_offer(None).unwrap();
        assert_eq!(
            offer.sdp.matches("m=audio").count(),
            1,
            "createOffer after rollback must emit an m=audio section for the added track"
        );
        // The transceiver has been re-associated (given a mid) for the new offer.
        assert!(pc.rtp_transceivers[0].mid().is_some());
    }

    #[test]
    fn add_track_then_rollback_local_offer_then_answer_remote_still_renegotiates_track() {
        // Polite-peer glare scenario (RFC 8829, Section 5.7): the application calls addTrack and
        // sends its own offer, then a remote offer arrives (collision). The polite peer rolls
        // back its local offer, applies the remote offer, and answers it. The locally-added
        // track was never negotiated, so it must still be pending and appear in a subsequent
        // offer — mirroring the RFC's addTrack/rollback/createOffer guarantee for the local case.
        let mut pc = media_pc();

        // 1. addTrack (audio) — local sendrecv audio transceiver with a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();

        // 2. set_local_description(our offer) — enters have-local-offer, audio gets a mid.
        let local_offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), local_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveLocalOffer);
        assert!(pc.rtp_transceivers[0].mid().is_some());

        // 3. A remote (video) offer arrives — glare.
        let mut video_offerer = media_pc();
        video_offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        let remote_offer = video_offerer.create_offer(None).unwrap();

        // 4. Roll back our local offer (via set_local_description, the polite-peer path).
        pc.set_local_description(Instant::now(), rollback())
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        // Our audio transceiver survives (has a track/sender) but is disassociated.
        assert_eq!(pc.rtp_transceivers.len(), 1);
        assert_eq!(pc.rtp_transceivers[0].kind(), RtpCodecKind::Audio);
        assert!(pc.rtp_transceivers[0].sender().is_some());
        assert!(pc.rtp_transceivers[0].mid().is_none());

        // 5. Apply the remote offer, then answer it.
        pc.set_remote_description(Instant::now(), remote_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        let answer = pc.create_answer(None).unwrap();
        // The answer only covers the remote's video m= section; our audio track is not yet
        // negotiated, so it must NOT appear in the answer.
        assert_eq!(answer.sdp.matches("m=video").count(), 1);
        assert_eq!(answer.sdp.matches("m=audio").count(), 0);
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);

        // 6. The locally-added track was never negotiated, so a follow-up offer must include an
        //    m=audio section for it (alongside the now-negotiated video section).
        let followup_offer = pc.create_offer(None).unwrap();
        assert_eq!(
            followup_offer.sdp.matches("m=audio").count(),
            1,
            "the added track must appear in the offer generated after rollback + answer"
        );
        assert_eq!(followup_offer.sdp.matches("m=video").count(), 1);
        assert!(
            pc.rtp_transceivers
                .iter()
                .find(|t| t.kind() == RtpCodecKind::Audio)
                .unwrap()
                .mid()
                .is_some(),
            "audio transceiver must be re-associated for the follow-up offer"
        );
    }
}
