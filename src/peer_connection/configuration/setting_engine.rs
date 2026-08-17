//! Advanced configuration engine for WebRTC peer connections.
//!
//! The `SettingEngine` provides low-level control over WebRTC transport behavior,
//! timeouts, security settings, and network configuration. Unlike the standard
//! `RTCConfiguration` which focuses on standards-compliant WebRTC settings, the
//! `SettingEngine` allows for advanced customization and optimization for specific
//! deployment scenarios.
//!
//! # Key Configuration Areas
//!
//! - **ICE Timeouts**: Configure connection health monitoring and keepalive intervals
//! - **NAT Traversal**: Set up 1:1 NAT mappings for cloud deployments (e.g., AWS EC2)
//! - **DTLS Security**: Control certificate verification and DTLS role behavior
//! - **Replay Protection**: Configure anti-replay windows for DTLS, SRTP, and SRTCP
//! - **Network Types**: Restrict candidate gathering to specific network types
//!
//! # Examples
//!
//! ## Configuring ICE timeouts for unstable networks
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use std::time::Duration;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase timeouts for mobile or unstable networks
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_ice_timeouts(
//!         Some(Duration::from_secs(10)),  // disconnected_timeout (default: 5s)
//!         Some(Duration::from_secs(30)),  // failed_timeout (default: 25s)
//!         Some(Duration::from_secs(3)),   // keep_alive_interval (default: 2s)
//!     )
//!     .build();
//!
//! // Use with RTCConfiguration
//! // let mut config = RTCConfiguration::default();
//! // config.setting_engine = Some(setting_engine);
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting up 1:1 NAT for cloud deployments
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use rtc::peer_connection::transport::RTCIceCandidateType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure for AWS EC2 instance with Elastic IP
//! // Private IP: 10.0.1.5, Public IP: 54.123.45.67
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_nat_1to1_ips(
//!         vec!["54.123.45.67".to_string()],
//!         RTCIceCandidateType::Host, // Use public IP for host candidates
//!     )
//!     .build();
//!
//! // This tells ICE to advertise the public IP instead of the private one
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring replay protection for security-critical applications
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase replay protection window sizes
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_dtls_replay_protection_window(128)  // DTLS anti-replay
//!     .with_srtp_replay_protection_window(256)  // SRTP anti-replay
//!     .with_srtcp_replay_protection_window(128) // SRTCP anti-replay
//!     .build();
//!
//! // Larger windows protect against more packet reordering but use more memory
//! # Ok(())
//! # }
//! ```
//!
//! ## Restricting network types for controlled environments
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use ice::network_type::NetworkType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Only gather IPv4 UDP candidates (no IPv6, no TCP)
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_network_types(vec![NetworkType::Udp4])
//!     .build();
//!
//! // This reduces candidate gathering time and SDP size
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`RTCConfiguration`](crate::peer_connection::configuration::RTCConfiguration) - Standard WebRTC configuration
//! - [`MediaEngine`](crate::peer_connection::configuration::media_engine::MediaEngine) - Codec registration
//! - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
//! - [RFC 8446 - TLS 1.3 (DTLS basis)](https://datatracker.ietf.org/doc/html/rfc8446)

//TODO:#[cfg(test)]
//mod setting_engine_test;

use std::net::IpAddr;
use std::sync::Arc;

use crypto::RTCCryptoProvider;
use dtls::cipher_suite::CipherSuiteId;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
//TODO: use ice::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
//TODO: use ice::mdns::MulticastDnsMode;
use ice::network_type::NetworkType;
//TODO: use ice::udp_network::UDPNetwork;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use ice::mdns::MulticastDnsMode;
use std::time::Duration;

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

/// ICE timeout configuration for connection health monitoring.
///
/// These timeouts control how ICE determines connection state transitions
/// and when to send keepalive packets. Adjust these for different network
/// conditions (mobile, satellite, etc.).
#[derive(Default, Clone)]
pub struct Timeout {
    /// Duration without network activity before ICE is considered disconnected.
    /// Default: 5 seconds.
    pub ice_disconnected_timeout: Option<Duration>,

    /// Duration without network activity before ICE is considered failed after disconnected.
    /// Default: 25 seconds.
    pub ice_failed_timeout: Option<Duration>,

    /// How often ICE sends keepalive packets when there's no media flow.
    /// Default: 2 seconds. If media is flowing, no keepalives are sent.
    pub ice_keepalive_interval: Option<Duration>,

    /// Controls how often ICE sends binding requests for a candidate pair.
    /// When combined with `ice_max_binding_requests`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_check_interval: Option<Duration>,

    /// The max amount of binding requests ICE will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    /// When combined with `ice_check_interval`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_max_binding_requests: Option<u16>,

    /// Minimum wait time before accepting host candidates.
    pub ice_host_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting server reflexive candidates.
    pub ice_srflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting peer reflexive candidates.
    pub ice_prflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting relay candidates.
    pub ice_relay_acceptance_min_wait: Option<Duration>,
}

/// MulticastDNS configuration for mDNS.
#[derive(Clone)]
pub struct MulticastDNS {
    /// Duration without network activity before mDNS query is considered failed.
    /// Default: 10 seconds.
    pub timeout: Option<Duration>,
    /// Represents the different Multicast modes that ICE can run.
    pub mode: MulticastDnsMode,
    /// Controls the local name for this agent. If none is specified a random one will be generated.
    pub local_name: String,
    /// Control mDNS local IP address
    pub local_ip: Option<IpAddr>,
}

impl Default for MulticastDNS {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
            // Safari and Chrome emit only mDNS ("<uuid>.local") host candidates
            // by default (to avoid leaking private IPs). With Disabled those are
            // silently dropped, leaving no usable remote candidates from such an
            // offer; QueryOnly resolves them via mDNS without publishing our own
            // host IPs as mDNS names. This matches the MulticastDnsMode enum's
            // own #[default].
            mode: MulticastDnsMode::QueryOnly,
            local_name: "".to_string(),
            local_ip: None,
        }
    }
}

/// ICE candidate gathering and filtering configuration.
///
/// Controls which types of candidates are gathered, NAT mappings,
/// and custom network filtering.
#[derive(Default, Clone)]
pub struct Candidates {
    /// Enable ICE Lite mode (only respond to connectivity checks, don't initiate).
    pub ice_lite: bool,

    /// Restrict candidate gathering to specific network types (e.g., UDP4, UDP6, TCP4).
    pub ice_network_types: Vec<NetworkType>,
    //TODO: pub interface_filter: Arc<Option<InterfaceFilterFn>>,
    //TODO: pub ip_filter: Arc<Option<IpFilterFn>>,
    /// External IP addresses for 1:1 NAT mappings (e.g., AWS Elastic IP).
    pub nat_1to1_ips: Vec<String>,

    /// Candidate type to use for NAT 1:1 IPs (Host or Srflx).
    pub nat_1to1_ip_candidate_type: RTCIceCandidateType,
    /// Static ICE username fragment (ufrag) for reproducible sessions.
    pub username_fragment: String,

    /// Static ICE password for reproducible sessions.
    pub password: String,

    /// Whether to discard local candidates during ICE restart.
    pub discard_local_candidates_during_ice_restart: bool,

    /// Allow gathering loopback candidates (useful for some VM configurations).
    /// Note: This is non-standard per RFC 8445.
    pub include_loopback_candidate: bool,
}

/// Replay attack protection window sizes.
///
/// Larger windows provide better protection against packet reordering
/// but consume more memory. Set to 0 to disable replay protection (not recommended).
#[derive(Default, Copy, Clone)]
pub struct ReplayProtection {
    /// DTLS replay protection window size (in packets).
    pub dtls: usize,

    /// SRTP replay protection window size (in packets).
    pub srtp: usize,

    /// SRTCP replay protection window size (in packets).
    pub srtcp: usize,
}

/// Maximum message size for SCTP data channels.
///
/// Controls the maximum size of messages that can be sent through data channels.
/// Per [RFC 8841](https://datatracker.ietf.org/doc/html/rfc8841), the default is 64KB.
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum SctpMaxMessageSize {
    /// Fixed maximum message size in bytes.
    Bounded(u32),

    /// No practical limit (uses MAX_MESSAGE_SIZE internally).
    Unbounded,
}

impl SctpMaxMessageSize {
    /// Default message size per RFC 8841 (64KB).
    pub const DEFAULT_MESSAGE_SIZE: u32 = 65536;

    /// Maximum message size (256KB).
    pub const MAX_MESSAGE_SIZE: u32 = 262144;

    /// Returns the message size as `usize`.
    pub fn as_usize(&self) -> usize {
        match self {
            Self::Bounded(result) => (*result).min(Self::MAX_MESSAGE_SIZE) as usize,
            Self::Unbounded => Self::MAX_MESSAGE_SIZE as usize,
        }
    }
}

impl Default for SctpMaxMessageSize {
    fn default() -> Self {
        // https://datatracker.ietf.org/doc/html/rfc8841#section-6.1-4
        // > If the SDP "max-message-size" attribute is not present, the default value is 64K.
        Self::Bounded(Self::DEFAULT_MESSAGE_SIZE)
    }
}

/// Advanced configuration engine for fine-tuning WebRTC behavior.
///
/// `SettingEngine` provides granular control over transport-level settings that
/// are not exposed through the standard WebRTC API. Use this to optimize for
/// specific deployment scenarios, network conditions, or security requirements.
///
/// # Configuration Categories
///
/// - **Timeout**: ICE connection health monitoring and keepalive
/// - **TURN**: Allocation maintenance behavior
/// - **Candidates**: NAT traversal, network filtering, ICE credentials
/// - **Replay Protection**: Anti-replay window sizes for DTLS/SRTP/SRTCP
/// - **DTLS**: Certificate verification and role selection
/// - **Media Engine**: Codec registration behavior
/// - **SCTP**: Data channel message size limits
///
/// # Examples
///
/// ## Basic usage with RTCConfiguration
///
/// ```
/// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let setting_engine = SettingEngineBuilder::new()
///     // Configure timeouts
///     .with_ice_timeouts(
///         Some(Duration::from_secs(10)),
///         Some(Duration::from_secs(30)),
///         Some(Duration::from_secs(3)),
///     )
///     // Enable loopback for testing
///     .with_include_loopback_candidate(true)
///     .build();
///
/// // Use with peer connection configuration
/// // let api = APIBuilder::new().with_setting_engine(setting_engine).build();
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [W3C WebRTC Spec](https://www.w3.org/TR/webrtc/)
/// - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
#[derive(Default, Clone)]
pub struct SettingEngine {
    pub(crate) crypto_provider: Option<Arc<dyn RTCCryptoProvider>>,
    pub(crate) timeout: Timeout,
    pub(crate) turn_allocation_refresh_interval_cap: Option<Duration>,
    pub(crate) candidates: Candidates,
    pub(crate) multicast_dns: MulticastDNS,
    pub(crate) replay_protection: ReplayProtection,
    pub(crate) sdp_media_level_fingerprints: bool,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_media_engine_copy: bool,
    pub(crate) disable_media_engine_multiple_codecs: bool,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) receive_mtu: usize,
    pub(crate) mid_generator: Option<Arc<dyn Fn(isize) -> String + Send + Sync>>,
    /// Determines the max size of any message that may be sent through an SCTP transport.
    pub(crate) sctp_max_message_size: SctpMaxMessageSize,
    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    /// `None` uses the rtc-sctp default (`INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub(crate) sctp_max_receive_buffer_size: Option<u32>,
    /// Overrides the outbound SCTP DATA-packet budget, converted to a payload
    /// budget via rtc-sctp's `max_payload_size_for_mtu`. `None` uses the rtc-sctp
    /// default (`INITIAL_MTU`, 1191 — the TURN-relayed IPv6 minimum-MTU budget).
    pub(crate) sctp_mtu: Option<u32>,
    pub(crate) ignore_rid_pause_for_recv: bool,
    pub(crate) write_ssrc_attributes_for_simulcast: bool,
}

impl SettingEngine {
    /// The crypto provider configured on this engine, if any.
    ///
    /// `None` means no provider has been set, so building a peer connection will resolve the
    /// feature-selected built-in.
    ///
    /// Callers assembling additional components around a peer connection — an async wrapper's
    /// TURN client, for instance — read the provider from here and pass it to
    /// [`with_crypto_provider`](SettingEngineBuilder::with_crypto_provider) before building, so the whole
    /// connection provably shares one provider instead of resolving a second.
    pub fn crypto_provider(&self) -> Option<&Arc<dyn RTCCryptoProvider>> {
        self.crypto_provider.as_ref()
    }

    /// Set crypto provider on this engine.
    #[doc(hidden)]
    pub fn set_crypto_provider(&mut self, crypto_provider: Arc<dyn RTCCryptoProvider>) {
        self.crypto_provider = Some(crypto_provider);
    }

    /// Returns the multicast DNS configuration.
    pub fn multicast_dns(&self) -> &MulticastDNS {
        &self.multicast_dns
    }

    /// Returns the configured maximum interval between TURN allocation Refresh requests.
    ///
    /// `None` preserves the TURN client's default cadence of half the lifetime advertised by
    /// the server.
    pub fn turn_allocation_refresh_interval_cap(&self) -> Option<Duration> {
        self.turn_allocation_refresh_interval_cap
    }

    /// Whether an ICE restart discards the local candidates gathered by the previous generation.
    ///
    /// Set through
    /// [`with_discard_local_candidates_during_ice_restart`](SettingEngineBuilder::with_discard_local_candidates_during_ice_restart),
    /// where the reasoning lives.
    ///
    /// Read by the layer that owns the sockets, because the two decisions are one decision.
    /// Discarding the old candidates is only necessary when the transport under them is being
    /// replaced, and replacing that transport is only safe when the candidates naming it are
    /// discarded — so an async wrapper treats this as "the sockets are replaced on restart" and
    /// rebinds them, rather than exposing a second switch the two halves could disagree on.
    pub fn discard_local_candidates_during_ice_restart(&self) -> bool {
        self.candidates.discard_local_candidates_during_ice_restart
    }
}

/// Fluent builder for [`SettingEngine`].
///
/// Mirrors [`RTCConfigurationBuilder`](crate::peer_connection::configuration::RTCConfigurationBuilder),
/// so a peer connection is configured in one style throughout rather than switching between a
/// fluent builder and a sequence of `&mut self` setters.
///
/// [`build`](Self::build) is infallible: every setting is either always valid or normalised on
/// the way in, so there is no failure mode to report.
#[derive(Default)]
pub struct SettingEngineBuilder(SettingEngine);

impl SettingEngineBuilder {
    /// A builder with every setting at its default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the cryptographic provider used by peer connections built with this setting engine.
    ///
    /// The provider is resolved once at peer-connection construction and shared with ICE, DTLS,
    /// SRTP, certificate, and fingerprint operations. Different peer connections may select
    /// different providers in the same process.
    pub fn with_crypto_provider(mut self, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        self.0.crypto_provider = Some(provider);
        self
    }

    /// Overrides the default SRTP protection profiles.
    ///
    /// SRTP profiles define the encryption algorithms used for media streams.
    /// Only override this if you need specific security requirements or
    /// compatibility with non-standard implementations.
    ///
    /// # Parameters
    ///
    /// * `profiles` - List of SRTP protection profiles to use
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use specific SRTP profile
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_protection_profiles(vec![
    ///         SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ///     ])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtp_protection_profiles(mut self, profiles: Vec<SrtpProtectionProfile>) -> Self {
        self.0.srtp_protection_profiles = profiles;
        self
    }

    /// Restricts the DTLS cipher suites offered during the handshake.
    ///
    /// An empty list (the default) uses the `dtls` crate's built-in set, which offers
    /// **both** ECDHE_ECDSA and ECDHE_RSA suites. That is deliberate — the local
    /// certificate is not known when the list is compiled — but it means a remote peer may
    /// select an ECDHE_RSA suite that an ECDSA certificate cannot satisfy, and the
    /// handshake then stalls with the connection stuck in `Connecting`.
    ///
    /// Certificates generated by this crate are ECDSA (P-256), so an application that does
    /// not supply its own RSA certificate can pin the ECDSA suites and remove that
    /// possibility:
    ///
    /// ```
    /// use dtls::cipher_suite::CipherSuiteId;
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_cipher_suites(vec![
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    ///     ])
    ///     .build();
    /// ```
    ///
    /// The order is a preference order. Every suite named must be one the `dtls` crate
    /// implements, or building the transport fails with `ErrInvalidCipherSuite`; a list
    /// that filters down to nothing usable fails with `ErrNoAvailableCipherSuites`.
    pub fn with_dtls_cipher_suites(mut self, cipher_suites: Vec<CipherSuiteId>) -> Self {
        self.0.dtls_cipher_suites = cipher_suites;
        self
    }

    /// Caps the interval between TURN allocation Refresh requests.
    ///
    /// By default, TURN allocations are refreshed at half the lifetime advertised by the server.
    /// A shorter cap can keep an otherwise idle client-to-server NAT mapping active. Values below
    /// one second are rounded up by the TURN client.
    pub fn with_turn_allocation_refresh_interval_cap(mut self, cap: Duration) -> Self {
        self.0.turn_allocation_refresh_interval_cap = Some(cap);
        self
    }

    /// Configures ICE timeout behavior for connection health monitoring.
    ///
    /// These timeouts control when ICE transitions between connection states
    /// and when keepalive packets are sent. Adjust these for different network
    /// conditions:
    /// - Increase for unstable networks (mobile, satellite)
    /// - Decrease for low-latency applications
    ///
    /// # Parameters
    ///
    /// * `disconnected_timeout` - Duration without activity before considered disconnected (default: 5s)
    /// * `failed_timeout` - Duration after disconnected before considered failed (default: 25s)
    /// * `keep_alive_interval` - How often to send keepalives when idle (default: 2s)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Conservative settings for mobile networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_timeouts(
    ///         Some(Duration::from_secs(10)),  // Longer before disconnected
    ///         Some(Duration::from_secs(40)),  // Longer before failed
    ///         Some(Duration::from_secs(5)),   // Less frequent keepalives
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §16 - Timers](https://datatracker.ietf.org/doc/html/rfc8445#section-16)
    pub fn with_ice_timeouts(
        mut self,
        disconnected_timeout: Option<Duration>,
        failed_timeout: Option<Duration>,
        keep_alive_interval: Option<Duration>,
    ) -> Self {
        self.0.timeout.ice_disconnected_timeout = disconnected_timeout;
        self.0.timeout.ice_failed_timeout = failed_timeout;
        self.0.timeout.ice_keepalive_interval = keep_alive_interval;
        self
    }

    /// Configures ICE connection attempt behavior, including number of connection attempts
    /// per candidate, and the amount of time between connection attempts.
    ///
    /// The default settings configure ICE to attempt to connect a candidate for up to 1.4 seconds.
    ///
    /// # Parameters
    ///
    /// * `check_interval` - The delay between each connection attempt (default: 200 ms)
    /// * `max_binding_requests` - Maximum number of connection attempts per candidate (default: 7)
    pub fn with_ice_connection_attempts(
        mut self,
        check_interval: Option<Duration>,
        max_binding_requests: Option<u16>,
    ) -> Self {
        self.0.timeout.ice_check_interval = check_interval;
        self.0.timeout.ice_max_binding_requests = max_binding_requests;
        self
    }

    /// Sets minimum wait time before accepting host candidates.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_host_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_host_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting server reflexive candidates.
    ///
    /// Server reflexive candidates are discovered through STUN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_srflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_srflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting peer reflexive candidates.
    ///
    /// Peer reflexive candidates are discovered during connectivity checks.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_prflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_prflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting relay candidates.
    ///
    /// Relay candidates are provided by TURN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_relay_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_relay_acceptance_min_wait = t;
        self
    }

    /*todo:
    /// set_udp_network allows ICE traffic to come through Ephemeral or UDPMux.
    /// UDPMux drastically simplifying deployments where ports will need to be opened/forwarded.
    /// UDPMux should be started prior to creating PeerConnections.
    pub fn with_udp_network(mut self, udp_network: UDPNetwork) -> Self {
        self.0.udp_network = udp_network;
    }*/

    /// Configures ICE Lite mode.
    ///
    /// In ICE Lite mode, the agent only responds to connectivity checks
    /// but does not initiate them. This is typically used by servers that
    /// have public IP addresses and don't need full ICE functionality.
    ///
    /// # Parameters
    ///
    /// * `lite` - `true` to enable ICE Lite, `false` for full ICE
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable ICE Lite for a publicly accessible server
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_lite(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §2.7 - Lite Implementation](https://datatracker.ietf.org/doc/html/rfc8445#section-2.7)
    pub fn with_lite(mut self, lite: bool) -> Self {
        self.0.candidates.ice_lite = lite;
        self
    }

    /// Restricts candidate gathering to specific network types.
    ///
    /// This reduces the number of candidates gathered, which can speed up
    /// connection establishment and reduce SDP size. Useful when you know
    /// certain network types won't work in your deployment.
    ///
    /// # Parameters
    ///
    /// * `candidate_types` - List of allowed network types (e.g., UDP4, UDP6, TCP4)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use ice::network_type::NetworkType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only use IPv4 UDP (most common case)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4])
    ///     .build();
    ///
    /// // Or allow both IPv4 and IPv6 UDP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4, NetworkType::Udp6])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_network_types(mut self, candidate_types: Vec<NetworkType>) -> Self {
        self.0.candidates.ice_network_types = candidate_types;
        self
    }

    /*todo:
    /// set_interface_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain network interfaces from ICE. Which may be
    /// useful if you know a certain interface will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_interface_filter(mut self, filter: InterfaceFilterFn) -> Self {
        self.0.candidates.interface_filter = Arc::new(Some(filter));
        self
    }


    /// set_ip_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain ip from ICE. Which may be
    /// useful if you know a certain ip will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_ip_filter(mut self, filter: IpFilterFn) -> Self {
        self.0.candidates.ip_filter = Arc::new(Some(filter));
    }*/

    /// Configures 1:1 NAT IP mapping for cloud deployments.
    ///
    /// This is essential for WebRTC servers running on cloud instances (e.g., AWS EC2)
    /// that have a private IP address but are accessible via a public IP through 1:1 NAT.
    ///
    /// # Parameters
    ///
    /// * `ips` - List of external/public IP addresses
    /// * `candidate_type` - How to advertise the public IPs:
    ///   - `RTCIceCandidateType::Host`: Replace private IP with public IP (mDNS disabled)
    ///   - `RTCIceCandidateType::Srflx`: Add public IP as server reflexive candidate
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtc::peer_connection::transport::RTCIceCandidateType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // AWS EC2: Private IP 10.0.1.5, Elastic IP 54.123.45.67
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Host,
    ///     )
    ///     .build();
    ///
    /// // Or use Srflx to keep private IP available
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Srflx,
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Notes
    ///
    /// - With `Host` type, the private IP is not advertised to the peer
    /// - With `Srflx` type, both private and public IPs are available
    /// - Cannot use STUN servers when using `Srflx` type
    /// - Cannot use with mDNS when using `Host` type
    pub fn with_nat_1to1_ips(
        mut self,
        ips: Vec<String>,
        candidate_type: RTCIceCandidateType,
    ) -> Self {
        self.0.candidates.nat_1to1_ips = ips;
        self.0.candidates.nat_1to1_ip_candidate_type = candidate_type;
        self
    }

    /// Sets the DTLS role to use when answering an offer.
    ///
    /// The DTLS role determines whether this peer acts as a DTLS client
    /// (initiating the handshake) or server (waiting for handshake). Normally
    /// this is negotiated automatically, but you can override it for debugging
    /// or compatibility with non-compliant implementations.
    ///
    /// # Parameters
    ///
    /// * `role` - DTLS role to use:
    ///   - `DTLSRole::Client`: Act as DTLS client, send ClientHello
    ///   - `DTLSRole::Server`: Act as DTLS server, wait for ClientHello
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(Error)` if role is not Client or Server
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtc::peer_connection::transport::RTCDtlsRole;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force this peer to always act as DTLS client when answering
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_answering_dtls_role(RTCDtlsRole::Client)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8842 - DTLS for WebRTC](https://datatracker.ietf.org/doc/html/rfc8842)
    pub fn with_answering_dtls_role(mut self, role: RTCDtlsRole) -> Self {
        // Deliberately unvalidated. `Unspecified` and `Auto` are not errors here: both
        // consumers already handle them — `to_connection_role()` maps `Unspecified` to
        // `ConnectionRole::Unspecified`, which the answer path detects and replaces with
        // `DEFAULT_DTLS_ROLE_ANSWER`, and the role-selection `match` falls through to the
        // ICE-derived default. Rejecting them contradicted behaviour that already worked.
        self.0.answering_dtls_role = role;
        self
    }

    /// Sets the timeout for multicast DNS resolution.
    pub fn with_multicast_dns_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.multicast_dns.timeout = timeout;
        self
    }

    /// set_ice_multicast_dns_mode controls if ice queries and generates mDNS ICE Candidates
    pub fn with_multicast_dns_mode(mut self, multicast_dns_mode: MulticastDnsMode) -> Self {
        self.0.multicast_dns.mode = multicast_dns_mode;
        self
    }

    /// set_ice_multicast_dns_host_name sets a static HostName to be used by ice instead of generating one on startup
    /// This should only be used for a single PeerConnection. Having multiple PeerConnections with the same HostName will cause
    /// undefined behavior
    pub fn with_multicast_dns_local_name(mut self, local_name: String) -> Self {
        self.0.multicast_dns.local_name = local_name;
        self
    }

    /// Sets the local IP address to use for multicast DNS.
    pub fn with_multicast_dns_local_ip(mut self, local_ip: Option<IpAddr>) -> Self {
        self.0.multicast_dns.local_ip = local_ip;
        self
    }

    /// Sets static ICE credentials for reproducible sessions.
    ///
    /// By default, ICE generates random credentials (ufrag/password) for each
    /// session. Setting static credentials allows for signalless WebRTC or
    /// reproducible testing environments.
    ///
    /// # Parameters
    ///
    /// * `username_fragment` - ICE username fragment (ufrag)
    /// * `password` - ICE password
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set static credentials for reproducible testing
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_credentials(
    ///         "test_ufrag".to_string(),
    ///         "test_password".to_string(),
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Only use static credentials in controlled environments. Random credentials
    /// provide better security for production deployments.
    pub fn with_ice_credentials(mut self, username_fragment: String, password: String) -> Self {
        self.0.candidates.username_fragment = username_fragment;
        self.0.candidates.password = password;
        self
    }

    /// Disables DTLS certificate fingerprint verification.
    ///
    /// **Warning**: Disabling fingerprint verification removes a critical
    /// security check and should only be used for testing or debugging.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to disable verification, `false` to enable
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only for testing/debugging!
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_certificate_fingerprint_verification(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_disable_certificate_fingerprint_verification(mut self, is_disabled: bool) -> Self {
        self.0.disable_certificate_fingerprint_verification = is_disabled;
        self
    }

    /// Allows insecure signature verification algorithms.
    ///
    /// Some signature algorithms are known to be vulnerable or deprecated.
    /// This setting allows their use for compatibility with legacy systems.
    ///
    /// **Warning**: Only enable this if absolutely necessary for compatibility.
    ///
    /// # Parameters
    ///
    /// * `is_allowed` - `true` to allow insecure algorithms, `false` to disallow
    pub fn with_allow_insecure_verification_algorithm(mut self, is_allowed: bool) -> Self {
        self.0.allow_insecure_verification_algorithm = is_allowed;
        self
    }

    /// Sets the DTLS replay protection window size.
    ///
    /// The replay protection window prevents attackers from re-sending captured
    /// packets. Larger windows protect against more packet reordering but use
    /// more memory. Set to 0 to disable (not recommended).
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Increase window for high-latency or reordering networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_replay_protection_window(128)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 6347 §4.1.2.6 - Anti-Replay](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6)
    pub fn with_dtls_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.dtls = n;
        self
    }

    /// Sets the SRTP replay protection window size.
    ///
    /// SRTP replay protection prevents replay attacks on encrypted media packets.
    /// Adjust the window size based on expected packet reordering in your network.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Standard size for most applications
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_replay_protection_window(256)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 3711 §3.3.2 - Replay Protection](https://datatracker.ietf.org/doc/html/rfc3711#section-3.3.2)
    pub fn with_srtp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtp = n;
        self
    }

    /// Sets the SRTCP replay protection window size.
    ///
    /// SRTCP replay protection applies to RTCP control packets. Usually
    /// a smaller window is sufficient since RTCP packets are less frequent.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Smaller window sufficient for RTCP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtcp_replay_protection_window(64)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtcp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtcp = n;
        self
    }

    /// Allows gathering of loopback candidates.
    ///
    /// By default, loopback candidates (127.x.x.x, ::1) are not gathered per
    /// RFC 8445. However, some VM configurations map public IPs to the loopback
    /// interface, making this necessary.
    ///
    /// # Parameters
    ///
    /// * `allow_loopback` - `true` to gather loopback candidates, `false` to skip
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable for certain VM configurations
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_include_loopback_candidate(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// This is non-standard behavior per [RFC 8445 §5.1.1.1](https://www.rfc-editor.org/rfc/rfc8445#section-5.1.1.1).
    /// Use with caution.
    pub fn with_include_loopback_candidate(mut self, allow_loopback: bool) -> Self {
        self.0.candidates.include_loopback_candidate = allow_loopback;
        self
    }

    /// Discards previously gathered local candidates when an ICE restart is applied.
    ///
    /// By default the restarted generation keeps its local candidates, which avoids re-gathering
    /// addresses that are usually still valid. [RFC 8445 §9] describes a restart as flushing all
    /// state except the roles and gathering anew, so keeping them is an optimisation rather than
    /// the specified behaviour — it is sound only while the underlying sockets outlive the
    /// restart.
    ///
    /// Set this when they do not. If the transport rebinds its sockets as part of recovery — for
    /// example an application that replaces its UDP sockets after the platform invalidated them —
    /// the retained candidates name addresses nothing is bound to any more. Connectivity checks
    /// are then written for a local address with no socket behind it and silently go nowhere, so
    /// the restarted generation exchanges credentials successfully and never leaves `Checking`.
    ///
    /// # Parameters
    ///
    /// * `discard` - `true` to drop local candidates on restart, `false` (default) to keep them
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Pairs with a transport that rebinds its sockets during ICE restart.
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_discard_local_candidates_during_ice_restart(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §9 - ICE Restarts](https://www.rfc-editor.org/rfc/rfc8445#section-9)
    ///
    /// [RFC 8445 §9]: https://www.rfc-editor.org/rfc/rfc8445#section-9
    pub fn with_discard_local_candidates_during_ice_restart(mut self, discard: bool) -> Self {
        self.0
            .candidates
            .discard_local_candidates_during_ice_restart = discard;
        self
    }

    /// Controls where DTLS fingerprints are placed in SDP.
    ///
    /// By default, fingerprints are placed at the session level. Setting this
    /// to `true` places them at the media level instead, which improves
    /// compatibility with some WebRTC implementations.
    ///
    /// # Parameters
    ///
    /// * `sdp_media_level_fingerprints` - `true` for media-level, `false` for session-level
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use media-level fingerprints for better compatibility
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sdp_media_level_fingerprints(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sdp_media_level_fingerprints(mut self, sdp_media_level_fingerprints: bool) -> Self {
        self.0.sdp_media_level_fingerprints = sdp_media_level_fingerprints;
        self
    }

    // SetICETCPMux enables ICE-TCP when set to a non-nil value. Make sure that
    // NetworkTypeTCP4 or NetworkTypeTCP6 is enabled as well.
    //pub fn SetICETCPMux(&mut self, tcpMux ice.TCPMux) {
    //    self.0.iceTCPMux = tcpMux
    //}

    // SetICEProxyDialer sets the proxy dialer interface based on golang.org/x/net/proxy.
    //pub fn SetICEProxyDialer(&mut self, d proxy.Dialer) {
    //    self.0.iceProxyDialer = d
    //}

    /// Prevents the MediaEngine from being copied for each PeerConnection.
    ///
    /// By default, each PeerConnection gets a copy of the MediaEngine, allowing
    /// independent codec configurations. Disabling this allows sharing a single
    /// MediaEngine and modifying it after PeerConnection creation.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to share MediaEngine, `false` to copy (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Share MediaEngine across connections
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_copy(true)
    ///     .build();
    ///
    /// // Warning: Don't share MediaEngine between multiple PeerConnections
    /// // unless you understand the implications
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Warning
    ///
    /// When disabled, ensure you don't share the same MediaEngine between
    /// multiple PeerConnections unless you specifically intend to do so.
    pub fn with_disable_media_engine_copy(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_copy = is_disabled;
        self
    }

    /// Disables negotiating different codecs for different media sections.
    ///
    /// By default, each media section in the SDP can negotiate different codecs,
    /// which is the spec-compliant behavior. This setting forces all media
    /// sections to use the same codecs.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to use single codec set, `false` for per-section (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force same codecs for all media sections
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_multiple_codecs(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Deprecation Note
    ///
    /// This setting is targeted for removal in a future release (4.2.0 or later).
    pub fn with_disable_media_engine_multiple_codecs(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_multiple_codecs = is_disabled;
        self
    }

    /// Sets the MTU size for the receive buffer.
    ///
    /// This controls the maximum size of packets that can be received. Leave
    /// at 0 to use the default MTU (1460 bytes, equal to UDP MTU).
    ///
    /// # Parameters
    ///
    /// * `receive_mtu` - MTU size in bytes, or 0 for default
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use larger MTU for jumbo frames
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(9000)
    ///     .build();
    ///
    /// // Or use default
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(0)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_receive_mtu(mut self, receive_mtu: usize) -> Self {
        self.0.receive_mtu = receive_mtu;
        self
    }

    /// Sets a custom MID (media stream ID) generator function.
    ///
    /// By default, MIDs are generated automatically. This allows you to provide
    /// a custom generation scheme, useful for reducing complexity when handling
    /// SDP offer/answer collisions.
    ///
    /// # Parameters
    ///
    /// * `f` - Function that takes the highest seen numeric MID and returns a new MID string
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate MIDs with a custom prefix
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_mid_generator(|max_mid| format!("custom_{}", max_mid + 1))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Notes
    ///
    /// - MIDs should be generated without leaking user information (e.g., randomly)
    /// - MIDs should be 3 bytes or less for efficient RTP header extension encoding
    /// - The `isize` argument is the greatest seen _numeric_ MID (doesn't include non-numeric MIDs)
    ///
    /// # See Also
    ///
    /// - [RFC 8843 - MID](https://datatracker.ietf.org/doc/html/rfc8843)
    pub fn with_mid_generator(
        mut self,
        f: impl Fn(isize) -> String + Send + Sync + 'static,
    ) -> Self {
        self.0.mid_generator = Some(Arc::new(f));
        self
    }

    /// Sets the maximum message size for SCTP data channels.
    ///
    /// This controls the largest message that can be sent through a data channel.
    /// Larger messages will be fragmented or rejected depending on the configuration.
    ///
    /// # Parameters
    ///
    /// * `max_message_size` - Maximum size (Bounded or Unbounded)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::{
    ///     SctpMaxMessageSize, SettingEngineBuilder,
    /// };
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use default 64KB
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
    ///         SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE,
    ///     ))
    ///     .build();
    ///
    /// // Or allow larger messages
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(256 * 1024)) // 256KB
    ///     .build();
    ///
    /// // Or unbounded (uses MAX_MESSAGE_SIZE internally)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8841 §6.1 - max-message-size](https://datatracker.ietf.org/doc/html/rfc8841#section-6.1)
    pub fn with_sctp_max_message_size(mut self, max_message_size: SctpMaxMessageSize) -> Self {
        self.0.sctp_max_message_size = max_message_size;
        self
    }

    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    ///
    /// This bounds how much unacknowledged data a peer may have in flight toward this
    /// endpoint — a bandwidth-delay-product ceiling. Lowering it reduces per-connection
    /// memory (the buffer fills only under load), which matters for servers holding many
    /// connections; but a smaller window can throttle throughput on high-latency,
    /// high-bandwidth paths, where more data must be in flight to keep the pipe full.
    ///
    /// **Bounds.** RFC 4960 §6 requires an advertised initial a_rwnd of at least **1500
    /// bytes**; smaller values (including `0`) are raised to that floor here, because a
    /// sub-1500 window makes the peer reject this endpoint's INIT/INIT-ACK and the SCTP
    /// association never establishes. The window should also be **≥ the largest SCTP
    /// message this endpoint will receive** ([`SettingEngineBuilder::with_sctp_max_message_size`], default
    /// 64 KiB): a buffer smaller than one message cannot hold it for reassembly, so a
    /// full-size inbound message would stall that receive direction. `0` here is *not*
    /// "unbounded" (unlike some other knobs) — to keep the default window, leave this
    /// unset (the default is `INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub fn with_sctp_max_receive_buffer_size(mut self, size: u32) -> Self {
        // RFC 4960 §6 (User Data Transfer) forbids advertising an initial a_rwnd below
        // 1500 bytes ("An SCTP receiver MUST be able to receive a minimum of 1500 bytes in
        // one SCTP packet. This means that an SCTP endpoint MUST NOT indicate less than
        // 1500 bytes in its initial a_rwnd sent in the INIT or INIT ACK."). This crate
        // enforces it in `ChunkInit::check()` (ErrInitAdvertisedReceiver1500), so a
        // sub-1500 (or 0) value would silently break the handshake. Clamp up to that floor.
        const MIN_SCTP_RECEIVE_BUFFER_SIZE: u32 = 1500;
        if size < MIN_SCTP_RECEIVE_BUFFER_SIZE {
            log::warn!(
                "sctp receive buffer size {size} is below the RFC 4960 minimum; raising to \
                 {MIN_SCTP_RECEIVE_BUFFER_SIZE} bytes"
            );
        }

        self.0.sctp_max_receive_buffer_size = Some(size.max(MIN_SCTP_RECEIVE_BUFFER_SIZE));
        self
    }

    /// Overrides the SCTP MTU: the size budget, in bytes, for each outbound DATA packet
    /// (common header plus bundled DATA chunks) this endpoint emits. Control packets
    /// (INIT, INIT ACK, SACK, RECONFIG, FORWARD TSN, shutdown) marshal without consulting
    /// this value.
    ///
    /// Each SCTP packet becomes one DTLS record carried in one UDP datagram, so the wire
    /// size is roughly this value + ~37 bytes of DTLS record overhead + IP/UDP headers
    /// (+ 4 bytes of TURN ChannelData framing when relayed). The default (1191) is the
    /// TURN-relayed IPv6 minimum-MTU budget of `1280 - 40 IPv6 - 8 UDP - 4 TURN
    /// ChannelData - 37 DTLS` (webrtc-rs/rtc#178). Set this only for paths with a known
    /// different budget: raise it where the path genuinely carries more (fewer, larger
    /// packets cut per-packet overhead), lower it for tunnels with an even smaller MTU.
    ///
    /// The per-chunk payload budget is derived from this value by the inverse of the
    /// default derivation (minus the 12-byte common header and 16-byte DATA chunk header,
    /// rounded down to the SCTP 4-byte chunk-padding boundary), so a single maximum-size
    /// DATA chunk always marshals within this budget. Values below 32 — the smallest
    /// representable padded DATA packet — are raised to 32 with a warning. To keep the
    /// default, leave this unset.
    pub fn with_sctp_mtu(mut self, mtu: u32) -> Self {
        self.0.sctp_mtu = Some(mtu);
        self
    }

    /// Controls whether to ignore RID pause signals for receiving transceivers.
    ///
    /// RID (RTP Stream Identifier) can signal pause/resume for individual streams
    /// in simulcast scenarios. This setting controls whether to honor those signals.
    ///
    /// # Parameters
    ///
    /// * `ignore_rid_pause_for_recv` - `true` to ignore pause signals, `false` to honor them
    pub fn with_ignore_rid_pause_for_recv(mut self, ignore_rid_pause_for_recv: bool) -> Self {
        self.0.ignore_rid_pause_for_recv = ignore_rid_pause_for_recv;
        self
    }

    /// Controls whether to ignore SSRC attribute in SDP's sendonly or sendrecv for simulcast
    ///
    /// # Parameters
    ///
    /// * `write_ssrc_attributes_for_simulcast` - `true` to write, `false` to ignore
    pub fn with_write_ssrc_attributes_for_simulcast(
        mut self,
        write_ssrc_attributes_for_simulcast: bool,
    ) -> Self {
        self.0.write_ssrc_attributes_for_simulcast = write_ssrc_attributes_for_simulcast;
        self
    }

    /// Finalises the settings.
    pub fn build(self) -> SettingEngine {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression guard for the Safari mDNS interop fix. Safari (and Chrome)
    // emit only mDNS "<uuid>.local" host candidates by default; a default
    // SettingEngine must accept and resolve them (QueryOnly), not silently
    // discard them (Disabled).
    #[test]
    fn test_default_multicast_dns_mode_is_query_only() {
        assert_eq!(MulticastDNS::default().mode, MulticastDnsMode::QueryOnly);
        assert_eq!(
            SettingEngine::default().multicast_dns.mode,
            MulticastDnsMode::QueryOnly
        );
    }

    #[test]
    fn test_turn_allocation_refresh_interval_cap() {
        assert_eq!(
            SettingEngine::default().turn_allocation_refresh_interval_cap(),
            None
        );

        let cap = Duration::from_secs(30);
        let setting_engine = SettingEngineBuilder::new()
            .with_turn_allocation_refresh_interval_cap(cap)
            .build();

        assert_eq!(
            setting_engine.turn_allocation_refresh_interval_cap(),
            Some(cap)
        );
    }
}
