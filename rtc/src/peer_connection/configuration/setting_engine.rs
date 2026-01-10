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
//! - **Data Channels**: Enable detached mode for custom transport handling
//!
//! # Examples
//!
//! ## Configuring ICE timeouts for unstable networks
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngine;
//! use std::time::Duration;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut setting_engine = SettingEngine::default();
//!
//! // Increase timeouts for mobile or unstable networks
//! setting_engine.set_ice_timeouts(
//!     Some(Duration::from_secs(10)),  // disconnected_timeout (default: 5s)
//!     Some(Duration::from_secs(30)),  // failed_timeout (default: 25s)
//!     Some(Duration::from_secs(3)),   // keep_alive_interval (default: 2s)
//! );
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
//! use rtc::peer_connection::configuration::setting_engine::SettingEngine;
//! use rtc::peer_connection::transport::RTCIceCandidateType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut setting_engine = SettingEngine::default();
//!
//! // Configure for AWS EC2 instance with Elastic IP
//! // Private IP: 10.0.1.5, Public IP: 54.123.45.67
//! setting_engine.set_nat_1to1_ips(
//!     vec!["54.123.45.67".to_string()],
//!     RTCIceCandidateType::Host, // Use public IP for host candidates
//! );
//!
//! // This tells ICE to advertise the public IP instead of the private one
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring replay protection for security-critical applications
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut setting_engine = SettingEngine::default();
//!
//! // Increase replay protection window sizes
//! setting_engine.set_dtls_replay_protection_window(128);  // DTLS anti-replay
//! setting_engine.set_srtp_replay_protection_window(256);  // SRTP anti-replay
//! setting_engine.set_srtcp_replay_protection_window(128); // SRTCP anti-replay
//!
//! // Larger windows protect against more packet reordering but use more memory
//! # Ok(())
//! # }
//! ```
//!
//! ## Restricting network types for controlled environments
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngine;
//! use ice::network_type::NetworkType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut setting_engine = SettingEngine::default();
//!
//! // Only gather IPv4 UDP candidates (no IPv6, no TCP)
//! setting_engine.set_network_types(vec![NetworkType::Udp4]);
//!
//! // This reduces candidate gathering time and SDP size
//! # Ok(())
//! # }
//! ```
//!
//! ## Enabling detached data channels
//!
//! ```no_run
//! use rtc::peer_connection::configuration::setting_engine::SettingEngine;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut setting_engine = SettingEngine::default();
//!
//! // Enable detached mode for custom data channel handling
//! setting_engine.detach_data_channels();
//!
//! // Now data channels must be detached in the on_open callback
//! // This is useful for custom protocols or zero-copy processing
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

use std::sync::Arc;

use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
//TODO: use ice::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
//TODO: use ice::mdns::MulticastDnsMode;
use ice::network_type::NetworkType;
//TODO: use ice::udp_network::UDPNetwork;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use ice::mdns::MulticastDnsMode;
use shared::error::{Error, Result};
use std::time::Duration;

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

/// Configuration for detaching WebRTC components.
///
/// Detaching allows for custom handling of data channels outside the standard
/// WebRTC event loop, enabling zero-copy processing and custom protocols.
#[derive(Default, Clone)]
pub struct Detach {
    /// Whether data channels should operate in detached mode.
    pub data_channels: bool,
}

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

    /// Duration without network activity before mDNS query is considered failed.
    /// Default: 25 seconds.
    pub ice_multicast_dns_timeout: Option<Duration>,

    /// How often ICE sends keepalive packets when there's no media flow.
    /// Default: 2 seconds. If media is flowing, no keepalives are sent.
    pub ice_keepalive_interval: Option<Duration>,

    /// Minimum wait time before accepting host candidates.
    pub ice_host_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting server reflexive candidates.
    pub ice_srflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting peer reflexive candidates.
    pub ice_prflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting relay candidates.
    pub ice_relay_acceptance_min_wait: Option<Duration>,
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
    pub multicast_dns_mode: MulticastDnsMode,
    pub multicast_dns_host_name: String,
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
            Self::Bounded(result) => *result as usize,
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
/// - **Detach**: Enable custom handling of data channels
/// - **Timeout**: ICE connection health monitoring and keepalive
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
/// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut setting_engine = SettingEngine::default();
///
/// // Configure timeouts
/// setting_engine.set_ice_timeouts(
///     Some(Duration::from_secs(10)),
///     Some(Duration::from_secs(30)),
///     Some(Duration::from_secs(3)),
/// );
///
/// // Enable loopback for testing
/// setting_engine.set_include_loopback_candidate(true);
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
    pub(crate) detach: Detach,
    pub(crate) timeout: Timeout,
    pub(crate) candidates: Candidates,
    pub(crate) replay_protection: ReplayProtection,
    pub(crate) sdp_media_level_fingerprints: bool,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) allow_insecure_verification_algorithm: bool,

    //BufferFactory                             :func(packetType packetio.BufferPacketType, ssrc uint32) io.ReadWriteCloser,
    //iceTCPMux                                 :ice.TCPMux,?
    //iceProxyDialer                            :proxy.Dialer,?
    //TODO: pub(crate) udp_network: UDPNetwork,
    pub(crate) disable_media_engine_copy: bool,
    pub(crate) disable_media_engine_multiple_codecs: bool,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) receive_mtu: usize,
    pub(crate) mid_generator: Option<Arc<dyn Fn(isize) -> String + Send + Sync>>,
    /// Determines the max size of any message that may be sent through an SCTP transport.
    pub(crate) sctp_max_message_size: SctpMaxMessageSize,
    pub(crate) ignore_rid_pause_for_recv: bool,
    pub(crate) write_ssrc_attributes_for_simulcast: bool,
}

impl SettingEngine {
    /// Returns the configured receive MTU, or the default if not set.
    pub(crate) fn get_receive_mtu(&self) -> usize {
        if self.receive_mtu != 0 {
            self.receive_mtu
        } else {
            RECEIVE_MTU
        }
    }

    /// Enables detached mode for data channels.
    ///
    /// When enabled, data channels must be explicitly detached in the `on_open`
    /// callback using the `DataChannel::detach()` method. This provides direct
    /// access to the underlying transport for custom protocols or zero-copy processing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    /// setting_engine.detach_data_channels();
    ///
    /// // In your data channel on_open handler:
    /// // let detached = data_channel.detach().await?;
    /// // Now you have raw read/write access to the transport
    /// # Ok(())
    /// # }
    /// ```
    pub fn detach_data_channels(&mut self) {
        self.detach.data_channels = true;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    /// use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Use specific SRTP profile
    /// setting_engine.set_srtp_protection_profiles(vec![
    ///     SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    /// ]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_srtp_protection_profiles(&mut self, profiles: Vec<SrtpProtectionProfile>) {
        self.srtp_protection_profiles = profiles
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Conservative settings for mobile networks
    /// setting_engine.set_ice_timeouts(
    ///     Some(Duration::from_secs(10)),  // Longer before disconnected
    ///     Some(Duration::from_secs(40)),  // Longer before failed
    ///     Some(Duration::from_secs(5)),   // Less frequent keepalives
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §16 - Timers](https://datatracker.ietf.org/doc/html/rfc8445#section-16)
    pub fn set_ice_timeouts(
        &mut self,
        disconnected_timeout: Option<Duration>,
        failed_timeout: Option<Duration>,
        keep_alive_interval: Option<Duration>,
    ) {
        self.timeout.ice_disconnected_timeout = disconnected_timeout;
        self.timeout.ice_failed_timeout = failed_timeout;
        self.timeout.ice_keepalive_interval = keep_alive_interval;
    }

    /// Sets minimum wait time before accepting host candidates.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn set_host_acceptance_min_wait(&mut self, t: Option<Duration>) {
        self.timeout.ice_host_acceptance_min_wait = t;
    }

    /// Sets minimum wait time before accepting server reflexive candidates.
    ///
    /// Server reflexive candidates are discovered through STUN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn set_srflx_acceptance_min_wait(&mut self, t: Option<Duration>) {
        self.timeout.ice_srflx_acceptance_min_wait = t;
    }

    /// Sets minimum wait time before accepting peer reflexive candidates.
    ///
    /// Peer reflexive candidates are discovered during connectivity checks.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn set_prflx_acceptance_min_wait(&mut self, t: Option<Duration>) {
        self.timeout.ice_prflx_acceptance_min_wait = t;
    }

    /// Sets minimum wait time before accepting relay candidates.
    ///
    /// Relay candidates are provided by TURN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn set_relay_acceptance_min_wait(&mut self, t: Option<Duration>) {
        self.timeout.ice_relay_acceptance_min_wait = t;
    }

    /*todo:
    /// set_udp_network allows ICE traffic to come through Ephemeral or UDPMux.
    /// UDPMux drastically simplifying deployments where ports will need to be opened/forwarded.
    /// UDPMux should be started prior to creating PeerConnections.
    pub fn set_udp_network(&mut self, udp_network: UDPNetwork) {
        self.udp_network = udp_network;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Enable ICE Lite for a publicly accessible server
    /// setting_engine.set_lite(true);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §2.7 - Lite Implementation](https://datatracker.ietf.org/doc/html/rfc8445#section-2.7)
    pub fn set_lite(&mut self, lite: bool) {
        self.candidates.ice_lite = lite;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    /// use ice::network_type::NetworkType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Only use IPv4 UDP (most common case)
    /// setting_engine.set_network_types(vec![NetworkType::Udp4]);
    ///
    /// // Or allow both IPv4 and IPv6 UDP
    /// setting_engine.set_network_types(vec![
    ///     NetworkType::Udp4,
    ///     NetworkType::Udp6,
    /// ]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_network_types(&mut self, candidate_types: Vec<NetworkType>) {
        self.candidates.ice_network_types = candidate_types;
    }

    /*todo:
    /// set_interface_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain network interfaces from ICE. Which may be
    /// useful if you know a certain interface will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn set_interface_filter(&mut self, filter: InterfaceFilterFn) {
        self.candidates.interface_filter = Arc::new(Some(filter));
    }

    /// set_ip_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain ip from ICE. Which may be
    /// useful if you know a certain ip will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn set_ip_filter(&mut self, filter: IpFilterFn) {
        self.candidates.ip_filter = Arc::new(Some(filter));
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    /// use rtc::peer_connection::transport::RTCIceCandidateType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // AWS EC2: Private IP 10.0.1.5, Elastic IP 54.123.45.67
    /// setting_engine.set_nat_1to1_ips(
    ///     vec!["54.123.45.67".to_string()],
    ///     RTCIceCandidateType::Host,
    /// );
    ///
    /// // Or use Srflx to keep private IP available
    /// setting_engine.set_nat_1to1_ips(
    ///     vec!["54.123.45.67".to_string()],
    ///     RTCIceCandidateType::Srflx,
    /// );
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
    pub fn set_nat_1to1_ips(&mut self, ips: Vec<String>, candidate_type: RTCIceCandidateType) {
        self.candidates.nat_1to1_ips = ips;
        self.candidates.nat_1to1_ip_candidate_type = candidate_type;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    /// use rtc::peer_connection::transport::RTCDtlsRole;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Force this peer to always act as DTLS client when answering
    /// setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8842 - DTLS for WebRTC](https://datatracker.ietf.org/doc/html/rfc8842)
    pub fn set_answering_dtls_role(&mut self, role: RTCDtlsRole) -> Result<()> {
        if role != RTCDtlsRole::Client && role != RTCDtlsRole::Server {
            return Err(Error::ErrSettingEngineSetAnsweringDTLSRole);
        }

        self.answering_dtls_role = role;
        Ok(())
    }

    pub fn set_ice_multicast_dns_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout.ice_multicast_dns_timeout = timeout;
    }

    /// set_ice_multicast_dns_mode controls if ice queries and generates mDNS ICE Candidates
    pub fn set_ice_multicast_dns_mode(&mut self, multicast_dns_mode: ice::mdns::MulticastDnsMode) {
        self.candidates.multicast_dns_mode = multicast_dns_mode
    }

    /// set_ice_multicast_dns_host_name sets a static HostName to be used by ice instead of generating one on startup
    /// This should only be used for a single PeerConnection. Having multiple PeerConnections with the same HostName will cause
    /// undefined behavior
    pub fn set_ice_multicast_dns_host_name(&mut self, host_name: String) {
        self.candidates.multicast_dns_host_name = host_name;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Set static credentials for reproducible testing
    /// setting_engine.set_ice_credentials(
    ///     "test_ufrag".to_string(),
    ///     "test_password".to_string(),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Only use static credentials in controlled environments. Random credentials
    /// provide better security for production deployments.
    pub fn set_ice_credentials(&mut self, username_fragment: String, password: String) {
        self.candidates.username_fragment = username_fragment;
        self.candidates.password = password;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Only for testing/debugging!
    /// setting_engine.disable_certificate_fingerprint_verification(true);
    /// # Ok(())
    /// # }
    /// ```
    pub fn disable_certificate_fingerprint_verification(&mut self, is_disabled: bool) {
        self.disable_certificate_fingerprint_verification = is_disabled;
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
    pub fn allow_insecure_verification_algorithm(&mut self, is_allowed: bool) {
        self.allow_insecure_verification_algorithm = is_allowed;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Increase window for high-latency or reordering networks
    /// setting_engine.set_dtls_replay_protection_window(128);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 6347 §4.1.2.6 - Anti-Replay](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6)
    pub fn set_dtls_replay_protection_window(&mut self, n: usize) {
        self.replay_protection.dtls = n;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Standard size for most applications
    /// setting_engine.set_srtp_replay_protection_window(256);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 3711 §3.3.2 - Replay Protection](https://datatracker.ietf.org/doc/html/rfc3711#section-3.3.2)
    pub fn set_srtp_replay_protection_window(&mut self, n: usize) {
        self.replay_protection.srtp = n;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Smaller window sufficient for RTCP
    /// setting_engine.set_srtcp_replay_protection_window(64);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_srtcp_replay_protection_window(&mut self, n: usize) {
        self.replay_protection.srtcp = n;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Enable for certain VM configurations
    /// setting_engine.set_include_loopback_candidate(true);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// This is non-standard behavior per [RFC 8445 §5.1.1.1](https://www.rfc-editor.org/rfc/rfc8445#section-5.1.1.1).
    /// Use with caution.
    pub fn set_include_loopback_candidate(&mut self, allow_loopback: bool) {
        self.candidates.include_loopback_candidate = allow_loopback;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Use media-level fingerprints for better compatibility
    /// setting_engine.set_sdp_media_level_fingerprints(true);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_sdp_media_level_fingerprints(&mut self, sdp_media_level_fingerprints: bool) {
        self.sdp_media_level_fingerprints = sdp_media_level_fingerprints;
    }

    // SetICETCPMux enables ICE-TCP when set to a non-nil value. Make sure that
    // NetworkTypeTCP4 or NetworkTypeTCP6 is enabled as well.
    //pub fn SetICETCPMux(&mut self, tcpMux ice.TCPMux) {
    //    self.iceTCPMux = tcpMux
    //}

    // SetICEProxyDialer sets the proxy dialer interface based on golang.org/x/net/proxy.
    //pub fn SetICEProxyDialer(&mut self, d proxy.Dialer) {
    //    self.iceProxyDialer = d
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Share MediaEngine across connections
    /// setting_engine.disable_media_engine_copy(true);
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
    pub fn disable_media_engine_copy(&mut self, is_disabled: bool) {
        self.disable_media_engine_copy = is_disabled;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Force same codecs for all media sections
    /// setting_engine.disable_media_engine_multiple_codecs(true);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Deprecation Note
    ///
    /// This setting is targeted for removal in a future release (4.2.0 or later).
    pub fn disable_media_engine_multiple_codecs(&mut self, is_disabled: bool) {
        self.disable_media_engine_multiple_codecs = is_disabled;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Use larger MTU for jumbo frames
    /// setting_engine.set_receive_mtu(9000);
    ///
    /// // Or use default
    /// setting_engine.set_receive_mtu(0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_receive_mtu(&mut self, receive_mtu: usize) {
        self.receive_mtu = receive_mtu;
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
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Generate MIDs with a custom prefix
    /// setting_engine.set_mid_generator(|max_mid| {
    ///     format!("custom_{}", max_mid + 1)
    /// });
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
    pub fn set_mid_generator(&mut self, f: impl Fn(isize) -> String + Send + Sync + 'static) {
        self.mid_generator = Some(Arc::new(f));
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
    /// use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SctpMaxMessageSize};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut setting_engine = SettingEngine::default();
    ///
    /// // Use default 64KB
    /// setting_engine.set_sctp_max_message_size(
    ///     SctpMaxMessageSize::Bounded(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE)
    /// );
    ///
    /// // Or allow larger messages
    /// setting_engine.set_sctp_max_message_size(
    ///     SctpMaxMessageSize::Bounded(256 * 1024) // 256KB
    /// );
    ///
    /// // Or unbounded (uses MAX_MESSAGE_SIZE internally)
    /// setting_engine.set_sctp_max_message_size(SctpMaxMessageSize::Unbounded);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8841 §6.1 - max-message-size](https://datatracker.ietf.org/doc/html/rfc8841#section-6.1)
    pub fn set_sctp_max_message_size(&mut self, max_message_size: SctpMaxMessageSize) {
        self.sctp_max_message_size = max_message_size;
    }

    /// Controls whether to ignore RID pause signals for receiving transceivers.
    ///
    /// RID (RTP Stream Identifier) can signal pause/resume for individual streams
    /// in simulcast scenarios. This setting controls whether to honor those signals.
    ///
    /// # Parameters
    ///
    /// * `ignore_rid_pause_for_recv` - `true` to ignore pause signals, `false` to honor them
    pub fn set_ignore_rid_pause_for_recv(&mut self, ignore_rid_pause_for_recv: bool) {
        self.ignore_rid_pause_for_recv = ignore_rid_pause_for_recv;
    }

    /// Controls whether to ignore SSRC attribute in SDP's sendonly or sendrecv for simulcast
    ///
    /// # Parameters
    ///
    /// * `write_ssrc_attributes_for_simulcast` - `true` to write, `false` to ignore
    pub fn set_write_ssrc_attributes_for_simulcast(
        &mut self,
        write_ssrc_attributes_for_simulcast: bool,
    ) {
        self.write_ssrc_attributes_for_simulcast = write_ssrc_attributes_for_simulcast;
    }
}
