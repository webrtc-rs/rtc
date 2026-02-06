//! WebRTC peer connection configuration module.
//!
//! This module provides comprehensive configuration options for RTCPeerConnection,
//! including ICE servers, transport policies, bundling strategies, and engine settings.
//!
//! # Overview
//!
//! WebRTC connections require careful configuration to work across various network
//! topologies, NAT traversal scenarios, and media requirements. This module provides:
//!
//! - **ICE Configuration** - STUN/TURN server setup for NAT traversal
//! - **Transport Policies** - Control ICE candidate selection and RTCP multiplexing
//! - **Bundle Policies** - Media track bundling strategies
//! - **Certificates** - Custom DTLS certificates for peer authentication
//! - **Media Engine** - Codec and RTP extension configuration
//! - **Setting Engine** - Low-level transport and timing parameters
//! - **Interceptor Registry** - RTP/RTCP interceptor chain configuration (NACK, TWCC, Reports)
//!
//! # Quick Start
//!
//! ```
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Simple configuration with STUN server
//! let peer_connection = RTCPeerConnectionBuilder::new()
//!     .with_configuration(
//!         RTCConfigurationBuilder::new()
//!             .with_ice_servers(vec![
//!                 RTCIceServer {
//!                     urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!                     ..Default::default()
//!                 }
//!             ])
//!             .build()
//!     )
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Configuration Examples
//!
//! ## STUN and TURN Servers
//!
//! ```
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::configuration::RTCIceServer;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![
//!         // Public STUN server
//!         RTCIceServer {
//!             urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!             ..Default::default()
//!         },
//!         // TURN server with authentication
//!         RTCIceServer {
//!             urls: vec!["turn:turn.example.com:3478".to_string()],
//!             username: "user".to_string(),
//!             credential: "password".to_string(),
//!             ..Default::default()
//!         },
//!     ])
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Force TURN/Relay Only (Privacy Mode)
//!
//! ```
//! use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
//! use rtc::peer_connection::configuration::RTCIceServer;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Only use TURN relays, hide local IP addresses
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![
//!         RTCIceServer {
//!             urls: vec!["turn:turn.example.com:3478".to_string()],
//!             username: "user".to_string(),
//!             credential: "password".to_string(),
//!             ..Default::default()
//!         },
//!     ])
//!     .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Certificate
//!
//! ```
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate custom certificate for peer identity
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//!
//! let config = RTCConfigurationBuilder::new()
//!     .with_certificates(vec![certificate])
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Bundle Policy Configuration
//!
//! ```
//! use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCBundlePolicy};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Use max-bundle for best performance (single transport)
//! let config = RTCConfigurationBuilder::new()
//!     .with_bundle_policy(RTCBundlePolicy::MaxBundle)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## RTCP Multiplexing
//!
//! ```
//! use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtcpMuxPolicy};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Require RTCP-mux (standard for modern WebRTC)
//! let config = RTCConfigurationBuilder::new()
//!     .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Complete Configuration
//!
//! ```
//! use rtc::peer_connection::configuration::{
//!     RTCConfigurationBuilder,
//!     RTCBundlePolicy,
//!     RTCRtcpMuxPolicy,
//!     RTCIceTransportPolicy,
//! };
//! use rtc::peer_connection::configuration::RTCIceServer;
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//!
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![
//!         RTCIceServer {
//!             urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!             ..Default::default()
//!         },
//!     ])
//!     .with_ice_transport_policy(RTCIceTransportPolicy::All)
//!     .with_bundle_policy(RTCBundlePolicy::MaxBundle)
//!     .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
//!     .with_certificates(vec![certificate])
//!     .with_ice_candidate_pool_size(5)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! # Configuration Policies
//!
//! ## Bundle Policy
//!
//! Controls how media tracks are bundled onto transports:
//!
//! - **Balanced** - Bundle audio/video separately if peer doesn't support bundling
//! - **MaxCompat** - Separate transports for each track (maximum compatibility)
//! - **MaxBundle** - Single transport for all media (best performance, recommended)
//!
//! ## ICE Transport Policy
//!
//! Controls which ICE candidates are used:
//!
//! - **All** - Use all candidates (host, srflx, relay) - default
//! - **Relay** - Only use TURN relays (hides IP addresses, privacy mode)
//!
//! ## RTCP Mux Policy
//!
//! Controls RTCP multiplexing:
//!
//! - **Negotiate** - Try to multiplex, fall back to separate ports
//! - **Require** - Require multiplexing (standard for WebRTC, recommended)
//!
//! # Specifications
//!
//! * [W3C RTCConfiguration](https://w3c.github.io/webrtc-pc/#rtcconfiguration-dictionary)
//! * [RFC 8834 - WebRTC Transports](https://tools.ietf.org/html/rfc8834)
//! * [RFC 8445 - ICE](https://tools.ietf.org/html/rfc8445)

use crate::peer_connection::certificate::RTCCertificate;
pub use crate::peer_connection::transport::ice::server::RTCIceServer;
use rcgen::KeyPair;
use shared::error::{Error, Result};
use std::time::SystemTime;

pub(crate) mod bundle_policy;
pub(crate) mod ice_transport_policy;
pub mod interceptor_registry;
pub mod media_engine;
pub(crate) mod offer_answer_options;
pub(crate) mod rtcp_mux_policy;
pub(crate) mod sdp_semantics;
pub mod setting_engine;

pub use bundle_policy::RTCBundlePolicy;
pub use ice_transport_policy::{ICEGatherPolicy, RTCIceTransportPolicy};
pub use offer_answer_options::{RTCAnswerOptions, RTCOfferOptions};
pub use rtcp_mux_policy::RTCRtcpMuxPolicy;
pub use sdp_semantics::RTCSdpSemantics;

pub(crate) const UNSPECIFIED_STR: &str = "Unspecified";

/// A Configuration defines how peer-to-peer communication via PeerConnection
/// is established or re-established.
/// Configurations may be set up once and reused across multiple connections.
/// Configurations are treated as readonly. As long as they are unmodified,
/// they are safe for concurrent use.
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcconfiguration-dictionary
#[derive(Default, Clone, Debug)]
pub struct RTCConfiguration {
    /// ice_servers defines a slice describing servers available to be used by
    /// ICE, such as STUN and TURN servers.
    pub(crate) ice_servers: Vec<RTCIceServer>,

    /// ice_transport_policy indicates which candidates the ICEAgent is allowed
    /// to use.
    pub(crate) ice_transport_policy: RTCIceTransportPolicy,

    /// bundle_policy indicates which media-bundling policy to use when gathering
    /// ICE candidates.
    pub(crate) bundle_policy: RTCBundlePolicy,

    /// rtcp_mux_policy indicates which rtcp-mux policy to use when gathering ICE
    /// candidates.
    pub(crate) rtcp_mux_policy: RTCRtcpMuxPolicy,

    /// peer_identity sets the target peer identity for the PeerConnection.
    /// The PeerConnection will not establish a connection to a remote peer
    /// unless it can be successfully authenticated with the provided name.
    pub(crate) peer_identity: String,

    /// certificates describes a set of certificates that the PeerConnection
    /// uses to authenticate. Valid values for this parameter are created
    /// through calls to the generate_certificate function. Although any given
    /// DTLS connection will use only one certificate, this attribute allows the
    /// caller to provide multiple certificates that support different
    /// algorithms. The final certificate will be selected based on the DTLS
    /// handshake, which establishes which certificates are allowed. The
    /// PeerConnection implementation selects which of the certificates is
    /// used for a given connection; how certificates are selected is outside
    /// the scope of this specification. If this value is absent, then a default
    /// set of certificates is generated for each PeerConnection instance.
    pub(crate) certificates: Vec<RTCCertificate>,

    /// ice_candidate_pool_size describes the size of the prefetched ICE pool.
    pub(crate) ice_candidate_pool_size: u8,
}

impl RTCConfiguration {
    /// Returns the ICE servers configured for this peer connection.
    ///
    /// This is useful for ICE candidate gathering implementations that need
    /// to know which STUN/TURN servers to use.
    pub fn ice_servers(&self) -> &[RTCIceServer] {
        &self.ice_servers
    }

    /// Returns the ICE transport policy.
    ///
    /// This indicates which candidates the ICE agent is allowed to use.
    pub fn ice_transport_policy(&self) -> RTCIceTransportPolicy {
        self.ice_transport_policy
    }

    /// Returns the bundle policy.
    ///
    /// This indicates which media-bundling policy to use when gathering ICE candidates.
    pub fn bundle_policy(&self) -> RTCBundlePolicy {
        self.bundle_policy
    }

    /// Returns the RTCP mux policy.
    ///
    /// This indicates which RTCP-mux policy to use when gathering ICE candidates.
    pub fn rtcp_mux_policy(&self) -> RTCRtcpMuxPolicy {
        self.rtcp_mux_policy
    }

    /// Returns the peer identity.
    ///
    /// This is the target peer identity for the PeerConnection.
    /// The PeerConnection will not establish a connection to a remote peer
    /// unless it can be successfully authenticated with the provided name.
    pub fn peer_identity(&self) -> &str {
        &self.peer_identity
    }

    /// Returns the certificates configured for this peer connection.
    ///
    /// These certificates are used for DTLS authentication.
    pub fn certificates(&self) -> &[RTCCertificate] {
        &self.certificates
    }

    /// Returns the ICE candidate pool size.
    ///
    /// This describes the size of the prefetched ICE pool.
    pub fn ice_candidate_pool_size(&self) -> u8 {
        self.ice_candidate_pool_size
    }

    /// get_ice_servers side-steps the strict parsing mode of the ice package
    /// (as defined in https://tools.ietf.org/html/rfc7064) by copying and then
    /// stripping any erroneous queries from "stun(s):" URLs before parsing.
    #[allow(clippy::assigning_clones)]
    fn get_ice_servers(&self) -> Vec<RTCIceServer> {
        let mut ice_servers = self.ice_servers.clone();

        for ice_server in &mut ice_servers {
            for raw_url in &mut ice_server.urls {
                if raw_url.starts_with("stun") {
                    // strip the query from "stun(s):" if present
                    let parts: Vec<&str> = raw_url.split('?').collect();
                    *raw_url = parts[0].to_owned();
                }
            }
        }

        ice_servers
    }

    pub(crate) fn validate(&mut self) -> Result<()> {
        let sanitized_ice_servers = self.get_ice_servers();
        if !sanitized_ice_servers.is_empty() {
            for server in &sanitized_ice_servers {
                server.validate()?;
            }
        }

        // <https://www.w3.org/TR/webrtc/#constructor> (step #3)
        if !self.certificates.is_empty() {
            let now = SystemTime::now();
            for cert in &self.certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }
        } else {
            let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = RTCCertificate::from_key_pair(kp)?;
            self.certificates = vec![cert];
        };

        Ok(())
    }
}

/// Builder for creating RTCConfiguration instances.
///
/// This builder provides a fluent API for configuring WebRTC peer connection settings:
/// - ICE servers (STUN/TURN) for NAT traversal
/// - Transport policies (which ICE candidates to use)
/// - Bundle and RTCP mux policies
/// - Custom DTLS certificates
/// - ICE candidate pool size
///
/// # Examples
///
/// ## Basic configuration with STUN
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RTCConfigurationBuilder::new()
///     .with_ice_servers(vec![
///         RTCIceServer {
///             urls: vec!["stun:stun.l.google.com:19302".to_string()],
///             ..Default::default()
///         }
///     ])
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## TURN server with credentials
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RTCConfigurationBuilder::new()
///     .with_ice_servers(vec![
///         RTCIceServer {
///             urls: vec!["turn:turn.example.com:3478".to_string()],
///             username: "user".to_string(),
///             credential: "password".to_string(),
///             ..Default::default()
///         }
///     ])
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Relay-only (privacy mode)
///
/// ```
/// use rtc::peer_connection::configuration::{
///     RTCConfigurationBuilder,
///     RTCIceServer,
///     RTCIceTransportPolicy
/// };
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RTCConfigurationBuilder::new()
///     .with_ice_servers(vec![
///         RTCIceServer {
///             urls: vec!["turn:turn.example.com:3478".to_string()],
///             username: "user".to_string(),
///             credential: "password".to_string(),
///             ..Default::default()
///         }
///     ])
///     .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Custom certificate
///
/// ```
/// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
/// use rtc::peer_connection::certificate::RTCCertificate;
/// use rcgen::KeyPair;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
/// let certificate = RTCCertificate::from_key_pair(key_pair)?;
///
/// let config = RTCConfigurationBuilder::new()
///     .with_certificates(vec![certificate])
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Default, Debug)]
pub struct RTCConfigurationBuilder {
    /// ice_servers defines a slice describing servers available to be used by
    /// ICE, such as STUN and TURN servers.
    pub(crate) ice_servers: Vec<RTCIceServer>,

    /// ice_transport_policy indicates which candidates the ICEAgent is allowed
    /// to use.
    pub(crate) ice_transport_policy: RTCIceTransportPolicy,

    /// bundle_policy indicates which media-bundling policy to use when gathering
    /// ICE candidates.
    pub(crate) bundle_policy: RTCBundlePolicy,

    /// rtcp_mux_policy indicates which rtcp-mux policy to use when gathering ICE
    /// candidates.
    pub(crate) rtcp_mux_policy: RTCRtcpMuxPolicy,

    /// peer_identity sets the target peer identity for the PeerConnection.
    /// The PeerConnection will not establish a connection to a remote peer
    /// unless it can be successfully authenticated with the provided name.
    pub(crate) peer_identity: String,

    /// certificates describes a set of certificates that the PeerConnection
    /// uses to authenticate. Valid values for this parameter are created
    /// through calls to the generate_certificate function. Although any given
    /// DTLS connection will use only one certificate, this attribute allows the
    /// caller to provide multiple certificates that support different
    /// algorithms. The final certificate will be selected based on the DTLS
    /// handshake, which establishes which certificates are allowed. The
    /// PeerConnection implementation selects which of the certificates is
    /// used for a given connection; how certificates are selected is outside
    /// the scope of this specification. If this value is absent, then a default
    /// set of certificates is generated for each PeerConnection instance.
    pub(crate) certificates: Vec<RTCCertificate>,

    /// ice_candidate_pool_size describes the size of the prefetched ICE pool.
    pub(crate) ice_candidate_pool_size: u8,
}

impl RTCConfigurationBuilder {
    /// Creates a new RTCConfigurationBuilder with default settings.
    ///
    /// Default values:
    /// - No ICE servers (local candidates only)
    /// - All ICE candidate types allowed
    /// - Balanced bundle policy
    /// - Required RTCP mux policy
    /// - No peer identity
    /// - Auto-generated certificates
    /// - ICE candidate pool size of 0
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    ///
    /// let config = RTCConfigurationBuilder::new().build();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ICE servers for STUN and TURN.
    ///
    /// ICE servers are used for NAT traversal to establish peer-to-peer connectivity.
    /// Multiple servers can be provided for redundancy.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_ice_servers(vec![
    ///         RTCIceServer {
    ///             urls: vec!["stun:stun.l.google.com:19302".to_string()],
    ///             ..Default::default()
    ///         },
    ///         RTCIceServer {
    ///             urls: vec!["turn:turn.example.com:3478".to_string()],
    ///             username: "user".to_string(),
    ///             credential: "pass".to_string(),
    ///             ..Default::default()
    ///         }
    ///     ])
    ///     .build();
    /// ```
    pub fn with_ice_servers(mut self, ice_servers: Vec<RTCIceServer>) -> Self {
        self.ice_servers = ice_servers;
        self
    }

    /// Sets the ICE transport policy.
    ///
    /// Controls which types of ICE candidates are allowed:
    /// - `All` (default): Use all candidate types (host, srflx, relay)
    /// - `Relay`: Only use TURN relay candidates (hides IP addresses)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
    ///
    /// // Privacy mode - only use TURN relays
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
    ///     .build();
    /// ```
    pub fn with_ice_transport_policy(
        mut self,
        ice_transport_policy: RTCIceTransportPolicy,
    ) -> Self {
        self.ice_transport_policy = ice_transport_policy;
        self
    }

    /// Sets the bundle policy.
    ///
    /// Controls how media tracks are bundled onto transports:
    /// - `Balanced` (default): Bundle audio/video separately if peer doesn't support bundling
    /// - `MaxCompat`: Separate transports for each track (maximum compatibility)
    /// - `MaxBundle`: Single transport for all media (best performance)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCBundlePolicy};
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_bundle_policy(RTCBundlePolicy::MaxBundle)
    ///     .build();
    /// ```
    pub fn with_bundle_policy(mut self, bundle_policy: RTCBundlePolicy) -> Self {
        self.bundle_policy = bundle_policy;
        self
    }

    /// Sets the RTCP multiplexing policy.
    ///
    /// Controls whether RTCP is multiplexed with RTP:
    /// - `Negotiate`: Try to multiplex, fall back to separate ports
    /// - `Require` (default): Require multiplexing (standard for WebRTC)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtcpMuxPolicy};
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
    ///     .build();
    /// ```
    pub fn with_rtcp_mux_policy(mut self, rtcp_mux_policy: RTCRtcpMuxPolicy) -> Self {
        self.rtcp_mux_policy = rtcp_mux_policy;
        self
    }

    /// Sets the target peer identity.
    ///
    /// If set, the peer connection will only connect to a remote peer that can be
    /// successfully authenticated with this identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_peer_identitys("peer@example.com".to_string())
    ///     .build();
    /// ```
    pub fn with_peer_identitys(mut self, peer_identity: String) -> Self {
        self.peer_identity = peer_identity;
        self
    }

    /// Sets custom DTLS certificates.
    ///
    /// If not provided, certificates are auto-generated. Providing certificates allows
    /// for consistent peer identity across connections.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    /// use rtc::peer_connection::certificate::RTCCertificate;
    /// use rcgen::KeyPair;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// let certificate = RTCCertificate::from_key_pair(key_pair)?;
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_certificates(vec![certificate])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_certificates(mut self, certificates: Vec<RTCCertificate>) -> Self {
        self.certificates = certificates;
        self
    }

    /// Sets the ICE candidate pool size.
    ///
    /// Specifies the number of ICE candidates to gather before needed.
    /// Pre-gathering candidates can reduce connection establishment time.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    ///
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_ice_candidate_pool_size(5)
    ///     .build();
    /// ```
    pub fn with_ice_candidate_pool_size(mut self, ice_candidate_pool_size: u8) -> Self {
        self.ice_candidate_pool_size = ice_candidate_pool_size;
        self
    }

    /// Builds the RTCConfiguration.
    ///
    /// Creates an immutable configuration that can be used to create a peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    ///
    /// let config = RTCConfigurationBuilder::new().build();
    /// ```
    pub fn build(self) -> RTCConfiguration {
        RTCConfiguration {
            ice_servers: self.ice_servers,
            ice_transport_policy: self.ice_transport_policy,
            bundle_policy: self.bundle_policy,
            rtcp_mux_policy: self.rtcp_mux_policy,
            peer_identity: self.peer_identity,
            certificates: self.certificates,
            ice_candidate_pool_size: self.ice_candidate_pool_size,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_configuration_get_iceservers() {
        {
            let expected_server_str = "stun:stun.l.google.com:19302";
            let cfg = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![expected_server_str.to_owned()],
                    ..Default::default()
                }])
                .build();

            let parsed_urls = cfg.get_ice_servers();
            assert_eq!(parsed_urls[0].urls[0], expected_server_str);
        }

        {
            // ignore the fact that stun URLs shouldn't have a query
            let server_str = "stun:global.stun.twilio.com:3478?transport=udp";
            let expected_server_str = "stun:global.stun.twilio.com:3478";
            let cfg = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![server_str.to_owned()],
                    ..Default::default()
                }])
                .build();

            let parsed_urls = cfg.get_ice_servers();
            assert_eq!(parsed_urls[0].urls[0], expected_server_str);
        }
    }

    /*TODO:#[test] fn test_configuration_json() {

         let j = r#"
            {
                "iceServers": [{"URLs": ["turn:turn.example.org"],
                                "username": "jch",
                                "credential": "topsecret"
                              }],
                "iceTransportPolicy": "relay",
                "bundlePolicy": "balanced",
                "rtcpMuxPolicy": "require"
            }"#;

        conf := Configuration{
            ICEServers: []ICEServer{
                {
                    URLs:       []string{"turn:turn.example.org"},
                    Username:   "jch",
                    Credential: "topsecret",
                },
            },
            ICETransportPolicy: ICETransportPolicyRelay,
            BundlePolicy:       BundlePolicyBalanced,
            RTCPMuxPolicy:      RTCPMuxPolicyRequire,
        }

        var conf2 Configuration
        assert.NoError(t, json.Unmarshal([]byte(j), &conf2))
        assert.Equal(t, conf, conf2)

        j2, err := json.Marshal(conf2)
        assert.NoError(t, err)

        var conf3 Configuration
        assert.NoError(t, json.Unmarshal(j2, &conf3))
        assert.Equal(t, conf2, conf3)
    }*/
}
