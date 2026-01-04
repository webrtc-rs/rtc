//! WebRTC transport layer types for ICE, DTLS, and SCTP.
//!
//! This module provides types for working with the three transport layers used in WebRTC:
//!
//! - **ICE (Interactive Connectivity Establishment)** - Establishes peer-to-peer network connections
//! - **DTLS (Datagram Transport Layer Security)** - Provides encryption over UDP
//! - **SCTP (Stream Control Transmission Protocol)** - Multiplexes data channels over DTLS
//!
//! # Transport Stack
//!
//! WebRTC uses a layered transport architecture:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │      Media/Data Channels            │  Application Layer
//! ├─────────────────────────────────────┤
//! │  RTP/RTCP    │      SCTP            │  Protocol Layer
//! ├──────────────┴──────────────────────┤
//! │           DTLS (encryption)         │  Security Layer
//! ├─────────────────────────────────────┤
//! │      ICE (NAT traversal)            │  Connectivity Layer
//! ├─────────────────────────────────────┤
//! │         UDP/TCP                     │  Network Layer
//! └─────────────────────────────────────┘
//! ```
//!
//! # ICE Transport
//!
//! ICE establishes connectivity through NATs and firewalls by:
//!
//! 1. Gathering local network addresses ([`RTCIceCandidate`])
//! 2. Exchanging candidates with the remote peer
//! 3. Testing candidate pairs for connectivity
//! 4. Selecting the best working path
//!
//! Key ICE types:
//!
//! - [`RTCIceCandidate`] - A potential network address for communication
//! - [`RTCIceCandidateType`] - Type of candidate (host, srflx, prflx, relay)
//! - [`RTCIceTransportState`] - Current state of ICE connectivity
//! - [`RTCIceProtocol`] - Transport protocol (UDP or TCP)
//! - [`RTCIceRole`] - Whether controlling or controlled
//! - [`RTCIceServer`] - STUN/TURN server configuration
//!
//! # DTLS Transport
//!
//! DTLS provides end-to-end encryption over UDP:
//!
//! - [`RTCDtlsFingerprint`] - Certificate fingerprint for authentication
//! - [`RTCDtlsRole`] - Whether client or server in handshake
//! - [`RTCDtlsTransportState`] - Current state of DTLS connection
//!
//! # SCTP Transport
//!
//! SCTP multiplexes data channels over DTLS:
//!
//! - [`RTCSctpTransportState`] - Current state of SCTP association
//!
//! # Examples
//!
//! ## Working with ICE Candidates
//!
//! ```
//! use rtc::peer_connection::transport::{RTCIceCandidate, RTCIceCandidateType, RTCIceProtocol};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Example candidate from ICE gathering
//! let candidate = RTCIceCandidate {
//!     address: "192.168.1.100".to_string(),
//!     port: 54321,
//!     protocol: RTCIceProtocol::from("udp"),
//!     typ: RTCIceCandidateType::Host,
//!     component: 1,
//!     priority: 2130706431,
//!     ..Default::default()
//! };
//!
//! println!("Candidate type: {}", candidate.typ);
//! println!("Address: {}:{}", candidate.address, candidate.port);
//! # Ok(())
//! # }
//! ```
//!
//! ## Checking Transport States
//!
//! ```
//! use rtc::peer_connection::transport::{
//!     RTCIceTransportState, RTCDtlsTransportState, RTCSctpTransportState
//! };
//!
//! fn is_connected(
//!     ice_state: RTCIceTransportState,
//!     dtls_state: RTCDtlsTransportState,
//! ) -> bool {
//!     matches!(ice_state, RTCIceTransportState::Connected | RTCIceTransportState::Completed)
//!         && dtls_state == RTCDtlsTransportState::Connected
//! }
//!
//! // All transports must be connected for media to flow
//! assert!(is_connected(
//!     RTCIceTransportState::Connected,
//!     RTCDtlsTransportState::Connected
//! ));
//! ```
//!
//! ## Candidate Type Classification
//!
//! ```
//! use rtc::peer_connection::transport::RTCIceCandidateType;
//!
//! fn requires_stun_server(candidate_type: RTCIceCandidateType) -> bool {
//!     matches!(candidate_type, RTCIceCandidateType::Srflx)
//! }
//!
//! fn requires_turn_server(candidate_type: RTCIceCandidateType) -> bool {
//!     matches!(candidate_type, RTCIceCandidateType::Relay)
//! }
//!
//! assert!(!requires_stun_server(RTCIceCandidateType::Host));
//! assert!(requires_stun_server(RTCIceCandidateType::Srflx));
//! assert!(requires_turn_server(RTCIceCandidateType::Relay));
//! ```
//!
//! ## DTLS Role Determination
//!
//! ```
//! use rtc::peer_connection::transport::RTCDtlsRole;
//!
//! // Offerer uses Auto (actpass in SDP)
//! let offerer_role = RTCDtlsRole::Auto;
//!
//! // Answerer should use Client (active in SDP) for lower latency
//! let answerer_role = RTCDtlsRole::Client;
//!
//! println!("Offerer: {}", offerer_role);
//! println!("Answerer: {}", answerer_role);
//! ```
//!
//! # Specifications
//!
//! - [RFC 8445] - ICE: Interactive Connectivity Establishment
//! - [RFC 6347] - DTLS: Datagram Transport Layer Security
//! - [RFC 8261] - SCTP over DTLS for WebRTC Data Channels
//! - [RFC 5245] - ICE (obsoleted by RFC 8445)
//! - [RFC 5389] - STUN: Session Traversal Utilities for NAT
//! - [RFC 8656] - TURN: Traversal Using Relays around NAT
//! - [W3C WebRTC Specification]
//!
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 6347]: https://datatracker.ietf.org/doc/html/rfc6347
//! [RFC 8261]: https://datatracker.ietf.org/doc/html/rfc8261
//! [RFC 5245]: https://datatracker.ietf.org/doc/html/rfc5245
//! [RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389
//! [RFC 8656]: https://datatracker.ietf.org/doc/html/rfc8656
//! [W3C WebRTC Specification]: https://w3c.github.io/webrtc-pc/

pub(crate) mod dtls;
pub(crate) mod ice;
pub(crate) mod sctp;

pub use dtls::fingerprint::RTCDtlsFingerprint;
pub use dtls::role::RTCDtlsRole;
pub use dtls::state::RTCDtlsTransportState;

pub use ice::candidate::{
    CandidateConfig, CandidateHostConfig, CandidatePeerReflexiveConfig, CandidateRelayConfig,
    CandidateServerReflexiveConfig, RTCIceCandidate, RTCIceCandidateInit,
};
pub use ice::candidate_pair::RTCIceCandidatePair;
pub use ice::candidate_type::RTCIceCandidateType;
pub use ice::parameters::RTCIceParameters;
pub use ice::protocol::RTCIceProtocol;
pub use ice::role::RTCIceRole;
pub use ice::server::RTCIceServer;
pub use ice::state::RTCIceTransportState;

pub use sctp::state::RTCSctpTransportState;
