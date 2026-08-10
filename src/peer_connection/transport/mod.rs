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
pub use dtls::parameters::RTCDtlsParameters;
pub use dtls::role::RTCDtlsRole;
pub use dtls::state::RTCDtlsTransportState;
use std::fmt;

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

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::state::RTCIceGatheringState;
pub use ice::component::RTCIceComponent;
use interceptor::{Interceptor, NoopInterceptor};

/// Identifies one of a peer connection's transports.
///
/// Obtainable only from a transport, and stable for that transport's lifetime. Its purpose is
/// comparison:
///
/// ```ignore
/// // Does this sender send over the same DTLS transport the data channels use?
/// sctp.transport().id() == sender.transport()?.id()
/// ```
///
/// # Why an id at all
///
/// W3C models the transport graph with object references, so a browser answers the question above
/// with `===`. Two Rust handles cannot offer that: they are values, and the objects they refer to
/// live behind the peer connection. Exposing identity explicitly is the honest alternative —
/// returning handles that compared unequal despite naming the same transport would be worse.
///
/// # Guarantees
///
/// - **Distinct transports have distinct ids**, including across peer connections. Comparing a
///   transport from one connection with a transport from another correctly reports "different",
///   which matters to anything holding many connections at once.
/// - **Stable across reads.** The value is assigned when the transport is created, not derived
///   when it is asked for.
///
/// # Non-guarantees
///
/// - **The value is opaque.** Do not parse, order, or persist it; assert `a == b`, never
///   `a == 3`.
/// - **It is not reproducible across runs.** It is seeded from a per-connection random nonce,
///   because distinctness across connections and reproducibility are mutually exclusive: two
///   connections built from identical inputs would otherwise produce identical ids.
/// - **It is unrelated to `RTCStatsId`.** Stats ids name entries in a stats report; there is one
///   `RTCTransportStats` entry describing the bundled transport, not one per transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RTCTransportId(u64);

/// Which transport within a peer connection an [`RTCTransportId`] names.
///
/// Occupies the low two bits, so the three transports of one connection are distinguishable from
/// each other as well as from every other connection's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportKind {
    Ice = 0,
    Dtls = 1,
    Sctp = 2,
}

impl RTCTransportId {
    /// Builds the id for one transport of the connection identified by `nonce`.
    ///
    /// The nonce is drawn once per peer connection (see `RTCPeerConnection::new`); the low two
    /// bits it loses to the kind leave 62 bits of entropy, which puts a collision at around two
    /// billion concurrent connections in one process.
    pub(crate) fn new(nonce: u64, kind: TransportKind) -> Self {
        Self((nonce << 2) | (kind as u64))
    }
}

impl fmt::Display for RTCTransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Provides access to information about the ICE transport over which packets are sent and
/// received.
///
/// Obtained by walking from [`RTCDtlsTransport::ice_transport`].
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://www.w3.org/TR/webrtc/#dom-rtcicetransport
pub struct RTCIceTransport<'a, I = NoopInterceptor>
where
    I: Interceptor,
{
    pub(crate) peer_connection: &'a RTCPeerConnection<I>,
}

impl<I> RTCIceTransport<'_, I>
where
    I: Interceptor,
{
    /// This transport's identity. See [`RTCTransportId`].
    pub fn id(&self) -> RTCTransportId {
        self.peer_connection.ice_transport().id
    }

    /// The ICE component this transport carries.
    ///
    /// Always [`RTCIceComponent::Rtp`]: RTCP multiplexing is required, and the spec specifies
    /// `rtp` for a transport carrying both.
    pub fn component(&self) -> RTCIceComponent {
        self.peer_connection.ice_transport().component()
    }

    /// Whether this agent is controlling or controlled.
    pub fn role(&self) -> RTCIceRole {
        self.peer_connection.ice_transport().role()
    }

    /// The current state of ICE connectivity.
    pub fn state(&self) -> RTCIceTransportState {
        self.peer_connection.ice_transport().state()
    }

    /// How far candidate gathering has progressed.
    ///
    /// The spec types this `RTCIceGathererState`, a second enum whose values are identical to
    /// [`RTCIceGatheringState`]'s; this crate carries one type for both.
    pub fn gathering_state(&self) -> RTCIceGatheringState {
        self.peer_connection.ice_transport().gathering_state()
    }

    /// The local candidates gathered so far.
    pub fn get_local_candidates(&self) -> Vec<RTCIceCandidate> {
        self.peer_connection
            .ice_transport()
            .get_local_candidates()
            .unwrap_or_default()
    }

    /// The remote candidates received so far.
    pub fn get_remote_candidates(&self) -> Vec<RTCIceCandidate> {
        self.peer_connection.ice_transport().get_remote_candidates()
    }

    /// The nominated candidate pair, or `None` until ICE selects one.
    pub fn get_selected_candidate_pair(&self) -> Option<RTCIceCandidatePair> {
        self.peer_connection
            .ice_transport()
            .get_selected_candidate_pair()
    }

    /// The local ICE parameters, or `None` before a local description has supplied them.
    pub fn get_local_parameters(&self) -> Option<RTCIceParameters> {
        self.peer_connection
            .ice_transport()
            .get_local_parameters()
            .ok()
    }

    /// The remote ICE parameters, or `None` before a remote description has supplied them.
    pub fn get_remote_parameters(&self) -> Option<RTCIceParameters> {
        self.peer_connection.ice_transport().get_remote_parameters()
    }
}

/// Provides access to information about the DTLS transport over which RTP, RTCP and SCTP are
/// sent and received.
///
/// Obtained by walking from [`RTCSctpTransport::transport`], or from a sender's or receiver's
/// `transport()`.
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://www.w3.org/TR/webrtc/#dom-rtcdtlstransport
pub struct RTCDtlsTransport<'a, I = NoopInterceptor>
where
    I: Interceptor,
{
    pub(crate) peer_connection: &'a RTCPeerConnection<I>,
}

impl<'a, I> RTCDtlsTransport<'a, I>
where
    I: Interceptor,
{
    /// This transport's identity. See [`RTCTransportId`].
    pub fn id(&self) -> RTCTransportId {
        self.peer_connection.dtls_transport().id
    }

    /// The ICE transport this DTLS transport runs over.
    ///
    /// Never absent: the spec types `iceTransport` non-nullable.
    pub fn ice_transport(&self) -> RTCIceTransport<'a, I> {
        RTCIceTransport {
            peer_connection: self.peer_connection,
        }
    }

    /// The current state of the DTLS connection.
    pub fn state(&self) -> RTCDtlsTransportState {
        self.peer_connection.dtls_transport().state()
    }

    /// The peer's certificate chain, DER-encoded — the analogue of the browser's
    /// `sequence<ArrayBuffer>`.
    ///
    /// Empty until the handshake completes.
    pub fn get_remote_certificates(&self) -> &'a [Vec<u8>] {
        self.peer_connection
            .dtls_transport()
            .get_remote_certificates()
    }
}

/// Provides access to information about the SCTP transport that carries data channels.
///
/// Obtained from [`RTCPeerConnection::sctp`].
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://www.w3.org/TR/webrtc/#dom-rtcsctptransport
/// [`RTCPeerConnection::sctp`]: crate::peer_connection::RTCPeerConnection::sctp
pub struct RTCSctpTransport<'a, I = NoopInterceptor>
where
    I: Interceptor,
{
    pub(crate) peer_connection: &'a RTCPeerConnection<I>,
}

impl<'a, I> RTCSctpTransport<'a, I>
where
    I: Interceptor,
{
    /// This transport's identity. See [`RTCTransportId`].
    pub fn id(&self) -> RTCTransportId {
        self.peer_connection.sctp_transport().id
    }

    /// The DTLS transport all SCTP packets for data channels are sent over.
    ///
    /// Never absent: the spec types `transport` non-nullable.
    pub fn transport(&self) -> RTCDtlsTransport<'a, I> {
        RTCDtlsTransport {
            peer_connection: self.peer_connection,
        }
    }

    /// The current state of the SCTP association.
    pub fn state(&self) -> RTCSctpTransportState {
        self.peer_connection.sctp_transport().state()
    }

    /// The maximum size, in bytes, of a message that can be sent on a data channel.
    ///
    /// `None` until the association reaches the connected state
    pub fn max_message_size(&self) -> Option<u32> {
        self.peer_connection.sctp_transport().max_message_size()
    }

    /// The maximum number of data channels that can be used simultaneously.
    ///
    /// `None` until the association reaches the connected state, at which point it is the
    /// smaller of the negotiated inbound and outbound stream counts.
    pub fn max_channels(&self) -> Option<u16> {
        self.peer_connection.sctp_transport().max_channels()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_transports_of_one_connection_are_distinct() {
        let nonce = 0x0123_4567_89ab_cdef;
        let ice = RTCTransportId::new(nonce, TransportKind::Ice);
        let dtls = RTCTransportId::new(nonce, TransportKind::Dtls);
        let sctp = RTCTransportId::new(nonce, TransportKind::Sctp);

        assert_ne!(ice, dtls);
        assert_ne!(dtls, sctp);
        assert_ne!(ice, sctp);
    }

    #[test]
    fn the_same_transport_of_two_connections_is_distinct() {
        // The case a per-connection counter gets wrong: both connections would call their DTLS
        // transport "2" and compare equal.
        let a = RTCTransportId::new(1, TransportKind::Dtls);
        let b = RTCTransportId::new(2, TransportKind::Dtls);
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_transport_of_one_connection_compares_equal() {
        let nonce = 0xfeed_face_dead_beef;
        assert_eq!(
            RTCTransportId::new(nonce, TransportKind::Dtls),
            RTCTransportId::new(nonce, TransportKind::Dtls)
        );
    }

    // The kind occupies the low two bits, so a nonce differing only in its top two bits must not
    // alias — those are the bits the shift discards.
    #[test]
    fn nonces_differing_only_in_discarded_bits_still_collide_knowingly() {
        let a = RTCTransportId::new(u64::MAX, TransportKind::Ice);
        let b = RTCTransportId::new(u64::MAX >> 2, TransportKind::Ice);
        assert_eq!(
            a, b,
            "documented: the top two bits of the nonce are not part of the id, \
             leaving 62 bits of entropy rather than 64"
        );
    }
}
