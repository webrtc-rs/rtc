use std::fmt;

use ice::candidate::CandidateType;
use serde::{Deserialize, Serialize};

/// Indicates the type of ICE candidate.
///
/// `RTCIceCandidateType` describes how an ICE candidate was obtained and what
/// kind of network path it represents. Different candidate types have different
/// characteristics in terms of connectivity, performance, and server requirements.
///
/// # Candidate Types
///
/// 1. **Host** - Direct connection via local network interface
/// 2. **Srflx** (Server Reflexive) - NAT mapping discovered via STUN
/// 3. **Prflx** (Peer Reflexive) - NAT mapping discovered during ICE checks
/// 4. **Relay** - Relayed connection via TURN server
///
/// # Selection Priority
///
/// ICE typically prefers candidates in this order (best to worst):
///
/// 1. Host (direct, lowest latency, no server cost)
/// 2. Srflx (through NAT, moderate latency, STUN server required)
/// 3. Relay (through relay, highest latency, TURN server required)
///
/// # Examples
///
/// ## Identifying Candidate Types
///
/// ```
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// fn describe_candidate(candidate_type: RTCIceCandidateType) {
///     match candidate_type {
///         RTCIceCandidateType::Host => {
///             println!("Local network address - best performance");
///         }
///         RTCIceCandidateType::Srflx => {
///             println!("Server reflexive - behind NAT, needs STUN");
///         }
///         RTCIceCandidateType::Prflx => {
///             println!("Peer reflexive - discovered during checks");
///         }
///         RTCIceCandidateType::Relay => {
///             println!("Relayed through TURN - fallback option");
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Checking Server Requirements
///
/// ```
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// fn needs_stun_server(candidate_type: RTCIceCandidateType) -> bool {
///     matches!(candidate_type, RTCIceCandidateType::Srflx)
/// }
///
/// fn needs_turn_server(candidate_type: RTCIceCandidateType) -> bool {
///     matches!(candidate_type, RTCIceCandidateType::Relay)
/// }
///
/// assert!(!needs_stun_server(RTCIceCandidateType::Host));
/// assert!(needs_stun_server(RTCIceCandidateType::Srflx));
/// assert!(needs_turn_server(RTCIceCandidateType::Relay));
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// let host = RTCIceCandidateType::Host;
/// assert_eq!(host.to_string(), "host");
///
/// let srflx: RTCIceCandidateType = "srflx".into();
/// assert_eq!(srflx, RTCIceCandidateType::Srflx);
/// ```
///
/// ## Performance Characteristics
///
/// ```
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// fn estimate_latency(candidate_type: RTCIceCandidateType) -> &'static str {
///     match candidate_type {
///         RTCIceCandidateType::Host => "Lowest (direct)",
///         RTCIceCandidateType::Srflx | RTCIceCandidateType::Prflx => "Moderate (NAT)",
///         RTCIceCandidateType::Relay => "Highest (relay)",
///         _ => "Unknown",
///     }
/// }
/// ```
///
/// # Specifications
///
/// - [RFC 8445 Section 5.1.1.1] - Candidate Types
/// - [W3C RTCIceCandidateStats.candidateType]
/// - [MDN RTCIceCandidateStats.candidateType]
///
/// [RFC 8445 Section 5.1.1.1]: https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.1
/// [W3C RTCIceCandidateStats.candidateType]: https://w3c.github.io/webrtc-stats/#dom-rtcicecandidatestats-candidatetype
/// [MDN RTCIceCandidateStats.candidateType]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidateStats/candidateType
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTCIceCandidateType {
    /// Type not specified. This should not occur in normal operation.
    #[default]
    Unspecified,

    /// Host candidate obtained from a local network interface.
    ///
    /// A candidate obtained by binding to a specific port from an IP address on
    /// the host. This includes IP addresses on physical interfaces and logical
    /// ones, such as those obtained through VPNs.
    ///
    /// **Characteristics:**
    /// - Direct peer-to-peer connection
    /// - Lowest latency
    /// - Best quality
    /// - No server required
    /// - Only works if both peers are on the same network or publicly routable
    ///
    /// **Example:** `192.168.1.100:54321` on local network
    #[serde(rename = "host")]
    Host,

    /// Server reflexive candidate obtained via STUN.
    ///
    /// A candidate whose IP address and port are a binding allocated by a NAT
    /// for an ICE agent after it sends a packet through the NAT to a STUN server.
    ///
    /// **Characteristics:**
    /// - Represents the public IP:port as seen by the STUN server
    /// - Works through most NATs
    /// - Requires STUN server
    /// - Moderate latency (NAT traversal)
    /// - Most common candidate type in typical deployments
    ///
    /// **Example:** `203.0.113.45:12345` (public IP from STUN server)
    #[serde(rename = "srflx")]
    Srflx,

    /// Peer reflexive candidate discovered during connectivity checks.
    ///
    /// A candidate whose IP address and port are a binding allocated by a NAT
    /// for an ICE agent after it sends a packet through the NAT to its peer.
    /// This type is discovered during the ICE checking process itself.
    ///
    /// **Characteristics:**
    /// - Discovered dynamically during ICE checks
    /// - Can appear after initial candidate exchange
    /// - Represents additional NAT bindings
    /// - Less common than other types
    ///
    /// **Note:** Prflx candidates are discovered automatically and rarely need
    /// explicit handling.
    #[serde(rename = "prflx")]
    Prflx,

    /// Relay candidate obtained from a TURN server.
    ///
    /// A candidate obtained from a relay server (TURN server). Traffic is relayed
    /// through the server when direct or server reflexive connections fail.
    ///
    /// **Characteristics:**
    /// - Fallback when direct connection fails
    /// - Works through symmetric NATs and firewalls
    /// - Requires TURN server (with authentication)
    /// - Highest latency (double hop)
    /// - Server bandwidth cost
    /// - Guaranteed connectivity (if TURN server reachable)
    ///
    /// **Example:** `198.51.100.10:3478` (TURN server address)
    #[serde(rename = "relay")]
    Relay,
}

const ICE_CANDIDATE_TYPE_HOST_STR: &str = "host";
const ICE_CANDIDATE_TYPE_SRFLX_STR: &str = "srflx";
const ICE_CANDIDATE_TYPE_PRFLX_STR: &str = "prflx";
const ICE_CANDIDATE_TYPE_RELAY_STR: &str = "relay";

///  takes a string and converts it into ICECandidateType
impl From<&str> for RTCIceCandidateType {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_CANDIDATE_TYPE_HOST_STR => RTCIceCandidateType::Host,
            ICE_CANDIDATE_TYPE_SRFLX_STR => RTCIceCandidateType::Srflx,
            ICE_CANDIDATE_TYPE_PRFLX_STR => RTCIceCandidateType::Prflx,
            ICE_CANDIDATE_TYPE_RELAY_STR => RTCIceCandidateType::Relay,
            _ => RTCIceCandidateType::Unspecified,
        }
    }
}

impl From<CandidateType> for RTCIceCandidateType {
    fn from(candidate_type: CandidateType) -> Self {
        match candidate_type {
            CandidateType::Host => RTCIceCandidateType::Host,
            CandidateType::ServerReflexive => RTCIceCandidateType::Srflx,
            CandidateType::PeerReflexive => RTCIceCandidateType::Prflx,
            CandidateType::Relay => RTCIceCandidateType::Relay,
            _ => RTCIceCandidateType::Unspecified,
        }
    }
}

impl fmt::Display for RTCIceCandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCIceCandidateType::Host => write!(f, "{ICE_CANDIDATE_TYPE_HOST_STR}"),
            RTCIceCandidateType::Srflx => write!(f, "{ICE_CANDIDATE_TYPE_SRFLX_STR}"),
            RTCIceCandidateType::Prflx => write!(f, "{ICE_CANDIDATE_TYPE_PRFLX_STR}"),
            RTCIceCandidateType::Relay => write!(f, "{ICE_CANDIDATE_TYPE_RELAY_STR}"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ice_candidate_type() {
        let tests = vec![
            ("Unspecified", RTCIceCandidateType::Unspecified),
            ("host", RTCIceCandidateType::Host),
            ("srflx", RTCIceCandidateType::Srflx),
            ("prflx", RTCIceCandidateType::Prflx),
            ("relay", RTCIceCandidateType::Relay),
        ];

        for (type_string, expected_type) in tests {
            let actual = RTCIceCandidateType::from(type_string);
            assert_eq!(actual, expected_type);
        }
    }

    #[test]
    fn test_ice_candidate_type_string() {
        let tests = vec![
            (RTCIceCandidateType::Unspecified, "Unspecified"),
            (RTCIceCandidateType::Host, "host"),
            (RTCIceCandidateType::Srflx, "srflx"),
            (RTCIceCandidateType::Prflx, "prflx"),
            (RTCIceCandidateType::Relay, "relay"),
        ];

        for (ctype, expected_string) in tests {
            assert_eq!(ctype.to_string(), expected_string);
        }
    }
}
