use std::fmt;

use serde::{Deserialize, Serialize};

/// ICE transport policy controlling which candidate types are used for connectivity.
///
/// This policy determines which ICE candidates the peer connection will use and gather
/// during the connection establishment process. It's primarily used for privacy control
/// and network security requirements.
///
/// # Privacy Considerations
///
/// - **All** - Exposes local IP addresses (host candidates) and public IPs (srflx)
/// - **Relay** - Hides all IP addresses, only TURN server address visible (privacy mode)
///
/// # Examples
///
/// ## Standard Configuration (All Candidates)
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Use all candidates for best connectivity (default)
/// let config = RTCConfigurationBuilder::new()
///     .with_ice_transport_policy(RTCIceTransportPolicy::All)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Privacy Mode (Relay Only)
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
/// use rtc::peer_connection::transport::ice::server::RTCIceServer;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Only use TURN relays to hide IP addresses
/// let config = RTCConfigurationBuilder::new()
///     .with_ice_servers(vec![
///         RTCIceServer {
///             urls: vec!["turn:turn.example.com:3478".to_string()],
///             username: "user".to_string(),
///             credential: "password".to_string(),
///             ..Default::default()
///         },
///     ])
///     .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [W3C RTCIceTransportPolicy](https://w3c.github.io/webrtc-pc/#rtcicetransportpolicy-enum)
/// * [RFC 8445 - ICE](https://tools.ietf.org/html/rfc8445)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum RTCIceTransportPolicy {
    /// Unspecified - not a valid policy, used as default value
    #[default]
    Unspecified = 0,

    /// Use all types of ICE candidates (recommended for best connectivity).
    ///
    /// Gathers and uses:
    /// - **Host candidates** - Local IP addresses
    /// - **Server reflexive (srflx)** - Public IP from STUN servers
    /// - **Relay candidates** - TURN server addresses
    ///
    /// This provides the best chance of establishing a connection but may expose
    /// local and public IP addresses.
    ///
    /// **Use when:** Normal operation, prioritizing connectivity over privacy
    #[serde(rename = "all")]
    All = 1,

    /// Only use relay candidates from TURN servers (privacy mode).
    ///
    /// Only gathers and uses relay candidates obtained through TURN servers.
    /// This hides the client's IP addresses from the remote peer but requires
    /// a TURN server and may reduce connection quality.
    ///
    /// **Use when:** Privacy is critical, IP addresses must be hidden
    ///
    /// **Requirements:** Must have TURN servers configured
    #[serde(rename = "relay")]
    Relay = 2,
}

/// ORTC-compatible alias for ICETransportPolicy.
///
/// In ORTC terminology, this is called ICEGatherPolicy, but it serves
/// the same purpose as ICETransportPolicy in WebRTC.
pub type ICEGatherPolicy = RTCIceTransportPolicy;

const ICE_TRANSPORT_POLICY_RELAY_STR: &str = "relay";
const ICE_TRANSPORT_POLICY_ALL_STR: &str = "all";

/// takes a string and converts it to ICETransportPolicy
impl From<&str> for RTCIceTransportPolicy {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_TRANSPORT_POLICY_RELAY_STR => RTCIceTransportPolicy::Relay,
            ICE_TRANSPORT_POLICY_ALL_STR => RTCIceTransportPolicy::All,
            _ => RTCIceTransportPolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCIceTransportPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCIceTransportPolicy::Relay => ICE_TRANSPORT_POLICY_RELAY_STR,
            RTCIceTransportPolicy::All => ICE_TRANSPORT_POLICY_ALL_STR,
            RTCIceTransportPolicy::Unspecified => {
                crate::peer_connection::configuration::UNSPECIFIED_STR
            }
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_ice_transport_policy() {
        let tests = vec![
            ("relay", RTCIceTransportPolicy::Relay),
            ("all", RTCIceTransportPolicy::All),
        ];

        for (policy_string, expected_policy) in tests {
            assert_eq!(RTCIceTransportPolicy::from(policy_string), expected_policy);
        }
    }

    #[test]
    fn test_ice_transport_policy_string() {
        let tests = vec![
            (RTCIceTransportPolicy::Relay, "relay"),
            (RTCIceTransportPolicy::All, "all"),
        ];

        for (policy, expected_string) in tests {
            assert_eq!(policy.to_string(), expected_string);
        }
    }
}
