use serde::{Deserialize, Serialize};
use std::fmt;

use super::candidate_type::RTCIceCandidateType;
use super::protocol::RTCIceProtocol;
use ice::tcp_type::TcpType;
use shared::error::{Error, Result};

pub use ice::candidate::{
    Candidate, CandidateConfig, candidate_host::CandidateHostConfig,
    candidate_peer_reflexive::CandidatePeerReflexiveConfig, candidate_relay::CandidateRelayConfig,
    candidate_server_reflexive::CandidateServerReflexiveConfig,
};

#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum RTCIceTcpCandidateType {
    #[default]
    Unspecified,

    #[serde(rename = "active")]
    Active,

    #[serde(rename = "passive")]
    Passive,

    #[serde(rename = "so")]
    SimultaneousOpen,
}

impl From<TcpType> for RTCIceTcpCandidateType {
    fn from(t: TcpType) -> Self {
        match t {
            TcpType::Unspecified => RTCIceTcpCandidateType::Unspecified,
            TcpType::Active => RTCIceTcpCandidateType::Active,
            TcpType::Passive => RTCIceTcpCandidateType::Passive,
            TcpType::SimultaneousOpen => RTCIceTcpCandidateType::SimultaneousOpen,
        }
    }
}

impl RTCIceTcpCandidateType {
    pub fn to_ice(self) -> TcpType {
        match self {
            RTCIceTcpCandidateType::Unspecified => TcpType::Unspecified,
            RTCIceTcpCandidateType::Active => TcpType::Active,
            RTCIceTcpCandidateType::Passive => TcpType::Passive,
            RTCIceTcpCandidateType::SimultaneousOpen => TcpType::SimultaneousOpen,
        }
    }
}

#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum RTCIceServerTransportProtocol {
    #[default]
    Unspecified,

    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "tls")]
    Tls,
}

/// ICECandidate represents a ice candidate
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcicecandidate-interface
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTCIceCandidate {
    pub stats_id: String,
    pub foundation: String,
    pub priority: u32,
    pub address: String,
    pub protocol: RTCIceProtocol,
    pub port: u16,
    pub typ: RTCIceCandidateType,
    pub component: u16,
    pub related_address: String,
    pub related_port: u16,
    pub tcp_type: RTCIceTcpCandidateType,
    pub relay_protocol: RTCIceServerTransportProtocol,
    pub url: Option<String>,
}

/// Conversion for ice_candidates
pub(crate) fn rtc_ice_candidates_from_ice_candidates(
    ice_candidates: &[Candidate],
) -> Vec<RTCIceCandidate> {
    ice_candidates.iter().map(|c| c.into()).collect()
}

impl From<&Candidate> for RTCIceCandidate {
    fn from(c: &Candidate) -> Self {
        let typ: RTCIceCandidateType = c.candidate_type().into();
        let protocol = RTCIceProtocol::from(c.network_type().network_short().as_str());
        let (related_address, related_port) = if let Some(ra) = c.related_address() {
            (ra.address, ra.port)
        } else {
            (String::new(), 0)
        };

        RTCIceCandidate {
            stats_id: c.id(),
            foundation: c.foundation(),
            priority: c.priority(),
            address: c.address().to_string(),
            protocol,
            port: c.port(),
            component: c.component(),
            typ,
            tcp_type: c.tcp_type().into(),
            related_address,
            related_port,
            relay_protocol: Default::default(),
            url: c.url().map(|u| u.to_string()),
        }
    }
}

impl RTCIceCandidate {
    pub(crate) fn to_ice(&self) -> Result<Candidate> {
        let candidate_id = self.stats_id.clone();
        let base_config = CandidateConfig {
            candidate_id,
            network: self.protocol.to_string(),
            address: self.address.clone(),
            port: self.port,
            component: self.component,
            foundation: self.foundation.clone(),
            priority: self.priority,
        };

        let c = match self.typ {
            RTCIceCandidateType::Host => {
                let config = CandidateHostConfig {
                    base_config,
                    tcp_type: self.tcp_type.to_ice(),
                };
                config.new_candidate_host()?
            }
            RTCIceCandidateType::Srflx => {
                let config = CandidateServerReflexiveConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                    url: self.url.clone(),
                };
                config.new_candidate_server_reflexive()?
            }
            RTCIceCandidateType::Prflx => {
                let config = CandidatePeerReflexiveConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                };
                config.new_candidate_peer_reflexive()?
            }
            RTCIceCandidateType::Relay => {
                let config = CandidateRelayConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                    url: self.url.clone(),
                };
                config.new_candidate_relay()?
            }
            _ => return Err(Error::ErrICECandidateTypeUnknown),
        };

        Ok(c)
    }

    /// to_json returns an ICECandidateInit
    /// as indicated by the spec <https://w3c.github.io/webrtc-pc/#dom-rtcicecandidate-tojson>
    pub fn to_json(&self) -> Result<RTCIceCandidateInit> {
        let candidate = self.to_ice()?;

        Ok(RTCIceCandidateInit {
            candidate: format!("candidate:{}", candidate.marshal()),
            sdp_mid: Some("".to_owned()),
            sdp_mline_index: Some(0u16),
            username_fragment: None,
            url: None,
        })
    }
}

impl fmt::Display for RTCIceCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}:{}{}",
            self.protocol, self.typ, self.address, self.port, self.related_address,
        )
    }
}

/// ICECandidateInit is used to serialize ice candidates
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateInit {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
    /// The URL of the STUN or TURN server used to gather this candidate.
    ///
    /// Per W3C spec, this field is only meaningful for local candidates of type
    /// "srflx" (server reflexive) or "relay". For other candidate types, this
    /// field should be `None`.
    ///
    /// This is a sansio extension - since gathering happens externally in the
    /// sansio architecture, the application must provide this URL when adding
    /// local candidates that were gathered from STUN/TURN servers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ice_candidate_serialization() {
        let tests = vec![
            (
                RTCIceCandidateInit {
                    candidate: "candidate:abc123".to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: Some("def".to_string()),
                    url: None,
                },
                r#"{"candidate":"candidate:abc123","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"def"}"#,
            ),
            (
                RTCIceCandidateInit {
                    candidate: "candidate:abc123".to_string(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                    username_fragment: None,
                    url: None,
                },
                r#"{"candidate":"candidate:abc123","sdpMid":null,"sdpMLineIndex":null,"usernameFragment":null}"#,
            ),
            (
                RTCIceCandidateInit {
                    candidate: "candidate:relay123".to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: Some("turn:turn.example.com:3478".to_string()),
                },
                r#"{"candidate":"candidate:relay123","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":null,"url":"turn:turn.example.com:3478"}"#,
            ),
        ];

        for (candidate_init, expected_string) in tests {
            let result = serde_json::to_string(&candidate_init);
            assert!(result.is_ok(), "testCase: marshal err: {result:?}");
            let candidate_data = result.unwrap();
            assert_eq!(candidate_data, expected_string, "string is not expected");

            let result = serde_json::from_str::<RTCIceCandidateInit>(&candidate_data);
            assert!(result.is_ok(), "testCase: unmarshal err: {result:?}");
            if let Ok(actual_candidate_init) = result {
                assert_eq!(actual_candidate_init, candidate_init);
            }
        }
    }
}
