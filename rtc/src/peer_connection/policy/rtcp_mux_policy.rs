use std::fmt;

use serde::{Deserialize, Serialize};

/// RTCPMuxPolicy affects what ICE candidates are gathered to support
/// non-multiplexed RTCP.
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum RTCRtcpMuxPolicy {
    #[default]
    Unspecified = 0,

    /// RTCPMuxPolicyRequire indicates to gather ICE candidates only for
    /// RTP and multiplex RTCP on the RTP candidates. If the remote endpoint is
    /// not capable of rtcp-mux, session negotiation will fail.
    #[serde(rename = "require")]
    Require = 2,
}

const RTCP_MUX_POLICY_REQUIRE_STR: &str = "require";

impl From<&str> for RTCRtcpMuxPolicy {
    fn from(raw: &str) -> Self {
        match raw {
            RTCP_MUX_POLICY_REQUIRE_STR => RTCRtcpMuxPolicy::Require,
            _ => RTCRtcpMuxPolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCRtcpMuxPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCRtcpMuxPolicy::Require => RTCP_MUX_POLICY_REQUIRE_STR,
            RTCRtcpMuxPolicy::Unspecified => crate::UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_rtcp_mux_policy() {
        let tests = vec![
            ("Unspecified", RTCRtcpMuxPolicy::Unspecified),
            ("require", RTCRtcpMuxPolicy::Require),
        ];

        for (policy_string, expected_policy) in tests {
            assert_eq!(RTCRtcpMuxPolicy::from(policy_string), expected_policy);
        }
    }

    #[test]
    fn test_rtcp_mux_policy_string() {
        let tests = vec![
            (RTCRtcpMuxPolicy::Unspecified, "Unspecified"),
            (RTCRtcpMuxPolicy::Require, "require"),
        ];

        for (policy, expected_string) in tests {
            assert_eq!(policy.to_string(), expected_string);
        }
    }
}
