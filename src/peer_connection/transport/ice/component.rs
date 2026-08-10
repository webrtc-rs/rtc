use serde::{Deserialize, Serialize};
use std::fmt;

/// ICEComponent describes if the ice transport is used for RTP
/// (or RTCP multiplexing).
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceTransport/component
/// [W3C]: https://w3c.github.io/webrtc-pc/#dom-rtcicecomponent
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCIceComponent {
    /// RTP is used for the transport, and RTCP is multiplexed onto it.
    ///
    /// This is the only component this implementation reports: RTCP multiplexing is required
    /// (`RTCRtcpMuxPolicy` has the single value `"require"`), and the spec says of a muxed
    /// transport that "a single `RTCIceTransport` transports both RTP and RTCP and `component` is
    /// set to `rtp`".
    #[default]
    #[serde(rename = "rtp")]
    Rtp,

    /// RTCP is carried on its own transport, which happens only without RTCP multiplexing.
    #[serde(rename = "rtcp")]
    Rtcp,
}

const ICE_COMPONENT_RTP_STR: &str = "rtp";
const ICE_COMPONENT_RTCP_STR: &str = "rtcp";

impl From<&str> for RTCIceComponent {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_COMPONENT_RTP_STR => RTCIceComponent::Rtp,
            ICE_COMPONENT_RTCP_STR => RTCIceComponent::Rtcp,
            _ => RTCIceComponent::Rtp,
        }
    }
}

impl fmt::Display for RTCIceComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCIceComponent::Rtp => ICE_COMPONENT_RTP_STR,
            RTCIceComponent::Rtcp => ICE_COMPONENT_RTCP_STR,
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ice_component_string_round_trip() {
        for component in [RTCIceComponent::Rtp, RTCIceComponent::Rtcp] {
            assert_eq!(
                RTCIceComponent::from(component.to_string().as_str()),
                component
            );
        }
    }

    #[test]
    fn test_ice_component_default_is_rtp() {
        assert_eq!(RTCIceComponent::default(), RTCIceComponent::Rtp);
        assert_eq!(
            RTCIceComponent::from("not a component"),
            RTCIceComponent::Rtp
        );
    }
}
