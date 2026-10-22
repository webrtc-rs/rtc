use std::fmt;

use serde::{Deserialize, Serialize};

/// Whether RTP header extensions and CSRCs are encrypted ([RFC 9335], "Cryptex").
///
/// SRTP leaves RTP header extensions in the clear, and they can carry sensitive data (audio
/// levels, for one). Cryptex encrypts them. It is negotiated with the `a=cryptex` SDP attribute;
/// when the peer supports it every media stream uses it, and this policy decides what happens when
/// the peer does not.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtpHeaderEncryptionPolicy};
///
/// // Refuse to talk to a peer that would leave header extensions in the clear.
/// let config = RTCConfigurationBuilder::new()
///     .with_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)
///     .build();
/// ```
///
/// [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCRtpHeaderEncryptionPolicy {
    /// Not set; behaves as [`Negotiate`](Self::Negotiate).
    #[default]
    Unspecified = 0,

    /// Cryptex is not offered and not accepted: header extensions go in the clear.
    #[serde(rename = "disable")]
    Disable = 1,

    /// Cryptex is offered, and used if the peer supports it; otherwise header extensions are sent
    /// in the clear.
    #[serde(rename = "negotiate")]
    Negotiate = 2,

    /// Cryptex is required: a session description that does not negotiate it for every RTP media
    /// section is rejected.
    #[serde(rename = "require")]
    Require = 3,
}

const RTP_HEADER_ENCRYPTION_POLICY_DISABLE_STR: &str = "disable";
const RTP_HEADER_ENCRYPTION_POLICY_NEGOTIATE_STR: &str = "negotiate";
const RTP_HEADER_ENCRYPTION_POLICY_REQUIRE_STR: &str = "require";

impl RTCRtpHeaderEncryptionPolicy {
    /// Whether Cryptex is offered and accepted at all.
    pub(crate) fn enabled(self) -> bool {
        self != RTCRtpHeaderEncryptionPolicy::Disable
    }
}

impl From<&str> for RTCRtpHeaderEncryptionPolicy {
    fn from(raw: &str) -> Self {
        match raw {
            RTP_HEADER_ENCRYPTION_POLICY_DISABLE_STR => RTCRtpHeaderEncryptionPolicy::Disable,
            RTP_HEADER_ENCRYPTION_POLICY_NEGOTIATE_STR => RTCRtpHeaderEncryptionPolicy::Negotiate,
            RTP_HEADER_ENCRYPTION_POLICY_REQUIRE_STR => RTCRtpHeaderEncryptionPolicy::Require,
            _ => RTCRtpHeaderEncryptionPolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCRtpHeaderEncryptionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCRtpHeaderEncryptionPolicy::Disable => RTP_HEADER_ENCRYPTION_POLICY_DISABLE_STR,
            RTCRtpHeaderEncryptionPolicy::Negotiate => RTP_HEADER_ENCRYPTION_POLICY_NEGOTIATE_STR,
            RTCRtpHeaderEncryptionPolicy::Require => RTP_HEADER_ENCRYPTION_POLICY_REQUIRE_STR,
            RTCRtpHeaderEncryptionPolicy::Unspecified => {
                crate::peer_connection::configuration::UNSPECIFIED_STR
            }
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// pion `TestNewRTPHeaderEncryptionPolicy` / `TestRTPHeaderEncryptionPolicy_String` /
    /// `_JSON`.
    #[test]
    fn parses_prints_and_serializes() {
        for (text, policy) in [
            ("Unspecified", RTCRtpHeaderEncryptionPolicy::Unspecified),
            ("disable", RTCRtpHeaderEncryptionPolicy::Disable),
            ("negotiate", RTCRtpHeaderEncryptionPolicy::Negotiate),
            ("require", RTCRtpHeaderEncryptionPolicy::Require),
        ] {
            assert_eq!(RTCRtpHeaderEncryptionPolicy::from(text), policy);
            assert_eq!(policy.to_string(), text);
            if policy != RTCRtpHeaderEncryptionPolicy::Unspecified {
                let json = serde_json::to_string(&policy).unwrap();
                assert_eq!(json, format!("\"{text}\""));
                assert_eq!(
                    serde_json::from_str::<RTCRtpHeaderEncryptionPolicy>(&json).unwrap(),
                    policy
                );
            }
        }
    }

    #[test]
    fn only_disable_turns_it_off() {
        assert!(!RTCRtpHeaderEncryptionPolicy::Disable.enabled());
        assert!(RTCRtpHeaderEncryptionPolicy::Unspecified.enabled());
        assert!(RTCRtpHeaderEncryptionPolicy::Negotiate.enabled());
        assert!(RTCRtpHeaderEncryptionPolicy::Require.enabled());
    }
}
