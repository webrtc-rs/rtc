use std::fmt;

use serde::{Deserialize, Serialize};

/// ICECredentialType indicates the type of credentials used to connect to
/// an ICE server.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum RTCIceCredentialType {
    #[default]
    Unspecified,

    /// ICECredential::Password describes username and password based
    /// credentials as described in <https://tools.ietf.org/html/rfc5389>.
    Password,
}

const ICE_CREDENTIAL_TYPE_PASSWORD_STR: &str = "password";

impl From<&str> for RTCIceCredentialType {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_CREDENTIAL_TYPE_PASSWORD_STR => RTCIceCredentialType::Password,
            _ => RTCIceCredentialType::Unspecified,
        }
    }
}

impl fmt::Display for RTCIceCredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCIceCredentialType::Password => write!(f, "{ICE_CREDENTIAL_TYPE_PASSWORD_STR}"),
            _ => write!(f, "{}", crate::constants::UNSPECIFIED_STR),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_ice_credential_type() {
        let tests = vec![
            ("Unspecified", RTCIceCredentialType::Unspecified),
            ("password", RTCIceCredentialType::Password),
        ];

        for (ct_str, expected_ct) in tests {
            assert_eq!(RTCIceCredentialType::from(ct_str), expected_ct);
        }
    }

    #[test]
    fn test_ice_credential_type_string() {
        let tests = vec![
            (RTCIceCredentialType::Unspecified, "Unspecified"),
            (RTCIceCredentialType::Password, "password"),
        ];

        for (ct, expected_string) in tests {
            assert_eq!(ct.to_string(), expected_string);
        }
    }
}
