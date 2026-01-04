use std::fmt;

use sdp::description::session::SessionDescription;
use sdp::util::ConnectionRole;
use serde::{Deserialize, Serialize};

/// RTCDtlsRole indicates the role of the DTLS transport.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTCDtlsRole {
    #[default]
    Unspecified = 0,

    /// DTLSRoleAuto defines the DTLS role is determined based on
    /// the resolved ICE role: the ICE controlled role acts as the DTLS
    /// client and the ICE controlling role acts as the DTLS server.
    #[serde(rename = "auto")]
    Auto = 1,

    /// DTLSRoleClient defines the DTLS client role.
    #[serde(rename = "client")]
    Client = 2,

    /// DTLSRoleServer defines the DTLS server role.
    #[serde(rename = "server")]
    Server = 3,
}

/// <https://tools.ietf.org/html/rfc5763>
/// The answerer MUST use either a
/// setup attribute value of setup:active or setup:passive.  Note that
/// if the answerer uses setup:passive, then the DTLS handshake will
/// not begin until the answerer is received, which adds additional
/// latency. setup:active allows the answer and the DTLS handshake to
/// occur in parallel.  Thus, setup:active is RECOMMENDED.
pub(crate) const DEFAULT_DTLS_ROLE_ANSWER: RTCDtlsRole = RTCDtlsRole::Client;

/// The endpoint that is the offerer MUST use the setup attribute
/// value of setup:actpass and be prepared to receive a client_hello
/// before it receives the answer.
pub(crate) const DEFAULT_DTLS_ROLE_OFFER: RTCDtlsRole = RTCDtlsRole::Auto;

impl fmt::Display for RTCDtlsRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCDtlsRole::Auto => write!(f, "auto"),
            RTCDtlsRole::Client => write!(f, "client"),
            RTCDtlsRole::Server => write!(f, "server"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

/// Iterate a SessionDescription from a remote to determine if an explicit
/// role can been determined from it. The decision is made from the first role we we parse.
/// If no role can be found we return DTLSRoleAuto
impl From<&SessionDescription> for RTCDtlsRole {
    fn from(session_description: &SessionDescription) -> Self {
        for media_section in &session_description.media_descriptions {
            for attribute in &media_section.attributes {
                if attribute.key == "setup" {
                    if let Some(value) = &attribute.value {
                        match value.as_str() {
                            "active" => return RTCDtlsRole::Client,
                            "passive" => return RTCDtlsRole::Server,
                            _ => return RTCDtlsRole::Auto,
                        };
                    } else {
                        return RTCDtlsRole::Auto;
                    }
                }
            }
        }

        RTCDtlsRole::Auto
    }
}

impl RTCDtlsRole {
    pub(crate) fn to_connection_role(self) -> ConnectionRole {
        match self {
            RTCDtlsRole::Client => ConnectionRole::Active,
            RTCDtlsRole::Server => ConnectionRole::Passive,
            RTCDtlsRole::Auto => ConnectionRole::Actpass,
            _ => ConnectionRole::Unspecified,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;
    use shared::error::Result;

    #[test]
    fn test_dtls_role_string() {
        let tests = vec![
            (RTCDtlsRole::Unspecified, "Unspecified"),
            (RTCDtlsRole::Auto, "auto"),
            (RTCDtlsRole::Client, "client"),
            (RTCDtlsRole::Server, "server"),
        ];

        for (role, expected_string) in tests {
            assert_eq!(role.to_string(), expected_string)
        }
    }

    #[test]
    fn test_dtls_role_from_remote_sdp() -> Result<()> {
        const NO_MEDIA: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
";

        const MEDIA_NO_SETUP: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
m=application 47299 DTLS/SCTP 5000
c=IN IP4 192.168.20.129
";

        const MEDIA_SETUP_DECLARED: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
m=application 47299 DTLS/SCTP 5000
c=IN IP4 192.168.20.129
a=setup:";

        let tests = vec![
            (
                "No MediaDescriptions",
                NO_MEDIA.to_owned(),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, no setup",
                MEDIA_NO_SETUP.to_owned(),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, setup:actpass",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "actpass"),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, setup:passive",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "passive"),
                RTCDtlsRole::Server,
            ),
            (
                "MediaDescription, setup:active",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "active"),
                RTCDtlsRole::Client,
            ),
        ];

        for (name, session_description_str, expected_role) in tests {
            let mut reader = Cursor::new(session_description_str.as_bytes());
            let session_description = SessionDescription::unmarshal(&mut reader)?;
            assert_eq!(
                RTCDtlsRole::from(&session_description),
                expected_role,
                "{name} failed"
            );
        }

        Ok(())
    }
}
