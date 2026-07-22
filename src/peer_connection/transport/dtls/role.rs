use std::fmt;

use sdp::description::session::SessionDescription;
use sdp::util::ConnectionRole;
use serde::{Deserialize, Serialize};

/// Indicates the role of the DTLS transport in the handshake.
///
/// `RTCDtlsRole` determines whether the peer acts as a DTLS client or server
/// during the DTLS handshake. This role is typically determined automatically
/// based on the ICE role, but can be explicitly set in certain scenarios.
///
/// # Role Selection
///
/// - **Offerer**: Should use [`Auto`](Self::Auto) (actpass in SDP), allowing the answerer to choose
/// - **Answerer**: Should use [`Client`](Self::Client) (active in SDP) for lower latency
///
/// The answerer using `Client` allows the DTLS handshake to start immediately
/// without waiting for the answer to be received by the offerer.
///
/// # Relationship with ICE Role
///
/// When `Auto` is used, the DTLS role is derived from the ICE role:
///
/// - **ICE Controlled** → DTLS Client
/// - **ICE Controlling** → DTLS Server
///
/// # Examples
///
/// ## Standard Offer/Answer
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// // Offerer uses Auto (actpass)
/// let offerer_role = RTCDtlsRole::Auto;
/// println!("Offerer SDP: a=setup:actpass");
///
/// // Answerer uses Client (active) - recommended
/// let answerer_role = RTCDtlsRole::Client;
/// println!("Answerer SDP: a=setup:active");
///
/// // This allows DTLS handshake to begin in parallel with signaling
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// let role = RTCDtlsRole::Client;
/// assert_eq!(role.to_string(), "client");
///
/// let role = RTCDtlsRole::Server;
/// assert_eq!(role.to_string(), "server");
/// ```
///
/// ## Checking Role
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// fn will_initiate_handshake(role: RTCDtlsRole) -> bool {
///     matches!(role, RTCDtlsRole::Client)
/// }
///
/// assert!(will_initiate_handshake(RTCDtlsRole::Client));
/// assert!(!will_initiate_handshake(RTCDtlsRole::Server));
/// ```
///
/// # Specifications
///
/// - [RFC 5763] - DTLS-SRTP Setup Attribute
/// - [RFC 8122] - Connection-Oriented Media Transport over TLS
///
/// [RFC 5763]: https://datatracker.ietf.org/doc/html/rfc5763
/// [RFC 8122]: https://datatracker.ietf.org/doc/html/rfc8122
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTCDtlsRole {
    /// Role not specified. This should not occur in normal operation.
    #[default]
    Unspecified = 0,

    /// DTLS role is determined automatically based on ICE role.
    ///
    /// The ICE controlled role acts as the DTLS client, and the ICE controlling
    /// role acts as the DTLS server. This maps to `setup:actpass` in SDP.
    ///
    /// The offerer MUST use `Auto` and be prepared to receive a client_hello
    /// before receiving the answer.
    #[serde(rename = "auto")]
    Auto = 1,

    /// DTLS client role - initiates the handshake.
    ///
    /// The client sends the first DTLS ClientHello message to begin the
    /// handshake. This maps to `setup:active` in SDP.
    ///
    /// The answerer SHOULD use `Client` to allow the answer and DTLS handshake
    /// to occur in parallel, reducing latency.
    #[serde(rename = "client")]
    Client = 2,

    /// DTLS server role - waits for the handshake to be initiated.
    ///
    /// The server waits to receive a DTLS ClientHello message before responding.
    /// This maps to `setup:passive` in SDP.
    ///
    /// Note: Using `Server` as the answerer adds latency since the DTLS
    /// handshake cannot begin until the answerer receives the offer.
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
