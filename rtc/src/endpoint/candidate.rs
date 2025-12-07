use crate::description::{RTCSessionDescription, UNSPECIFIED_STR};
use crate::server::certificate::RTCDtlsFingerprint;
use crate::types::{EndpointId, SessionId, UserName};
use base64::{prelude::BASE64_STANDARD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use sdp::util::ConnectionRole;
use sdp::SessionDescription;
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};
use std::fmt;
use std::time::Instant;

/// DtlsRole indicates the role of the DTLS transport.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DTLSRole {
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
pub(crate) const DEFAULT_DTLS_ROLE_ANSWER: DTLSRole = DTLSRole::Client;

/// The endpoint that is the offerer MUST use the setup attribute
/// value of setup:actpass and be prepared to receive a client_hello
/// before it receives the answer.
pub(crate) const DEFAULT_DTLS_ROLE_OFFER: DTLSRole = DTLSRole::Auto;

impl fmt::Display for DTLSRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DTLSRole::Auto => write!(f, "auto"),
            DTLSRole::Client => write!(f, "client"),
            DTLSRole::Server => write!(f, "server"),
            _ => write!(f, "{}", UNSPECIFIED_STR),
        }
    }
}

/// Iterate a SessionDescription from a remote to determine if an explicit
/// role can been determined from it. The decision is made from the first role we we parse.
/// If no role can be found we return DTLSRoleAuto
impl From<&SessionDescription> for DTLSRole {
    fn from(session_description: &SessionDescription) -> Self {
        for media_section in &session_description.media_descriptions {
            for attribute in &media_section.attributes {
                if attribute.key == "setup" {
                    if let Some(value) = &attribute.value {
                        match value.as_str() {
                            "active" => return DTLSRole::Client,
                            "passive" => return DTLSRole::Server,
                            _ => return DTLSRole::Auto,
                        };
                    } else {
                        return DTLSRole::Auto;
                    }
                }
            }
        }

        DTLSRole::Auto
    }
}

impl DTLSRole {
    pub(crate) fn to_connection_role(self) -> ConnectionRole {
        match self {
            DTLSRole::Client => ConnectionRole::Active,
            DTLSRole::Server => ConnectionRole::Passive,
            DTLSRole::Auto => ConnectionRole::Actpass,
            _ => ConnectionRole::Unspecified,
        }
    }
}

/// ICEParameters includes the ICE username fragment
/// and password and other ICE-related parameters.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RTCIceParameters {
    pub(crate) username_fragment: String,
    pub(crate) password: String,
}

/// DTLSParameters holds information relating to DTLS configuration.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DTLSParameters {
    pub(crate) role: DTLSRole,
    pub(crate) fingerprints: Vec<RTCDtlsFingerprint>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ConnectionCredentials {
    pub(crate) ice_params: RTCIceParameters,
    pub(crate) dtls_params: DTLSParameters,
}

impl ConnectionCredentials {
    pub(crate) fn new(fingerprints: Vec<RTCDtlsFingerprint>, remote_role: DTLSRole) -> Self {
        let rng = SystemRandom::new();

        let mut user = [0u8; 9];
        let _ = rng.fill(&mut user);
        let mut password = [0u8; 18];
        let _ = rng.fill(&mut password);

        Self {
            ice_params: RTCIceParameters {
                username_fragment: BASE64_STANDARD.encode(&user[..]),
                password: BASE64_STANDARD.encode(&password[..]),
            },
            dtls_params: DTLSParameters {
                fingerprints,
                role: if remote_role == DTLSRole::Server {
                    DTLSRole::Client
                } else {
                    DTLSRole::Server
                },
            },
        }
    }

    pub(crate) fn from_sdp(sdp: &SessionDescription) -> Result<Self> {
        let username_fragment = sdp
            .media_descriptions
            .iter()
            .find_map(|m| m.attribute("ice-ufrag"))
            .ok_or(Error::ErrAttributeNotFound)?
            .ok_or(Error::ErrAttributeNotFound)?
            .to_string();
        let password = sdp
            .media_descriptions
            .iter()
            .find_map(|m| m.attribute("ice-pwd"))
            .ok_or(Error::ErrAttributeNotFound)?
            .ok_or(Error::ErrAttributeNotFound)?
            .to_string();
        let fingerprint = if let Some(fingerprint) = sdp.attribute("fingerprint") {
            fingerprint.as_str().try_into()?
        } else {
            sdp.media_descriptions
                .iter()
                .find_map(|m| m.attribute("fingerprint"))
                .ok_or(Error::ErrAttributeNotFound)?
                .ok_or(Error::ErrAttributeNotFound)?
                .try_into()?
        };
        let role = DTLSRole::from(sdp);

        Ok(Self {
            ice_params: RTCIceParameters {
                username_fragment,
                password,
            },
            dtls_params: DTLSParameters {
                role,
                fingerprints: vec![fingerprint],
            },
        })
    }

    pub(crate) fn valid(&self) -> bool {
        self.ice_params.username_fragment.len() >= 4
            && self.ice_params.username_fragment.len() <= 256
            && self.ice_params.password.len() >= 22
            && self.ice_params.password.len() <= 256
    }
}

#[derive(Debug)]
pub(crate) struct Candidate {
    session_id: SessionId,
    endpoint_id: EndpointId,
    remote_conn_cred: ConnectionCredentials,
    local_conn_cred: ConnectionCredentials,
    remote_description: RTCSessionDescription,
    local_description: RTCSessionDescription,
    expired_time: Instant,
}

impl Candidate {
    pub(crate) fn new(
        session_id: SessionId,
        endpoint_id: EndpointId,
        remote_conn_cred: ConnectionCredentials,
        local_conn_cred: ConnectionCredentials,
        remote_description: RTCSessionDescription,
        local_description: RTCSessionDescription,
        expired_time: Instant,
    ) -> Self {
        Self {
            session_id,
            endpoint_id,
            local_conn_cred,
            remote_conn_cred,
            remote_description,
            local_description,
            expired_time,
        }
    }

    pub(crate) fn remote_connection_credentials(&self) -> &ConnectionCredentials {
        &self.remote_conn_cred
    }

    pub(crate) fn local_connection_credentials(&self) -> &ConnectionCredentials {
        &self.local_conn_cred
    }

    /// get_remote_parameters returns the remote's ICE parameters
    pub(crate) fn get_remote_parameters(&self) -> &RTCIceParameters {
        &self.remote_conn_cred.ice_params
    }

    /// get_local_parameters returns the local's ICE parameters.
    pub(crate) fn get_local_parameters(&self) -> &RTCIceParameters {
        &self.local_conn_cred.ice_params
    }

    pub(crate) fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub(crate) fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub(crate) fn username(&self) -> UserName {
        format!(
            "{}:{}",
            self.local_conn_cred.ice_params.username_fragment,
            self.remote_conn_cred.ice_params.username_fragment
        )
    }

    pub(crate) fn remote_description(&self) -> &RTCSessionDescription {
        &self.remote_description
    }

    pub(crate) fn local_description(&self) -> &RTCSessionDescription {
        &self.local_description
    }

    pub(crate) fn expired_time(&self) -> Instant {
        self.expired_time
    }
}
