use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::transport::dtls_transport::dtls_fingerprint::RTCDtlsFingerprint;
use crate::transport::dtls_transport::dtls_parameters::DTLSParameters;
use crate::transport::dtls_transport::dtls_role::DTLSRole;
use crate::transport::ice_transport::ice_parameters::RTCIceParameters;
use base64::{prelude::BASE64_STANDARD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use sdp::SessionDescription;
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};
use std::time::Instant;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionCredentials {
    pub(crate) ice_params: RTCIceParameters,
    pub(crate) dtls_params: DTLSParameters,
}

impl ConnectionCredentials {
    pub fn new(fingerprints: Vec<RTCDtlsFingerprint>, remote_role: DTLSRole) -> Self {
        let rng = SystemRandom::new();

        let mut user = [0u8; 9];
        let _ = rng.fill(&mut user);
        let mut password = [0u8; 18];
        let _ = rng.fill(&mut password);

        Self {
            ice_params: RTCIceParameters {
                username_fragment: BASE64_STANDARD.encode(&user[..]),
                password: BASE64_STANDARD.encode(&password[..]),
                ice_lite: false,
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

    pub fn from_sdp(sdp: &SessionDescription) -> Result<Self> {
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
            fingerprint.try_into()?
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
                ice_lite: false,
            },
            dtls_params: DTLSParameters {
                role,
                fingerprints: vec![fingerprint],
            },
        })
    }

    pub fn valid(&self) -> bool {
        self.ice_params.username_fragment.len() >= 4
            && self.ice_params.username_fragment.len() <= 256
            && self.ice_params.password.len() >= 22
            && self.ice_params.password.len() <= 256
    }
}

#[derive(Debug)]
pub struct Candidate {
    remote_conn_cred: ConnectionCredentials,
    local_conn_cred: ConnectionCredentials,
    remote_description: RTCSessionDescription,
    local_description: RTCSessionDescription,
    expired_time: Instant,
}

impl Candidate {
    pub fn new(
        remote_conn_cred: ConnectionCredentials,
        local_conn_cred: ConnectionCredentials,
        remote_description: RTCSessionDescription,
        local_description: RTCSessionDescription,
        expired_time: Instant,
    ) -> Self {
        Self {
            local_conn_cred,
            remote_conn_cred,
            remote_description,
            local_description,
            expired_time,
        }
    }

    pub fn remote_connection_credentials(&self) -> &ConnectionCredentials {
        &self.remote_conn_cred
    }

    pub fn local_connection_credentials(&self) -> &ConnectionCredentials {
        &self.local_conn_cred
    }

    /// get_remote_parameters returns the remote's ICE parameters
    pub fn get_remote_parameters(&self) -> &RTCIceParameters {
        &self.remote_conn_cred.ice_params
    }

    /// get_local_parameters returns the local's ICE parameters.
    pub fn get_local_parameters(&self) -> &RTCIceParameters {
        &self.local_conn_cred.ice_params
    }

    pub fn username(&self) -> String {
        format!(
            "{}:{}",
            self.local_conn_cred.ice_params.username_fragment,
            self.remote_conn_cred.ice_params.username_fragment
        )
    }

    pub fn remote_description(&self) -> &RTCSessionDescription {
        &self.remote_description
    }

    pub fn local_description(&self) -> &RTCSessionDescription {
        &self.local_description
    }

    pub fn expired_time(&self) -> Instant {
        self.expired_time
    }
}
