use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::transport::dtls::parameters::DTLSParameters;
use crate::peer_connection::transport::dtls::role::{DTLSRole, DEFAULT_DTLS_ROLE_ANSWER};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use dtls::config::{ClientAuthType, VerifyPeerCertificateFn};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rcgen::KeyPair;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use shared::error::{Error, Result};
use shared::TransportProtocol;
use std::sync::Arc;
use std::time::SystemTime;

pub mod fingerprint;
pub mod parameters;
pub mod role;
pub mod state;

pub(crate) fn default_srtp_protection_profiles() -> Vec<SrtpProtectionProfile> {
    vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
    ]
}

/// DTLSTransport allows an application access to information about the DTLS
/// transport over which RTP and RTCP packets are sent and received by
/// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
/// and received by data channels.
#[derive(Default)]
pub struct RTCDtlsTransport {
    pub(crate) dtls_role: DTLSRole,
    pub(crate) dtls_handshake_config: Option<Arc<::dtls::config::HandshakeConfig>>,
    pub(crate) dtls_endpoint: Option<::dtls::endpoint::Endpoint>,

    pub(crate) state: RTCDtlsTransportState,
    pub(crate) certificates: Vec<RTCCertificate>,
    //pub(crate) srtp_protection_profile: ProtectionProfile,

    // From SettingEngine
    answering_dtls_role: DTLSRole,
    srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    allow_insecure_verification_algorithm: bool,
    dtls_replay_protection_window: usize,
}

impl RTCDtlsTransport {
    pub(crate) fn new(
        mut certificates: Vec<RTCCertificate>,
        answering_dtls_role: DTLSRole,
        srtp_protection_profiles: Vec<SrtpProtectionProfile>,
        allow_insecure_verification_algorithm: bool,
        dtls_replay_protection_window: usize,
    ) -> Result<Self> {
        if !certificates.is_empty() {
            let now = SystemTime::now();
            for cert in &certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }
        } else {
            let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = RTCCertificate::from_key_pair(kp)?;
            certificates = vec![cert];
        };

        Ok(Self {
            dtls_role: DTLSRole::Auto,
            dtls_handshake_config: None,
            dtls_endpoint: None,
            state: RTCDtlsTransportState::New,
            certificates,

            answering_dtls_role,
            srtp_protection_profiles,
            allow_insecure_verification_algorithm,
            dtls_replay_protection_window,
        })
    }

    pub(crate) fn state_change(&mut self, state: RTCDtlsTransportState) {
        self.state = state;
    }

    fn derive_role(&self, ice_role: RTCIceRole, remote_dtls_role: DTLSRole) -> DTLSRole {
        // If remote has an explicit role use the inverse
        match remote_dtls_role {
            DTLSRole::Client => return DTLSRole::Server,
            DTLSRole::Server => return DTLSRole::Client,
            _ => {}
        };

        // If SettingEngine has an explicit role
        match self.answering_dtls_role {
            DTLSRole::Server => return DTLSRole::Server,
            DTLSRole::Client => return DTLSRole::Client,
            _ => {}
        };

        // Remote was auto and no explicit role was configured via SettingEngine
        if ice_role == RTCIceRole::Controlling {
            return DTLSRole::Server;
        }

        DEFAULT_DTLS_ROLE_ANSWER
    }

    pub(crate) fn prepare_transport(
        &mut self,
        ice_role: RTCIceRole,
        remote_dtls_parameters: DTLSParameters,
    ) -> Result<Arc<::dtls::config::HandshakeConfig>> {
        if self.state != RTCDtlsTransportState::New {
            return Err(Error::ErrInvalidDTLSStart);
        }

        self.dtls_role = self.derive_role(ice_role, remote_dtls_parameters.role);

        let remote_fingerprints = remote_dtls_parameters.fingerprints;
        let verify_peer_certificate: VerifyPeerCertificateFn = Arc::new(
            move |certs: &[Vec<u8>], _chains: &[CertificateDer<'static>]| -> Result<()> {
                if certs.is_empty() {
                    return Err(Error::ErrNonCertificate);
                }

                for fp in &remote_fingerprints {
                    if fp.algorithm != "sha-256" {
                        return Err(Error::ErrUnsupportedFingerprintAlgorithm);
                    }

                    let mut h = Sha256::new();
                    h.update(&certs[0]);
                    let hashed = h.finalize();
                    let values: Vec<String> = hashed.iter().map(|x| format! {"{x:02x}"}).collect();
                    let remote_value = values.join(":").to_lowercase();

                    if remote_value == fp.value.to_lowercase() {
                        return Ok(());
                    }
                }

                Err(Error::ErrNoMatchingCertificateFingerprint)
            },
        );

        let certificate = if let Some(cert) = self.certificates.first() {
            cert.dtls_certificate.clone()
        } else {
            return Err(Error::ErrNonCertificate);
        };
        self.state_change(RTCDtlsTransportState::Connecting);

        Ok(Arc::new(
            ::dtls::config::ConfigBuilder::default()
                .with_certificates(vec![certificate])
                .with_srtp_protection_profiles(if !self.srtp_protection_profiles.is_empty() {
                    self.srtp_protection_profiles.clone()
                } else {
                    default_srtp_protection_profiles()
                })
                .with_client_auth(ClientAuthType::RequireAnyClientCert)
                .with_insecure_skip_verify(true)
                .with_insecure_verification(self.allow_insecure_verification_algorithm)
                .with_verify_peer_certificate(Some(verify_peer_certificate))
                .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
                .with_replay_protection_window(self.dtls_replay_protection_window)
                .build(self.dtls_role == DTLSRole::Client, None)?,
        ))
    }

    pub(crate) fn role(&self) -> DTLSRole {
        self.dtls_role
    }

    pub(crate) fn start(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: DTLSParameters,
    ) -> Result<()> {
        let dtls_handshake_config =
            self.prepare_transport(local_ice_role, remote_dtls_parameters)?;

        if self.dtls_role == DTLSRole::Client {
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                "127.0.0.1:0".parse()?, //local_addr doesn't matter
                TransportProtocol::UDP, // TransportProtocol doesn't matter
                None,
            ));
            self.dtls_handshake_config = Some(dtls_handshake_config);
        } else {
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                "127.0.0.1:0".parse()?, //local_addr doesn't matter
                TransportProtocol::UDP, // TransportProtocol doesn't matter
                Some(dtls_handshake_config),
            ));
        }

        Ok(())
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        self.state_change(RTCDtlsTransportState::Closed);
        Ok(())
    }
}
