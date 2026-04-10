use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::transport::dtls::parameters::DTLSParameters;
use crate::peer_connection::transport::dtls::role::{DEFAULT_DTLS_ROLE_ANSWER, RTCDtlsRole};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use dtls::config::{ClientAuthType, VerifyPeerCertificateFn};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rcgen::KeyPair;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::SystemTime;

pub(crate) mod fingerprint;
pub(crate) mod parameters;
pub(crate) mod role;
pub(crate) mod state;

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
pub(crate) struct RTCDtlsTransport {
    pub(crate) dtls_role: RTCDtlsRole,
    pub(crate) dtls_handshake_config: Option<Arc<::dtls::config::HandshakeConfig>>,
    pub(crate) dtls_endpoint: Option<::dtls::endpoint::Endpoint>,

    pub(crate) state: RTCDtlsTransportState,
    pub(crate) certificates: Vec<RTCCertificate>,

    // From SettingEngine
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) replay_protection: ReplayProtection,
}

impl RTCDtlsTransport {
    pub(crate) fn new(
        mut certificates: Vec<RTCCertificate>,
        answering_dtls_role: RTCDtlsRole,
        srtp_protection_profiles: Vec<SrtpProtectionProfile>,
        allow_insecure_verification_algorithm: bool,
        replay_protection: ReplayProtection,
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
            dtls_role: RTCDtlsRole::Auto,
            dtls_handshake_config: None,
            dtls_endpoint: None,
            state: RTCDtlsTransportState::New,
            certificates,

            answering_dtls_role,
            srtp_protection_profiles,
            allow_insecure_verification_algorithm,
            replay_protection,
        })
    }

    pub(crate) fn state_change(&mut self, state: RTCDtlsTransportState) {
        self.state = state;
    }

    fn derive_role(&self, ice_role: RTCIceRole, remote_dtls_role: RTCDtlsRole) -> RTCDtlsRole {
        // If remote has an explicit role use the inverse
        match remote_dtls_role {
            RTCDtlsRole::Client => return RTCDtlsRole::Server,
            RTCDtlsRole::Server => return RTCDtlsRole::Client,
            _ => {}
        };

        // If SettingEngine has an explicit role
        match self.answering_dtls_role {
            RTCDtlsRole::Server => return RTCDtlsRole::Server,
            RTCDtlsRole::Client => return RTCDtlsRole::Client,
            _ => {}
        };

        // Remote was auto and no explicit role was configured via SettingEngine
        if ice_role == RTCIceRole::Controlling {
            return RTCDtlsRole::Server;
        }

        DEFAULT_DTLS_ROLE_ANSWER
    }

    /// Build a DTLS HandshakeConfig from remote fingerprints.
    /// Does not check or change transport state — callable from both initial start and restart.
    fn make_handshake_config(
        &self,
        remote_dtls_parameters: &DTLSParameters,
    ) -> Result<Arc<::dtls::config::HandshakeConfig>> {
        let remote_fingerprints = remote_dtls_parameters.fingerprints.clone();
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
                .with_replay_protection_window(self.replay_protection.dtls)
                .build(self.dtls_role == RTCDtlsRole::Client, None)?,
        ))
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
        let dtls_handshake_config = self.make_handshake_config(&remote_dtls_parameters)?;
        self.state_change(RTCDtlsTransportState::Connecting);
        Ok(dtls_handshake_config)
    }

    /// Re-initialise the DTLS transport for re-handshake after an ICE restart.
    ///
    /// When DTLS is `Connected`, `Failed`, `Closed`, or `Connecting` (handshake was
    /// in-flight and lost), the endpoint is replaced so the next
    /// `ICESelectedCandidatePairChange` event triggers a fresh handshake.
    /// No-ops if state is `New` (initial `start_transports` handles it).
    ///
    /// **Note on identity**: the local certificate and its fingerprint are *not*
    /// regenerated — the same identity is reused across ICE restarts.  Only the
    /// DTLS endpoint and handshake state are reset, which is sufficient for a new
    /// handshake over the refreshed ICE transport (RFC 8842 §4.4).
    pub(crate) fn restart(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: DTLSParameters,
    ) -> Result<()> {
        if self.state == RTCDtlsTransportState::New {
            // Not started yet — initial start_transports handles this path.
            return Ok(());
        }

        // Derive and update the role (may differ if ICE role swapped during restart).
        self.dtls_role = self.derive_role(local_ice_role, remote_dtls_parameters.role);

        let dtls_handshake_config = self.make_handshake_config(&remote_dtls_parameters)?;

        self.state_change(RTCDtlsTransportState::Connecting);

        if self.dtls_role == RTCDtlsRole::Client {
            // Client: create a fresh endpoint and store the handshake config so the
            // next ICESelectedCandidatePairChange event triggers connect().
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr,
                TransportProtocol::UDP,
                None,
            ));
            self.dtls_handshake_config = Some(dtls_handshake_config);
        } else {
            // Server: create a new accepting endpoint with the updated config.
            // Clear any stale client handshake config from a previous role.
            self.dtls_handshake_config = None;
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr,
                TransportProtocol::UDP,
                Some(dtls_handshake_config),
            ));
        }

        Ok(())
    }

    pub(crate) fn role(&self) -> RTCDtlsRole {
        self.dtls_role
    }

    pub(crate) fn start(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: DTLSParameters,
    ) -> Result<()> {
        let dtls_handshake_config =
            self.prepare_transport(local_ice_role, remote_dtls_parameters)?;

        if self.dtls_role == RTCDtlsRole::Client {
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr, // local_addr doesn't matter
                TransportProtocol::UDP,                 // TransportProtocol doesn't matter
                None,
            ));
            self.dtls_handshake_config = Some(dtls_handshake_config);
        } else {
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr, // local_addr doesn't matter
                TransportProtocol::UDP,                 // TransportProtocol doesn't matter
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

#[cfg(test)]
mod test {
    use super::*;

    /// Build a minimal `RTCDtlsTransport` with a freshly-generated certificate.
    fn make_transport() -> RTCDtlsTransport {
        RTCDtlsTransport::new(
            vec![],            // auto-generate certificate
            RTCDtlsRole::Auto, // answering role
            vec![],            // default SRTP profiles
            false,             // no insecure verification
            ReplayProtection::default(),
        )
        .expect("transport construction must succeed")
    }

    /// Build `DTLSParameters` with a dummy sha-256 fingerprint that will pass
    /// config construction (the actual value only matters during handshake
    /// verification, not config building).
    fn dummy_params(role: RTCDtlsRole) -> DTLSParameters {
        DTLSParameters {
            role,
            fingerprints: vec![fingerprint::RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:\
                        00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
                    .to_owned(),
            }],
        }
    }

    // ── prepare_transport ────────────────────────────────────────────

    #[test]
    fn prepare_transport_transitions_to_connecting_after_config() {
        let mut t = make_transport();
        assert_eq!(t.state, RTCDtlsTransportState::New);

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    #[test]
    fn prepare_transport_rejects_non_new_state() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Connecting);

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err());
        // State must remain unchanged on error.
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    #[test]
    fn prepare_transport_stays_new_on_config_failure() {
        let mut t = make_transport();
        // Empty fingerprints → make_handshake_config succeeds but verification
        // closure is built; however, an empty params with *no* fingerprints at
        // all still builds a config (the closure checks at handshake time).
        // Instead, force a failure by removing certificates.
        t.certificates.clear();

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "should fail without certificates");
        // State must NOT have moved to Connecting.
        assert_eq!(t.state, RTCDtlsTransportState::New);
    }

    // ── restart ──────────────────────────────────────────────────────

    #[test]
    fn restart_noop_when_new() {
        let mut t = make_transport();
        assert_eq!(t.state, RTCDtlsTransportState::New);

        let result = t.restart(RTCIceRole::Controlling, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        // Must still be New — restart is a no-op in this state.
        assert_eq!(t.state, RTCDtlsTransportState::New);
        assert!(t.dtls_endpoint.is_none());
    }

    #[test]
    fn restart_from_connected_as_client() {
        let mut t = make_transport();
        // Simulate a fully-connected transport.
        t.state_change(RTCDtlsTransportState::Connected);

        let result = t.restart(
            RTCIceRole::Controlled, // controlled → DTLS client
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Client);
        assert!(t.dtls_endpoint.is_some(), "endpoint must be replaced");
        assert!(
            t.dtls_handshake_config.is_some(),
            "client must store handshake config"
        );
    }

    #[test]
    fn restart_from_connected_as_server() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Connected);

        let result = t.restart(
            RTCIceRole::Controlling, // controlling → DTLS server
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        assert!(t.dtls_endpoint.is_some(), "endpoint must be replaced");
        assert!(
            t.dtls_handshake_config.is_none(),
            "server must clear stale client handshake config"
        );
    }

    #[test]
    fn restart_from_failed() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Failed);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_from_closed() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Closed);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_from_connecting() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Connecting);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_clears_stale_client_config_when_switching_to_server() {
        let mut t = make_transport();
        // First start as client.
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = Some(Arc::new(
            ::dtls::config::ConfigBuilder::default()
                .build(true, None)
                .unwrap(),
        ));

        // Now restart as server (remote says Client → we become Server).
        let result = t.restart(
            RTCIceRole::Controlling,
            dummy_params(RTCDtlsRole::Client), // remote=Client → local=Server
        );
        assert!(result.is_ok());
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        assert!(
            t.dtls_handshake_config.is_none(),
            "stale client config must be cleared in server branch"
        );
    }

    #[test]
    fn restart_preserves_certificates() {
        let mut t = make_transport();
        let fingerprint_before: Vec<_> = t
            .certificates
            .first()
            .unwrap()
            .get_fingerprints()
            .iter()
            .map(|fp| fp.value.clone())
            .collect();

        t.state_change(RTCDtlsTransportState::Connected);
        t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();

        let fingerprint_after: Vec<_> = t
            .certificates
            .first()
            .unwrap()
            .get_fingerprints()
            .iter()
            .map(|fp| fp.value.clone())
            .collect();

        assert_eq!(
            fingerprint_before, fingerprint_after,
            "restart must NOT regenerate certificates — same identity, new handshake"
        );
    }

    #[test]
    fn restart_fails_without_certificates() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Connected);
        t.certificates.clear();

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "restart without certs must fail");
        // State should NOT advance to Connecting on config build failure.
        assert_eq!(t.state, RTCDtlsTransportState::Connected);
    }

    // ── start ────────────────────────────────────────────────────────

    #[test]
    fn start_as_client_stores_config_and_endpoint() {
        let mut t = make_transport();
        let result = t.start(
            RTCIceRole::Controlled, // controlled → client
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Client);
        assert!(t.dtls_handshake_config.is_some());
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn start_as_server_creates_endpoint_no_stored_config() {
        let mut t = make_transport();
        let result = t.start(
            RTCIceRole::Controlling, // controlling → server
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        // Server passes config directly to endpoint, not stored separately.
        assert!(t.dtls_handshake_config.is_none());
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn start_rejects_double_start() {
        let mut t = make_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();

        let result = t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "double-start must be rejected");
    }

    // ── stop ─────────────────────────────────────────────────────────

    #[test]
    fn stop_transitions_to_closed() {
        let mut t = make_transport();
        t.state_change(RTCDtlsTransportState::Connected);
        t.stop().unwrap();
        assert_eq!(t.state, RTCDtlsTransportState::Closed);
    }

    // ── derive_role ──────────────────────────────────────────────────

    #[test]
    fn derive_role_from_remote_client() {
        let t = make_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Client),
            RTCDtlsRole::Server
        );
    }

    #[test]
    fn derive_role_from_remote_server() {
        let t = make_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Server),
            RTCDtlsRole::Client
        );
    }

    #[test]
    fn derive_role_auto_controlling_becomes_server() {
        let t = make_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlling, RTCDtlsRole::Auto),
            RTCDtlsRole::Server
        );
    }

    #[test]
    fn derive_role_auto_controlled_becomes_client() {
        let t = make_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Auto),
            DEFAULT_DTLS_ROLE_ANSWER
        );
    }
}
