use std::collections::{/*HashMap,*/ VecDeque};
use std::sync::Arc;

use bytes::Bytes;
//use retty::transport::Protocol;
//use dtls::config::ClientAuthType;
//use dtls::conn::DTLSConn;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls_role::*;
//use interceptor::stream_info::StreamInfo;
//use interceptor::{Interceptor, RTCPReader, RTPReader};
use dtls::config::ClientAuthType;
use sha2::{Digest, Sha256};
use srtp::protection_profile::ProtectionProfile;
//use srtp::session::Session;
//use srtp::stream::Stream;

use crate::api::setting_engine::SettingEngine;
use crate::transport::dtls_transport::dtls_parameters::DTLSParameters;
use crate::transport::dtls_transport::dtls_transport_state::RTCDtlsTransportState;
/*use crate::transports::ice_transport::ice_role::RTCIceRole;
use crate::transports::ice_transport::ice_transport_state::RTCIceTransportState;
use crate::transports::ice_transport::RTCIceTransport;*/
use crate::peer_connection::certificate::RTCCertificate;
//use crate::rtp_transceiver::SSRC;
use crate::constants::DEFAULT_DTLS_REPLAY_PROTECTION_WINDOW;
use crate::stats::stats_collector::StatsCollector;
use shared::error::{Error, Result};

//TODO:#[cfg(test)]
//TODO:mod dtls_transport_test;

pub mod dtls_fingerprint;
pub mod dtls_parameters;
pub mod dtls_role;
pub mod dtls_transport_state;

pub(crate) fn default_srtp_protection_profiles() -> Vec<SrtpProtectionProfile> {
    vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ]
}

#[derive(Debug)]
pub enum DtlsTransportEvent {
    OnDtlsTransportStateChange(RTCDtlsTransportState),
}

/// DTLSTransport allows an application access to information about the DTLS
/// transport over which RTP and RTCP packets are sent and received by
/// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
/// and received by data channels.
#[derive(Default)]
pub struct RTCDtlsTransport {
    pub(crate) certificates: Vec<RTCCertificate>,
    pub(crate) setting_engine: Arc<SettingEngine>,
    pub(crate) remote_parameters: DTLSParameters,
    pub(crate) remote_certificate: Bytes,
    pub(crate) state: RTCDtlsTransportState,
    pub(crate) events: VecDeque<DtlsTransportEvent>,
    pub(crate) srtp_protection_profile: ProtectionProfile,
    pub(crate) dtls_endpoint: Option<dtls::endpoint::Endpoint>,
}

impl RTCDtlsTransport {
    pub(crate) fn new(
        certificates: Vec<RTCCertificate>,
        setting_engine: Arc<SettingEngine>,
    ) -> Self {
        RTCDtlsTransport {
            certificates,
            setting_engine,
            state: RTCDtlsTransportState::New,
            events: VecDeque::new(),
            ..Default::default()
        }
    }

    /// state_change requires the caller holds the lock
    fn state_change(&mut self, state: RTCDtlsTransportState) {
        self.state = state;
        self.events
            .push_back(DtlsTransportEvent::OnDtlsTransportStateChange(state));
    }

    /// state returns the current dtls_transport transport state.
    pub fn state(&self) -> RTCDtlsTransportState {
        self.state
    }

    /// get_local_parameters returns the DTLS parameters of the local DTLSTransport upon construction.
    pub fn get_local_parameters(&self) -> Result<DTLSParameters> {
        let mut fingerprints = vec![];

        for c in &self.certificates {
            fingerprints.extend(c.get_fingerprints());
        }

        Ok(DTLSParameters {
            role: DTLSRole::Auto, // always returns the default role
            fingerprints,
        })
    }

    /// get_remote_certificate returns the certificate chain in use by the remote side
    /// returns an empty list prior to selection of the remote certificate
    pub fn get_remote_certificate(&self) -> &Bytes {
        &self.remote_certificate
    }

    pub(crate) fn role(&self) -> DTLSRole {
        // If remote has an explicit role use the inverse
        match self.remote_parameters.role {
            DTLSRole::Client => return DTLSRole::Server,
            DTLSRole::Server => return DTLSRole::Client,
            _ => {}
        };

        // If SettingEngine has an explicit role
        match self.setting_engine.answering_dtls_role {
            DTLSRole::Server => return DTLSRole::Server,
            DTLSRole::Client => return DTLSRole::Client,
            _ => {}
        };

        DEFAULT_DTLS_ROLE_ANSWER
    }

    pub(crate) fn collect_stats(&self, collector: &mut StatsCollector) {
        for cert in &self.certificates {
            cert.collect_stats(collector);
        }
    }

    fn prepare_transport(
        &mut self,
        remote_parameters: DTLSParameters,
    ) -> Result<dtls::config::HandshakeConfig> {
        if self.state() != RTCDtlsTransportState::New {
            return Err(Error::ErrInvalidDTLSStart);
        }

        self.remote_parameters = remote_parameters;

        let certificate = if let Some(cert) = self.certificates.first() {
            cert.dtls_certificate.clone()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        let replay_protection_window = if self.setting_engine.replay_protection.dtls != 0 {
            self.setting_engine.replay_protection.dtls
        } else {
            DEFAULT_DTLS_REPLAY_PROTECTION_WINDOW
        };

        self.state_change(RTCDtlsTransportState::Connecting);

        let handshake_config = dtls::config::ConfigBuilder::default()
            .with_certificates(vec![certificate])
            .with_srtp_protection_profiles(
                if !self.setting_engine.srtp_protection_profiles.is_empty() {
                    self.setting_engine.srtp_protection_profiles.clone()
                } else {
                    default_srtp_protection_profiles()
                },
            )
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_insecure_skip_verify(true)
            .with_insecure_verification(self.setting_engine.allow_insecure_verification_algorithm)
            .with_replay_protection_window(replay_protection_window)
            .build(self.role() == DTLSRole::Client, None)?;

        Ok(handshake_config)
    }

    /// stop the DTLSTransport object.
    pub fn stop(&mut self) -> Result<()> {
        // Try closing everything and collect the errors
        self.state_change(RTCDtlsTransportState::Closed);
        if let Some(mut dtls_endpoint) = self.dtls_endpoint.take() {
            dtls_endpoint.close()?;
        }
        Ok(())
    }

    pub(crate) fn validate_fingerprint(&self, remote_cert: &[u8]) -> Result<()> {
        for fp in &self.remote_parameters.fingerprints {
            if fp.algorithm != "sha-256" {
                return Err(Error::ErrUnsupportedFingerprintAlgorithm);
            }

            let mut h = Sha256::new();
            h.update(remote_cert);
            let hashed = h.finalize();
            let values: Vec<String> = hashed.iter().map(|x| format! {"{x:02x}"}).collect();
            let remote_value = values.join(":").to_lowercase();

            if remote_value == fp.value.to_lowercase() {
                return Ok(());
            }
        }

        Err(Error::ErrNoMatchingCertificateFingerprint)
    }
}
