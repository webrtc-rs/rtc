use std::collections::{/*HashMap,*/ VecDeque};

use bytes::Bytes;
//use dtls::config::ClientAuthType;
//use dtls::conn::DTLSConn;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls_role::*;
//use interceptor::stream_info::StreamInfo;
//use interceptor::{Interceptor, RTCPReader, RTPReader};
use sha2::{Digest, Sha256};
use srtp::protection_profile::ProtectionProfile;
//use srtp::session::Session;
//use srtp::stream::Stream;

use crate::api::setting_engine::SettingEngine;
use crate::dtls_transport::dtls_parameters::DTLSParameters;
use crate::dtls_transport::dtls_transport_state::RTCDtlsTransportState;
/*use crate::ice_transport::ice_role::RTCIceRole;
use crate::ice_transport::ice_transport_state::RTCIceTransportState;
use crate::ice_transport::RTCIceTransport;*/
use crate::peer_connection::certificate::RTCCertificate;
//use crate::rtp_transceiver::SSRC;
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
    pub(crate) setting_engine: SettingEngine,
    pub(crate) remote_parameters: DTLSParameters,
    pub(crate) remote_certificate: Bytes,
    pub(crate) state: RTCDtlsTransportState,
    pub(crate) events: VecDeque<DtlsTransportEvent>,
    pub(crate) srtp_protection_profile: ProtectionProfile,
    /*TODO:pub(crate) srtp_session: Mutex<Option<Arc<Session>>>,
    pub(crate) srtcp_session: Mutex<Option<Arc<Session>>>,
    pub(crate) srtp_endpoint: Mutex<Option<Arc<Endpoint>>>,
    pub(crate) srtcp_endpoint: Mutex<Option<Arc<Endpoint>>>,
    pub(crate) simulcast_streams: Mutex<HashMap<SSRC, Arc<Stream>>>,*/
}

impl RTCDtlsTransport {
    pub(crate) fn new(certificates: Vec<RTCCertificate>, setting_engine: SettingEngine) -> Self {
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

    /// write_rtcp sends a user provided RTCP packet to the connected peer. If no peer is connected the
    /// packet is discarded.
    /*TODO: pub async fn write_rtcp(
        &self,
        pkts: &[Box<dyn rtcp::packet::Packet + Send + Sync>],
    ) -> Result<usize> {
        let srtcp_session = self.srtcp_session.lock().await;
        if let Some(srtcp_session) = &*srtcp_session {
            let raw = rtcp::packet::marshal(pkts)?;
            Ok(srtcp_session.write(&raw, false).await?)
        } else {
            Ok(0)
        }
    }*/

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

    /*TODO: pub(crate) fn start_srtp(&self) -> Result<()> {
        let profile = {
            let srtp_protection_profile = self.srtp_protection_profile.lock().await;
            *srtp_protection_profile
        };

        let mut srtp_config = srtp::config::Config {
            profile,
            ..Default::default()
        };

        if self.setting_engine.replay_protection.srtp != 0 {
            srtp_config.remote_rtp_options = Some(srtp::option::srtp_replay_protection(
                self.setting_engine.replay_protection.srtp,
            ));
        } else if self.setting_engine.disable_srtp_replay_protection {
            srtp_config.remote_rtp_options = Some(srtp::option::srtp_no_replay_protection());
        }

        if let Some(conn) = self.conn().await {
            let conn_state = conn.connection_state().await;
            srtp_config
                .extract_session_keys_from_dtls(conn_state, self.role().await == DTLSRole::Client)
                .await?;
        } else {
            return Err(Error::ErrDtlsTransportNotStarted);
        }

        {
            let mut srtp_session = self.srtp_session.lock().await;
            *srtp_session = {
                let se = self.srtp_endpoint.lock().await;
                if let Some(srtp_endpoint) = &*se {
                    Some(Arc::new(
                        Session::new(
                            Arc::clone(srtp_endpoint) as Arc<dyn Conn + Send + Sync>,
                            srtp_config,
                            true,
                        )
                        .await?,
                    ))
                } else {
                    None
                }
            };
        }

        let mut srtcp_config = srtp::config::Config {
            profile,
            ..Default::default()
        };
        if self.setting_engine.replay_protection.srtcp != 0 {
            srtcp_config.remote_rtcp_options = Some(srtp::option::srtcp_replay_protection(
                self.setting_engine.replay_protection.srtcp,
            ));
        } else if self.setting_engine.disable_srtcp_replay_protection {
            srtcp_config.remote_rtcp_options = Some(srtp::option::srtcp_no_replay_protection());
        }

        if let Some(conn) = self.conn().await {
            let conn_state = conn.connection_state().await;
            srtcp_config
                .extract_session_keys_from_dtls(conn_state, self.role().await == DTLSRole::Client)
                .await?;
        } else {
            return Err(Error::ErrDtlsTransportNotStarted);
        }

        {
            let mut srtcp_session = self.srtcp_session.lock().await;
            *srtcp_session = {
                let se = self.srtcp_endpoint.lock().await;
                if let Some(srtcp_endpoint) = &*se {
                    Some(Arc::new(
                        Session::new(
                            Arc::clone(srtcp_endpoint) as Arc<dyn Conn + Send + Sync>,
                            srtcp_config,
                            false,
                        )
                        .await?,
                    ))
                } else {
                    None
                }
            };
        }

        {
            let mut srtp_ready_tx = self.srtp_ready_tx.lock().await;
            srtp_ready_tx.take();
            if srtp_ready_tx.is_none() {
                self.srtp_ready_signal.store(true, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    pub(crate) async fn get_srtp_session(&self) -> Option<Arc<Session>> {
        let srtp_session = self.srtp_session.lock().await;
        srtp_session.clone()
    }

    pub(crate) async fn get_srtcp_session(&self) -> Option<Arc<Session>> {
        let srtcp_session = self.srtcp_session.lock().await;
        srtcp_session.clone()
    }*/

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

        // Remote was auto and no explicit role was configured via SettingEngine
        /*todo:if self.ice_transport.role().await == RTCIceRole::Controlling {
            return DTLSRole::Server;
        }*/

        DEFAULT_DTLS_ROLE_ANSWER
    }

    pub(crate) fn collect_stats(&self, collector: &mut StatsCollector) {
        for cert in &self.certificates {
            cert.collect_stats(collector);
        }
    }

    /*todo:async fn prepare_transport(
        &self,
        remote_parameters: DTLSParameters,
    ) -> Result<(DTLSRole, dtls::config::Config)> {
        self.ensure_ice_conn()?;

        if self.state() != RTCDtlsTransportState::New {
            return Err(Error::ErrInvalidDTLSStart);
        }

        {
            let mut srtp_endpoint = self.srtp_endpoint.lock().await;
            *srtp_endpoint = self.ice_transport.new_endpoint(Box::new(match_srtp)).await;
        }
        {
            let mut srtcp_endpoint = self.srtcp_endpoint.lock().await;
            *srtcp_endpoint = self.ice_transport.new_endpoint(Box::new(match_srtcp)).await;
        }
        {
            let mut rp = self.remote_parameters.lock().await;
            *rp = remote_parameters;
        }

        let certificate = if let Some(cert) = self.certificates.first() {
            cert.dtls_certificate.clone()
        } else {
            return Err(Error::ErrNonCertificate);
        };
        self.state_change(RTCDtlsTransportState::Connecting).await;

        Ok((
            self.role().await,
            dtls::config::Config {
                certificates: vec![certificate],
                srtp_protection_profiles: if !self
                    .setting_engine
                    .srtp_protection_profiles
                    .is_empty()
                {
                    self.setting_engine.srtp_protection_profiles.clone()
                } else {
                    default_srtp_protection_profiles()
                },
                client_auth: ClientAuthType::RequireAnyClientCert,
                insecure_skip_verify: true,
                insecure_verification: self.setting_engine.allow_insecure_verification_algorithm,
                ..Default::default()
            },
        ))
    }

    /// start DTLS transport negotiation with the parameters of the remote DTLS transport
    pub async fn start(&self, remote_parameters: DTLSParameters) -> Result<()> {
        let dtls_conn_result = if let Some(dtls_endpoint) =
            self.ice_transport.new_endpoint(Box::new(match_dtls)).await
        {
            let (role, mut dtls_config) = self.prepare_transport(remote_parameters).await?;
            if self.setting_engine.replay_protection.dtls != 0 {
                dtls_config.replay_protection_window = self.setting_engine.replay_protection.dtls;
            }

            // Connect as DTLS Client/Server, function is blocking and we
            // must not hold the DTLSTransport lock
            if role == DTLSRole::Client {
                dtls::conn::DTLSConn::new(
                    dtls_endpoint as Arc<dyn Conn + Send + Sync>,
                    dtls_config,
                    true,
                    None,
                )
                .await
            } else {
                dtls::conn::DTLSConn::new(
                    dtls_endpoint as Arc<dyn Conn + Send + Sync>,
                    dtls_config,
                    false,
                    None,
                )
                .await
            }
        } else {
            Err(dtls::Error::Other(
                "ice_transport.new_endpoint failed".to_owned(),
            ))
        };

        let dtls_conn = match dtls_conn_result {
            Ok(dtls_conn) => dtls_conn,
            Err(err) => {
                self.state_change(RTCDtlsTransportState::Failed).await;
                return Err(err.into());
            }
        };

        let srtp_profile = dtls_conn.selected_srtpprotection_profile();
        {
            let mut srtp_protection_profile = self.srtp_protection_profile.lock().await;
            *srtp_protection_profile = match srtp_profile {
                dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => {
                    srtp::protection_profile::ProtectionProfile::AeadAes128Gcm
                }
                dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
                    srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80
                }
                _ => {
                    if let Err(err) = dtls_conn.close().await {
                        log::error!("{}", err);
                    }

                    self.state_change(RTCDtlsTransportState::Failed).await;
                    return Err(Error::ErrNoSRTPProtectionProfile);
                }
            };
        }

        // Check the fingerprint if a certificate was exchanged
        let remote_certs = &dtls_conn.connection_state().await.peer_certificates;
        if remote_certs.is_empty() {
            if let Err(err) = dtls_conn.close().await {
                log::error!("{}", err);
            }

            self.state_change(RTCDtlsTransportState::Failed).await;
            return Err(Error::ErrNoRemoteCertificate);
        }

        {
            let mut remote_certificate = self.remote_certificate.lock().await;
            *remote_certificate = Bytes::from(remote_certs[0].clone());
        }

        if !self
            .setting_engine
            .disable_certificate_fingerprint_verification
        {
            if let Err(err) = self.validate_fingerprint(&remote_certs[0]).await {
                if let Err(close_err) = dtls_conn.close().await {
                    log::error!("{}", close_err);
                }

                self.state_change(RTCDtlsTransportState::Failed).await;
                return Err(err);
            }
        }

        {
            let mut conn = self.conn.lock().await;
            *conn = Some(Arc::new(dtls_conn));
        }
        self.state_change(RTCDtlsTransportState::Connected).await;

        self.start_srtp().await
    }*/

    /// stops and closes the DTLSTransport object.
    pub fn stop(&mut self) -> Result<()> {
        // Try closing everything and collect the errors
        self.state_change(RTCDtlsTransportState::Closed);
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
