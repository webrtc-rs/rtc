use crate::peer_connection::certificate::RTCCertificate;
use crate::transport::dtls::parameters::DTLSParameters;
use crate::transport::dtls::role::{DTLSRole, DEFAULT_DTLS_ROLE_ANSWER};
use crate::transport::dtls::state::RTCDtlsTransportState;
use crate::transport::ice::role::RTCIceRole;
use bytes::Bytes;
use rcgen::KeyPair;
use shared::error::{Error, Result};
use srtp::protection_profile::ProtectionProfile;
use std::time::SystemTime;

pub mod fingerprint;
pub mod parameters;
pub mod role;
pub mod state;

/// DTLSTransport allows an application access to information about the DTLS
/// transport over which RTP and RTCP packets are sent and received by
/// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
/// and received by data channels.
#[derive(Default, Clone)]
pub struct RTCDtlsTransport {
    //TODO: ice_transport: RTCIceTransport,
    pub(crate) state: RTCDtlsTransportState,

    pub(crate) certificates: Vec<RTCCertificate>,
    //pub(crate) setting_engine: Arc<SettingEngine>,
    pub(crate) remote_parameters: DTLSParameters,
    pub(crate) remote_certificate: Bytes,
    pub(crate) srtp_protection_profile: ProtectionProfile,
    /*pub(crate) on_state_change_handler: ArcSwapOption<Mutex<OnDTLSTransportStateChangeHdlrFn>>,
    pub(crate) conn: Mutex<Option<Arc<DTLSConn>>>,

    pub(crate) srtp_session: Mutex<Option<Arc<Session>>>,
    pub(crate) srtcp_session: Mutex<Option<Arc<Session>>>,
    pub(crate) srtp_endpoint: Mutex<Option<Arc<Endpoint>>>,
    pub(crate) srtcp_endpoint: Mutex<Option<Arc<Endpoint>>>,

    pub(crate) simulcast_streams: Mutex<HashMap<SSRC, Arc<Stream>>>,

    pub(crate) srtp_ready_signal: Arc<AtomicBool>,
    pub(crate) srtp_ready_tx: Mutex<Option<mpsc::Sender<()>>>,
    pub(crate) srtp_ready_rx: Mutex<Option<mpsc::Receiver<()>>>,

    pub(crate) dtls_matcher: Option<MatchFunc>,*/
    // From SettingEngine
    answering_dtls_role: DTLSRole,
}

impl RTCDtlsTransport {
    pub(crate) fn new(
        mut certificates: Vec<RTCCertificate>,
        answering_dtls_role: DTLSRole,
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
            certificates,
            state: RTCDtlsTransportState::New,
            answering_dtls_role,
            //dtls_matcher: Some(Box::new(match_dtls)),
            ..Default::default()
        })
    }

    fn state_change(&mut self, state: RTCDtlsTransportState) {
        self.state = state;
        //TODO: put event to events
    }

    pub(crate) fn role(&self, ice_role: RTCIceRole) -> DTLSRole {
        // If remote has an explicit role use the inverse
        match self.remote_parameters.role {
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

    /// set DTLS transport negotiation with the parameters of the remote DTLS transport
    pub(crate) fn set_parameters(&mut self, remote_parameters: DTLSParameters) -> Result<()> {
        //(DTLSRole, dtls::config::Config)
        //self.ensure_ice_conn()?;

        //if self.state != RTCDtlsTransportState::New {
        //    return Err(Error::ErrInvalidDTLSStart);
        //}

        /*{
            let mut srtp_endpoint = self.srtp_endpoint.lock().await;
            *srtp_endpoint = self.ice_transport.new_endpoint(Box::new(match_srtp)).await;
        }
        {
            let mut srtcp_endpoint = self.srtcp_endpoint.lock().await;
            *srtcp_endpoint = self.ice_transport.new_endpoint(Box::new(match_srtcp)).await;
        }*/
        self.remote_parameters = remote_parameters;

        /*let certificate = if let Some(cert) = self.certificates.first() {
            cert.dtls_certificate.clone()
        } else {
            return Err(Error::ErrNonCertificate);
        };*/
        self.state_change(RTCDtlsTransportState::Connecting);

        /*Ok((
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
        ))*/
        Ok(())
    }

    //pub fn set_parameters(&mut self, _remote_parameters: DTLSParameters) {
    /*
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
            dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => {
                srtp::protection_profile::ProtectionProfile::AeadAes256Gcm
            }
            dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
                srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80
            }
            dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => {
                srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_32
            }
            _ => {
                if let Err(err) = dtls_conn.close().await {
                    log::error!("{err}");
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
            log::error!("{err}");
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
                log::error!("{close_err}");
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

    self.start_srtp().await*/
    //}
}
