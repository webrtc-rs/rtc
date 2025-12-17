use crate::peer_connection::certificate::RTCCertificate;
use crate::transport::dtls::parameters::DTLSParameters;
use crate::transport::dtls::state::RTCDtlsTransportState;
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
}

impl RTCDtlsTransport {
    pub(crate) fn new(mut certificates: Vec<RTCCertificate>) -> Result<Self> {
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
            //dtls_matcher: Some(Box::new(match_dtls)),
            ..Default::default()
        })
    }
}
