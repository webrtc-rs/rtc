use crate::peer::certificate::RTCCertificate;

pub struct RTCIceServer {
    urls: Vec<String>,
    username: String,
    credential: String,
}

#[derive(Default)]
pub enum RTCIceTransportPolicy {
    Relay,
    #[default]
    All,
}

#[derive(Default)]
pub enum RTCBundlePolicy {
    #[default]
    Balanced,
    MaxCompat,
    MaxBundle,
}

#[derive(Default)]
pub enum RTCRtcpMuxPolicy {
    #[default]
    Require,
}

pub trait RTCOfferAnswerOptions {}

pub struct RTCOfferOptions {
    pub ice_restart: bool,
}

impl RTCOfferAnswerOptions for RTCOfferOptions {}

pub struct RTCAnswerOptions {}

impl RTCOfferAnswerOptions for RTCAnswerOptions {}

#[derive(Default)]
pub struct RTCConfiguration {
    pub ice_servers: Vec<RTCIceServer>,
    pub ice_transport_policy: RTCIceTransportPolicy,
    pub bundle_policy: RTCBundlePolicy,
    pub rtcp_mux_policy: RTCRtcpMuxPolicy,
    pub certificates: Vec<RTCCertificate>,
    pub ice_candidate_pool_size: usize,
}
