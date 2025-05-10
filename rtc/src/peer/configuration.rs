use crate::peer::certificate::RTCCertificate;

#[derive(Default, Debug, Clone)]
pub struct RTCIceServer {
    urls: Vec<String>,
    username: String,
    credential: String,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCIceTransportPolicy {
    Relay,
    #[default]
    All,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCBundlePolicy {
    #[default]
    Balanced,
    MaxCompat,
    MaxBundle,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCRtcpMuxPolicy {
    #[default]
    Require,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct RTCOfferOptions {
    pub ice_restart: bool,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct RTCAnswerOptions;

#[derive(Default, Debug, Clone)]
pub struct RTCConfiguration {
    pub ice_servers: Vec<RTCIceServer>,
    pub ice_transport_policy: RTCIceTransportPolicy,
    pub bundle_policy: RTCBundlePolicy,
    pub rtcp_mux_policy: RTCRtcpMuxPolicy,
    pub certificates: Vec<RTCCertificate>,
    pub ice_candidate_pool_size: usize,
}
