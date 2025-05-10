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

#[derive(Debug, Clone)]
pub struct RTCConfiguration {
    pub ice_servers: Vec<RTCIceServer>,
    pub ice_transport_policy: RTCIceTransportPolicy,
    pub bundle_policy: RTCBundlePolicy,
    pub rtcp_mux_policy: RTCRtcpMuxPolicy,
    pub certificates: Vec<RTCCertificate>,
    pub ice_candidate_pool_size: usize,

    // Port range
    pub port_range_begin: u16,
    pub port_range_end: u16,

    // Network MTU
    pub mtu: Option<usize>,

    // Local maximum message size for Data Channels
    pub max_message_size: Option<usize>,
}

impl Default for RTCConfiguration {
    fn default() -> Self {
        Self {
            ice_servers: vec![],
            ice_transport_policy: Default::default(),
            bundle_policy: Default::default(),
            rtcp_mux_policy: Default::default(),
            certificates: vec![],
            ice_candidate_pool_size: 0,
            port_range_begin: 1024,
            port_range_end: 65535,
            mtu: None,
            max_message_size: None,
        }
    }
}
