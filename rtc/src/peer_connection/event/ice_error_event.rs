#[derive(Default, Clone)]
pub struct RTCPeerConnectionIceErrorEvent {
    pub address: String,
    pub port: u16,
    pub url: String,
    pub error_code: u16,
    pub error_text: String,
}
