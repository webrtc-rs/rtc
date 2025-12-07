use crate::transport::ice::candidate::RTCIceCandidate;

#[derive(Default, Clone)]
pub struct RTCPeerConnectionIceEvent {
    pub candidate: RTCIceCandidate,
    pub url: String,
}
