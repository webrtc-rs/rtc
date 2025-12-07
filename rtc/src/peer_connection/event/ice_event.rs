use crate::peer_connection::ice::ice_candidate::RTCIceCandidate;

#[derive(Default, Clone)]
pub struct RTCPeerConnectionIceEvent {
    pub candidate: RTCIceCandidate,
    pub url: String,
}
