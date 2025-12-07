use crate::peer_connection::ice::ice_candidate::RTCIceCandidate;

pub struct RTCPeerConnectionIceEvent {
    pub candidate: RTCIceCandidate,
    pub url: String,
}
