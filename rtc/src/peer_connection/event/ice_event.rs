use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;

#[derive(Default, Clone, Debug)]
pub struct RTCPeerConnectionIceEvent {
    pub candidate: RTCIceCandidate,
    pub url: String,
}
