use crate::data_channel::event::RTCDataChannelEvent;
use crate::peer_connection::event::ice_error_event::RTCPeerConnectionIceErrorEvent;
use crate::peer_connection::event::ice_event::RTCPeerConnectionIceEvent;

pub(crate) mod ice_error_event;
pub(crate) mod ice_event;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone)]
pub enum RTCPeerConnectionEvent {
    #[default]
    OnNegotiationNeededEvent,
    OnIceCandidateEvent(RTCPeerConnectionIceEvent),
    OnIceCandidateErrorEvent(RTCPeerConnectionIceErrorEvent),
    OnSignalingStateChangeEvent,
    OnIceConnectionStateChangeEvent,
    OnIceGatheringStateChangeEvent,
    OnConnectionStateChangeEvent,

    // The Peer-to-peer data API extends the RTCPeerConnection interface as described below.
    OnDataChannel(RTCDataChannelEvent),

    // The RTP media API extends the RTCPeerConnection interface as described below.
    OnTrack,
}
