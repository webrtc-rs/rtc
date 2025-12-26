use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::ice_error_event::RTCPeerConnectionIceErrorEvent;
use crate::peer_connection::event::ice_event::RTCPeerConnectionIceEvent;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;

pub mod data_channel_event;
pub mod ice_error_event;
pub mod ice_event;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone)]
pub enum RTCPeerConnectionEvent {
    #[default]
    OnNegotiationNeededEvent,
    OnIceCandidateEvent(RTCPeerConnectionIceEvent),
    OnIceCandidateErrorEvent(RTCPeerConnectionIceErrorEvent),
    OnSignalingStateChangeEvent(RTCSignalingState),
    OnIceConnectionStateChangeEvent(RTCIceConnectionState),
    OnIceGatheringStateChangeEvent(RTCIceGatheringState),
    OnConnectionStateChangeEvent(RTCPeerConnectionState),

    // The Peer-to-peer data API extends the RTCPeerConnection interface as described below.
    OnDataChannel(RTCDataChannelEvent),

    // The RTP media API extends the RTCPeerConnection interface as described below.
    OnTrack,
}
