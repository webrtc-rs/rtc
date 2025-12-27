use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::ice_error_event::RTCPeerConnectionIceErrorEvent;
use crate::peer_connection::event::ice_event::RTCPeerConnectionIceEvent;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;

use ice::candidate::Candidate;
use srtp::context::Context;
use std::net::SocketAddr;

pub mod data_channel_event;
pub mod ice_error_event;
pub mod ice_event;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone, Debug)]
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

#[derive(Debug, Clone)]
pub enum RTCEvent {}

#[allow(clippy::large_enum_variant)]
pub(crate) enum RTCEventInternal {
    RTCEvent(RTCEvent),
    RTCPeerConnectionEvent(RTCPeerConnectionEvent),

    // ICE Event
    ICESelectedCandidatePairChange(Box<Candidate>, Box<Candidate>),
    // DTLS Event
    DTLSHandshakeComplete(SocketAddr, Option<Context>, Option<Context>),
    // SCTP Event
    SCTPHandshakeComplete(usize /*AssociationHandle*/),
    SCTPStreamClosed(usize /*AssociationHandle*/, u16 /*StreamID*/),
}
