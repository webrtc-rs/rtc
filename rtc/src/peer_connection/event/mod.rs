use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use srtp::context::Context;
use std::net::SocketAddr;

pub(crate) mod data_channel_event;
pub(crate) mod ice_error_event;
pub(crate) mod ice_event;
pub(crate) mod track_event;

pub use data_channel_event::RTCDataChannelEvent;

pub use ice_error_event::RTCPeerConnectionIceErrorEvent;

pub use ice_event::RTCPeerConnectionIceEvent;

pub use track_event::{RTCTrackEvent, RTCTrackEventInit};

/// Events that can be emitted by an `RTCPeerConnection`.
///
/// This enum represents all the events defined in the WebRTC specification that
/// can occur during the lifecycle of a peer connection. Applications should handle
/// these events in their event loop to respond to state changes, receive tracks,
/// handle ICE candidates, etc.
///
/// # Specification
///
/// See [RTCPeerConnection Events](https://www.w3.org/TR/webrtc/#rtcpeerconnection-interface)
#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone, Debug)]
pub enum RTCPeerConnectionEvent {
    /// Fired when negotiation is needed to maintain the connection.
    ///
    /// This event indicates that renegotiation is needed, usually because tracks
    /// have been added or removed. The application should create a new offer.
    ///
    /// # Specification
    ///
    /// See [negotiationneeded](https://www.w3.org/TR/webrtc/#event-negotiation)
    #[default]
    OnNegotiationNeededEvent,

    /// Fired when a new ICE candidate is available.
    ///
    /// This event provides an ICE candidate that should be sent to the remote peer
    /// over the signaling channel.
    ///
    /// # Specification
    ///
    /// See [icecandidate](https://www.w3.org/TR/webrtc/#event-icecandidate)
    OnIceCandidateEvent(RTCPeerConnectionIceEvent),

    /// Fired when an error occurs during ICE candidate gathering.
    ///
    /// # Specification
    ///
    /// See [icecandidateerror](https://www.w3.org/TR/webrtc/#event-icecandidateerror)
    OnIceCandidateErrorEvent(RTCPeerConnectionIceErrorEvent),

    /// Fired when the signaling state changes.
    ///
    /// The signaling state describes where the peer connection is in the
    /// offer/answer negotiation process.
    ///
    /// # Specification
    ///
    /// See [signalingstatechange](https://www.w3.org/TR/webrtc/#event-signalingstatechange)
    OnSignalingStateChangeEvent(RTCSignalingState),

    /// Fired when the ICE connection state changes.
    ///
    /// This indicates the state of the ICE connection (new, checking, connected, etc.).
    ///
    /// # Specification
    ///
    /// See [iceconnectionstatechange](https://www.w3.org/TR/webrtc/#event-iceconnectionstatechange)
    OnIceConnectionStateChangeEvent(RTCIceConnectionState),

    /// Fired when the ICE gathering state changes.
    ///
    /// This indicates whether ICE is gathering candidates, has completed, etc.
    ///
    /// # Specification
    ///
    /// See [icegatheringstatechange](https://www.w3.org/TR/webrtc/#event-icegatheringstatechange)
    OnIceGatheringStateChangeEvent(RTCIceGatheringState),

    /// Fired when the peer connection state changes.
    ///
    /// This represents the overall connection state (new, connecting, connected, etc.).
    ///
    /// # Specification
    ///
    /// See [connectionstatechange](https://www.w3.org/TR/webrtc/#event-connectionstatechange)
    OnConnectionStateChangeEvent(RTCPeerConnectionState),

    /// Fired when a new data channel is received from the remote peer.
    ///
    /// # Specification
    ///
    /// See [datachannel](https://www.w3.org/TR/webrtc/#event-datachannel)
    OnDataChannel(RTCDataChannelEvent),

    /// Fired when a new media track is received from the remote peer.
    ///
    /// This event provides access to the incoming media stream and allows
    /// the application to receive RTP and RTCP packets.
    ///
    /// # Specification
    ///
    /// See [track](https://www.w3.org/TR/webrtc/#event-track)
    OnTrack(RTCTrackEvent),
}

#[derive(Debug, Clone)]
pub enum RTCEvent {}

#[allow(clippy::large_enum_variant)]
pub(crate) enum RTCEventInternal {
    RTCEvent(RTCEvent),
    RTCPeerConnectionEvent(RTCPeerConnectionEvent),

    // ICE Event
    ICESelectedCandidatePairChange,
    // DTLS Event
    DTLSHandshakeComplete(SocketAddr, Option<Context>, Option<Context>),
    // SCTP Event
    SCTPHandshakeComplete(usize /*AssociationHandle*/),
    SCTPStreamClosed(usize /*AssociationHandle*/, u16 /*StreamID*/),
}
