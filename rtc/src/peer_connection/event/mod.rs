//! WebRTC peer connection event types.
//!
//! This module defines all events that can be emitted by an `RTCPeerConnection`
//! according to the WebRTC specification. These events notify applications about
//! state changes, incoming media tracks, data channels, ICE candidates, and errors.
//!
//! # Sans-I/O Event Pattern
//!
//! This crate uses a sans-I/O design where events are polled from the peer connection
//! rather than delivered via callbacks. Applications drive the event loop by calling
//! `poll_event()` and handling the returned events.
//!
//! # Examples
//!
//! ## Basic event loop pattern (conceptual)
//!
//! ```ignore
//! // Note: poll_event() and related methods are part of the sans-I/O design
//! // but may not be fully exposed in the current public API
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//! use std::time::Instant;
//!
//! let config = RTCConfigurationBuilder::new().build();
//! let mut peer_connection = RTCPeerConnection::new(config)?;
//!
//! loop {
//!     // Poll and handle events
//!     while let Some(event) = peer_connection.poll_event() {
//!         match event {
//!             RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
//!                 println!("New ICE candidate");
//!                 // Send candidate to remote peer via signaling
//!             }
//!             RTCPeerConnectionEvent::OnTrack(_track_event) => {
//!                 println!("New track received");
//!             }
//!             _ => {}
//!         }
//!     }
//!
//!     // Handle timeouts
//!     if let Some(timeout) = peer_connection.poll_timeout() {
//!         if timeout <= Instant::now() {
//!             peer_connection.handle_timeout(Instant::now())?;
//!         }
//!     }
//!     
//!     break; // Exit for example
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Handling connection state changes
//!
//! ```
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//! use rtc::peer_connection::state::RTCPeerConnectionState;
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
//!         match state {
//!             RTCPeerConnectionState::Connected => {
//!                 println!("Peer connection established!");
//!             }
//!             RTCPeerConnectionState::Failed => {
//!                 println!("Connection failed - cleanup required");
//!             }
//!             RTCPeerConnectionState::Disconnected => {
//!                 println!("Connection lost - may reconnect");
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Handling data channels
//!
//! ```
//! use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCDataChannelEvent};
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
//!         match dc_event {
//!             RTCDataChannelEvent::OnOpen(channel_id) => {
//!                 println!("Data channel opened: {:?}", channel_id);
//!             }
//!             RTCDataChannelEvent::OnClose(channel_id) => {
//!                 println!("Data channel closed: {:?}", channel_id);
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Handling incoming tracks
//!
//! ```
//! use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnTrack(track_event) => {
//!         match track_event {
//!             RTCTrackEvent::OnOpen(init) => {
//!                 println!("Track opened with receiver: {:?}", init.receiver_id);
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! # Event Types
//!
//! - **Negotiation**: [`OnNegotiationNeededEvent`](RTCPeerConnectionEvent::OnNegotiationNeededEvent) - Signals need for renegotiation
//! - **ICE**: [`OnIceCandidateEvent`](RTCPeerConnectionEvent::OnIceCandidateEvent) - New ICE candidate available
//! - **ICE Error**: [`OnIceCandidateErrorEvent`](RTCPeerConnectionEvent::OnIceCandidateErrorEvent) - ICE gathering error
//! - **State Changes**: Various state change events for signaling, ICE, and connection
//! - **Media**: [`OnTrack`](RTCPeerConnectionEvent::OnTrack) - Incoming media track
//! - **Data**: [`OnDataChannel`](RTCPeerConnectionEvent::OnDataChannel) - Incoming data channel
//!
//! # See Also
//!
//! - [W3C WebRTC Events](https://www.w3.org/TR/webrtc/#rtcpeerconnection-interface)
//! - [`RTCPeerConnection`](crate::peer_connection::RTCPeerConnection)

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
/// these events to respond to state changes, receive tracks, handle ICE candidates,
/// and manage the connection lifecycle.
///
/// # Event Categories
///
/// ## Negotiation Events
/// - [`OnNegotiationNeededEvent`](Self::OnNegotiationNeededEvent) - Triggered when SDP renegotiation is needed
///
/// ## ICE Events
/// - [`OnIceCandidateEvent`](Self::OnIceCandidateEvent) - New ICE candidate discovered
/// - [`OnIceCandidateErrorEvent`](Self::OnIceCandidateErrorEvent) - Error during ICE gathering
/// - [`OnIceConnectionStateChangeEvent`](Self::OnIceConnectionStateChangeEvent) - ICE connection state changed
/// - [`OnIceGatheringStateChangeEvent`](Self::OnIceGatheringStateChangeEvent) - ICE gathering state changed
///
/// ## State Change Events
/// - [`OnSignalingStateChangeEvent`](Self::OnSignalingStateChangeEvent) - Offer/answer state changed
/// - [`OnConnectionStateChangeEvent`](Self::OnConnectionStateChangeEvent) - Overall connection state changed
///
/// ## Media & Data Events
/// - [`OnTrack`](Self::OnTrack) - New incoming media track
/// - [`OnDataChannel`](Self::OnDataChannel) - New incoming data channel
///
/// # Examples
///
/// ## Pattern matching on events
///
/// ```
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
/// use rtc::peer_connection::state::RTCPeerConnectionState;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
///         match state {
///             RTCPeerConnectionState::Connected => {
///                 println!("Peer connection established!");
///             }
///             RTCPeerConnectionState::Failed => {
///                 println!("Connection failed");
///             }
///             _ => {}
///         }
///     }
///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
///         // Send candidate to remote peer
///         println!("ICE candidate: {:?}", ice_event.candidate);
///     }
///     RTCPeerConnectionEvent::OnTrack(track_event) => {
///         println!("New track received");
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specification
///
/// See [RTCPeerConnection Events](https://www.w3.org/TR/webrtc/#rtcpeerconnection-interface)
#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone, Debug)]
pub enum RTCPeerConnectionEvent {
    /// Fired when negotiation is needed to maintain the connection.
    ///
    /// This event indicates that renegotiation is needed, usually because:
    /// - Media tracks have been added or removed
    /// - Transceiver direction has changed
    /// - Data channels have been created
    ///
    /// When this event fires, the application should create a new offer
    /// by calling `create_offer()`, set it as the local description, and
    /// send it to the remote peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn example(event: RTCPeerConnectionEvent) {
    /// if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
    ///     println!("Negotiation needed - create new offer");
    ///     // Call peer_connection.create_offer()
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [negotiationneeded](https://www.w3.org/TR/webrtc/#event-negotiation)
    #[default]
    OnNegotiationNeededEvent,

    /// Fired when a new ICE candidate is available.
    ///
    /// This event provides an ICE candidate that should be sent to the remote peer
    /// over the signaling channel. The remote peer will use this candidate to
    /// establish connectivity.
    ///
    /// Candidates are generated during the ICE gathering process after
    /// `setLocalDescription` is called.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
    ///         // Send ice_event to remote peer via signaling
    ///         println!("Send ICE candidate: {}", ice_event.candidate.address);
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icecandidate](https://www.w3.org/TR/webrtc/#event-icecandidate)
    OnIceCandidateEvent(RTCPeerConnectionIceEvent),

    /// Fired when an error occurs during ICE candidate gathering.
    ///
    /// This event provides details about errors encountered while gathering
    /// ICE candidates, such as STUN/TURN server failures or network issues.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceCandidateErrorEvent(error) => {
    ///         eprintln!("ICE error: {} - {}", error.error_code, error.error_text);
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icecandidateerror](https://www.w3.org/TR/webrtc/#event-icecandidateerror)
    OnIceCandidateErrorEvent(RTCPeerConnectionIceErrorEvent),

    /// Fired when the signaling state changes.
    ///
    /// The signaling state describes where the peer connection is in the
    /// offer/answer negotiation process (stable, have-local-offer, etc.).
    ///
    /// # State Transitions
    ///
    /// - `Stable` → `HaveLocalOffer` (after creating offer)
    /// - `Stable` → `HaveRemoteOffer` (after receiving offer)
    /// - `HaveLocalOffer` → `Stable` (after receiving answer)
    /// - `HaveRemoteOffer` → `Stable` (after creating answer)
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
    ///         println!("Signaling state: {:?}", state);
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [signalingstatechange](https://www.w3.org/TR/webrtc/#event-signalingstatechange)
    OnSignalingStateChangeEvent(RTCSignalingState),

    /// Fired when the ICE connection state changes.
    ///
    /// This indicates the state of the ICE connection: new, checking, connected,
    /// completed, failed, disconnected, or closed.
    ///
    /// # Important States
    ///
    /// - `Connected` - ICE has successfully connected
    /// - `Completed` - ICE has finished gathering and checking
    /// - `Failed` - ICE has failed to connect
    /// - `Disconnected` - ICE connection lost (may recover)
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtc::peer_connection::state::RTCIceConnectionState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
    ///         match state {
    ///             RTCIceConnectionState::Connected => println!("ICE connected!"),
    ///             RTCIceConnectionState::Failed => println!("ICE failed"),
    ///             RTCIceConnectionState::Disconnected => println!("ICE disconnected"),
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [iceconnectionstatechange](https://www.w3.org/TR/webrtc/#event-iceconnectionstatechange)
    OnIceConnectionStateChangeEvent(RTCIceConnectionState),

    /// Fired when the ICE gathering state changes.
    ///
    /// This indicates whether ICE is gathering candidates, has completed
    /// gathering, or is in the initial state.
    ///
    /// # States
    ///
    /// - `New` - ICE gathering has not started
    /// - `Gathering` - ICE agent is gathering candidates
    /// - `Complete` - ICE gathering has finished
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtc::peer_connection::state::RTCIceGatheringState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) => {
    ///         if state == RTCIceGatheringState::Complete {
    ///             println!("ICE gathering complete");
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icegatheringstatechange](https://www.w3.org/TR/webrtc/#event-icegatheringstatechange)
    OnIceGatheringStateChangeEvent(RTCIceGatheringState),

    /// Fired when the peer connection state changes.
    ///
    /// This represents the overall connection state and is the recommended
    /// event to monitor for connection health. It aggregates ICE and DTLS states.
    ///
    /// # States
    ///
    /// - `New` - Initial state
    /// - `Connecting` - Establishing connection
    /// - `Connected` - Connection established and ready
    /// - `Disconnected` - Connection lost (may recover)
    /// - `Failed` - Connection failed permanently
    /// - `Closed` - Connection has been closed
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtc::peer_connection::state::RTCPeerConnectionState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) -> bool {
    /// match event {
    ///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
    ///         match state {
    ///             RTCPeerConnectionState::Connected => {
    ///                 println!("Peer connection ready!");
    ///             }
    ///             RTCPeerConnectionState::Failed => {
    ///                 println!("Connection failed - cleanup");
    ///                 return false; // Exit event loop
    ///             }
    ///             RTCPeerConnectionState::Disconnected => {
    ///                 println!("Connection lost - may reconnect");
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # true
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [connectionstatechange](https://www.w3.org/TR/webrtc/#event-connectionstatechange)
    OnConnectionStateChangeEvent(RTCPeerConnectionState),

    /// Fired when a new data channel is received from the remote peer.
    ///
    /// This event is triggered when the remote peer creates a data channel.
    /// The application should handle the data channel events (OnOpen, OnMessage, etc.)
    /// by polling and matching on the channel ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCDataChannelEvent};
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
    ///         match dc_event {
    ///             RTCDataChannelEvent::OnOpen(channel_id) => {
    ///                 println!("New data channel: {:?}", channel_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [datachannel](https://www.w3.org/TR/webrtc/#event-datachannel)
    OnDataChannel(RTCDataChannelEvent),

    /// Fired when a new media track is received from the remote peer.
    ///
    /// This event provides access to the incoming media stream. The event includes
    /// the track ID, receiver ID, transceiver ID, and associated stream IDs.
    /// Use these IDs to access the actual objects via the peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnTrack(track_event) => {
    ///         match track_event {
    ///             RTCTrackEvent::OnOpen(init) => {
    ///                 println!("New track with receiver: {:?}", init.receiver_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [track](https://www.w3.org/TR/webrtc/#event-track)
    OnTrack(RTCTrackEvent),
}

/// Reserved for future use.
///
/// This enum is currently empty but reserved for potential future event types.
#[derive(Debug, Clone)]
pub enum RTCEvent {}

/// Internal event types for WebRTC implementation.
///
/// These events are used internally by the WebRTC stack to coordinate between
/// different components (ICE, DTLS, SCTP). They are not exposed to the public API.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RTCEventInternal {
    /// Public RTC event (currently unused)
    RTCEvent(RTCEvent),

    /// Public peer connection event
    RTCPeerConnectionEvent(RTCPeerConnectionEvent),

    /// ICE selected candidate pair has changed
    ICESelectedCandidatePairChange,

    /// DTLS handshake completed successfully
    ///
    /// Parameters:
    /// - Remote socket address
    /// - Optional SRTP context (send)
    /// - Optional SRTCP context (receive)
    DTLSHandshakeComplete(SocketAddr, Option<Context>, Option<Context>),

    /// SCTP handshake completed successfully
    ///
    /// Parameter: Association handle
    SCTPHandshakeComplete(usize /*AssociationHandle*/),

    /// SCTP stream has been closed
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    SCTPStreamClosed(usize /*AssociationHandle*/, u16 /*StreamID*/),
}
