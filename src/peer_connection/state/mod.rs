//! WebRTC connection state types.
//!
//! This module provides enums representing the various states of a WebRTC peer
//! connection, including ICE connectivity, candidate gathering, overall connection
//! status, and SDP signaling progress.
//!
//! # Overview
//!
//! WebRTC connections have multiple independent state machines that track different
//! aspects of the connection lifecycle:
//!
//! - **[`RTCIceConnectionState`]** - ICE transport connectivity (new, checking, connected, etc.)
//! - **[`RTCIceGatheringState`]** - ICE candidate gathering progress (new, gathering, complete)
//! - **[`RTCPeerConnectionState`]** - Overall connection state (new, connecting, connected, etc.)
//! - **[`RTCSignalingState`]** - SDP offer/answer negotiation progress (stable, have-local-offer, etc.)
//!
//! # State Monitoring Pattern
//!
//! In this sans-I/O library, states are monitored by polling events and checking
//! state transitions rather than registering callbacks.
//!
//! # Examples
//!
//! ## Monitoring ICE Connection State
//!
//! ```no_run
//! use rtc::peer_connection::state::RTCIceConnectionState;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//!
//! # fn example(event: RTCPeerConnectionEvent) {
//! // Handle ICE connection state change event
//! match event {
//!     RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
//!         match state {
//!             RTCIceConnectionState::New => println!("ICE starting"),
//!             RTCIceConnectionState::Checking => println!("ICE checking connectivity"),
//!             RTCIceConnectionState::Connected => println!("ICE connected!"),
//!             RTCIceConnectionState::Completed => println!("ICE completed"),
//!             RTCIceConnectionState::Disconnected => println!("ICE disconnected"),
//!             RTCIceConnectionState::Failed => println!("ICE failed"),
//!             RTCIceConnectionState::Closed => println!("ICE closed"),
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Monitoring Candidate Gathering
//!
//! ```no_run
//! use rtc::peer_connection::state::RTCIceGatheringState;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//!
//! # fn example(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) => {
//!         match state {
//!             RTCIceGatheringState::New => println!("Gathering not started"),
//!             RTCIceGatheringState::Gathering => println!("Gathering candidates..."),
//!             RTCIceGatheringState::Complete => {
//!                 println!("All candidates gathered - ready to send offer/answer");
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Checking Overall Connection State
//!
//! ```no_run
//! use rtc::peer_connection::state::RTCPeerConnectionState;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//!
//! # fn example(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
//!         match state {
//!             RTCPeerConnectionState::New => println!("Connection initializing"),
//!             RTCPeerConnectionState::Connecting => println!("Connection in progress"),
//!             RTCPeerConnectionState::Connected => {
//!                 println!("Connection established - media can flow");
//!             }
//!             RTCPeerConnectionState::Disconnected => {
//!                 println!("Connection lost - attempting to reconnect");
//!             }
//!             RTCPeerConnectionState::Failed => println!("Connection failed permanently"),
//!             RTCPeerConnectionState::Closed => println!("Connection closed"),
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Tracking Signaling State
//!
//! ```no_run
//! use rtc::peer_connection::state::RTCSignalingState;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//!
//! # fn example(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
//!         match state {
//!             RTCSignalingState::Stable => println!("Ready for new negotiation"),
//!             RTCSignalingState::HaveLocalOffer => {
//!                 println!("Local offer set - waiting for answer");
//!             }
//!             RTCSignalingState::HaveRemoteOffer => {
//!                 println!("Remote offer received - need to send answer");
//!             }
//!             RTCSignalingState::HaveLocalPranswer => {
//!                 println!("Provisional answer sent");
//!             }
//!             RTCSignalingState::HaveRemotePranswer => {
//!                 println!("Provisional answer received");
//!             }
//!             RTCSignalingState::Closed => println!("Signaling closed"),
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## State Transitions and String Conversion
//!
//! ```
//! use rtc::peer_connection::state::{
//!     RTCIceConnectionState, RTCPeerConnectionState, RTCSignalingState
//! };
//!
//! // Convert to string
//! let state = RTCIceConnectionState::Connected;
//! assert_eq!(state.to_string(), "connected");
//!
//! // Parse from string
//! let state: RTCPeerConnectionState = "connecting".into();
//! assert_eq!(state, RTCPeerConnectionState::Connecting);
//!
//! // Parse signaling state
//! let state: RTCSignalingState = "have-local-offer".into();
//! assert_eq!(state, RTCSignalingState::HaveLocalOffer);
//! ```
//!
//! # State Machine Details
//!
//! ## ICE Connection States
//!
//! The ICE connection state progresses through these typical transitions:
//!
//! ```text
//! New → Checking → Connected → Completed
//!   ↓       ↓          ↓
//!   ↓       ↓          ↓
//!   ↓       ↓      Disconnected → Failed
//!   ↓       ↓          ↓           ↓
//!   └───────┴──────────┴───────────┴→ Closed
//! ```
//!
//! ## ICE Gathering States
//!
//! ```text
//! New → Gathering → Complete
//! ```
//!
//! ## Signaling States (Offer/Answer)
//!
//! Successful negotiation (typical flow):
//!
//! ```text
//! Stable → HaveLocalOffer → Stable
//!   or
//! Stable → HaveRemoteOffer → Stable
//! ```
//!
//! With provisional answers:
//!
//! ```text
//! Stable → HaveLocalOffer → HaveRemotePranswer → Stable
//!   or
//! Stable → HaveRemoteOffer → HaveLocalPranswer → Stable
//! ```
//!
//! # Specifications
//!
//! - [W3C WebRTC Specification]
//! - [RFC 8445] - ICE: Interactive Connectivity Establishment
//! - [RFC 5245] - ICE (obsoleted by RFC 8445)
//!
//! [W3C WebRTC Specification]: https://w3c.github.io/webrtc-pc/
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 5245]: https://datatracker.ietf.org/doc/html/rfc5245

pub(crate) mod ice_connection_state;
pub(crate) mod ice_gathering_state;
pub(crate) mod peer_connection_state;
pub(crate) mod signaling_state;

pub use ice_connection_state::RTCIceConnectionState;
pub use ice_gathering_state::RTCIceGatheringState;
pub use peer_connection_state::RTCPeerConnectionState;
pub use signaling_state::RTCSignalingState;
