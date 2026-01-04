//! # RTC - Sans-I/O WebRTC Implementation
//!
//! A Rust implementation of the [WebRTC specification](https://www.w3.org/TR/webrtc/) using a sans-I/O architecture.
//!
//! This crate provides a WebRTC peer connection implementation that follows the W3C WebRTC standard.
//! The sans-I/O design separates protocol logic from I/O operations, giving you full control over
//! networking, threading, and async runtime integration.
//!
//! ## Features
//!
//! - **Sans-I/O Architecture**: Complete separation of protocol logic and I/O
//! - **W3C Compliant**: Follows the official WebRTC specification
//! - **Full WebRTC Support**: Peer connections, data channels, media tracks, and transceivers
//! - **Flexible Integration**: Use with any async runtime or threading model
//!
//! ## Example
//!
//! ```no_run
//! use rtc::peer_connection::{RTCPeerConnection, configuration::RTCConfiguration};
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a peer connection
//! let config = RTCConfiguration::default();
//! let mut pc = RTCPeerConnection::new(config)?;
//!
//! // Create an offer
//! let offer = pc.create_offer(None)?;
//! pc.set_local_description(offer)?;
//!
//! // Handle events in your event loop
//! loop {
//!     // Poll for events
//!     // Handle RTCPeerConnectionEvent variants
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Core Types
//!
//! - [`RTCPeerConnection`](peer_connection::RTCPeerConnection): The main peer connection interface
//! - [`RTCPeerConnectionEvent`](peer_connection::event::RTCPeerConnectionEvent): Events emitted by the peer connection
//! - [`RTCDataChannel`](data_channel::RTCDataChannel): WebRTC data channels for arbitrary data transfer
//! - [`MediaStreamTrack`](media_stream::track::MediaStreamTrack): Media tracks for audio/video
//!
//! ## Specification Compliance
//!
//! This implementation follows the [W3C WebRTC 1.0 specification](https://www.w3.org/TR/webrtc/).

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub use {
    datachannel, dtls, ice, interceptor, mdns, media, rtcp, rtp, sansio, sctp, sdp, shared, srtp,
    stun, turn,
};

pub mod data_channel;
pub mod media_stream;
pub mod peer_connection;
pub mod rtp_transceiver;
pub mod statistics;
