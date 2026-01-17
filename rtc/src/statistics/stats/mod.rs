//! WebRTC Statistics API types.
//!
//! This module contains the W3C WebRTC Statistics API types as defined in
//! the [WebRTC Statistics API specification](https://www.w3.org/TR/webrtc-stats/).
//!
//! These types are returned by [`RTCPeerConnection::get_stats()`](crate::peer_connection::RTCPeerConnection::get_stats)
//! and provide detailed information about the WebRTC connection, including:
//!
//! - Transport statistics (ICE, DTLS)
//! - RTP stream statistics (inbound/outbound)
//! - Data channel statistics
//! - Codec information
//! - ICE candidate information
//!
//! # Example
//!
//! ```ignore
//! use std::time::Instant;
//!
//! let report = peer_connection.get_stats(Instant::now());
//!
//! // Access transport statistics
//! if let Some(transport) = report.transport() {
//!     println!("Bytes sent: {}", transport.bytes_sent);
//!     println!("Bytes received: {}", transport.bytes_received);
//! }
//!
//! // Iterate over data channels
//! for dc in report.data_channels() {
//!     println!("Channel '{}': {} messages sent", dc.label, dc.messages_sent);
//! }
//! ```

use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

pub mod certificate;
pub mod codec;
pub mod data_channel;
pub mod ice_candidate;
pub mod ice_candidate_pair;
pub mod media;
pub mod peer_connection;
pub mod rtp_stream;
pub mod transport;

/// The type of a statistics object.
///
/// This enum corresponds to the `RTCStatsType` enum in the W3C WebRTC Statistics API.
/// Each variant represents a different category of statistics that can be collected.
///
/// # Serialization
///
/// Values are serialized using the W3C-specified lowercase hyphenated format
/// (e.g., `InboundRTP` serializes to `"inbound-rtp"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTCStatsType {
    /// Statistics for a media codec.
    #[serde(rename = "codec")]
    Codec,
    /// Statistics for an inbound RTP stream.
    #[serde(rename = "inbound-rtp")]
    InboundRTP,
    /// Statistics for an outbound RTP stream.
    #[serde(rename = "outbound-rtp")]
    OutboundRTP,
    /// Statistics for an inbound RTP stream from the remote peer's perspective.
    #[serde(rename = "remote-inbound-rtp")]
    RemoteInboundRTP,
    /// Statistics for an outbound RTP stream from the remote peer's perspective.
    #[serde(rename = "remote-outbound-rtp")]
    RemoteOutboundRTP,
    /// Statistics for a media source (audio or video).
    #[serde(rename = "media-source")]
    MediaSource,
    /// Statistics for audio playout.
    #[serde(rename = "media-playout")]
    MediaPlayout,
    /// Statistics for the peer connection.
    #[serde(rename = "peer-connection")]
    PeerConnection,
    /// Statistics for a data channel.
    #[serde(rename = "data-channel")]
    DataChannel,
    /// Statistics for the transport layer.
    #[serde(rename = "transport")]
    Transport,
    /// Statistics for an ICE candidate pair.
    #[serde(rename = "candidate-pair")]
    CandidatePair,
    /// Statistics for a local ICE candidate.
    #[serde(rename = "local-candidate")]
    LocalCandidate,
    /// Statistics for a remote ICE candidate.
    #[serde(rename = "remote-candidate")]
    RemoteCandidate,
    /// Statistics for a certificate.
    #[serde(rename = "certificate")]
    Certificate,
}

/// The unique identifier for a statistics object.
///
/// Each statistics object has a unique ID that can be used to look up
/// the object in the statistics report or to reference it from other
/// statistics objects.
pub type RTCStatsId = String;

/// Base statistics fields common to all statistics objects.
///
/// This struct is embedded (via `#[serde(flatten)]`) in all specific
/// statistics types and provides the common fields required by the
/// W3C WebRTC Statistics API.
///
/// # JSON Serialization
///
/// The `timestamp` field is serialized as milliseconds since the Unix epoch,
/// and `typ` is serialized as `"type"` with the W3C-specified string value.
#[derive(Debug, Serialize, Deserialize)]
pub struct RTCStats {
    /// The timestamp when this statistics object was generated.
    ///
    /// Serialized as milliseconds since the Unix epoch for W3C compatibility.
    #[serde(with = "instant_to_epoch")]
    pub timestamp: Instant,

    /// The type of this statistics object.
    #[serde(rename = "type")]
    pub typ: RTCStatsType,

    /// The unique identifier for this statistics object.
    pub id: RTCStatsId,
}

/// The reason for quality limitation in video encoding.
///
/// This enum indicates why the video encoder may have reduced quality
/// (resolution, frame rate, or bitrate) during encoding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTCQualityLimitationReason {
    /// No quality limitation is active.
    #[default]
    #[serde(rename = "none")]
    None,
    /// Quality is limited due to CPU constraints.
    #[serde(rename = "cpu")]
    Cpu,
    /// Quality is limited due to bandwidth constraints.
    #[serde(rename = "bandwidth")]
    Bandwidth,
    /// Quality is limited for another reason.
    #[serde(rename = "other")]
    Other,
}
