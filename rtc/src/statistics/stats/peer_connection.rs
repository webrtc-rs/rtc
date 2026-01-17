//! Peer connection statistics.
//!
//! This module contains the [`RTCPeerConnectionStats`] type which provides
//! information about the peer connection as a whole.

use super::RTCStats;
use serde::{Deserialize, Serialize};

/// Statistics for the peer connection.
///
/// This struct corresponds to the `RTCPeerConnectionStats` dictionary in the
/// W3C WebRTC Statistics API. It provides aggregate statistics about the
/// peer connection.
///
/// # W3C Reference
///
/// See [RTCPeerConnectionStats](https://www.w3.org/TR/webrtc-stats/#pcstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCPeerConnectionStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// Total number of data channels that have been opened.
    ///
    /// This includes data channels that are currently open and
    /// data channels that have been closed.
    pub data_channels_opened: u32,

    /// Total number of data channels that have been closed.
    pub data_channels_closed: u32,
}
