//! Data channel statistics.
//!
//! This module contains the [`RTCDataChannelStats`] type which provides
//! information about data channels.

use super::RTCStats;
use crate::data_channel::RTCDataChannelState;
use serde::{Deserialize, Serialize};

/// Statistics for a data channel.
///
/// This struct corresponds to the `RTCDataChannelStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about a data channel,
/// including message and byte counters.
///
/// # W3C Reference
///
/// See [RTCDataChannelStats](https://www.w3.org/TR/webrtc-stats/#dcstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCDataChannelStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The data channel identifier.
    ///
    /// This is the SCTP stream ID used for this data channel.
    pub data_channel_identifier: u16,

    /// The label assigned to the data channel.
    ///
    /// This is the label specified when creating the data channel.
    pub label: String,

    /// The sub-protocol negotiated for this data channel.
    ///
    /// Empty string if no protocol was specified.
    pub protocol: String,

    /// The current state of the data channel.
    pub state: RTCDataChannelState,

    /// Total number of messages sent on this data channel.
    pub messages_sent: u32,

    /// Total number of bytes sent on this data channel.
    ///
    /// This counts application data bytes, not including any protocol overhead.
    pub bytes_sent: u64,

    /// Total number of messages received on this data channel.
    pub messages_received: u32,

    /// Total number of bytes received on this data channel.
    ///
    /// This counts application data bytes, not including any protocol overhead.
    pub bytes_received: u64,
}
