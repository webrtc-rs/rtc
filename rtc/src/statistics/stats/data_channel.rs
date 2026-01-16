use super::RTCStats;
use crate::data_channel::RTCDataChannelState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCDataChannelStats {
    /// General Stats Fields
    pub stats: RTCStats,

    /// The data channel identifier.
    pub data_channel_identifier: u16,
    /// The label assigned to the data channel.
    pub label: String,
    /// The sub-protocol name.
    pub protocol: String,
    /// The current state of the data channel.
    pub state: RTCDataChannelState,

    // Message/byte counters
    /// Total messages sent through the data channel.
    pub messages_sent: u32,
    /// Total bytes sent through the data channel.
    pub bytes_sent: u64,
    /// Total messages received through the data channel.
    pub messages_received: u32,
    /// Total bytes received through the data channel.
    pub bytes_received: u64,
}
