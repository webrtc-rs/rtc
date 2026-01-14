use crate::data_channel::RTCDataChannelState;
use crate::stats::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCDataChannelStats {
    pub stats: RTCStats,

    pub label: String,
    pub protocol: String,
    pub data_channel_identifier: u16,
    pub state: RTCDataChannelState,
    pub messages_sent: u32,
    pub bytes_sent: u64,
    pub messages_received: u32,
    pub bytes_received: u64,
}
