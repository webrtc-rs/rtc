use crate::stats::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCPeerConnectionStats {
    pub stats: RTCStats,

    pub data_channels_opened: u32,
    pub data_channels_closed: u32,
}
