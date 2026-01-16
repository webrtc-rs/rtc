use super::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCPeerConnectionStats {
    /// General Stats Fields
    pub stats: RTCStats,

    /// Total number of data channels opened.
    pub data_channels_opened: u32,
    /// Total number of data channels closed.
    pub data_channels_closed: u32,
}
