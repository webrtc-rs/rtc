use crate::rtp_transceiver::PayloadType;
use crate::stats::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCCodecStats {
    pub stats: RTCStats,

    pub payload_type: PayloadType,
    pub mime_type: String,
    pub channels: u16,
    pub clock_rate: u32,
    pub sdp_fmtp_line: String,
}
