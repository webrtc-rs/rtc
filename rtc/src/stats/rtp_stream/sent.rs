use crate::stats::rtp_stream::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCSentRtpStreamStats {
    pub rtp_stream_stats: RTCRtpStreamStats,

    pub packets_sent: u64,
    pub bytes_sent: u64,
}
