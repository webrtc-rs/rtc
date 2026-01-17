use super::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

pub mod outbound;
pub mod remote_outbound;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCSentRtpStreamStats {
    #[serde(flatten)]
    pub rtp_stream_stats: RTCRtpStreamStats,

    pub packets_sent: u64,
    pub bytes_sent: u64,
}
