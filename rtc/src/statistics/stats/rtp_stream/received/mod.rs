use super::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

pub mod inbound;
pub mod remote_inbound;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCReceivedRtpStreamStats {
    #[serde(flatten)]
    pub rtp_stream_stats: RTCRtpStreamStats,

    pub packets_received: u64,
    pub packets_received_with_ect1: u64,
    pub packets_received_with_ce: u64,
    pub packets_reported_as_lost: u64,
    pub packets_reported_as_lost_but_recovered: u64,
    pub packets_lost: i64,
    pub jitter: f64,
}
