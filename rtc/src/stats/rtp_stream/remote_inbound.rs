use crate::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteInboundRtpStreamStats {
    pub received_rtp_stream_stats: RTCReceivedRtpStreamStats,

    pub local_id: String,
    pub round_trip_time: f64,
    pub total_round_trip_time: f64,
    pub fraction_lost: f64,
    pub round_trip_time_measurements: u64,
    pub packets_with_bleached_ect1_marking: u64,
}
