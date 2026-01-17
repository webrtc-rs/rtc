use super::RTCSentRtpStreamStats;
use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteOutboundRtpStreamStats {
    #[serde(flatten)]
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    pub local_id: String,
    #[serde(with = "instant_to_epoch")]
    pub remote_timestamp: Instant,
    pub reports_sent: u64,
    pub round_trip_time: f64,
    pub total_round_trip_time: f64,
    pub round_trip_time_measurements: u64,
}
