use super::RTCStats;
use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum RTCStatsIceCandidatePairState {
    #[default]
    Unspecified,

    #[serde(rename = "frozen")]
    Frozen,
    #[serde(rename = "waiting")]
    Waiting,
    #[serde(rename = "in-progress")]
    InProgress,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "succeeded")]
    Succeeded,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidatePairStats {
    /// General Stats Fields
    pub stats: RTCStats,

    pub transport_id: String,
    pub local_candidate_id: String,
    pub remote_candidate_id: String,
    pub state: RTCStatsIceCandidatePairState,
    pub nominated: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(with = "instant_to_epoch")]
    pub last_packet_sent_timestamp: Instant,
    #[serde(with = "instant_to_epoch")]
    pub last_packet_received_timestamp: Instant,
    pub total_round_trip_time: f64,
    pub current_round_trip_time: f64,
    pub available_outgoing_bitrate: f64,
    pub available_incoming_bitrate: f64,
    pub requests_received: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
    pub responses_sent: u64,
    pub consent_requests_sent: u64,
    pub packets_discarded_on_send: u32,
    pub bytes_discarded_on_send: u32,
}
