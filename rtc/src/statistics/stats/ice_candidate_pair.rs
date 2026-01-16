use super::RTCStats;
use ::serde::{Deserialize, Serialize};
use ice::candidate::candidate_pair::CandidatePairState;
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

impl From<CandidatePairState> for RTCStatsIceCandidatePairState {
    fn from(state: CandidatePairState) -> Self {
        match state {
            CandidatePairState::Unspecified => RTCStatsIceCandidatePairState::Unspecified,
            CandidatePairState::Waiting => RTCStatsIceCandidatePairState::Waiting,
            CandidatePairState::InProgress => RTCStatsIceCandidatePairState::InProgress,
            CandidatePairState::Failed => RTCStatsIceCandidatePairState::Failed,
            CandidatePairState::Succeeded => RTCStatsIceCandidatePairState::Succeeded,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidatePairStats {
    /// General Stats Fields
    pub stats: RTCStats,

    /// The transport ID this candidate belongs to.
    pub transport_id: String,

    /// Reference to the local candidate ID.
    pub local_candidate_id: String,
    /// Reference to the remote candidate ID.
    pub remote_candidate_id: String,

    // Packet/byte counters - incremented during handle_read/handle_write
    /// Total packets sent through this pair.
    pub packets_sent: u64,
    /// Total packets received through this pair.
    pub packets_received: u64,
    /// Total bytes sent through this pair.
    pub bytes_sent: u64,
    /// Total bytes received through this pair.
    pub bytes_received: u64,

    // Timestamps for last activity
    /// Timestamp of the last packet sent.
    #[serde(with = "instant_to_epoch")]
    pub last_packet_sent_timestamp: Instant,
    /// Timestamp of the last packet received.
    #[serde(with = "instant_to_epoch")]
    pub last_packet_received_timestamp: Instant,

    // RTT tracking (updated from STUN responses)
    /// Total accumulated round trip time in seconds.
    pub total_round_trip_time: f64,
    /// Most recent round trip time measurement in seconds.
    pub current_round_trip_time: f64,

    // Request/response counters
    /// Number of STUN connectivity check requests sent.
    pub requests_sent: u64,
    /// Number of STUN connectivity check requests received.
    pub requests_received: u64,
    /// Number of STUN connectivity check responses sent.
    pub responses_sent: u64,
    /// Number of STUN connectivity check responses received.
    pub responses_received: u64,
    /// Number of ICE consent freshness requests sent.
    pub consent_requests_sent: u64,

    // Discard counters
    /// Packets discarded due to send failure.
    pub packets_discarded_on_send: u32,
    /// Bytes discarded due to send failure.
    pub bytes_discarded_on_send: u32,

    // Bitrate estimation (from TWCC/congestion control)
    /// Estimated available outgoing bitrate in bits per second.
    pub available_outgoing_bitrate: f64,
    /// Estimated available incoming bitrate in bits per second.
    pub available_incoming_bitrate: f64,

    // State
    /// Current state of the candidate pair.
    pub state: RTCStatsIceCandidatePairState,
    /// Whether this pair has been nominated.
    pub nominated: bool,
}
