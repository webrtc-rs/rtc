//! ICE candidate pair statistics.
//!
//! This module contains the [`RTCIceCandidatePairStats`] type which provides
//! information about ICE candidate pairs used for connectivity checks.

use super::RTCStats;
use ::serde::{Deserialize, Serialize};
use ice::candidate::candidate_pair::CandidatePairState;
use shared::serde::instant_to_epoch;
use std::time::Instant;

/// The state of an ICE candidate pair.
///
/// This enum represents the current state of a candidate pair
/// in the ICE connectivity check process.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum RTCStatsIceCandidatePairState {
    /// State has not been set.
    #[default]
    Unspecified,

    /// Connectivity checks have not started for this pair.
    #[serde(rename = "frozen")]
    Frozen,

    /// Connectivity checks are waiting to be performed.
    #[serde(rename = "waiting")]
    Waiting,

    /// Connectivity checks are in progress.
    #[serde(rename = "in-progress")]
    InProgress,

    /// Connectivity checks have failed for this pair.
    #[serde(rename = "failed")]
    Failed,

    /// Connectivity checks have succeeded for this pair.
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

/// Statistics for an ICE candidate pair.
///
/// This struct corresponds to the `RTCIceCandidatePairStats` dictionary in the
/// W3C WebRTC Statistics API. It provides detailed information about
/// connectivity checks and data transfer for a specific candidate pair.
///
/// # W3C Reference
///
/// See [RTCIceCandidatePairStats](https://www.w3.org/TR/webrtc-stats/#candidatepair-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidatePairStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The ID of the transport this candidate pair belongs to.
    pub transport_id: String,

    /// The ID of the local candidate in this pair.
    pub local_candidate_id: String,

    /// The ID of the remote candidate in this pair.
    pub remote_candidate_id: String,

    /// Total number of packets sent using this candidate pair.
    pub packets_sent: u64,

    /// Total number of packets received using this candidate pair.
    pub packets_received: u64,

    /// Total number of bytes sent using this candidate pair.
    pub bytes_sent: u64,

    /// Total number of bytes received using this candidate pair.
    pub bytes_received: u64,

    /// Timestamp of the last packet sent using this candidate pair.
    #[serde(with = "instant_to_epoch")]
    pub last_packet_sent_timestamp: Instant,

    /// Timestamp of the last packet received using this candidate pair.
    #[serde(with = "instant_to_epoch")]
    pub last_packet_received_timestamp: Instant,

    /// Total round trip time in seconds for all STUN requests.
    ///
    /// Divide by `responses_received` to get the average RTT.
    pub total_round_trip_time: f64,

    /// The most recent round trip time measurement in seconds.
    pub current_round_trip_time: f64,

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

    /// Number of packets discarded due to send errors.
    pub packets_discarded_on_send: u32,

    /// Number of bytes discarded due to send errors.
    pub bytes_discarded_on_send: u32,

    /// Estimated available outgoing bitrate in bits per second.
    ///
    /// Calculated using congestion control feedback.
    pub available_outgoing_bitrate: f64,

    /// Estimated available incoming bitrate in bits per second.
    ///
    /// Calculated using congestion control feedback.
    pub available_incoming_bitrate: f64,

    /// Current state of the candidate pair.
    pub state: RTCStatsIceCandidatePairState,

    /// Whether this candidate pair has been nominated.
    ///
    /// A nominated pair is one that has been selected for use
    /// by the ICE controlling agent.
    pub nominated: bool,
}
