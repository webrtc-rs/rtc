use super::super::RTCStats;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCAudioPlayoutStats {
    /// General Stats Fields
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The media kind (always Audio for this type).
    pub kind: RtpCodecKind,
    /// Duration of synthesized samples in seconds.
    pub synthesized_samples_duration: f64,
    /// Number of sample synthesis events.
    pub synthesized_samples_events: u32,
    /// Total duration of samples played in seconds.
    pub total_samples_duration: f64,
    /// Total playout delay in seconds.
    pub total_playout_delay: f64,
    /// Total number of samples played.
    pub total_samples_count: u64,
}
