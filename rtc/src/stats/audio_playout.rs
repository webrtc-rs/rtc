use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::stats::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCAudioPlayoutStats {
    pub stats: RTCStats,

    pub kind: RtpCodecKind,
    pub synthesized_samples_duration: f64,
    pub synthesized_samples_events: u32,
    pub total_samples_duration: f64,
    pub total_playout_delay: f64,
    pub total_samples_count: u64,
}
