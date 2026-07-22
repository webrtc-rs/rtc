//! Audio playout statistics.
//!
//! This module contains the [`RTCAudioPlayoutStats`] type which provides
//! information about audio playout devices.

use super::super::RTCStats;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

/// Statistics for audio playout.
///
/// This struct corresponds to the `RTCAudioPlayoutStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about audio playout
/// devices, including synthesized samples for concealment and playout delay.
///
/// # W3C Reference
///
/// See [RTCAudioPlayoutStats](https://www.w3.org/TR/webrtc-stats/#playoutstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCAudioPlayoutStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The media kind (always `Audio` for this type).
    pub kind: RtpCodecKind,

    /// Duration of synthesized samples in seconds.
    ///
    /// Synthesized samples are generated to fill gaps when
    /// packets are lost or delayed.
    pub synthesized_samples_duration: f64,

    /// Number of sample synthesis events.
    ///
    /// Each event represents a gap that required sample synthesis.
    pub synthesized_samples_events: u32,

    /// Total duration of samples played in seconds.
    pub total_samples_duration: f64,

    /// Total playout delay in seconds.
    ///
    /// The accumulated delay from the jitter buffer.
    pub total_playout_delay: f64,

    /// Total number of samples played.
    pub total_samples_count: u64,
}
