//! Audio source statistics.
//!
//! This module contains the [`RTCAudioSourceStats`] type which provides
//! information about audio capture sources.

use super::media_source::RTCMediaSourceStats;
use serde::{Deserialize, Serialize};

/// Statistics for an audio source.
///
/// This struct corresponds to the `RTCAudioSourceStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about the audio
/// capture source, including audio levels and echo cancellation metrics.
///
/// # W3C Reference
///
/// See [RTCAudioSourceStats](https://www.w3.org/TR/webrtc-stats/#audiosourcestats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCAudioSourceStats {
    /// Base media source statistics.
    #[serde(flatten)]
    pub media_source_stats: RTCMediaSourceStats,

    /// The current audio level (0.0 to 1.0).
    ///
    /// This is an instantaneous measurement of the audio signal level.
    pub audio_level: f64,

    /// Total audio energy in the signal.
    ///
    /// This is the sum of squared audio levels over time.
    pub total_audio_energy: f64,

    /// Total duration of captured audio samples in seconds.
    pub total_samples_duration: f64,

    /// Echo return loss in decibels.
    ///
    /// Measures how much the acoustic echo is attenuated.
    /// Higher values indicate better echo cancellation.
    pub echo_return_loss: f64,

    /// Echo return loss enhancement in decibels.
    ///
    /// Measures the improvement provided by the echo canceller.
    pub echo_return_loss_enhancement: f64,
}
