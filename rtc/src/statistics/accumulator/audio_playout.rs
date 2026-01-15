//! Audio playout statistics accumulator.

use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::stats::audio_playout::RTCAudioPlayoutStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated audio playout statistics.
///
/// This struct holds audio playout information that is primarily provided
/// by the application, since sansio doesn't handle audio decoding/playback.
#[derive(Debug, Default)]
pub struct AudioPlayoutStatsAccumulator {
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

impl AudioPlayoutStatsAccumulator {
    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCAudioPlayoutStats {
        RTCAudioPlayoutStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::MediaPlayout,
                id: id.to_string(),
            },
            kind: self.kind,
            synthesized_samples_duration: self.synthesized_samples_duration,
            synthesized_samples_events: self.synthesized_samples_events,
            total_samples_duration: self.total_samples_duration,
            total_playout_delay: self.total_playout_delay,
            total_samples_count: self.total_samples_count,
        }
    }
}
