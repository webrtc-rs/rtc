//! Media source statistics accumulator.

use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::stats::media::audio_source::RTCAudioSourceStats;
use crate::statistics::stats::media::media_source::RTCMediaSourceStats;
use crate::statistics::stats::media::video_source::RTCVideoSourceStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated media source statistics.
///
/// This struct holds media source information that is primarily provided
/// by the application, since sansio doesn't handle media capture.
#[derive(Debug, Default)]
pub struct MediaSourceStatsAccumulator {
    /// The track identifier from the MediaStreamTrack.
    pub track_id: String,
    /// The media kind (audio/video).
    pub kind: RtpCodecKind,

    // Audio-specific (from application)
    /// Current audio level (0.0 - 1.0).
    pub audio_level: Option<f64>,
    /// Total audio energy in joules.
    pub total_audio_energy: Option<f64>,
    /// Total duration of audio samples in seconds.
    pub total_samples_duration: Option<f64>,
    /// Echo return loss in decibels.
    pub echo_return_loss: Option<f64>,
    /// Echo return loss enhancement in decibels.
    pub echo_return_loss_enhancement: Option<f64>,

    // Video-specific (from application)
    /// Video frame width.
    pub width: Option<u32>,
    /// Video frame height.
    pub height: Option<u32>,
    /// Total frames captured.
    pub frames: Option<u32>,
    /// Current frame rate.
    pub frames_per_second: Option<f64>,
}

impl MediaSourceStatsAccumulator {
    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCMediaSourceStats {
        RTCMediaSourceStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::MediaSource,
                id: id.to_string(),
            },
            track_id: self.track_id.clone(),
            kind: self.kind,
        }
    }

    /// Creates an audio source stats snapshot.
    pub fn snapshot_audio(&self, now: Instant, id: &str) -> RTCAudioSourceStats {
        RTCAudioSourceStats {
            media_source_stats: self.snapshot(now, id),
            audio_level: self.audio_level.unwrap_or(0.0),
            total_audio_energy: self.total_audio_energy.unwrap_or(0.0),
            total_samples_duration: self.total_samples_duration.unwrap_or(0.0),
            echo_return_loss: self.echo_return_loss.unwrap_or(0.0),
            echo_return_loss_enhancement: self.echo_return_loss_enhancement.unwrap_or(0.0),
        }
    }

    /// Creates a video source stats snapshot.
    pub fn snapshot_video(&self, now: Instant, id: &str) -> RTCVideoSourceStats {
        RTCVideoSourceStats {
            media_source_stats: self.snapshot(now, id),
            width: self.width.unwrap_or(0),
            height: self.height.unwrap_or(0),
            frames: self.frames.unwrap_or(0),
            frames_per_second: self.frames_per_second.unwrap_or(0.0),
        }
    }
}
