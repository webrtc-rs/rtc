//! Video source statistics.
//!
//! This module contains the [`RTCVideoSourceStats`] type which provides
//! information about video capture sources.

use super::media_source::RTCMediaSourceStats;
use serde::{Deserialize, Serialize};

/// Statistics for a video source.
///
/// This struct corresponds to the `RTCVideoSourceStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about the video
/// capture source, including resolution and frame rate metrics.
///
/// # W3C Reference
///
/// See [RTCVideoSourceStats](https://www.w3.org/TR/webrtc-stats/#videosourcestats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCVideoSourceStats {
    /// Base media source statistics.
    #[serde(flatten)]
    pub media_source_stats: RTCMediaSourceStats,

    /// The width of video frames in pixels.
    pub width: u32,

    /// The height of video frames in pixels.
    pub height: u32,

    /// Total number of frames captured from this source.
    pub frames: u32,

    /// Current frame rate in frames per second.
    pub frames_per_second: f64,
}
