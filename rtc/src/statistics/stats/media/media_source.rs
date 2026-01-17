//! Media source statistics.
//!
//! This module contains the [`RTCMediaSourceStats`] type which provides
//! base statistics for audio and video sources.

use super::super::RTCStats;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

/// Base statistics for a media source.
///
/// This struct corresponds to the `RTCMediaSourceStats` dictionary in the
/// W3C WebRTC Statistics API. It provides common fields shared by both
/// audio and video source statistics.
///
/// This type is typically not used directly; instead, use
/// [`RTCAudioSourceStats`](super::audio_source::RTCAudioSourceStats) or
/// [`RTCVideoSourceStats`](super::video_source::RTCVideoSourceStats).
///
/// # W3C Reference
///
/// See [RTCMediaSourceStats](https://www.w3.org/TR/webrtc-stats/#mediasourcestats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCMediaSourceStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The identifier of the media track.
    pub track_id: String,

    /// The kind of media source (audio or video).
    pub kind: RtpCodecKind,
}
