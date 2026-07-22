//! Codec statistics.
//!
//! This module contains the [`RTCCodecStats`] type which provides
//! information about codecs used for RTP streams.

use super::RTCStats;
use crate::rtp_transceiver::PayloadType;
use serde::{Deserialize, Serialize};

/// Statistics for a codec used in an RTP stream.
///
/// This struct corresponds to the `RTCCodecStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about codecs
/// currently in use for sending or receiving RTP streams.
///
/// Codec stats are only present when the codec is actively used by
/// at least one RTP stream.
///
/// # W3C Reference
///
/// See [RTCCodecStats](https://www.w3.org/TR/webrtc-stats/#codec-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCCodecStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The RTP payload type for this codec.
    ///
    /// This is the numeric payload type used in RTP packets.
    pub payload_type: PayloadType,

    /// The MIME type of the codec.
    ///
    /// Examples: "video/VP8", "video/H264", "audio/opus".
    pub mime_type: String,

    /// The number of audio channels for audio codecs.
    ///
    /// For video codecs, this is 0.
    pub channels: u16,

    /// The codec clock rate in Hz.
    ///
    /// For audio, this is typically 48000 (Opus) or 8000 (G.711).
    /// For video, this is typically 90000.
    pub clock_rate: u32,

    /// The SDP format-specific parameters line (fmtp).
    ///
    /// This contains codec-specific configuration from the SDP.
    /// For example, H.264 profile-level-id or Opus parameters.
    pub sdp_fmtp_line: String,
}
