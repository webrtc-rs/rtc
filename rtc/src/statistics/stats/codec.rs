use super::RTCStats;
use crate::rtp_transceiver::PayloadType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCCodecStats {
    /// General Stats Fields
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The RTP payload type for this codec.
    pub payload_type: PayloadType,
    /// The MIME type of the codec (e.g., "video/VP8", "audio/opus").
    pub mime_type: String,
    /// Number of audio channels (0 for video codecs).
    pub channels: u16,
    /// The codec clock rate in Hz.
    pub clock_rate: u32,
    /// The SDP format-specific parameters line.
    pub sdp_fmtp_line: String,
}
