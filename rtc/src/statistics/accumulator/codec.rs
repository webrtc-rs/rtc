//! Codec statistics accumulator.

use crate::rtp_transceiver::PayloadType;
use crate::statistics::stats::codec::RTCCodecStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated codec statistics.
///
/// This struct holds static codec information captured during SDP negotiation.
/// The data doesn't change after creation.
#[derive(Debug, Default, Clone)]
pub struct CodecStatsAccumulator {
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

impl CodecStatsAccumulator {
    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCCodecStats {
        RTCCodecStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::Codec,
                id: id.to_string(),
            },
            payload_type: self.payload_type,
            mime_type: self.mime_type.clone(),
            channels: self.channels,
            clock_rate: self.clock_rate,
            sdp_fmtp_line: self.sdp_fmtp_line.clone(),
        }
    }
}
