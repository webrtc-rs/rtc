//! Codec statistics accumulator.

use crate::rtp_transceiver::PayloadType;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::statistics::stats::codec::RTCCodecStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Direction qualifier for codec stats IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecDirection {
    /// Codec used for sending (encoding).
    Send,
    /// Codec used for receiving (decoding).
    Receive,
}

impl std::fmt::Display for CodecDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecDirection::Send => write!(f, "send"),
            CodecDirection::Receive => write!(f, "recv"),
        }
    }
}

/// Accumulated codec statistics.
///
/// This struct holds static codec information captured during SDP negotiation.
/// The data doesn't change after creation.
///
/// Per W3C spec:
/// - Codecs are only exposed when referenced by an RTP stream
/// - Codec stats are per payload type per transport
/// - May need separate encode/decode entries if sdpFmtpLine differs
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
    /// Creates a new codec stats accumulator from RTCRtpCodecParameters.
    pub fn from_codec_parameters(params: &RTCRtpCodecParameters) -> Self {
        Self {
            payload_type: params.payload_type,
            mime_type: params.rtp_codec.mime_type.clone(),
            channels: params.rtp_codec.channels,
            clock_rate: params.rtp_codec.clock_rate,
            sdp_fmtp_line: params.rtp_codec.sdp_fmtp_line.clone(),
        }
    }

    /// Creates a new codec stats accumulator from RTCRtpCodec and payload type.
    pub fn from_codec(codec: &RTCRtpCodec, payload_type: PayloadType) -> Self {
        Self {
            payload_type,
            mime_type: codec.mime_type.clone(),
            channels: codec.channels,
            clock_rate: codec.clock_rate,
            sdp_fmtp_line: codec.sdp_fmtp_line.clone(),
        }
    }

    /// Generates a codec stats ID following the W3C recommended format.
    ///
    /// Format: `RTCCodec_{transport_id}_{direction}_{payload_type}`
    ///
    /// The direction qualifier is used to distinguish between encode and decode
    /// codecs when they have different parameters (e.g., different sdpFmtpLine).
    pub fn generate_id(
        transport_id: &str,
        direction: CodecDirection,
        payload_type: PayloadType,
    ) -> String {
        format!("RTCCodec_{}_{}_PT{}", transport_id, direction, payload_type)
    }

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
