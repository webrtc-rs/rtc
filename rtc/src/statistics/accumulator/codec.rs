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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = CodecStatsAccumulator::default();
        assert_eq!(acc.payload_type, 0);
        assert_eq!(acc.mime_type, "");
        assert_eq!(acc.channels, 0);
        assert_eq!(acc.clock_rate, 0);
        assert_eq!(acc.sdp_fmtp_line, "");
    }

    #[test]
    fn test_codec_direction_display() {
        assert_eq!(format!("{}", CodecDirection::Send), "send");
        assert_eq!(format!("{}", CodecDirection::Receive), "recv");
    }

    #[test]
    fn test_codec_direction_equality() {
        assert_eq!(CodecDirection::Send, CodecDirection::Send);
        assert_eq!(CodecDirection::Receive, CodecDirection::Receive);
        assert_ne!(CodecDirection::Send, CodecDirection::Receive);
    }

    #[test]
    fn test_generate_id_send() {
        let id = CodecStatsAccumulator::generate_id("RTCTransport_0", CodecDirection::Send, 96);
        assert_eq!(id, "RTCCodec_RTCTransport_0_send_PT96");
    }

    #[test]
    fn test_generate_id_receive() {
        let id = CodecStatsAccumulator::generate_id("RTCTransport_0", CodecDirection::Receive, 111);
        assert_eq!(id, "RTCCodec_RTCTransport_0_recv_PT111");
    }

    #[test]
    fn test_from_codec() {
        let codec = RTCRtpCodec {
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_string(),
            ..Default::default()
        };

        let acc = CodecStatsAccumulator::from_codec(&codec, 96);

        assert_eq!(acc.payload_type, 96);
        assert_eq!(acc.mime_type, "video/VP8");
        assert_eq!(acc.clock_rate, 90000);
        assert_eq!(acc.channels, 0);
    }

    #[test]
    fn test_from_codec_audio_with_fmtp() {
        let codec = RTCRtpCodec {
            mime_type: "audio/opus".to_string(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "minptime=10;useinbandfec=1".to_string(),
            ..Default::default()
        };

        let acc = CodecStatsAccumulator::from_codec(&codec, 111);

        assert_eq!(acc.payload_type, 111);
        assert_eq!(acc.mime_type, "audio/opus");
        assert_eq!(acc.clock_rate, 48000);
        assert_eq!(acc.channels, 2);
        assert_eq!(acc.sdp_fmtp_line, "minptime=10;useinbandfec=1");
    }

    #[test]
    fn test_snapshot_video_codec() {
        let now = Instant::now();
        let acc = CodecStatsAccumulator {
            payload_type: 96,
            mime_type: "video/H264".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCodec_RTCTransport_0_send_PT96");

        assert_eq!(stats.stats.id, "RTCCodec_RTCTransport_0_send_PT96");
        assert_eq!(stats.stats.typ, RTCStatsType::Codec);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(stats.payload_type, 96);
        assert_eq!(stats.mime_type, "video/H264");
        assert_eq!(stats.clock_rate, 90000);
        assert_eq!(stats.channels, 0);
        assert!(stats.sdp_fmtp_line.contains("profile-level-id=42e01f"));
    }

    #[test]
    fn test_snapshot_audio_codec() {
        let now = Instant::now();
        let acc = CodecStatsAccumulator {
            payload_type: 111,
            mime_type: "audio/opus".to_string(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "minptime=10;useinbandfec=1".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCodec_RTCTransport_0_recv_PT111");

        assert_eq!(stats.stats.id, "RTCCodec_RTCTransport_0_recv_PT111");
        assert_eq!(stats.payload_type, 111);
        assert_eq!(stats.mime_type, "audio/opus");
        assert_eq!(stats.clock_rate, 48000);
        assert_eq!(stats.channels, 2);
    }

    #[test]
    fn test_clone() {
        let acc = CodecStatsAccumulator {
            payload_type: 96,
            mime_type: "video/VP9".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "profile-id=0".to_string(),
        };

        let cloned = acc.clone();

        assert_eq!(cloned.payload_type, acc.payload_type);
        assert_eq!(cloned.mime_type, acc.mime_type);
        assert_eq!(cloned.clock_rate, acc.clock_rate);
        assert_eq!(cloned.sdp_fmtp_line, acc.sdp_fmtp_line);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let acc = CodecStatsAccumulator {
            payload_type: 96,
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCodec_test");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"payloadType\":96"));
        assert!(json.contains("\"mimeType\":\"video/VP8\""));
        assert!(json.contains("\"clockRate\":90000"));
        assert!(json.contains("\"type\":\"codec\""));
    }

    #[test]
    fn test_different_payload_types_same_codec() {
        // Same codec can have different payload types in different sessions
        let acc1 = CodecStatsAccumulator {
            payload_type: 96,
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_string(),
        };

        let acc2 = CodecStatsAccumulator {
            payload_type: 100,
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_string(),
        };

        assert_ne!(acc1.payload_type, acc2.payload_type);
        assert_eq!(acc1.mime_type, acc2.mime_type);

        let id1 = CodecStatsAccumulator::generate_id("t", CodecDirection::Send, acc1.payload_type);
        let id2 = CodecStatsAccumulator::generate_id("t", CodecDirection::Send, acc2.payload_type);
        assert_ne!(id1, id2);
    }
}
