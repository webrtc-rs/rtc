//! Outbound RTP stream statistics.
//!
//! This module contains the [`RTCOutboundRtpStreamStats`] type which provides
//! detailed statistics about locally sent RTP streams.

use super::super::super::RTCQualityLimitationReason;
use super::RTCSentRtpStreamStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Statistics for a locally sent outbound RTP stream.
///
/// This struct corresponds to the `RTCOutboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides comprehensive statistics about media
/// sent to a remote peer, including encoding, quality, and bandwidth metrics.
///
/// # W3C Reference
///
/// See [RTCOutboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#outboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCOutboundRtpStreamStats {
    /// Base sent RTP stream statistics.
    #[serde(flatten)]
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    /// The media ID (mid) from SDP.
    pub mid: String,

    /// The ID of the media source stats.
    ///
    /// References an [`RTCAudioSourceStats`](super::super::super::media::audio_source::RTCAudioSourceStats)
    /// or [`RTCVideoSourceStats`](super::super::super::media::video_source::RTCVideoSourceStats) object.
    pub media_source_id: String,

    /// The ID of the corresponding remote inbound stats.
    ///
    /// References an [`RTCRemoteInboundRtpStreamStats`](super::super::received::remote_inbound::RTCRemoteInboundRtpStreamStats) object.
    pub remote_id: String,

    /// The RTP stream identifier (RID) for simulcast.
    pub rid: String,

    /// Index of this encoding in the encoding parameters.
    pub encoding_index: u32,

    /// Total bytes sent in RTP headers.
    pub header_bytes_sent: u64,

    /// Number of retransmitted packets sent.
    pub retransmitted_packets_sent: u64,

    /// Bytes sent via retransmission.
    pub retransmitted_bytes_sent: u64,

    /// SSRC of the RTX (retransmission) stream.
    pub rtx_ssrc: u32,

    /// Target bitrate in bits per second.
    pub target_bitrate: f64,

    /// Cumulative target encoded bytes.
    pub total_encoded_bytes_target: u64,

    /// Width of the last encoded frame in pixels.
    pub frame_width: u32,

    /// Height of the last encoded frame in pixels.
    pub frame_height: u32,

    /// Current encoding frame rate in frames per second.
    pub frames_per_second: f64,

    /// Total video frames sent.
    pub frames_sent: u32,

    /// Number of huge frames sent.
    ///
    /// Huge frames are frames significantly larger than average.
    pub huge_frames_sent: u32,

    /// Number of frames encoded.
    pub frames_encoded: u32,

    /// Number of key frames encoded.
    pub key_frames_encoded: u32,

    /// Sum of quantization parameters for encoded frames.
    ///
    /// Used to estimate video quality (lower QP = higher quality).
    pub qp_sum: u64,

    /// PSNR (Peak Signal-to-Noise Ratio) measurements by component.
    ///
    /// Keys are typically "y", "u", "v" for YUV components.
    pub psnr_sum: HashMap<String, f64>,

    /// Number of PSNR measurements taken.
    pub psnr_measurements: u64,

    /// Total time spent encoding frames in seconds.
    pub total_encode_time: f64,

    /// Total delay from encoding to sending in seconds.
    pub total_packet_send_delay: f64,

    /// The current quality limitation reason.
    pub quality_limitation_reason: RTCQualityLimitationReason,

    /// Time spent in each quality limitation state.
    ///
    /// Keys are limitation reasons ("none", "cpu", "bandwidth", "other").
    pub quality_limitation_durations: HashMap<String, f64>,

    /// Number of resolution changes due to quality limitations.
    pub quality_limitation_resolution_changes: u32,

    /// Number of NACK (Negative Acknowledgement) packets received.
    pub nack_count: u32,

    /// Number of FIR (Full Intra Request) packets received.
    pub fir_count: u32,

    /// Number of PLI (Picture Loss Indication) packets received.
    pub pli_count: u32,

    /// Name of the encoder implementation.
    pub encoder_implementation: String,

    /// Whether the encoder is power efficient.
    pub power_efficient_encoder: bool,

    /// Whether this stream is currently active.
    pub active: bool,

    /// The SVC (Scalable Video Coding) scalability mode.
    ///
    /// For example: "L1T1", "L1T2", "L1T3", "L2T1", etc.
    pub scalability_mode: String,

    /// Packets sent with ECT(1) marking.
    pub packets_sent_with_ect1: u64,
}
