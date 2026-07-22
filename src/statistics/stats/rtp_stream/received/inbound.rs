//! Inbound RTP stream statistics.
//!
//! This module contains the [`RTCInboundRtpStreamStats`] type which provides
//! detailed statistics about locally received RTP streams.

use super::RTCReceivedRtpStreamStats;
use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

/// Statistics for a locally received inbound RTP stream.
///
/// This struct corresponds to the `RTCInboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides comprehensive statistics about media
/// received from a remote peer, including decoding, rendering, and quality metrics.
///
/// # W3C Reference
///
/// See [RTCInboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCInboundRtpStreamStats {
    /// Base received RTP stream statistics.
    #[serde(flatten)]
    pub received_rtp_stream_stats: RTCReceivedRtpStreamStats,

    /// The track identifier associated with this stream.
    pub track_identifier: String,

    /// The media ID (mid) from SDP.
    pub mid: String,

    /// The ID of the corresponding remote outbound stats.
    ///
    /// References an [`RTCRemoteOutboundRtpStreamStats`](super::super::sent::remote_outbound::RTCRemoteOutboundRtpStreamStats) object.
    pub remote_id: String,

    /// Number of frames successfully decoded.
    pub frames_decoded: u32,

    /// Number of key frames decoded.
    pub key_frames_decoded: u32,

    /// Number of frames rendered to the display.
    pub frames_rendered: u32,

    /// Number of frames dropped before rendering.
    pub frames_dropped: u32,

    /// Width of the last decoded frame in pixels.
    pub frame_width: u32,

    /// Height of the last decoded frame in pixels.
    pub frame_height: u32,

    /// Current frame rate in frames per second.
    pub frames_per_second: f64,

    /// Sum of quantization parameters for decoded frames.
    ///
    /// Used to estimate video quality (lower QP = higher quality).
    pub qp_sum: u64,

    /// Total time spent decoding frames in seconds.
    pub total_decode_time: f64,

    /// Sum of inter-frame delays in seconds.
    pub total_inter_frame_delay: f64,

    /// Sum of squared inter-frame delays.
    ///
    /// Used to calculate jitter variance.
    pub total_squared_inter_frame_delay: f64,

    /// Number of times playback was paused.
    pub pause_count: u32,

    /// Total duration of pauses in seconds.
    pub total_pauses_duration: f64,

    /// Number of video freezes detected.
    ///
    /// A freeze occurs when a frame is displayed for significantly
    /// longer than expected.
    pub freeze_count: u32,

    /// Total duration of freezes in seconds.
    pub total_freezes_duration: f64,

    /// Timestamp of the last received packet.
    #[serde(with = "instant_to_epoch")]
    pub last_packet_received_timestamp: Instant,

    /// Total bytes received in RTP headers.
    pub header_bytes_received: u64,

    /// Number of packets discarded by the jitter buffer.
    pub packets_discarded: u64,

    /// Total bytes received for forward error correction.
    pub fec_bytes_received: u64,

    /// Number of FEC packets received.
    pub fec_packets_received: u64,

    /// Number of FEC packets discarded.
    pub fec_packets_discarded: u64,

    /// Total payload bytes received (excluding headers).
    pub bytes_received: u64,

    /// Number of NACK (Negative Acknowledgement) packets sent.
    pub nack_count: u32,

    /// Number of FIR (Full Intra Request) packets sent.
    pub fir_count: u32,

    /// Number of PLI (Picture Loss Indication) packets sent.
    pub pli_count: u32,

    /// Total processing delay in seconds.
    ///
    /// Time from packet reception to frame rendering.
    pub total_processing_delay: f64,

    /// Estimated playout timestamp for synchronization.
    #[serde(with = "instant_to_epoch")]
    pub estimated_playout_timestamp: Instant,

    /// Cumulative jitter buffer delay in seconds.
    pub jitter_buffer_delay: f64,

    /// Target jitter buffer delay in seconds.
    pub jitter_buffer_target_delay: f64,

    /// Number of samples/frames emitted from the jitter buffer.
    pub jitter_buffer_emitted_count: u64,

    /// Minimum jitter buffer delay in seconds.
    pub jitter_buffer_minimum_delay: f64,

    /// Total audio samples received.
    pub total_samples_received: u64,

    /// Number of audio samples synthesized for concealment.
    pub concealed_samples: u64,

    /// Number of silent samples used for concealment.
    pub silent_concealed_samples: u64,

    /// Number of concealment events.
    pub concealment_events: u64,

    /// Samples inserted to slow down playback.
    pub inserted_samples_for_deceleration: u64,

    /// Samples removed to speed up playback.
    pub removed_samples_for_acceleration: u64,

    /// Current audio level (0.0 to 1.0).
    pub audio_level: f64,

    /// Total audio energy in the signal.
    pub total_audio_energy: f64,

    /// Total duration of received audio samples in seconds.
    pub total_samples_duration: f64,

    /// Total video frames received.
    pub frames_received: u32,

    /// Name of the decoder implementation.
    pub decoder_implementation: String,

    /// ID of the audio playout device stats.
    ///
    /// References an [`RTCAudioPlayoutStats`](super::super::super::media::audio_playout::RTCAudioPlayoutStats) object.
    pub playout_id: String,

    /// Whether the decoder is power efficient.
    pub power_efficient_decoder: bool,

    /// Frames assembled from multiple packets.
    pub frames_assembled_from_multiple_packets: u32,

    /// Total time to assemble frames from packets.
    pub total_assembly_time: f64,

    /// Number of retransmitted packets received.
    pub retransmitted_packets_received: u64,

    /// Bytes received via retransmission.
    pub retransmitted_bytes_received: u64,

    /// SSRC of the RTX (retransmission) stream.
    pub rtx_ssrc: u32,

    /// SSRC of the FEC stream.
    pub fec_ssrc: u32,

    /// Total corruption probability estimate.
    pub total_corruption_probability: f64,

    /// Sum of squared corruption probabilities.
    pub total_squared_corruption_probability: f64,

    /// Number of corruption measurements.
    pub corruption_measurements: u64,
}
