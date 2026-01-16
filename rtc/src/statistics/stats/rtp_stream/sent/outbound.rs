use super::super::super::RTCQualityLimitationReason;
use super::RTCSentRtpStreamStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCOutboundRtpStreamStats {
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    pub mid: String,
    pub media_source_id: String,
    pub remote_id: String,
    pub rid: String,
    pub encoding_index: u32,
    pub header_bytes_sent: u64,
    pub retransmitted_packets_sent: u64,
    pub retransmitted_bytes_sent: u64,
    pub rtx_ssrc: u32,
    pub target_bitrate: f64,
    pub total_encoded_bytes_target: u64,
    pub frame_width: u32,
    pub frame_height: u32,
    pub frames_per_second: f64,
    pub frames_sent: u32,
    pub huge_frames_sent: u32,
    pub frames_encoded: u32,
    pub key_frames_encoded: u32,
    pub qp_sum: u64,
    pub psnr_sum: HashMap<String, f64>,
    pub psnr_measurements: u64,
    pub total_encode_time: f64,
    pub total_packet_send_delay: f64,
    pub quality_limitation_reason: RTCQualityLimitationReason,
    pub quality_limitation_durations: HashMap<String, f64>,
    pub quality_limitation_resolution_changes: u32,
    pub nack_count: u32,
    pub fir_count: u32,
    pub pli_count: u32,
    pub encoder_implementation: String,
    pub power_efficient_encoder: bool,
    pub active: bool,
    pub scalability_mode: String,
    pub packets_sent_with_ect1: u64,
}
