use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::EncoderStatsUpdate;
use crate::statistics::stats::rtp_stream::RTCRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::remote_inbound::RTCRemoteInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::RTCSentRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::outbound::RTCOutboundRtpStreamStats;
use crate::statistics::stats::{RTCQualityLimitationReason, RTCStats, RTCStatsType};
use std::collections::HashMap;
use std::time::Instant;

/// Accumulated statistics for an outbound RTP stream.
///
/// This struct tracks packet counters, RTCP feedback received,
/// and video frame metrics for an outgoing RTP stream.
#[derive(Debug, Default)]
pub struct OutboundRtpStreamAccumulator {
    // Base identification
    /// The SSRC identifier for this stream.
    pub ssrc: SSRC,
    /// The media kind (audio/video).
    pub kind: RtpCodecKind,
    /// Reference to the transport stats.
    pub transport_id: String,
    /// Reference to the codec stats.
    pub codec_id: String,
    /// The media stream identification tag from SDP.
    pub mid: String,
    /// The RTP stream ID (RID) for simulcast.
    pub rid: String,
    /// The encoding index in simulcast.
    pub encoding_index: u32,
    /// Reference to the media source stats.
    pub media_source_id: String,
    /// The transceiver ID that owns this stream (for filtering).
    pub transceiver_id: RTCRtpTransceiverId,

    // Packet counters
    /// Total RTP packets sent.
    pub packets_sent: u64,
    /// Total payload bytes sent.
    pub bytes_sent: u64,
    /// Total RTP header bytes sent.
    pub header_bytes_sent: u64,
    /// Timestamp of the last RTP packet sent.
    pub last_packet_sent_timestamp: Option<Instant>,

    // Retransmission
    /// Retransmitted packets sent (RTX).
    pub retransmitted_packets_sent: u64,
    /// Retransmitted bytes sent.
    pub retransmitted_bytes_sent: u64,
    /// RTX SSRC if available.
    pub rtx_ssrc: Option<u32>,

    // Frame tracking (RTP-level)
    /// Frames sent.
    pub frames_sent: u32,
    /// Huge frames sent (larger than average).
    pub huge_frames_sent: u32,
    /// Current frame rate.
    pub frames_per_second: f64,

    // RTCP feedback received
    /// Number of NACKs received for this stream.
    pub nack_count: u32,
    /// Number of FIRs received for this stream.
    pub fir_count: u32,
    /// Number of PLIs received for this stream.
    pub pli_count: u32,

    // Timing
    /// Total packet send delay in seconds.
    pub total_packet_send_delay: f64,

    // State
    /// Whether the stream is actively sending.
    pub active: bool,

    // Quality limitation (from BWE/interceptor)
    /// Current quality limitation reason.
    pub quality_limitation_reason: RTCQualityLimitationReason,
    /// Number of resolution changes due to quality limitations.
    pub quality_limitation_resolution_changes: u32,
    /// Target bitrate from bandwidth estimation.
    pub target_bitrate: f64,

    // Remote receiver info (from RTCP RR)
    /// Packets received by the remote receiver (from RR).
    pub remote_packets_received: u64,
    /// Packets lost at the remote receiver (from RR).
    pub remote_packets_lost: u64,
    /// Jitter at the remote receiver (from RR).
    pub remote_jitter: f64,
    /// Fraction lost at the remote receiver (from RR).
    pub remote_fraction_lost: f64,
    /// Round trip time calculated from RR.
    pub remote_round_trip_time: f64,
    /// Number of RTT measurements.
    pub rtt_measurements: u64,

    // Application-provided stats (encoder)
    /// Encoder statistics provided by the application.
    pub encoder_stats: Option<EncoderStatsUpdate>,
}

impl OutboundRtpStreamAccumulator {
    /// Called when an RTP packet is sent.
    pub fn on_rtp_sent(&mut self, header_bytes: usize, payload_bytes: usize, now: Instant) {
        self.packets_sent += 1;
        self.header_bytes_sent += header_bytes as u64;
        self.bytes_sent += payload_bytes as u64;
        self.last_packet_sent_timestamp = Some(now);
    }

    /// Called when a NACK is received.
    pub fn on_nack_received(&mut self) {
        self.nack_count += 1;
    }

    /// Called when a FIR is received.
    pub fn on_fir_received(&mut self) {
        self.fir_count += 1;
    }

    /// Called when a PLI is received.
    pub fn on_pli_received(&mut self) {
        self.pli_count += 1;
    }

    /// Called when an RTX packet is sent.
    pub fn on_rtx_sent(&mut self, bytes: usize) {
        self.retransmitted_packets_sent += 1;
        self.retransmitted_bytes_sent += bytes as u64;
    }

    /// Called when RTCP Receiver Report is received from remote.
    pub fn on_rtcp_rr_received(
        &mut self,
        packets_received: u64,
        packets_lost: u64,
        jitter: f64,
        fraction_lost: f64,
        rtt: f64,
    ) {
        self.remote_packets_received = packets_received;
        self.remote_packets_lost = packets_lost;
        self.remote_jitter = jitter;
        self.remote_fraction_lost = fraction_lost;
        self.remote_round_trip_time = rtt;
        self.rtt_measurements += 1;
    }

    /// Called when a video frame is sent (marker bit set).
    pub fn on_frame_sent(&mut self, is_huge: bool) {
        self.frames_sent += 1;
        if is_huge {
            self.huge_frames_sent += 1;
        }
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCOutboundRtpStreamStats {
        RTCOutboundRtpStreamStats {
            sent_rtp_stream_stats: RTCSentRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: now,
                        typ: RTCStatsType::OutboundRTP,
                        id: id.to_string(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_sent: self.packets_sent,
                bytes_sent: self.bytes_sent,
            },
            mid: self.mid.clone(),
            media_source_id: self.media_source_id.clone(),
            remote_id: format!("RTCRemoteInboundRTPStream_{}_{}", self.kind, self.ssrc),
            rid: self.rid.clone(),
            encoding_index: self.encoding_index,
            header_bytes_sent: self.header_bytes_sent,
            retransmitted_packets_sent: self.retransmitted_packets_sent,
            retransmitted_bytes_sent: self.retransmitted_bytes_sent,
            rtx_ssrc: self.rtx_ssrc.unwrap_or(0),
            target_bitrate: self.target_bitrate,
            total_encoded_bytes_target: 0,
            frame_width: self
                .encoder_stats
                .as_ref()
                .map(|s| s.frame_width)
                .unwrap_or(0),
            frame_height: self
                .encoder_stats
                .as_ref()
                .map(|s| s.frame_height)
                .unwrap_or(0),
            frames_per_second: self.frames_per_second,
            frames_sent: self.frames_sent,
            huge_frames_sent: self.huge_frames_sent,
            frames_encoded: self
                .encoder_stats
                .as_ref()
                .map(|s| s.frames_encoded)
                .unwrap_or(0),
            key_frames_encoded: self
                .encoder_stats
                .as_ref()
                .map(|s| s.key_frames_encoded)
                .unwrap_or(0),
            qp_sum: self.encoder_stats.as_ref().map(|s| s.qp_sum).unwrap_or(0),
            psnr_sum: HashMap::new(),
            psnr_measurements: 0,
            total_encode_time: self
                .encoder_stats
                .as_ref()
                .map(|s| s.total_encode_time)
                .unwrap_or(0.0),
            total_packet_send_delay: self.total_packet_send_delay,
            quality_limitation_reason: self.quality_limitation_reason,
            quality_limitation_durations: HashMap::new(),
            quality_limitation_resolution_changes: self.quality_limitation_resolution_changes,
            nack_count: self.nack_count,
            fir_count: self.fir_count,
            pli_count: self.pli_count,
            encoder_implementation: self
                .encoder_stats
                .as_ref()
                .map(|s| s.encoder_implementation.clone())
                .unwrap_or_default(),
            power_efficient_encoder: self
                .encoder_stats
                .as_ref()
                .map(|s| s.power_efficient_encoder)
                .unwrap_or(false),
            active: self.active,
            scalability_mode: self
                .encoder_stats
                .as_ref()
                .map(|s| s.scalability_mode.clone())
                .unwrap_or_default(),
            packets_sent_with_ect1: 0,
        }
    }

    /// Creates a snapshot of remote inbound stats from RTCP RR data.
    pub fn snapshot_remote(&self, now: Instant) -> RTCRemoteInboundRtpStreamStats {
        RTCRemoteInboundRtpStreamStats {
            received_rtp_stream_stats: RTCReceivedRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: now,
                        typ: RTCStatsType::RemoteInboundRTP,
                        id: format!("RTCRemoteInboundRTPStream_{}_{}", self.kind, self.ssrc),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_received: self.remote_packets_received,
                packets_received_with_ect1: 0,
                packets_received_with_ce: 0,
                packets_reported_as_lost: self.remote_packets_lost,
                packets_reported_as_lost_but_recovered: 0,
                packets_lost: self.remote_packets_lost as i64,
                jitter: self.remote_jitter,
            },
            local_id: format!("RTCOutboundRTPStream_{}_{}", self.kind, self.ssrc),
            round_trip_time: self.remote_round_trip_time,
            total_round_trip_time: self.remote_round_trip_time * self.rtt_measurements as f64,
            fraction_lost: self.remote_fraction_lost,
            round_trip_time_measurements: self.rtt_measurements,
            packets_with_bleached_ect1_marking: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = OutboundRtpStreamAccumulator::default();
        assert_eq!(acc.ssrc, 0);
        assert_eq!(acc.packets_sent, 0);
        assert_eq!(acc.bytes_sent, 0);
        assert_eq!(acc.header_bytes_sent, 0);
        assert_eq!(acc.retransmitted_packets_sent, 0);
        assert_eq!(acc.retransmitted_bytes_sent, 0);
        assert_eq!(acc.frames_sent, 0);
        assert_eq!(acc.huge_frames_sent, 0);
        assert_eq!(acc.nack_count, 0);
        assert_eq!(acc.fir_count, 0);
        assert_eq!(acc.pli_count, 0);
        assert!(!acc.active);
    }

    #[test]
    fn test_on_rtp_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();
        let now = Instant::now();

        acc.on_rtp_sent(12, 1188, now);
        assert_eq!(acc.packets_sent, 1);
        assert_eq!(acc.header_bytes_sent, 12);
        assert_eq!(acc.bytes_sent, 1188);
        assert_eq!(acc.last_packet_sent_timestamp, Some(now));

        let later = now + std::time::Duration::from_millis(20);
        acc.on_rtp_sent(12, 1000, later);
        assert_eq!(acc.packets_sent, 2);
        assert_eq!(acc.header_bytes_sent, 24);
        assert_eq!(acc.bytes_sent, 2188);
        assert_eq!(acc.last_packet_sent_timestamp, Some(later));
    }

    #[test]
    fn test_rtcp_feedback_counters() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_nack_received();
        acc.on_nack_received();
        assert_eq!(acc.nack_count, 2);

        acc.on_fir_received();
        assert_eq!(acc.fir_count, 1);

        acc.on_pli_received();
        acc.on_pli_received();
        acc.on_pli_received();
        assert_eq!(acc.pli_count, 3);
    }

    #[test]
    fn test_on_rtx_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_rtx_sent(500);
        acc.on_rtx_sent(600);
        assert_eq!(acc.retransmitted_packets_sent, 2);
        assert_eq!(acc.retransmitted_bytes_sent, 1100);
    }

    #[test]
    fn test_on_rtcp_rr_received() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_rtcp_rr_received(100, 5, 0.003, 0.05, 0.025);
        assert_eq!(acc.remote_packets_received, 100);
        assert_eq!(acc.remote_packets_lost, 5);
        assert_eq!(acc.remote_jitter, 0.003);
        assert_eq!(acc.remote_fraction_lost, 0.05);
        assert_eq!(acc.remote_round_trip_time, 0.025);
        assert_eq!(acc.rtt_measurements, 1);

        // Second RR with updated values
        acc.on_rtcp_rr_received(200, 8, 0.004, 0.04, 0.030);
        assert_eq!(acc.remote_packets_received, 200);
        assert_eq!(acc.remote_packets_lost, 8);
        assert_eq!(acc.remote_jitter, 0.004);
        assert_eq!(acc.remote_fraction_lost, 0.04);
        assert_eq!(acc.remote_round_trip_time, 0.030);
        assert_eq!(acc.rtt_measurements, 2);
    }

    #[test]
    fn test_on_frame_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_frame_sent(false);
        acc.on_frame_sent(false);
        acc.on_frame_sent(true); // huge frame
        acc.on_frame_sent(false);
        acc.on_frame_sent(true); // huge frame

        assert_eq!(acc.frames_sent, 5);
        assert_eq!(acc.huge_frames_sent, 2);
    }

    #[test]
    fn test_full_outbound_stream_flow() {
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 87654321,
            kind: RtpCodecKind::Video,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_video_96".to_string(),
            mid: "0".to_string(),
            rid: "h".to_string(),
            rtx_ssrc: Some(87654322),
            active: true,
            ..Default::default()
        };

        let now = Instant::now();

        // Send RTP packets
        for i in 0..100 {
            acc.on_rtp_sent(12, 1200, now + std::time::Duration::from_millis(i * 33));
        }

        // Send frames
        for _ in 0..30 {
            acc.on_frame_sent(false);
        }
        acc.on_frame_sent(true); // One huge frame

        // Receive NACK and resend
        acc.on_nack_received();
        acc.on_rtx_sent(1200);

        // Receive RR from remote
        acc.on_rtcp_rr_received(95, 5, 0.002, 0.05, 0.020);

        assert_eq!(acc.packets_sent, 100);
        assert_eq!(acc.bytes_sent, 120000);
        assert_eq!(acc.frames_sent, 31);
        assert_eq!(acc.huge_frames_sent, 1);
        assert_eq!(acc.nack_count, 1);
        assert_eq!(acc.retransmitted_packets_sent, 1);
        assert_eq!(acc.retransmitted_bytes_sent, 1200);
        assert_eq!(acc.remote_packets_received, 95);
        assert_eq!(acc.remote_packets_lost, 5);
        assert_eq!(acc.rtt_measurements, 1);
    }

    #[test]
    fn test_snapshot() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 44444444,
            kind: RtpCodecKind::Audio,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_audio_111".to_string(),
            mid: "1".to_string(),
            active: true,
            ..Default::default()
        };

        acc.on_rtp_sent(12, 160, now);
        acc.on_rtp_sent(12, 160, now);

        let stats = acc.snapshot(now, "RTCOutboundRTPStream_audio_44444444");

        assert_eq!(
            stats.sent_rtp_stream_stats.rtp_stream_stats.stats.id,
            "RTCOutboundRTPStream_audio_44444444"
        );
        assert_eq!(
            stats.sent_rtp_stream_stats.rtp_stream_stats.stats.typ,
            RTCStatsType::OutboundRTP
        );
        assert_eq!(stats.sent_rtp_stream_stats.rtp_stream_stats.ssrc, 44444444);
        assert_eq!(
            stats.sent_rtp_stream_stats.rtp_stream_stats.kind,
            RtpCodecKind::Audio
        );
        assert_eq!(stats.sent_rtp_stream_stats.packets_sent, 2);
        assert_eq!(stats.sent_rtp_stream_stats.bytes_sent, 320);
        assert_eq!(stats.header_bytes_sent, 24);
        assert_eq!(stats.mid, "1");
        assert!(stats.active);
    }

    #[test]
    fn test_snapshot_remote() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 55555555,
            kind: RtpCodecKind::Video,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_video_96".to_string(),
            ..Default::default()
        };

        acc.on_rtcp_rr_received(500, 10, 0.005, 0.02, 0.035);
        acc.on_rtcp_rr_received(1000, 20, 0.004, 0.02, 0.030);

        let remote_stats = acc.snapshot_remote(now);

        assert_eq!(
            remote_stats
                .received_rtp_stream_stats
                .rtp_stream_stats
                .stats
                .typ,
            RTCStatsType::RemoteInboundRTP
        );
        assert_eq!(
            remote_stats.received_rtp_stream_stats.rtp_stream_stats.ssrc,
            55555555
        );
        assert_eq!(
            remote_stats.received_rtp_stream_stats.packets_received,
            1000
        );
        assert_eq!(remote_stats.received_rtp_stream_stats.packets_lost, 20);
        assert_eq!(remote_stats.received_rtp_stream_stats.jitter, 0.004);
        assert_eq!(remote_stats.round_trip_time, 0.030);
        assert_eq!(remote_stats.round_trip_time_measurements, 2);
        assert_eq!(remote_stats.fraction_lost, 0.02);
        assert!(remote_stats.local_id.contains("RTCOutboundRTPStream"));
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 66666666,
            kind: RtpCodecKind::Video,
            active: true,
            ..Default::default()
        };

        acc.on_rtp_sent(12, 1200, now);
        acc.on_frame_sent(false);
        acc.on_nack_received();

        let stats = acc.snapshot(now, "RTCOutboundRTPStream_video_66666666");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"ssrc\":66666666"));
        assert!(json.contains("\"packetsSent\":1"));
        assert!(json.contains("\"bytesSent\":1200"));
        assert!(json.contains("\"framesSent\":1"));
        assert!(json.contains("\"nackCount\":1"));
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"type\":\"outbound-rtp\""));
    }

    #[test]
    fn test_quality_limitation_tracking() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.quality_limitation_reason = RTCQualityLimitationReason::Bandwidth;
        acc.quality_limitation_resolution_changes = 3;
        acc.target_bitrate = 1_500_000.0;

        let now = Instant::now();
        let stats = acc.snapshot(now, "test");

        assert_eq!(
            stats.quality_limitation_reason,
            RTCQualityLimitationReason::Bandwidth
        );
        assert_eq!(stats.quality_limitation_resolution_changes, 3);
        assert_eq!(stats.target_bitrate, 1_500_000.0);
    }
}
