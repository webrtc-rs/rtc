use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::{AudioReceiverStatsUpdate, DecoderStatsUpdate};
use crate::statistics::stats::rtp_stream::RTCRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::inbound::RTCInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::RTCSentRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::remote_outbound::RTCRemoteOutboundRtpStreamStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated statistics for an inbound RTP stream.
///
/// This struct tracks packet counters, RTCP feedback, FEC stats,
/// and video frame metrics for an incoming RTP stream.
#[derive(Debug, Default)]
pub struct InboundRtpStreamAccumulator {
    // Base identification
    /// The SSRC identifier for this stream.
    pub ssrc: SSRC,
    /// The media kind (audio/video).
    pub kind: RtpCodecKind,
    /// Reference to the transport stats.
    pub transport_id: String,
    /// Reference to the codec stats.
    pub codec_id: String,
    /// The track identifier from the MediaStreamTrack.
    pub track_identifier: String,
    /// The media stream identification tag from SDP.
    pub mid: String,

    // Packet counters
    /// Total RTP packets received.
    pub packets_received: u64,
    /// Total payload bytes received (excluding headers).
    pub bytes_received: u64,
    /// Total RTP header bytes received.
    pub header_bytes_received: u64,
    /// Cumulative packets lost (can be negative due to duplication).
    pub packets_lost: i64,
    /// Current jitter in seconds.
    pub jitter: f64,
    /// Discarded packets count.
    pub packets_discarded: u64,
    /// Timestamp of the last RTP packet received.
    pub last_packet_received_timestamp: Option<Instant>,

    // ECN support
    /// Packets received with ECT(1) marking.
    pub packets_received_with_ect1: u64,
    /// Packets received with CE (Congestion Experienced) marking.
    pub packets_received_with_ce: u64,
    /// Packets reported as lost in RTCP.
    pub packets_reported_as_lost: u64,
    /// Packets reported lost but later recovered via retransmission.
    pub packets_reported_as_lost_but_recovered: u64,

    // RTCP feedback sent
    /// Number of NACKs sent for this stream.
    pub nack_count: u32,
    /// Number of FIRs sent for this stream.
    pub fir_count: u32,
    /// Number of PLIs sent for this stream.
    pub pli_count: u32,

    // FEC stats
    /// FEC packets received.
    pub fec_packets_received: u64,
    /// FEC bytes received.
    pub fec_bytes_received: u64,
    /// FEC packets discarded.
    pub fec_packets_discarded: u64,

    // Retransmission
    /// Retransmitted packets received (RTX).
    pub retransmitted_packets_received: u64,
    /// Retransmitted bytes received.
    pub retransmitted_bytes_received: u64,
    /// RTX SSRC if available.
    pub rtx_ssrc: Option<u32>,
    /// FEC SSRC if available.
    pub fec_ssrc: Option<u32>,

    // Video frame tracking (RTP-level)
    /// Frames received (detected from RTP marker bit).
    pub frames_received: u32,
    /// Frames dropped before decoding.
    pub frames_dropped: u32,
    /// Current frame rate.
    pub frames_per_second: f64,

    // Pause/freeze detection (RTP-level)
    /// Number of pause events detected.
    pub pause_count: u32,
    /// Total duration of pauses in seconds.
    pub total_pauses_duration: f64,
    /// Number of freeze events detected.
    pub freeze_count: u32,
    /// Total duration of freezes in seconds.
    pub total_freezes_duration: f64,

    // Frame assembly
    /// Frames assembled from multiple RTP packets.
    pub frames_assembled_from_multiple_packets: u32,
    /// Total time spent assembling frames.
    pub total_assembly_time: f64,

    // Remote sender info (from RTCP SR)
    /// Packets sent by the remote sender (from SR).
    pub remote_packets_sent: u64,
    /// Bytes sent by the remote sender (from SR).
    pub remote_bytes_sent: u64,
    /// Timestamp of the remote sender report.
    pub remote_timestamp: Option<Instant>,
    /// Number of RTCP SR reports received.
    pub reports_received: u64,

    // Application-provided stats (decoder/audio)
    /// Decoder statistics provided by the application.
    pub decoder_stats: Option<DecoderStatsUpdate>,
    /// Audio receiver statistics provided by the application.
    pub audio_receiver_stats: Option<AudioReceiverStatsUpdate>,
}

impl InboundRtpStreamAccumulator {
    /// Called when an RTP packet is received.
    pub fn on_rtp_received(&mut self, payload_bytes: usize, header_bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.bytes_received += payload_bytes as u64;
        self.header_bytes_received += header_bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    /// Called when RTCP Receiver Report is generated.
    pub fn on_rtcp_rr_generated(&mut self, packets_lost: i64, jitter: f64) {
        self.packets_lost = packets_lost;
        self.jitter = jitter;
    }

    /// Called when a NACK is sent.
    pub fn on_nack_sent(&mut self) {
        self.nack_count += 1;
    }

    /// Called when a FIR is sent.
    pub fn on_fir_sent(&mut self) {
        self.fir_count += 1;
    }

    /// Called when a PLI is sent.
    pub fn on_pli_sent(&mut self) {
        self.pli_count += 1;
    }

    /// Called when RTCP Sender Report is received from remote.
    pub fn on_rtcp_sr_received(&mut self, packets_sent: u64, bytes_sent: u64, now: Instant) {
        self.remote_packets_sent = packets_sent;
        self.remote_bytes_sent = bytes_sent;
        self.remote_timestamp = Some(now);
        self.reports_received += 1;
    }

    /// Called when a video frame is received (marker bit set).
    pub fn on_frame_received(&mut self) {
        self.frames_received += 1;
    }

    /// Called when a frame is dropped.
    pub fn on_frame_dropped(&mut self) {
        self.frames_dropped += 1;
    }

    /// Called when an RTX packet is received.
    pub fn on_rtx_received(&mut self, bytes: usize) {
        self.retransmitted_packets_received += 1;
        self.retransmitted_bytes_received += bytes as u64;
    }

    /// Called when a FEC packet is received.
    pub fn on_fec_received(&mut self, bytes: usize) {
        self.fec_packets_received += 1;
        self.fec_bytes_received += bytes as u64;
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCInboundRtpStreamStats {
        RTCInboundRtpStreamStats {
            received_rtp_stream_stats: RTCReceivedRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: now,
                        typ: RTCStatsType::InboundRTP,
                        id: id.to_string(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_received: self.packets_received,
                packets_received_with_ect1: self.packets_received_with_ect1,
                packets_received_with_ce: self.packets_received_with_ce,
                packets_reported_as_lost: self.packets_reported_as_lost,
                packets_reported_as_lost_but_recovered: self.packets_reported_as_lost_but_recovered,
                packets_lost: self.packets_lost,
                jitter: self.jitter,
            },
            track_identifier: self.track_identifier.clone(),
            mid: self.mid.clone(),
            remote_id: format!("RTCRemoteOutboundRTPStream_{}_{}", self.kind, self.ssrc),
            frames_decoded: self
                .decoder_stats
                .as_ref()
                .map(|s| s.frames_decoded)
                .unwrap_or(0),
            key_frames_decoded: self
                .decoder_stats
                .as_ref()
                .map(|s| s.key_frames_decoded)
                .unwrap_or(0),
            frames_rendered: self
                .decoder_stats
                .as_ref()
                .map(|s| s.frames_rendered)
                .unwrap_or(0),
            frames_dropped: self.frames_dropped,
            frame_width: self
                .decoder_stats
                .as_ref()
                .map(|s| s.frame_width)
                .unwrap_or(0),
            frame_height: self
                .decoder_stats
                .as_ref()
                .map(|s| s.frame_height)
                .unwrap_or(0),
            frames_per_second: self.frames_per_second,
            qp_sum: self.decoder_stats.as_ref().map(|s| s.qp_sum).unwrap_or(0),
            total_decode_time: self
                .decoder_stats
                .as_ref()
                .map(|s| s.total_decode_time)
                .unwrap_or(0.0),
            total_inter_frame_delay: self
                .decoder_stats
                .as_ref()
                .map(|s| s.total_inter_frame_delay)
                .unwrap_or(0.0),
            total_squared_inter_frame_delay: self
                .decoder_stats
                .as_ref()
                .map(|s| s.total_squared_inter_frame_delay)
                .unwrap_or(0.0),
            pause_count: self.pause_count,
            total_pauses_duration: self.total_pauses_duration,
            freeze_count: self.freeze_count,
            total_freezes_duration: self.total_freezes_duration,
            last_packet_received_timestamp: self.last_packet_received_timestamp.unwrap_or(now),
            header_bytes_received: self.header_bytes_received,
            packets_discarded: self.packets_discarded,
            fec_bytes_received: self.fec_bytes_received,
            fec_packets_received: self.fec_packets_received,
            fec_packets_discarded: self.fec_packets_discarded,
            bytes_received: self.bytes_received,
            nack_count: self.nack_count,
            fir_count: self.fir_count,
            pli_count: self.pli_count,
            total_processing_delay: 0.0,
            estimated_playout_timestamp: now,
            jitter_buffer_delay: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.jitter_buffer_delay)
                .unwrap_or(0.0),
            jitter_buffer_target_delay: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.jitter_buffer_target_delay)
                .unwrap_or(0.0),
            jitter_buffer_emitted_count: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.jitter_buffer_emitted_count)
                .unwrap_or(0),
            jitter_buffer_minimum_delay: 0.0,
            total_samples_received: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.total_samples_received)
                .unwrap_or(0),
            concealed_samples: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.concealed_samples)
                .unwrap_or(0),
            silent_concealed_samples: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.silent_concealed_samples)
                .unwrap_or(0),
            concealment_events: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.concealment_events)
                .unwrap_or(0),
            inserted_samples_for_deceleration: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.inserted_samples_for_deceleration)
                .unwrap_or(0),
            removed_samples_for_acceleration: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.removed_samples_for_acceleration)
                .unwrap_or(0),
            audio_level: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.audio_level)
                .unwrap_or(0.0),
            total_audio_energy: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.total_audio_energy)
                .unwrap_or(0.0),
            total_samples_duration: self
                .audio_receiver_stats
                .as_ref()
                .map(|s| s.total_samples_duration)
                .unwrap_or(0.0),
            frames_received: self.frames_received,
            decoder_implementation: self
                .decoder_stats
                .as_ref()
                .map(|s| s.decoder_implementation.clone())
                .unwrap_or_default(),
            playout_id: String::new(),
            power_efficient_decoder: self
                .decoder_stats
                .as_ref()
                .map(|s| s.power_efficient_decoder)
                .unwrap_or(false),
            frames_assembled_from_multiple_packets: self.frames_assembled_from_multiple_packets,
            total_assembly_time: self.total_assembly_time,
            retransmitted_packets_received: self.retransmitted_packets_received,
            retransmitted_bytes_received: self.retransmitted_bytes_received,
            rtx_ssrc: self.rtx_ssrc.unwrap_or(0),
            fec_ssrc: self.fec_ssrc.unwrap_or(0),
            total_corruption_probability: 0.0,
            total_squared_corruption_probability: 0.0,
            corruption_measurements: 0,
        }
    }

    /// Creates a snapshot of remote outbound stats from RTCP SR data.
    pub fn snapshot_remote(&self, now: Instant) -> RTCRemoteOutboundRtpStreamStats {
        RTCRemoteOutboundRtpStreamStats {
            sent_rtp_stream_stats: RTCSentRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: now,
                        typ: RTCStatsType::RemoteOutboundRTP,
                        id: format!("RTCRemoteOutboundRTPStream_{}_{}", self.kind, self.ssrc),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_sent: self.remote_packets_sent,
                bytes_sent: self.remote_bytes_sent,
            },
            local_id: format!("RTCInboundRTPStream_{}_{}", self.kind, self.ssrc),
            remote_timestamp: self.remote_timestamp.unwrap_or(now),
            reports_sent: self.reports_received,
            round_trip_time: 0.0,
            total_round_trip_time: 0.0,
            round_trip_time_measurements: 0,
        }
    }
}
