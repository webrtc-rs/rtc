//! Statistics accumulator module.
//!
//! This module provides incremental statistics accumulation for WebRTC
//! peer connections. The accumulators are updated as events occur in the
//! handler pipeline, and snapshots can be taken at any time to produce
//! immutable stats reports.

mod certificate;
mod codec;
mod data_channel;
mod ice_candidate;
mod ice_candidate_pair;
mod media;
mod peer_connection;
mod rtp_stream;
mod transport;

pub use certificate::CertificateStatsAccumulator;
pub use codec::{CodecDirection, CodecStatsAccumulator};
pub use data_channel::DataChannelStatsAccumulator;
pub use ice_candidate::IceCandidateAccumulator;
pub use ice_candidate_pair::IceCandidatePairAccumulator;
pub use media::app_provided::*;
pub use media::audio_playout::AudioPlayoutStatsAccumulator;
pub use media::media_source::MediaSourceStatsAccumulator;
pub use peer_connection::PeerConnectionStatsAccumulator;
pub use rtp_stream::inbound::InboundRtpStreamAccumulator;
pub use rtp_stream::outbound::OutboundRtpStreamAccumulator;
pub use transport::TransportStatsAccumulator;

use crate::data_channel::RTCDataChannelId;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::rtp_transceiver::{PayloadType, SSRC};
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use ice::CandidatePairStats;
use std::collections::HashMap;
use std::time::Instant;

/// Master statistics accumulator for a peer connection.
///
/// This struct aggregates all category-specific accumulators and provides
/// a unified interface for updating stats and generating snapshots.
///
/// # Design
///
/// The accumulator follows the "incremental accumulation + snapshot" pattern:
/// - Handler code calls methods like `on_rtp_received()` as events occur
/// - The `snapshot()` method produces an immutable `RTCStatsReport`
/// - All timestamps are provided explicitly for deterministic testing
///
/// # Thread Safety
///
/// This struct is not thread-safe. It is designed to be owned by the
/// pipeline context and accessed only from the handler thread.
#[derive(Debug, Default)]
pub struct RTCStatsAccumulator {
    /// Peer connection level stats.
    pub peer_connection: PeerConnectionStatsAccumulator,

    /// Transport stats (typically one per peer connection).
    pub transport: TransportStatsAccumulator,

    /// ICE candidate pairs keyed by pair ID.
    pub ice_candidate_pairs: HashMap<String, IceCandidatePairAccumulator>,

    /// Local ICE candidates keyed by candidate ID.
    pub local_candidates: HashMap<String, IceCandidateAccumulator>,

    /// Remote ICE candidates keyed by candidate ID.
    pub remote_candidates: HashMap<String, IceCandidateAccumulator>,

    /// Certificate stats keyed by fingerprint.
    pub certificates: HashMap<String, CertificateStatsAccumulator>,

    /// Codec stats keyed by codec ID.
    pub codecs: HashMap<String, CodecStatsAccumulator>,

    /// Data channel stats keyed by channel ID.
    pub data_channels: HashMap<RTCDataChannelId, DataChannelStatsAccumulator>,

    /// Inbound RTP stream accumulators keyed by SSRC.
    pub inbound_rtp_streams: HashMap<SSRC, InboundRtpStreamAccumulator>,

    /// Outbound RTP stream accumulators keyed by SSRC.
    pub outbound_rtp_streams: HashMap<SSRC, OutboundRtpStreamAccumulator>,

    /// Media source stats keyed by track ID.
    pub media_sources: HashMap<String, MediaSourceStatsAccumulator>,

    /// Audio playout stats keyed by playout ID.
    pub audio_playouts: HashMap<String, AudioPlayoutStatsAccumulator>,
}

impl RTCStatsAccumulator {
    /// Creates a new empty stats accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a snapshot of all accumulated stats at the given timestamp.
    ///
    /// This method iterates through all accumulators and produces an
    /// immutable `RTCStatsReport` containing all current statistics.
    ///
    /// # Arguments
    ///
    /// * `now` - The timestamp to use for all stats in the report
    ///
    /// # Returns
    ///
    /// An `RTCStatsReport` containing snapshots of all accumulated stats.
    pub fn snapshot(&self, now: Instant) -> RTCStatsReport {
        let mut entries = Vec::new();

        // Peer connection stats
        entries.push(RTCStatsReportEntry::PeerConnection(
            self.peer_connection.snapshot(now),
        ));

        // Transport stats
        entries.push(RTCStatsReportEntry::Transport(self.transport.snapshot(now)));

        // ICE candidate pair stats
        for (id, pair) in &self.ice_candidate_pairs {
            entries.push(RTCStatsReportEntry::IceCandidatePair(
                pair.snapshot(now, id),
            ));
        }

        // Local ICE candidate stats
        for (id, candidate) in &self.local_candidates {
            entries.push(RTCStatsReportEntry::LocalCandidate(
                candidate.snapshot_local(now, id),
            ));
        }

        // Remote ICE candidate stats
        for (id, candidate) in &self.remote_candidates {
            entries.push(RTCStatsReportEntry::RemoteCandidate(
                candidate.snapshot_remote(now, id),
            ));
        }

        // Certificate stats
        for (id, cert) in &self.certificates {
            entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
        }

        // Codec stats
        for (id, codec) in &self.codecs {
            entries.push(RTCStatsReportEntry::Codec(codec.snapshot(now, id)));
        }

        // Data channel stats
        for (id, channel) in &self.data_channels {
            entries.push(RTCStatsReportEntry::DataChannel(
                channel.snapshot(now, &format!("RTCDataChannel_{}", id)),
            ));
        }

        // Inbound RTP stream stats
        for (ssrc, stream) in &self.inbound_rtp_streams {
            let id = format!("RTCInboundRTPStream_{}_{}", stream.kind, ssrc);
            entries.push(RTCStatsReportEntry::InboundRtp(stream.snapshot(now, &id)));
            // Also add remote outbound stats derived from RTCP SR
            entries.push(RTCStatsReportEntry::RemoteOutboundRtp(
                stream.snapshot_remote(now),
            ));
        }

        // Outbound RTP stream stats
        for (ssrc, stream) in &self.outbound_rtp_streams {
            let id = format!("RTCOutboundRTPStream_{}_{}", stream.kind, ssrc);
            entries.push(RTCStatsReportEntry::OutboundRtp(stream.snapshot(now, &id)));
            // Also add remote inbound stats derived from RTCP RR
            entries.push(RTCStatsReportEntry::RemoteInboundRtp(
                stream.snapshot_remote(now),
            ));
        }

        // Media source stats
        for (id, source) in &self.media_sources {
            match source.kind {
                RtpCodecKind::Audio => {
                    entries.push(RTCStatsReportEntry::AudioSource(
                        source.snapshot_audio(now, id),
                    ));
                }
                RtpCodecKind::Video => {
                    entries.push(RTCStatsReportEntry::VideoSource(
                        source.snapshot_video(now, id),
                    ));
                }
                _ => {}
            }
        }

        // Audio playout stats
        for (id, playout) in &self.audio_playouts {
            entries.push(RTCStatsReportEntry::AudioPlayout(playout.snapshot(now, id)));
        }

        RTCStatsReport::new(entries)
    }

    // ========================================================================
    // Convenience methods for updating stats
    // ========================================================================

    /// Gets or creates an inbound stream accumulator for the given SSRC.
    pub fn get_or_create_inbound_rtp_streams(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
    ) -> &mut InboundRtpStreamAccumulator {
        self.inbound_rtp_streams
            .entry(ssrc)
            .or_insert_with(|| InboundRtpStreamAccumulator {
                ssrc,
                kind,
                transport_id: "transport".to_string(),
                ..Default::default()
            })
    }

    /// Gets or creates an outbound stream accumulator for the given SSRC.
    pub fn get_or_create_outbound_rtp_streams(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
    ) -> &mut OutboundRtpStreamAccumulator {
        self.outbound_rtp_streams
            .entry(ssrc)
            .or_insert_with(|| OutboundRtpStreamAccumulator {
                ssrc,
                kind,
                transport_id: "transport".to_string(),
                active: true,
                ..Default::default()
            })
    }

    /// Gets or creates a data channel accumulator.
    pub fn get_or_create_data_channel(
        &mut self,
        id: RTCDataChannelId,
    ) -> &mut DataChannelStatsAccumulator {
        self.data_channels
            .entry(id)
            .or_insert_with(|| DataChannelStatsAccumulator {
                data_channel_identifier: id,
                ..Default::default()
            })
    }

    /// Gets or creates an ICE candidate pair accumulator.
    pub fn get_or_create_candidate_pair(
        &mut self,
        pair_id: &str,
    ) -> &mut IceCandidatePairAccumulator {
        self.ice_candidate_pairs
            .entry(pair_id.to_string())
            .or_default()
    }

    /// Registers a local ICE candidate.
    pub fn register_local_candidate(&mut self, id: String, candidate: IceCandidateAccumulator) {
        self.local_candidates.insert(id, candidate);
    }

    /// Registers a remote ICE candidate.
    pub fn register_remote_candidate(&mut self, id: String, candidate: IceCandidateAccumulator) {
        self.remote_candidates.insert(id, candidate);
    }

    /// Registers a certificate.
    pub fn register_certificate(&mut self, fingerprint: String, cert: CertificateStatsAccumulator) {
        self.certificates.insert(fingerprint, cert);
    }

    /// Gets or creates a media source accumulator.
    pub fn get_or_create_media_source(
        &mut self,
        track_id: &str,
        kind: RtpCodecKind,
    ) -> &mut MediaSourceStatsAccumulator {
        self.media_sources
            .entry(track_id.to_string())
            .or_insert_with(|| MediaSourceStatsAccumulator {
                track_id: track_id.to_string(),
                kind,
                ..Default::default()
            })
    }

    /// Gets or creates an audio playout accumulator.
    pub fn get_or_create_audio_playout(
        &mut self,
        playout_id: &str,
    ) -> &mut AudioPlayoutStatsAccumulator {
        self.audio_playouts
            .entry(playout_id.to_string())
            .or_insert_with(|| AudioPlayoutStatsAccumulator {
                kind: RtpCodecKind::Audio,
                ..Default::default()
            })
    }

    // ========================================================================
    // Application-provided stats updates
    // ========================================================================

    /// Updates decoder stats for an inbound video stream.
    pub fn update_decoder_stats(&mut self, ssrc: SSRC, stats: DecoderStatsUpdate) {
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.decoder_stats = Some(stats);
        }
    }

    /// Updates encoder stats for an outbound video stream.
    pub fn update_encoder_stats(&mut self, ssrc: SSRC, stats: EncoderStatsUpdate) {
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.encoder_stats = Some(stats);
        }
    }

    /// Updates audio receiver stats for an inbound audio stream.
    pub fn update_audio_receiver_stats(&mut self, ssrc: SSRC, stats: AudioReceiverStatsUpdate) {
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.audio_receiver_stats = Some(stats);
        }
    }

    /// Updates audio source stats.
    pub fn update_audio_source_stats(&mut self, track_id: &str, stats: AudioSourceStatsUpdate) {
        if let Some(source) = self.media_sources.get_mut(track_id) {
            source.audio_level = Some(stats.audio_level);
            source.total_audio_energy = Some(stats.total_audio_energy);
            source.total_samples_duration = Some(stats.total_samples_duration);
            source.echo_return_loss = Some(stats.echo_return_loss);
            source.echo_return_loss_enhancement = Some(stats.echo_return_loss_enhancement);
        }
    }

    /// Updates video source stats.
    pub fn update_video_source_stats(&mut self, track_id: &str, stats: VideoSourceStatsUpdate) {
        if let Some(source) = self.media_sources.get_mut(track_id) {
            source.width = Some(stats.width);
            source.height = Some(stats.height);
            source.frames = Some(stats.frames);
            source.frames_per_second = Some(stats.frames_per_second);
        }
    }

    /// Updates audio playout stats.
    pub fn update_audio_playout_stats(&mut self, playout_id: &str, stats: AudioPlayoutStatsUpdate) {
        if let Some(playout) = self.audio_playouts.get_mut(playout_id) {
            playout.synthesized_samples_duration = stats.synthesized_samples_duration;
            playout.synthesized_samples_events = stats.synthesized_samples_events;
            playout.total_samples_duration = stats.total_samples_duration;
            playout.total_playout_delay = stats.total_playout_delay;
            playout.total_samples_count = stats.total_samples_count;
        }
    }

    /// Updates STUN transaction stats from the ice agent's CandidatePairStats to the RTC accumulator.
    ///
    /// This method merges the STUN-level stats (requests, responses, RTT) from the ice agent
    /// with the application-level stats (packets, bytes) tracked at the RTC layer.
    ///
    /// # Arguments
    ///
    /// * `pair_id` - The ID of the candidate pair to sync
    /// * `cp_stats.` - CandidatePairStats
    pub fn update_ice_agent_stats(&mut self, pair_id: &str, cp_stats: &CandidatePairStats) {
        let pair = self.get_or_create_candidate_pair(pair_id);
        pair.requests_sent = cp_stats.requests_sent;
        pair.requests_received = cp_stats.requests_received;
        pair.responses_sent = cp_stats.responses_sent;
        pair.responses_received = cp_stats.responses_received;
        pair.consent_requests_sent = cp_stats.consent_requests_sent;
        pair.total_round_trip_time = cp_stats.total_round_trip_time;
        pair.current_round_trip_time = cp_stats.current_round_trip_time;
    }

    // ========================================================================
    // Codec stats methods
    // ========================================================================

    /// Registers a codec for an inbound RTP stream and sets the codec_id.
    ///
    /// Per W3C spec, codecs are only exposed when referenced by an RTP stream.
    /// This method registers the codec (if not already registered) and links it
    /// to the inbound RTP stream.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - The SSRC of the inbound RTP stream
    /// * `codec` - The codec information
    /// * `payload_type` - The payload type for this codec
    pub fn register_inbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        let transport_id = self.transport.transport_id.clone();
        let codec_id = CodecStatsAccumulator::generate_id(
            &transport_id,
            CodecDirection::Receive,
            payload_type,
        );

        // Register the codec if not already present
        self.codecs
            .entry(codec_id.clone())
            .or_insert_with(|| CodecStatsAccumulator::from_codec(codec, payload_type));

        // Link the codec to the inbound RTP stream
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.codec_id = codec_id;
        }
    }

    /// Registers a codec for an outbound RTP stream and sets the codec_id.
    ///
    /// Per W3C spec, codecs are only exposed when referenced by an RTP stream.
    /// This method registers the codec (if not already registered) and links it
    /// to the outbound RTP stream.
    ///
    /// # Arguments
    ///
    /// * `ssrc` - The SSRC of the outbound RTP stream
    /// * `codec` - The codec information
    /// * `payload_type` - The payload type for this codec
    pub fn register_outbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        let transport_id = self.transport.transport_id.clone();
        let codec_id =
            CodecStatsAccumulator::generate_id(&transport_id, CodecDirection::Send, payload_type);

        // Register the codec if not already present
        self.codecs
            .entry(codec_id.clone())
            .or_insert_with(|| CodecStatsAccumulator::from_codec(codec, payload_type));

        // Link the codec to the outbound RTP stream
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.codec_id = codec_id;
        }
    }

    /// Removes codecs that are no longer referenced by any RTP stream.
    ///
    /// Per W3C spec, when there is no longer any reference to an RTCCodecStats,
    /// the stats object should be deleted.
    pub fn cleanup_unreferenced_codecs(&mut self) {
        // Collect all referenced codec IDs
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();

        for stream in self.inbound_rtp_streams.values() {
            if !stream.codec_id.is_empty() {
                referenced.insert(stream.codec_id.clone());
            }
        }

        for stream in self.outbound_rtp_streams.values() {
            if !stream.codec_id.is_empty() {
                referenced.insert(stream.codec_id.clone());
            }
        }

        // Remove codecs that are not referenced
        self.codecs.retain(|id, _| referenced.contains(id));
    }
}
