//! Statistics accumulator module.
//!
//! This module provides incremental statistics accumulation for WebRTC
//! peer connections. The accumulators are updated as events occur in the
//! handler pipeline, and snapshots can be taken at any time to produce
//! immutable stats reports.

mod app_provided;
mod audio_playout;
mod certificate;
mod codec;
mod data_channel;
mod ice;
mod media_source;
mod peer_connection;
mod rtp_stream;
mod transport;

pub use app_provided::*;
pub use audio_playout::AudioPlayoutStatsAccumulator;
pub use certificate::CertificateStatsAccumulator;
pub use codec::CodecStatsAccumulator;
pub use data_channel::DataChannelStatsAccumulator;
pub use ice::{IceCandidateAccumulator, IceCandidatePairAccumulator, IceCandidatePairCollection};
pub use media_source::MediaSourceStatsAccumulator;
pub use peer_connection::PeerConnectionStatsAccumulator;
pub use rtp_stream::{
    InboundRtpStreamAccumulator, OutboundRtpStreamAccumulator, RtpStreamStatsCollection,
};
pub use transport::TransportStatsAccumulator;

use crate::data_channel::RTCDataChannelId;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
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
    pub ice_candidate_pairs: IceCandidatePairCollection,

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

    /// RTP stream stats (inbound and outbound).
    pub rtp_streams: RtpStreamStatsCollection,

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
        for (id, pair) in &self.ice_candidate_pairs.pairs {
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
        for (ssrc, stream) in &self.rtp_streams.inbound {
            let id = format!("RTCInboundRTPStream_{}_{}", stream.kind, ssrc);
            entries.push(RTCStatsReportEntry::InboundRtp(stream.snapshot(now, &id)));
            // Also add remote outbound stats derived from RTCP SR
            entries.push(RTCStatsReportEntry::RemoteOutboundRtp(
                stream.snapshot_remote(now),
            ));
        }

        // Outbound RTP stream stats
        for (ssrc, stream) in &self.rtp_streams.outbound {
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

    /// Gets or creates an inbound RTP stream accumulator.
    pub fn get_or_create_inbound_rtp(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
    ) -> &mut InboundRtpStreamAccumulator {
        self.rtp_streams.get_or_create_inbound(ssrc, kind)
    }

    /// Gets or creates an outbound RTP stream accumulator.
    pub fn get_or_create_outbound_rtp(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
    ) -> &mut OutboundRtpStreamAccumulator {
        self.rtp_streams.get_or_create_outbound(ssrc, kind)
    }

    /// Gets or creates a data channel accumulator.
    pub fn get_or_create_data_channel(
        &mut self,
        id: RTCDataChannelId,
    ) -> &mut DataChannelStatsAccumulator {
        self.data_channels
            .entry(id)
            .or_insert_with(|| DataChannelStatsAccumulator {
                id,
                ..Default::default()
            })
    }

    /// Gets or creates an ICE candidate pair accumulator.
    pub fn get_or_create_candidate_pair(
        &mut self,
        pair_id: &str,
    ) -> &mut IceCandidatePairAccumulator {
        self.ice_candidate_pairs.get_or_create(pair_id)
    }

    /// Registers a local ICE candidate.
    pub fn register_local_candidate(&mut self, id: String, candidate: IceCandidateAccumulator) {
        self.local_candidates.insert(id, candidate);
    }

    /// Registers a remote ICE candidate.
    pub fn register_remote_candidate(&mut self, id: String, candidate: IceCandidateAccumulator) {
        self.remote_candidates.insert(id, candidate);
    }

    /// Registers a codec.
    pub fn register_codec(&mut self, id: String, codec: CodecStatsAccumulator) {
        self.codecs.insert(id, codec);
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
        if let Some(stream) = self.rtp_streams.inbound.get_mut(&ssrc) {
            stream.decoder_stats = Some(stats);
        }
    }

    /// Updates encoder stats for an outbound video stream.
    pub fn update_encoder_stats(&mut self, ssrc: SSRC, stats: EncoderStatsUpdate) {
        if let Some(stream) = self.rtp_streams.outbound.get_mut(&ssrc) {
            stream.encoder_stats = Some(stats);
        }
    }

    /// Updates audio receiver stats for an inbound audio stream.
    pub fn update_audio_receiver_stats(&mut self, ssrc: SSRC, stats: AudioReceiverStatsUpdate) {
        if let Some(stream) = self.rtp_streams.inbound.get_mut(&ssrc) {
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
}
