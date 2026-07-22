//! WebRTC Statistics Report types.
//!
//! This module provides the `RTCStatsReport` type which is the return value
//! of `getStats()` and contains a collection of statistics objects.

use crate::statistics::stats::RTCStatsType;
use crate::statistics::stats::certificate::RTCCertificateStats;
use crate::statistics::stats::codec::RTCCodecStats;
use crate::statistics::stats::data_channel::RTCDataChannelStats;
use crate::statistics::stats::ice_candidate::RTCIceCandidateStats;
use crate::statistics::stats::ice_candidate_pair::RTCIceCandidatePairStats;
use crate::statistics::stats::media::audio_playout::RTCAudioPlayoutStats;
use crate::statistics::stats::media::audio_source::RTCAudioSourceStats;
use crate::statistics::stats::media::video_source::RTCVideoSourceStats;
use crate::statistics::stats::peer_connection::RTCPeerConnectionStats;
use crate::statistics::stats::rtp_stream::received::inbound::RTCInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::remote_inbound::RTCRemoteInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::outbound::RTCOutboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::remote_outbound::RTCRemoteOutboundRtpStreamStats;
use crate::statistics::stats::transport::RTCTransportStats;
use std::collections::HashMap;

/// An entry in the stats report representing a single statistics object.
///
/// Each variant corresponds to a different W3C WebRTC stats dictionary type.
#[derive(Debug)]
pub enum RTCStatsReportEntry {
    /// Peer connection level statistics.
    PeerConnection(RTCPeerConnectionStats),
    /// Transport statistics.
    Transport(RTCTransportStats),
    /// ICE candidate pair statistics.
    IceCandidatePair(RTCIceCandidatePairStats),
    /// Local ICE candidate statistics.
    LocalCandidate(RTCIceCandidateStats),
    /// Remote ICE candidate statistics.
    RemoteCandidate(RTCIceCandidateStats),
    /// Certificate statistics.
    Certificate(RTCCertificateStats),
    /// Codec statistics.
    Codec(RTCCodecStats),
    /// Data channel statistics.
    DataChannel(RTCDataChannelStats),
    /// Inbound RTP stream statistics.
    InboundRtp(RTCInboundRtpStreamStats),
    /// Outbound RTP stream statistics.
    OutboundRtp(RTCOutboundRtpStreamStats),
    /// Remote inbound RTP stream statistics (from RTCP RR).
    RemoteInboundRtp(RTCRemoteInboundRtpStreamStats),
    /// Remote outbound RTP stream statistics (from RTCP SR).
    RemoteOutboundRtp(RTCRemoteOutboundRtpStreamStats),
    /// Audio source statistics.
    AudioSource(RTCAudioSourceStats),
    /// Video source statistics.
    VideoSource(RTCVideoSourceStats),
    /// Audio playout statistics.
    AudioPlayout(RTCAudioPlayoutStats),
}

impl RTCStatsReportEntry {
    /// Returns the stats type for this entry.
    pub fn stats_type(&self) -> RTCStatsType {
        match self {
            RTCStatsReportEntry::PeerConnection(_) => RTCStatsType::PeerConnection,
            RTCStatsReportEntry::Transport(_) => RTCStatsType::Transport,
            RTCStatsReportEntry::IceCandidatePair(_) => RTCStatsType::CandidatePair,
            RTCStatsReportEntry::LocalCandidate(_) => RTCStatsType::LocalCandidate,
            RTCStatsReportEntry::RemoteCandidate(_) => RTCStatsType::RemoteCandidate,
            RTCStatsReportEntry::Certificate(_) => RTCStatsType::Certificate,
            RTCStatsReportEntry::Codec(_) => RTCStatsType::Codec,
            RTCStatsReportEntry::DataChannel(_) => RTCStatsType::DataChannel,
            RTCStatsReportEntry::InboundRtp(_) => RTCStatsType::InboundRTP,
            RTCStatsReportEntry::OutboundRtp(_) => RTCStatsType::OutboundRTP,
            RTCStatsReportEntry::RemoteInboundRtp(_) => RTCStatsType::RemoteInboundRTP,
            RTCStatsReportEntry::RemoteOutboundRtp(_) => RTCStatsType::RemoteOutboundRTP,
            RTCStatsReportEntry::AudioSource(_) => RTCStatsType::MediaSource,
            RTCStatsReportEntry::VideoSource(_) => RTCStatsType::MediaSource,
            RTCStatsReportEntry::AudioPlayout(_) => RTCStatsType::MediaPlayout,
        }
    }

    /// Returns the unique ID for this stats entry.
    pub fn id(&self) -> &str {
        match self {
            RTCStatsReportEntry::PeerConnection(s) => &s.stats.id,
            RTCStatsReportEntry::Transport(s) => &s.stats.id,
            RTCStatsReportEntry::IceCandidatePair(s) => &s.stats.id,
            RTCStatsReportEntry::LocalCandidate(s) => &s.stats.id,
            RTCStatsReportEntry::RemoteCandidate(s) => &s.stats.id,
            RTCStatsReportEntry::Certificate(s) => &s.stats.id,
            RTCStatsReportEntry::Codec(s) => &s.stats.id,
            RTCStatsReportEntry::DataChannel(s) => &s.stats.id,
            RTCStatsReportEntry::InboundRtp(s) => {
                &s.received_rtp_stream_stats.rtp_stream_stats.stats.id
            }
            RTCStatsReportEntry::OutboundRtp(s) => {
                &s.sent_rtp_stream_stats.rtp_stream_stats.stats.id
            }
            RTCStatsReportEntry::RemoteInboundRtp(s) => {
                &s.received_rtp_stream_stats.rtp_stream_stats.stats.id
            }
            RTCStatsReportEntry::RemoteOutboundRtp(s) => {
                &s.sent_rtp_stream_stats.rtp_stream_stats.stats.id
            }
            RTCStatsReportEntry::AudioSource(s) => &s.media_source_stats.stats.id,
            RTCStatsReportEntry::VideoSource(s) => &s.media_source_stats.stats.id,
            RTCStatsReportEntry::AudioPlayout(s) => &s.stats.id,
        }
    }
}

/// A collection of statistics objects returned by `getStats()`.
///
/// This type implements the W3C RTCStatsReport interface, providing
/// map-like access to statistics objects keyed by their unique IDs.
///
/// # Example
///
/// ```ignore
/// use rtc::statistics::StatsSelector;
///
/// let report = peer_connection.get_stats(Instant::now(), StatsSelector::None);
///
/// // Iterate over all stats
/// for entry in report.iter() {
///     println!("{:?}: {:?}", entry.stats_type(), entry.id());
/// }
///
/// // Get a specific stat by ID
/// if let Some(entry) = report.get("RTCPeerConnection") {
///     println!("Found peer connection stats");
/// }
///
/// // Filter by type
/// for inbound in report.iter_by_type(RTCStatsType::InboundRTP) {
///     println!("Inbound RTP: {:?}", inbound.id());
/// }
/// ```
#[derive(Debug, Default)]
pub struct RTCStatsReport {
    /// The stats entries indexed by their unique ID.
    entries: HashMap<String, RTCStatsReportEntry>,
    /// Ordered list of entry IDs for iteration.
    order: Vec<String>,
}

impl RTCStatsReport {
    /// Creates a new stats report from a list of entries.
    pub(crate) fn new(entries: Vec<RTCStatsReportEntry>) -> Self {
        let mut map = HashMap::new();
        let mut order = Vec::with_capacity(entries.len());

        for entry in entries {
            let id = entry.id().to_string();
            order.push(id.clone());
            map.insert(id, entry);
        }

        Self {
            entries: map,
            order,
        }
    }

    /// Returns the number of stats entries in the report.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the report contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Gets a stats entry by its unique ID.
    pub fn get(&self, id: &str) -> Option<&RTCStatsReportEntry> {
        self.entries.get(id)
    }

    /// Returns true if the report contains an entry with the given ID.
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Returns an iterator over all stats entries.
    pub fn iter(&self) -> impl Iterator<Item = &RTCStatsReportEntry> {
        self.order.iter().filter_map(|id| self.entries.get(id))
    }

    /// Returns an iterator over stats entries of a specific type.
    pub fn iter_by_type(&self, typ: RTCStatsType) -> impl Iterator<Item = &RTCStatsReportEntry> {
        self.iter().filter(move |e| e.stats_type() == typ)
    }

    /// Returns an iterator over all entry IDs.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(|s| s.as_str())
    }

    // ========================================================================
    // Convenience accessors for specific stats types
    // ========================================================================

    /// Returns the peer connection stats if present.
    pub fn peer_connection(&self) -> Option<&RTCPeerConnectionStats> {
        self.get("RTCPeerConnection").and_then(|e| match e {
            RTCStatsReportEntry::PeerConnection(s) => Some(s),
            _ => None,
        })
    }

    /// Returns the transport stats if present.
    pub fn transport(&self) -> Option<&RTCTransportStats> {
        // Try both "transport" and empty transport_id
        self.entries.values().find_map(|e| match e {
            RTCStatsReportEntry::Transport(s) => Some(s),
            _ => None,
        })
    }

    /// Returns an iterator over all inbound RTP stream stats.
    pub fn inbound_rtp_streams(&self) -> impl Iterator<Item = &RTCInboundRtpStreamStats> {
        self.iter().filter_map(|e| match e {
            RTCStatsReportEntry::InboundRtp(s) => Some(s),
            _ => None,
        })
    }

    /// Returns an iterator over all outbound RTP stream stats.
    pub fn outbound_rtp_streams(&self) -> impl Iterator<Item = &RTCOutboundRtpStreamStats> {
        self.iter().filter_map(|e| match e {
            RTCStatsReportEntry::OutboundRtp(s) => Some(s),
            _ => None,
        })
    }

    /// Returns an iterator over all data channel stats.
    pub fn data_channels(&self) -> impl Iterator<Item = &RTCDataChannelStats> {
        self.iter().filter_map(|e| match e {
            RTCStatsReportEntry::DataChannel(s) => Some(s),
            _ => None,
        })
    }

    /// Returns an iterator over all ICE candidate pair stats.
    pub fn candidate_pairs(&self) -> impl Iterator<Item = &RTCIceCandidatePairStats> {
        self.iter().filter_map(|e| match e {
            RTCStatsReportEntry::IceCandidatePair(s) => Some(s),
            _ => None,
        })
    }
}
