//! Remote inbound RTP stream statistics.
//!
//! This module contains the [`RTCRemoteInboundRtpStreamStats`] type which provides
//! statistics about streams received by the remote peer, derived from RTCP reports.

use super::RTCReceivedRtpStreamStats;
use serde::{Deserialize, Serialize};

/// Statistics for a remote inbound RTP stream.
///
/// This struct corresponds to the `RTCRemoteInboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It represents the remote endpoint's view of the
/// stream sent by the local endpoint, derived from RTCP Receiver Reports.
///
/// This provides insight into how well the remote peer is receiving the local
/// peer's transmitted media.
///
/// # W3C Reference
///
/// See [RTCRemoteInboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#remoteinboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteInboundRtpStreamStats {
    /// Base received RTP stream statistics.
    #[serde(flatten)]
    pub received_rtp_stream_stats: RTCReceivedRtpStreamStats,

    /// The ID of the corresponding local outbound stats.
    ///
    /// References an [`RTCOutboundRtpStreamStats`](super::super::sent::outbound::RTCOutboundRtpStreamStats) object.
    pub local_id: String,

    /// The most recent round trip time in seconds.
    ///
    /// Calculated from RTCP sender and receiver reports.
    pub round_trip_time: f64,

    /// Cumulative round trip time in seconds.
    pub total_round_trip_time: f64,

    /// Fraction of packets lost (0.0 to 1.0).
    ///
    /// Derived from RTCP receiver reports.
    pub fraction_lost: f64,

    /// Number of round trip time measurements.
    pub round_trip_time_measurements: u64,

    /// Packets with bleached ECT(1) marking.
    ///
    /// Indicates ECN marking was removed in transit.
    pub packets_with_bleached_ect1_marking: u64,
}
