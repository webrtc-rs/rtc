//! Remote outbound RTP stream statistics.
//!
//! This module contains the [`RTCRemoteOutboundRtpStreamStats`] type which provides
//! statistics about streams sent by the remote peer, derived from RTCP reports.

use super::RTCSentRtpStreamStats;
use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

/// Statistics for a remote outbound RTP stream.
///
/// This struct corresponds to the `RTCRemoteOutboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It represents the remote endpoint's view of the
/// stream it is sending, derived from RTCP Sender Reports.
///
/// This provides insight into the remote peer's transmission characteristics.
///
/// # W3C Reference
///
/// See [RTCRemoteOutboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#remoteoutboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteOutboundRtpStreamStats {
    /// Base sent RTP stream statistics.
    #[serde(flatten)]
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    /// The ID of the corresponding local inbound stats.
    ///
    /// References an [`RTCInboundRtpStreamStats`](super::super::received::inbound::RTCInboundRtpStreamStats) object.
    pub local_id: String,

    /// The remote timestamp from the RTCP SR.
    ///
    /// This is the NTP timestamp from the sender report.
    #[serde(with = "instant_to_epoch")]
    pub remote_timestamp: Instant,

    /// Number of RTCP Sender Reports sent.
    pub reports_sent: u64,

    /// The most recent round trip time in seconds.
    ///
    /// Calculated from RTCP sender and receiver reports.
    pub round_trip_time: f64,

    /// Cumulative round trip time in seconds.
    pub total_round_trip_time: f64,

    /// Number of round trip time measurements.
    pub round_trip_time_measurements: u64,
}
