//! Sent RTP stream statistics.
//!
//! This module contains statistics types for sent RTP streams:
//!
//! - [`RTCSentRtpStreamStats`] - Base statistics for sent streams
//! - [`outbound::RTCOutboundRtpStreamStats`] - Local outbound stream statistics
//! - [`remote_outbound::RTCRemoteOutboundRtpStreamStats`] - Remote outbound stream statistics

use super::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

pub mod outbound;
pub mod remote_outbound;

/// Base statistics for a sent RTP stream.
///
/// This struct corresponds to the `RTCSentRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides common fields for streams sent
/// over the network.
///
/// This type is typically not used directly; instead, use
/// [`RTCOutboundRtpStreamStats`](outbound::RTCOutboundRtpStreamStats) or
/// [`RTCRemoteOutboundRtpStreamStats`](remote_outbound::RTCRemoteOutboundRtpStreamStats).
///
/// # W3C Reference
///
/// See [RTCSentRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#sentrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCSentRtpStreamStats {
    /// Base RTP stream statistics.
    #[serde(flatten)]
    pub rtp_stream_stats: RTCRtpStreamStats,

    /// Total number of RTP packets sent.
    pub packets_sent: u64,

    /// Total number of bytes sent (excluding headers and padding).
    pub bytes_sent: u64,
}
