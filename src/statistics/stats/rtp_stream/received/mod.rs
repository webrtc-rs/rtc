//! Received RTP stream statistics.
//!
//! This module contains statistics types for received RTP streams:
//!
//! - [`RTCReceivedRtpStreamStats`] - Base statistics for received streams
//! - [`inbound::RTCInboundRtpStreamStats`] - Local inbound stream statistics
//! - [`remote_inbound::RTCRemoteInboundRtpStreamStats`] - Remote inbound stream statistics

use super::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

pub mod inbound;
pub mod remote_inbound;

/// Base statistics for a received RTP stream.
///
/// This struct corresponds to the `RTCReceivedRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides common fields for streams received
/// from the network, including packet counts and jitter measurements.
///
/// This type is typically not used directly; instead, use
/// [`RTCInboundRtpStreamStats`](inbound::RTCInboundRtpStreamStats) or
/// [`RTCRemoteInboundRtpStreamStats`](remote_inbound::RTCRemoteInboundRtpStreamStats).
///
/// # W3C Reference
///
/// See [RTCReceivedRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#receivedrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCReceivedRtpStreamStats {
    /// Base RTP stream statistics.
    #[serde(flatten)]
    pub rtp_stream_stats: RTCRtpStreamStats,

    /// Total number of RTP packets received.
    pub packets_received: u64,

    /// Number of packets received with ECT(1) marking.
    ///
    /// ECT (ECN-Capable Transport) indicates congestion-aware transport.
    pub packets_received_with_ect1: u64,

    /// Number of packets received with CE (Congestion Experienced) marking.
    ///
    /// CE indicates network congestion was experienced.
    pub packets_received_with_ce: u64,

    /// Number of packets reported as lost in RTCP RR.
    pub packets_reported_as_lost: u64,

    /// Number of packets reported lost but later recovered.
    ///
    /// This can happen with retransmission or FEC recovery.
    pub packets_reported_as_lost_but_recovered: u64,

    /// Total number of packets lost.
    ///
    /// This value can be negative if more packets are received
    /// than expected (e.g., due to duplicates).
    pub packets_lost: i64,

    /// Inter-arrival jitter in seconds.
    ///
    /// Measured according to RFC 3550.
    pub jitter: f64,
}
