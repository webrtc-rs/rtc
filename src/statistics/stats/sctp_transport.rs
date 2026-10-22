//! SCTP transport statistics.
//!
//! This module contains the [`RTCSctpTransportStats`] type which provides
//! information about the SCTP association carrying this connection's data
//! channels.

use super::RTCStats;
use serde::{Deserialize, Serialize};

/// Statistics for the SCTP association carrying data channels.
///
/// This struct corresponds to the `RTCSctpTransportStats` dictionary in the
/// W3C WebRTC Statistics API. It reports the SCTP-level congestion state and
/// payload counters, which are the numbers an operator needs to diagnose a
/// slow or lossy data-channel path independently of the ICE/DTLS transport
/// underneath.
///
/// # Specification
///
/// See [RTCSctpTransportStats](https://www.w3.org/TR/webrtc-stats/#sctptransportstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCSctpTransportStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The identifier of the [`RTCTransportStats`](super::transport::RTCTransportStats) object for the DTLS/ICE
    /// transport that carries this SCTP association.
    pub transport_id: String,

    /// The latest smoothed round-trip time, in seconds.
    ///
    /// Corresponds to `spinfo_srtt` from [RFC 6458]. Zero when no RTT has been
    /// measured yet.
    ///
    /// [RFC 6458]: https://datatracker.ietf.org/doc/html/rfc6458#section-8.1.1
    pub smoothed_round_trip_time: f64,

    /// The current congestion window, in bytes.
    ///
    /// Corresponds to `spinfo_cwnd` from [RFC 6458].
    ///
    /// [RFC 6458]: https://datatracker.ietf.org/doc/html/rfc6458#section-8.1.1
    pub congestion_window: u32,

    /// The peer's latest advertised receiver window, in bytes.
    ///
    /// Corresponds to `sstat_rwnd` from [RFC 6458].
    ///
    /// [RFC 6458]: https://datatracker.ietf.org/doc/html/rfc6458#section-8.1.2
    pub receiver_window: u32,

    /// The path MTU the association transmits with, in bytes.
    pub mtu: u32,

    /// Total application payload bytes accepted for transmission on the
    /// association. Retransmissions are not double-counted.
    pub bytes_sent: u64,

    /// Total application payload bytes accepted from the peer.
    pub bytes_received: u64,
}
