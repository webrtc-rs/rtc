//! ICE candidate statistics.
//!
//! This module contains the [`RTCIceCandidateStats`] type which provides
//! information about ICE candidates.

use super::RTCStats;
use crate::peer_connection::transport::RTCIceCandidateType;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use serde::{Deserialize, Serialize};

/// Statistics for an ICE candidate.
///
/// This struct corresponds to the `RTCIceCandidateStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about a local or
/// remote ICE candidate discovered during ICE gathering.
///
/// # W3C Reference
///
/// See [RTCIceCandidateStats](https://www.w3.org/TR/webrtc-stats/#icecandidate-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The ID of the transport this candidate belongs to.
    pub transport_id: String,

    /// The IP address of the candidate.
    ///
    /// This may be `None` if the address is not available or redacted
    /// for privacy reasons.
    pub address: Option<String>,

    /// The port number of the candidate.
    pub port: u16,

    /// The transport protocol used ("udp" or "tcp").
    pub protocol: String,

    /// The type of ICE candidate.
    ///
    /// Values: host, srflx (server-reflexive), prflx (peer-reflexive), relay.
    pub candidate_type: RTCIceCandidateType,

    /// The priority of the candidate.
    ///
    /// Higher values indicate higher priority candidates.
    pub priority: u16,

    /// The URL of the ICE server used to gather this candidate.
    ///
    /// For host candidates, this is empty.
    pub url: String,

    /// The protocol used to communicate with the TURN server.
    ///
    /// Only applicable for relay candidates.
    pub relay_protocol: RTCIceServerTransportProtocol,

    /// The foundation string for the candidate.
    ///
    /// Candidates with the same foundation can potentially be
    /// used for candidate pair pruning.
    pub foundation: String,

    /// The related address for derived candidates.
    ///
    /// For server-reflexive candidates, this is the host address.
    /// For relay candidates, this is the server-reflexive address.
    pub related_address: String,

    /// The related port for derived candidates.
    pub related_port: u16,

    /// The username fragment from ICE credentials.
    pub username_fragment: String,

    /// The TCP candidate type.
    ///
    /// Only applicable when protocol is "tcp".
    /// Values: active, passive, so (simultaneous-open).
    pub tcp_type: RTCIceTcpCandidateType,
}
