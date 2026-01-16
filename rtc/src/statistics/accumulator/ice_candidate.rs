//! ICE candidate and candidate pair statistics accumulators.

use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use crate::statistics::stats::ice_candidate::RTCIceCandidateStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated ICE candidate statistics.
///
/// This struct holds static candidate information that doesn't change after
/// the candidate is gathered/received.
#[derive(Debug, Default, Clone)]
pub struct IceCandidateAccumulator {
    /// The transport ID this candidate belongs to.
    pub transport_id: String,
    /// The IP address of the candidate.
    pub address: Option<String>,
    /// The port number of the candidate.
    pub port: u16,
    /// The protocol used (UDP/TCP).
    pub protocol: String,
    /// The type of candidate (host, srflx, prflx, relay).
    pub candidate_type: RTCIceCandidateType,
    /// The priority of the candidate.
    pub priority: u16,
    /// The URL of the STUN/TURN server used to gather this candidate.
    pub url: String,
    /// The relay protocol used for TURN candidates.
    pub relay_protocol: RTCIceServerTransportProtocol,
    /// The foundation string for the candidate.
    pub foundation: String,
    /// The related address for server-reflexive/relayed candidates.
    pub related_address: String,
    /// The related port for server-reflexive/relayed candidates.
    pub related_port: u16,
    /// The username fragment from ICE.
    pub username_fragment: String,
    /// The TCP type (active, passive, so) for TCP candidates.
    pub tcp_type: RTCIceTcpCandidateType,
}

impl IceCandidateAccumulator {
    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str, is_local: bool) -> RTCIceCandidateStats {
        RTCIceCandidateStats {
            stats: RTCStats {
                timestamp: now,
                typ: if is_local {
                    RTCStatsType::LocalCandidate
                } else {
                    RTCStatsType::RemoteCandidate
                },
                id: id.to_string(),
            },
            transport_id: self.transport_id.clone(),
            address: self.address.clone(),
            port: self.port,
            protocol: self.protocol.clone(),
            candidate_type: self.candidate_type,
            priority: self.priority,
            url: self.url.clone(),
            relay_protocol: self.relay_protocol,
            foundation: self.foundation.clone(),
            related_address: self.related_address.clone(),
            related_port: self.related_port,
            username_fragment: self.username_fragment.clone(),
            tcp_type: self.tcp_type,
        }
    }

    /// Creates a snapshot for a local candidate.
    pub fn snapshot_local(&self, now: Instant, id: &str) -> RTCIceCandidateStats {
        self.snapshot(now, id, true)
    }

    /// Creates a snapshot for a remote candidate.
    pub fn snapshot_remote(&self, now: Instant, id: &str) -> RTCIceCandidateStats {
        self.snapshot(now, id, false)
    }
}
