use super::RTCStats;
use crate::peer_connection::transport::RTCIceCandidateType;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateStats {
    /// General Stats Fields
    pub stats: RTCStats,

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
