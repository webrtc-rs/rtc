use crate::peer_connection::transport::RTCIceCandidateType;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use crate::stats::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateStats {
    pub stats: RTCStats,

    pub transport_id: String,
    pub address: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub candidate_type: RTCIceCandidateType,
    pub priority: u16,
    pub url: String,
    pub relay_protocol: RTCIceServerTransportProtocol,
    pub foundation: String,
    pub related_address: String,
    pub related_port: u16,
    pub username_fragment: String,
    pub tcp_type: RTCIceTcpCandidateType,
}
