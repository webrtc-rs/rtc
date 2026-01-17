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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = IceCandidateAccumulator::default();
        assert_eq!(acc.transport_id, "");
        assert_eq!(acc.address, None);
        assert_eq!(acc.port, 0);
        assert_eq!(acc.protocol, "");
        assert_eq!(acc.candidate_type, RTCIceCandidateType::default());
        assert_eq!(acc.priority, 0);
        assert_eq!(acc.url, "");
        assert_eq!(acc.foundation, "");
        assert_eq!(acc.related_address, "");
        assert_eq!(acc.related_port, 0);
        assert_eq!(acc.username_fragment, "");
    }

    #[test]
    fn test_snapshot_local_host_candidate() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("192.168.1.100".to_string()),
            port: 50000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            priority: 65535, // Max u16 value for testing
            foundation: "1234567890".to_string(),
            username_fragment: "abcd1234".to_string(),
            ..Default::default()
        };

        let stats = acc.snapshot_local(now, "RTCIceCandidate_host_udp_192.168.1.100_50000");

        assert_eq!(stats.stats.id, "RTCIceCandidate_host_udp_192.168.1.100_50000");
        assert_eq!(stats.stats.typ, RTCStatsType::LocalCandidate);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(stats.transport_id, "RTCTransport_0");
        assert_eq!(stats.address, Some("192.168.1.100".to_string()));
        assert_eq!(stats.port, 50000);
        assert_eq!(stats.protocol, "udp");
        assert_eq!(stats.candidate_type, RTCIceCandidateType::Host);
        assert_eq!(stats.priority, 65535);
        assert_eq!(stats.foundation, "1234567890");
        assert_eq!(stats.username_fragment, "abcd1234");
    }

    #[test]
    fn test_snapshot_remote_srflx_candidate() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("203.0.113.50".to_string()),
            port: 60000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Srflx,
            priority: 50000,
            foundation: "9876543210".to_string(),
            related_address: "192.168.1.100".to_string(),
            related_port: 50000,
            url: "stun:stun.example.com:3478".to_string(),
            username_fragment: "efgh5678".to_string(),
            ..Default::default()
        };

        let stats = acc.snapshot_remote(now, "RTCIceCandidate_srflx_udp_203.0.113.50_60000");

        assert_eq!(stats.stats.typ, RTCStatsType::RemoteCandidate);
        assert_eq!(stats.address, Some("203.0.113.50".to_string()));
        assert_eq!(stats.port, 60000);
        assert_eq!(stats.candidate_type, RTCIceCandidateType::Srflx);
        assert_eq!(stats.related_address, "192.168.1.100");
        assert_eq!(stats.related_port, 50000);
        assert_eq!(stats.url, "stun:stun.example.com:3478");
    }

    #[test]
    fn test_snapshot_relay_candidate() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("10.0.0.50".to_string()),
            port: 49152,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Relay,
            priority: 10000,
            foundation: "relay123".to_string(),
            related_address: "192.168.1.100".to_string(),
            related_port: 50000,
            url: "turn:turn.example.com:3478".to_string(),
            relay_protocol: RTCIceServerTransportProtocol::Udp,
            username_fragment: "ijkl9012".to_string(),
            ..Default::default()
        };

        let stats = acc.snapshot_local(now, "RTCIceCandidate_relay");

        assert_eq!(stats.stats.typ, RTCStatsType::LocalCandidate);
        assert_eq!(stats.candidate_type, RTCIceCandidateType::Relay);
        assert_eq!(stats.relay_protocol, RTCIceServerTransportProtocol::Udp);
        assert_eq!(stats.url, "turn:turn.example.com:3478");
    }

    #[test]
    fn test_snapshot_tcp_candidate() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("192.168.1.100".to_string()),
            port: 9,
            protocol: "tcp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            priority: 60000,
            foundation: "tcp123".to_string(),
            tcp_type: RTCIceTcpCandidateType::Active,
            ..Default::default()
        };

        let stats = acc.snapshot_local(now, "RTCIceCandidate_host_tcp");

        assert_eq!(stats.protocol, "tcp");
        assert_eq!(stats.tcp_type, RTCIceTcpCandidateType::Active);
    }

    #[test]
    fn test_snapshot_local_vs_remote_type() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("192.168.1.100".to_string()),
            port: 50000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            ..Default::default()
        };

        let local_stats = acc.snapshot_local(now, "local_id");
        let remote_stats = acc.snapshot_remote(now, "remote_id");

        assert_eq!(local_stats.stats.typ, RTCStatsType::LocalCandidate);
        assert_eq!(remote_stats.stats.typ, RTCStatsType::RemoteCandidate);
    }

    #[test]
    fn test_clone() {
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("192.168.1.100".to_string()),
            port: 50000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            priority: 65535,
            foundation: "1234567890".to_string(),
            ..Default::default()
        };

        let cloned = acc.clone();

        assert_eq!(cloned.transport_id, acc.transport_id);
        assert_eq!(cloned.address, acc.address);
        assert_eq!(cloned.port, acc.port);
        assert_eq!(cloned.candidate_type, acc.candidate_type);
    }

    #[test]
    fn test_snapshot_json_serialization_local() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("192.168.1.100".to_string()),
            port: 50000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            priority: 65535,
            foundation: "abcd1234".to_string(),
            username_fragment: "user123".to_string(),
            ..Default::default()
        };

        let stats = acc.snapshot_local(now, "RTCIceCandidate_1");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"address\":\"192.168.1.100\""));
        assert!(json.contains("\"port\":50000"));
        assert!(json.contains("\"protocol\":\"udp\""));
        assert!(json.contains("\"candidateType\":\"host\""));
        assert!(json.contains("\"type\":\"local-candidate\""));
    }

    #[test]
    fn test_snapshot_json_serialization_remote() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: Some("203.0.113.50".to_string()),
            port: 60000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Srflx,
            ..Default::default()
        };

        let stats = acc.snapshot_remote(now, "RTCIceCandidate_2");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"candidateType\":\"srflx\""));
        assert!(json.contains("\"type\":\"remote-candidate\""));
    }

    #[test]
    fn test_address_none() {
        let now = Instant::now();
        let acc = IceCandidateAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            address: None, // Address not exposed (mDNS candidate)
            port: 50000,
            protocol: "udp".to_string(),
            candidate_type: RTCIceCandidateType::Host,
            ..Default::default()
        };

        let stats = acc.snapshot_local(now, "RTCIceCandidate_mdns");

        assert_eq!(stats.address, None);

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"address\":null"));
    }
}
