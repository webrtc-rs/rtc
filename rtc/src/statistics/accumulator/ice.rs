//! ICE candidate and candidate pair statistics accumulators.

use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use crate::statistics::stats::ice_candidate::RTCIceCandidateStats;
use crate::statistics::stats::ice_candidate_pair::{RTCIceCandidatePairStats, RTCStatsIceCandidatePairState};
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::collections::HashMap;
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

/// Accumulated ICE candidate pair statistics.
///
/// This struct tracks packet/byte counters, RTT measurements, and state
/// for a candidate pair during ICE connectivity checks and media flow.
#[derive(Debug, Default)]
pub struct IceCandidatePairAccumulator {
    /// Reference to the local candidate ID.
    pub local_candidate_id: String,
    /// Reference to the remote candidate ID.
    pub remote_candidate_id: String,

    // Packet/byte counters - incremented during handle_read/handle_write
    /// Total packets sent through this pair.
    pub packets_sent: u64,
    /// Total packets received through this pair.
    pub packets_received: u64,
    /// Total bytes sent through this pair.
    pub bytes_sent: u64,
    /// Total bytes received through this pair.
    pub bytes_received: u64,

    // Timestamps for last activity
    /// Timestamp of the last packet sent.
    pub last_packet_sent_timestamp: Option<Instant>,
    /// Timestamp of the last packet received.
    pub last_packet_received_timestamp: Option<Instant>,

    // RTT tracking (updated from STUN responses)
    /// Total accumulated round trip time in seconds.
    pub total_round_trip_time: f64,
    /// Most recent round trip time measurement in seconds.
    pub current_round_trip_time: f64,
    /// Number of RTT measurements taken.
    pub rtt_measurements: u32,

    // Request/response counters
    /// Number of STUN connectivity check requests sent.
    pub requests_sent: u64,
    /// Number of STUN connectivity check requests received.
    pub requests_received: u64,
    /// Number of STUN connectivity check responses sent.
    pub responses_sent: u64,
    /// Number of STUN connectivity check responses received.
    pub responses_received: u64,
    /// Number of ICE consent freshness requests sent.
    pub consent_requests_sent: u64,

    // Discard counters
    /// Packets discarded due to send failure.
    pub packets_discarded_on_send: u32,
    /// Bytes discarded due to send failure.
    pub bytes_discarded_on_send: u32,

    // Bitrate estimation (from TWCC/congestion control)
    /// Estimated available outgoing bitrate in bits per second.
    pub available_outgoing_bitrate: f64,
    /// Estimated available incoming bitrate in bits per second.
    pub available_incoming_bitrate: f64,

    // State
    /// Current state of the candidate pair.
    pub state: RTCStatsIceCandidatePairState,
    /// Whether this pair has been nominated.
    pub nominated: bool,
}

impl IceCandidatePairAccumulator {
    /// Called when a packet is sent through this candidate pair.
    pub fn on_packet_sent(&mut self, bytes: usize, now: Instant) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.last_packet_sent_timestamp = Some(now);
    }

    /// Called when a packet is received through this candidate pair.
    pub fn on_packet_received(&mut self, bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    /// Called when RTT is measured from a STUN transaction.
    pub fn on_rtt_measured(&mut self, rtt_seconds: f64) {
        self.current_round_trip_time = rtt_seconds;
        self.total_round_trip_time += rtt_seconds;
        self.rtt_measurements += 1;
    }

    /// Called when a STUN connectivity check request is sent.
    pub fn on_stun_request_sent(&mut self) {
        self.requests_sent += 1;
    }

    /// Called when a STUN connectivity check request is received.
    pub fn on_stun_request_received(&mut self) {
        self.requests_received += 1;
    }

    /// Called when a STUN connectivity check response is sent.
    pub fn on_stun_response_sent(&mut self) {
        self.responses_sent += 1;
    }

    /// Called when a STUN connectivity check response is received.
    pub fn on_stun_response_received(&mut self) {
        self.responses_received += 1;
    }

    /// Called when a consent freshness request is sent.
    pub fn on_consent_request_sent(&mut self) {
        self.consent_requests_sent += 1;
    }

    /// Called when a packet send fails.
    pub fn on_packet_discarded(&mut self, bytes: usize) {
        self.packets_discarded_on_send += 1;
        self.bytes_discarded_on_send += bytes as u32;
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCIceCandidatePairStats {
        RTCIceCandidatePairStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::CandidatePair,
                id: id.to_string(),
            },
            transport_id: "transport".to_string(),
            local_candidate_id: self.local_candidate_id.clone(),
            remote_candidate_id: self.remote_candidate_id.clone(),
            state: self.state,
            nominated: self.nominated,
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            last_packet_sent_timestamp: self.last_packet_sent_timestamp.unwrap_or(now),
            last_packet_received_timestamp: self.last_packet_received_timestamp.unwrap_or(now),
            total_round_trip_time: self.total_round_trip_time,
            current_round_trip_time: self.current_round_trip_time,
            available_outgoing_bitrate: self.available_outgoing_bitrate,
            available_incoming_bitrate: self.available_incoming_bitrate,
            requests_received: self.requests_received,
            requests_sent: self.requests_sent,
            responses_received: self.responses_received,
            responses_sent: self.responses_sent,
            consent_requests_sent: self.consent_requests_sent,
            packets_discarded_on_send: self.packets_discarded_on_send,
            bytes_discarded_on_send: self.bytes_discarded_on_send,
        }
    }
}

/// Collection of ICE candidate pair accumulators indexed by pair ID.
#[derive(Debug, Default)]
pub struct IceCandidatePairCollection {
    /// ICE candidate pairs keyed by pair ID.
    pub pairs: HashMap<String, IceCandidatePairAccumulator>,
}

impl IceCandidatePairCollection {
    /// Gets or creates a candidate pair accumulator for the given pair ID.
    pub fn get_or_create(&mut self, pair_id: &str) -> &mut IceCandidatePairAccumulator {
        self.pairs.entry(pair_id.to_string()).or_default()
    }

    /// Gets an existing candidate pair accumulator.
    pub fn get(&self, pair_id: &str) -> Option<&IceCandidatePairAccumulator> {
        self.pairs.get(pair_id)
    }

    /// Gets a mutable reference to an existing candidate pair accumulator.
    pub fn get_mut(&mut self, pair_id: &str) -> Option<&mut IceCandidatePairAccumulator> {
        self.pairs.get_mut(pair_id)
    }
}
