use crate::statistics::stats::ice_candidate_pair::{
    RTCIceCandidatePairStats, RTCStatsIceCandidatePairState,
};
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated ICE candidate pair statistics.
///
/// This struct tracks packet/byte counters, RTT measurements, and state
/// for a candidate pair during ICE connectivity checks and media flow.
#[derive(Debug, Default)]
pub struct IceCandidatePairAccumulator {
    /// The transport ID this candidate belongs to.
    pub transport_id: String,

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
            transport_id: self.transport_id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = IceCandidatePairAccumulator::default();
        assert_eq!(acc.packets_sent, 0);
        assert_eq!(acc.packets_received, 0);
        assert_eq!(acc.bytes_sent, 0);
        assert_eq!(acc.bytes_received, 0);
        assert_eq!(acc.requests_sent, 0);
        assert_eq!(acc.responses_received, 0);
        assert_eq!(acc.total_round_trip_time, 0.0);
        assert_eq!(acc.current_round_trip_time, 0.0);
        assert!(!acc.nominated);
    }

    #[test]
    fn test_on_packet_sent() {
        let mut acc = IceCandidatePairAccumulator::default();
        let now = Instant::now();

        acc.on_packet_sent(100, now);
        assert_eq!(acc.packets_sent, 1);
        assert_eq!(acc.bytes_sent, 100);
        assert_eq!(acc.last_packet_sent_timestamp, Some(now));

        let later = now + std::time::Duration::from_millis(10);
        acc.on_packet_sent(200, later);
        assert_eq!(acc.packets_sent, 2);
        assert_eq!(acc.bytes_sent, 300);
        assert_eq!(acc.last_packet_sent_timestamp, Some(later));
    }

    #[test]
    fn test_on_packet_received() {
        let mut acc = IceCandidatePairAccumulator::default();
        let now = Instant::now();

        acc.on_packet_received(150, now);
        assert_eq!(acc.packets_received, 1);
        assert_eq!(acc.bytes_received, 150);
        assert_eq!(acc.last_packet_received_timestamp, Some(now));
    }

    #[test]
    fn test_on_rtt_measured() {
        let mut acc = IceCandidatePairAccumulator::default();

        acc.on_rtt_measured(0.050); // 50ms
        assert_eq!(acc.current_round_trip_time, 0.050);
        assert_eq!(acc.total_round_trip_time, 0.050);

        acc.on_rtt_measured(0.030); // 30ms
        assert_eq!(acc.current_round_trip_time, 0.030);
        assert_eq!(acc.total_round_trip_time, 0.080);

        acc.on_rtt_measured(0.040); // 40ms
        assert_eq!(acc.current_round_trip_time, 0.040);
        assert_eq!(acc.total_round_trip_time, 0.120);
    }

    #[test]
    fn test_stun_transactions() {
        let mut acc = IceCandidatePairAccumulator::default();

        acc.on_stun_request_sent();
        acc.on_stun_request_sent();
        assert_eq!(acc.requests_sent, 2);

        acc.on_stun_request_received();
        assert_eq!(acc.requests_received, 1);

        acc.on_stun_response_sent();
        assert_eq!(acc.responses_sent, 1);

        acc.on_stun_response_received();
        acc.on_stun_response_received();
        assert_eq!(acc.responses_received, 2);
    }

    #[test]
    fn test_consent_requests() {
        let mut acc = IceCandidatePairAccumulator::default();

        acc.on_consent_request_sent();
        acc.on_consent_request_sent();
        acc.on_consent_request_sent();
        assert_eq!(acc.consent_requests_sent, 3);
    }

    #[test]
    fn test_on_packet_discarded() {
        let mut acc = IceCandidatePairAccumulator::default();

        acc.on_packet_discarded(100);
        assert_eq!(acc.packets_discarded_on_send, 1);
        assert_eq!(acc.bytes_discarded_on_send, 100);

        acc.on_packet_discarded(200);
        assert_eq!(acc.packets_discarded_on_send, 2);
        assert_eq!(acc.bytes_discarded_on_send, 300);
    }

    #[test]
    fn test_full_ice_connectivity_check_flow() {
        let mut acc = IceCandidatePairAccumulator {
            transport_id: "RTCTransport".to_string(),
            local_candidate_id: "local_1".to_string(),
            remote_candidate_id: "remote_1".to_string(),
            ..Default::default()
        };

        let now = Instant::now();

        // Simulate connectivity check
        acc.on_stun_request_sent();
        acc.on_stun_response_received();
        acc.on_rtt_measured(0.025);

        // Pair succeeds and gets nominated
        acc.state = RTCStatsIceCandidatePairState::Succeeded;
        acc.nominated = true;

        // Media flows
        acc.on_packet_sent(1200, now);
        acc.on_packet_received(1000, now);

        assert_eq!(acc.requests_sent, 1);
        assert_eq!(acc.responses_received, 1);
        assert_eq!(acc.current_round_trip_time, 0.025);
        assert!(acc.nominated);
        assert_eq!(acc.state, RTCStatsIceCandidatePairState::Succeeded);
        assert_eq!(acc.packets_sent, 1);
        assert_eq!(acc.bytes_sent, 1200);
    }

    #[test]
    fn test_snapshot() {
        let now = Instant::now();
        let mut acc = IceCandidatePairAccumulator {
            transport_id: "RTCTransport_0".to_string(),
            local_candidate_id: "local_abc".to_string(),
            remote_candidate_id: "remote_xyz".to_string(),
            state: RTCStatsIceCandidatePairState::Succeeded,
            nominated: true,
            ..Default::default()
        };

        acc.on_packet_sent(500, now);
        acc.on_packet_received(400, now);
        acc.on_rtt_measured(0.020);

        let stats = acc.snapshot(now, "RTCIceCandidatePair_abc_xyz");

        assert_eq!(stats.stats.id, "RTCIceCandidatePair_abc_xyz");
        assert_eq!(stats.stats.typ, RTCStatsType::CandidatePair);
        assert_eq!(stats.local_candidate_id, "local_abc");
        assert_eq!(stats.remote_candidate_id, "remote_xyz");
        assert_eq!(stats.state, RTCStatsIceCandidatePairState::Succeeded);
        assert!(stats.nominated);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.bytes_sent, 500);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_received, 400);
        assert_eq!(stats.current_round_trip_time, 0.020);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let mut acc = IceCandidatePairAccumulator {
            state: RTCStatsIceCandidatePairState::Succeeded,
            nominated: true,
            ..Default::default()
        };

        acc.on_packet_sent(1000, now);
        acc.on_rtt_measured(0.050);

        let stats = acc.snapshot(now, "pair_1");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"packetsSent\":1"));
        assert!(json.contains("\"bytesSent\":1000"));
        assert!(json.contains("\"nominated\":true"));
        assert!(json.contains("\"currentRoundTripTime\":0.05"));
        assert!(json.contains("\"type\":\"candidate-pair\""));
    }
}
