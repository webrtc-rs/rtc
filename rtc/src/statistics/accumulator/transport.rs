//! Transport statistics accumulator.

use crate::peer_connection::transport::{
    RTCDtlsRole, RTCDtlsTransportState, RTCIceRole, RTCIceTransportState,
};
use crate::statistics::stats::transport::RTCTransportStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated transport-level statistics.
///
/// This struct tracks packet/byte counters, ICE/DTLS state, and
/// security parameters for the transport layer.
#[derive(Debug)]
pub struct TransportStatsAccumulator {
    /// Unique identifier for this transport.
    pub transport_id: String,

    // Packet/byte counters
    /// Total packets sent through the transport.
    pub packets_sent: u64,
    /// Total packets received through the transport.
    pub packets_received: u64,
    /// Total bytes sent through the transport.
    pub bytes_sent: u64,
    /// Total bytes received through the transport.
    pub bytes_received: u64,

    // ICE state
    /// The ICE role (controlling/controlled).
    pub ice_role: RTCIceRole,
    /// The local ICE username fragment.
    pub ice_local_username_fragment: String,
    /// The current ICE transport state.
    pub ice_state: RTCIceTransportState,

    // DTLS state
    /// The current DTLS transport state.
    pub dtls_state: RTCDtlsTransportState,
    /// The DTLS role (client/server).
    pub dtls_role: RTCDtlsRole,
    /// The TLS version negotiated (e.g., "DTLS 1.2").
    pub tls_version: String,
    /// The DTLS cipher suite name.
    pub dtls_cipher: String,

    // SRTP
    /// The SRTP cipher suite name.
    pub srtp_cipher: String,

    // Selected candidate pair
    /// ID of the currently selected candidate pair.
    pub selected_candidate_pair_id: String,
    /// Number of times the selected candidate pair has changed.
    pub selected_candidate_pair_changes: u32,

    // Certificate references
    /// ID of the local certificate stats.
    pub local_certificate_id: String,
    /// ID of the remote certificate stats.
    pub remote_certificate_id: String,

    // Congestion control feedback
    /// Number of RTCP congestion control feedback messages sent.
    pub ccfb_messages_sent: u32,
    /// Number of RTCP congestion control feedback messages received.
    pub ccfb_messages_received: u32,
}

impl TransportStatsAccumulator {
    /// Called when a packet is sent through the transport.
    pub fn on_packet_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Called when a packet is received through the transport.
    pub fn on_packet_received(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
    }

    /// Called when the selected candidate pair changes.
    pub fn on_selected_candidate_pair_changed(&mut self, pair_id: String) {
        self.selected_candidate_pair_id = pair_id;
        self.selected_candidate_pair_changes += 1;
    }

    /// Called when ICE state changes.
    pub fn on_ice_state_changed(&mut self, state: RTCIceTransportState) {
        self.ice_state = state;
    }

    /// Called when DTLS state changes.
    pub fn on_dtls_state_changed(&mut self, state: RTCDtlsTransportState) {
        self.dtls_state = state;
    }

    /// Called when DTLS handshake completes to record security parameters.
    pub fn on_dtls_handshake_complete(
        &mut self,
        tls_version: String,
        dtls_cipher: String,
        srtp_cipher: String,
        dtls_role: RTCDtlsRole,
    ) {
        self.tls_version = tls_version;
        self.dtls_cipher = dtls_cipher;
        self.srtp_cipher = srtp_cipher;
        self.dtls_role = dtls_role;
    }

    /// Called when CCFB message is sent.
    pub fn on_ccfb_sent(&mut self) {
        self.ccfb_messages_sent += 1;
    }

    /// Called when CCFB message is received.
    pub fn on_ccfb_received(&mut self) {
        self.ccfb_messages_received += 1;
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant) -> RTCTransportStats {
        RTCTransportStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::Transport,
                id: self.transport_id.clone(),
            },
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            ice_role: self.ice_role,
            ice_local_username_fragment: self.ice_local_username_fragment.clone(),
            dtls_state: self.dtls_state,
            ice_state: self.ice_state,
            selected_candidate_pair_id: self.selected_candidate_pair_id.clone(),
            local_certificate_id: self.local_certificate_id.clone(),
            remote_certificate_id: self.remote_certificate_id.clone(),
            tls_version: self.tls_version.clone(),
            dtls_cipher: self.dtls_cipher.clone(),
            dtls_role: self.dtls_role,
            srtp_cipher: self.srtp_cipher.clone(),
            selected_candidate_pair_changes: self.selected_candidate_pair_changes,
            ccfb_messages_sent: self.ccfb_messages_sent,
            ccfb_messages_received: self.ccfb_messages_received,
        }
    }
}

impl Default for TransportStatsAccumulator {
    fn default() -> Self {
        Self {
            transport_id: "RTCTransport".to_string(),
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            ice_role: RTCIceRole::default(),
            ice_local_username_fragment: String::new(),
            ice_state: RTCIceTransportState::default(),
            dtls_state: RTCDtlsTransportState::default(),
            dtls_role: RTCDtlsRole::default(),
            tls_version: String::new(),
            dtls_cipher: String::new(),
            srtp_cipher: String::new(),
            selected_candidate_pair_id: String::new(),
            selected_candidate_pair_changes: 0,
            local_certificate_id: String::new(),
            remote_certificate_id: String::new(),
            ccfb_messages_sent: 0,
            ccfb_messages_received: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = TransportStatsAccumulator::default();
        assert_eq!(acc.transport_id, "RTCTransport");
        assert_eq!(acc.packets_sent, 0);
        assert_eq!(acc.packets_received, 0);
        assert_eq!(acc.bytes_sent, 0);
        assert_eq!(acc.bytes_received, 0);
        assert_eq!(acc.selected_candidate_pair_changes, 0);
        assert_eq!(acc.ccfb_messages_sent, 0);
        assert_eq!(acc.ccfb_messages_received, 0);
    }

    #[test]
    fn test_on_packet_sent() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_packet_sent(100);
        assert_eq!(acc.packets_sent, 1);
        assert_eq!(acc.bytes_sent, 100);

        acc.on_packet_sent(200);
        assert_eq!(acc.packets_sent, 2);
        assert_eq!(acc.bytes_sent, 300);
    }

    #[test]
    fn test_on_packet_received() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_packet_received(150);
        assert_eq!(acc.packets_received, 1);
        assert_eq!(acc.bytes_received, 150);

        acc.on_packet_received(250);
        assert_eq!(acc.packets_received, 2);
        assert_eq!(acc.bytes_received, 400);
    }

    #[test]
    fn test_on_selected_candidate_pair_changed() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_selected_candidate_pair_changed("pair_1".to_string());
        assert_eq!(acc.selected_candidate_pair_id, "pair_1");
        assert_eq!(acc.selected_candidate_pair_changes, 1);

        acc.on_selected_candidate_pair_changed("pair_2".to_string());
        assert_eq!(acc.selected_candidate_pair_id, "pair_2");
        assert_eq!(acc.selected_candidate_pair_changes, 2);
    }

    #[test]
    fn test_on_ice_state_changed() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_ice_state_changed(RTCIceTransportState::Checking);
        assert_eq!(acc.ice_state, RTCIceTransportState::Checking);

        acc.on_ice_state_changed(RTCIceTransportState::Connected);
        assert_eq!(acc.ice_state, RTCIceTransportState::Connected);

        acc.on_ice_state_changed(RTCIceTransportState::Completed);
        assert_eq!(acc.ice_state, RTCIceTransportState::Completed);
    }

    #[test]
    fn test_on_dtls_state_changed() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_dtls_state_changed(RTCDtlsTransportState::Connecting);
        assert_eq!(acc.dtls_state, RTCDtlsTransportState::Connecting);

        acc.on_dtls_state_changed(RTCDtlsTransportState::Connected);
        assert_eq!(acc.dtls_state, RTCDtlsTransportState::Connected);
    }

    #[test]
    fn test_on_dtls_handshake_complete() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_dtls_handshake_complete(
            "DTLS 1.2".to_string(),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
            "SRTP_AES128_CM_HMAC_SHA1_80".to_string(),
            RTCDtlsRole::Client,
        );

        assert_eq!(acc.tls_version, "DTLS 1.2");
        assert_eq!(acc.dtls_cipher, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(acc.srtp_cipher, "SRTP_AES128_CM_HMAC_SHA1_80");
        assert_eq!(acc.dtls_role, RTCDtlsRole::Client);
    }

    #[test]
    fn test_on_ccfb_sent_received() {
        let mut acc = TransportStatsAccumulator::default();

        acc.on_ccfb_sent();
        acc.on_ccfb_sent();
        assert_eq!(acc.ccfb_messages_sent, 2);

        acc.on_ccfb_received();
        assert_eq!(acc.ccfb_messages_received, 1);
    }

    #[test]
    fn test_bidirectional_traffic() {
        let mut acc = TransportStatsAccumulator::default();

        // Simulate traffic flow
        acc.on_packet_sent(100);
        acc.on_packet_received(80);
        acc.on_packet_sent(200);
        acc.on_packet_received(150);
        acc.on_packet_sent(50);
        acc.on_packet_received(120);

        assert_eq!(acc.packets_sent, 3);
        assert_eq!(acc.bytes_sent, 350);
        assert_eq!(acc.packets_received, 3);
        assert_eq!(acc.bytes_received, 350);
    }

    #[test]
    fn test_snapshot() {
        let mut acc = TransportStatsAccumulator::default();
        acc.transport_id = "RTCTransport_0".to_string();
        acc.on_packet_sent(100);
        acc.on_packet_received(80);
        acc.on_ice_state_changed(RTCIceTransportState::Connected);
        acc.on_dtls_state_changed(RTCDtlsTransportState::Connected);
        acc.on_dtls_handshake_complete(
            "DTLS 1.2".to_string(),
            "AES_GCM".to_string(),
            "SRTP_AES".to_string(),
            RTCDtlsRole::Server,
        );
        acc.on_selected_candidate_pair_changed("pair_1".to_string());
        acc.on_ccfb_sent();
        acc.on_ccfb_received();

        let now = Instant::now();
        let stats = acc.snapshot(now);

        assert_eq!(stats.stats.id, "RTCTransport_0");
        assert_eq!(stats.stats.typ, RTCStatsType::Transport);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_received, 80);
        assert_eq!(stats.ice_state, RTCIceTransportState::Connected);
        assert_eq!(stats.dtls_state, RTCDtlsTransportState::Connected);
        assert_eq!(stats.tls_version, "DTLS 1.2");
        assert_eq!(stats.dtls_cipher, "AES_GCM");
        assert_eq!(stats.srtp_cipher, "SRTP_AES");
        assert_eq!(stats.dtls_role, RTCDtlsRole::Server);
        assert_eq!(stats.selected_candidate_pair_id, "pair_1");
        assert_eq!(stats.selected_candidate_pair_changes, 1);
        assert_eq!(stats.ccfb_messages_sent, 1);
        assert_eq!(stats.ccfb_messages_received, 1);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let mut acc = TransportStatsAccumulator::default();
        acc.on_packet_sent(500);
        acc.on_packet_received(400);

        let now = Instant::now();
        let stats = acc.snapshot(now);

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"packetsSent\":1"));
        assert!(json.contains("\"bytesSent\":500"));
        assert!(json.contains("\"packetsReceived\":1"));
        assert!(json.contains("\"bytesReceived\":400"));
        assert!(json.contains("\"type\":\"transport\""));
    }
}
