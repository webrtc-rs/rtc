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
            transport_id: "RTCTransport_0".to_string(),
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
