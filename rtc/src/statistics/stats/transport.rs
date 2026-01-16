use super::RTCStats;
use crate::peer_connection::transport::{
    RTCDtlsRole, RTCDtlsTransportState, RTCIceRole, RTCIceTransportState,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCTransportStats {
    /// General Stats Fields
    pub stats: RTCStats,

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
