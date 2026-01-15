use super::RTCStats;
use crate::peer_connection::transport::{
    RTCDtlsRole, RTCDtlsTransportState, RTCIceRole, RTCIceTransportState,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCTransportStats {
    pub stats: RTCStats,

    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ice_role: RTCIceRole,
    pub ice_local_username_fragment: String,
    pub dtls_state: RTCDtlsTransportState,
    pub ice_state: RTCIceTransportState,
    pub selected_candidate_pair_id: String,
    pub local_certificate_id: String,
    pub remote_certificate_id: String,
    pub tls_version: String,
    pub dtls_cipher: String,
    pub dtls_role: RTCDtlsRole,
    pub srtp_cipher: String,
    pub selected_candidate_pair_changes: u32,
    pub ccfb_messages_sent: u32,
    pub ccfb_messages_received: u32,
}
