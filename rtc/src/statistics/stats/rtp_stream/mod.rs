use super::RTCStats;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

pub mod received;
pub mod sent;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRtpStreamStats {
    pub stats: RTCStats,

    pub ssrc: SSRC,
    pub kind: RtpCodecKind,
    pub transport_id: String,
    pub codec_id: String,
}
