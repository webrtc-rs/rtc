use super::super::RTCStats;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCMediaSourceStats {
    pub stats: RTCStats,

    pub track_id: String,
    pub kind: RtpCodecKind,
}
