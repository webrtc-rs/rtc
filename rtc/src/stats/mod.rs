//! Statistics Model (WIP)

use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use std::time::Instant;

pub mod audio_playout;
pub mod certificate;
pub mod codec;
pub mod data_channel;
pub mod ice_candidate;
pub mod ice_candidate_pair;
pub mod peer_connection;
pub mod rtp_stream;
pub mod source;
pub mod transport;

#[derive(Debug, Serialize, Deserialize)]
pub enum RTCStatsType {
    #[serde(rename = "codec")]
    Codec,
    #[serde(rename = "inbound-rtp")]
    InboundRTP,
    #[serde(rename = "outbound-rtp")]
    OutboundRTP,
    #[serde(rename = "remote-inbound-rtp")]
    RemoteInboundRTP,
    #[serde(rename = "remote-outbound-rtp")]
    RemoteOutboundRTP,
    #[serde(rename = "media-source")]
    MediaSource,
    #[serde(rename = "media-playout")]
    MediaPlayout,
    #[serde(rename = "peer-connection")]
    PeerConnection,
    #[serde(rename = "data-channel")]
    DataChannel,
    #[serde(rename = "transport")]
    Transport,
    #[serde(rename = "candidate-pair")]
    CandidatePair,
    #[serde(rename = "local-candidate")]
    LocalCandidate,
    #[serde(rename = "remote-candidate")]
    RemoteCandidate,
    #[serde(rename = "certificate")]
    Certificate,
}

pub type RTCStatsId = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct RTCStats {
    #[serde(with = "instant_to_epoch")]
    pub timestamp: Instant,
    #[serde(rename = "type")]
    pub typ: RTCStatsType,
    pub id: RTCStatsId,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RTCQualityLimitationReason {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "cpu")]
    Cpu,
    #[serde(rename = "bandwidth")]
    Bandwidth,
    #[serde(rename = "other")]
    Other,
}
