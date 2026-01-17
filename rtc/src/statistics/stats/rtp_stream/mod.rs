//! RTP stream statistics.
//!
//! This module contains statistics types for RTP streams:
//!
//! - [`RTCRtpStreamStats`] - Base statistics shared by all RTP streams
//! - [`received::RTCReceivedRtpStreamStats`] - Base for received streams
//! - [`sent::RTCSentRtpStreamStats`] - Base for sent streams
//! - [`received::inbound::RTCInboundRtpStreamStats`] - Local inbound stream stats
//! - [`received::remote_inbound::RTCRemoteInboundRtpStreamStats`] - Remote inbound stream stats
//! - [`sent::outbound::RTCOutboundRtpStreamStats`] - Local outbound stream stats
//! - [`sent::remote_outbound::RTCRemoteOutboundRtpStreamStats`] - Remote outbound stream stats

use super::RTCStats;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use serde::{Deserialize, Serialize};

pub mod received;
pub mod sent;

/// Base statistics for an RTP stream.
///
/// This struct corresponds to the `RTCRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides common fields shared by all
/// RTP stream statistics types.
///
/// This type is typically not used directly; instead, use the derived types
/// for specific stream directions.
///
/// # W3C Reference
///
/// See [RTCRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#rtpstreamstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRtpStreamStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The SSRC (Synchronization Source) identifier of this stream.
    pub ssrc: SSRC,

    /// The media kind (audio or video).
    pub kind: RtpCodecKind,

    /// The ID of the transport used for this stream.
    ///
    /// References an [`RTCTransportStats`](super::transport::RTCTransportStats) object.
    pub transport_id: String,

    /// The ID of the codec used for this stream.
    ///
    /// References an [`RTCCodecStats`](super::codec::RTCCodecStats) object.
    pub codec_id: String,
}
