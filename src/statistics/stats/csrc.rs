//! Contributing source statistics.
//!
//! This module contains the [`RTCRTPContributingSourceStats`] type which
//! reports, per inbound RTP stream, the CSRCs that recently contributed to it.

use super::RTCStats;
use serde::{Deserialize, Serialize};

/// Statistics for a contributing source (CSRC) of an inbound RTP stream.
///
/// One entry exists per (inbound stream, CSRC) pair that contributed within the
/// receiver's source memory window. The underlying data is the same list the
/// W3C `getContributingSources` API returns; this stats view additionally
/// carries the per-source packet count.
///
/// # Specification
///
/// The W3C stats dictionary is not standard; this type follows the shape
/// `RTPContributingSourceStats` exposes for report compatibility with pion.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRTPContributingSourceStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The SSRC identifier of the contributing source, as it appeared in the
    /// CSRC list of the packets it contributed to.
    pub contributor_ssrc: u32,

    /// The identifier of the [`RTCRtpStreamStats`](crate::statistics::stats::rtp_stream) object
    /// for the inbound stream this source contributed to.
    pub inbound_rtp_stream_id: String,

    /// The number of RTP packets this source has contributed to since tracking
    /// began.
    pub packets_contributed_to: u32,

    /// The audio level of the contributing source, ranging from 0 (silence)
    /// to 1 (maximum), or 0 when the stream carries no RFC 6464 audio level.
    pub audio_level: f64,
}
