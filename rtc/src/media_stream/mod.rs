pub mod track_local;
pub mod track_remote;

use crate::media_stream::track_local::TrackLocal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTPCodecType;
use crate::rtp_transceiver::SSRC;
use interceptor::stream_info::StreamInfo;
use track_remote::*;

pub(crate) const RTP_OUTBOUND_MTU: usize = 1200;
pub(crate) const RTP_PAYLOAD_TYPE_BITMASK: u8 = 0x7F;

#[derive(Debug, Clone)]
pub(crate) struct TrackStream {
    pub(crate) stream_info: Option<StreamInfo>,
}

/// TrackStreams maintains a mapping of RTP/RTCP streams to a specific track
/// a RTPReceiver may contain multiple streams if we are dealing with Simulcast
#[derive(Debug, Clone)]
pub(crate) struct TrackStreams {
    pub(crate) track: TrackRemote,
    pub(crate) stream: TrackStream,
    pub(crate) repair_stream: TrackStream,
}

/// TrackDetails represents any media source that can be represented in a SDP
/// This isn't keyed by SSRC because it also needs to support rid based sources
#[derive(Default, Debug, Clone)]
pub(crate) struct TrackDetails {
    pub(crate) mid: String,
    pub(crate) kind: RTPCodecType,
    pub(crate) stream_id: String,
    pub(crate) id: String,
    pub(crate) ssrcs: Vec<SSRC>,
    pub(crate) repair_ssrc: SSRC,
    pub(crate) rids: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct TrackEncoding {
    pub(crate) track: TrackLocal,
    //pub(crate) srtp_stream: Arc<SrtpWriterFuture>,
    //pub(crate) rtcp_interceptor: Arc<dyn RTCPReader + Send + Sync>,
    pub(crate) stream_info: StreamInfo,
    //pub(crate) context: TrackLocalContext,
    pub(crate) ssrc: SSRC,

    pub(crate) rtx: Option<RtxEncoding>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct RtxEncoding {
    //pub(crate) srtp_stream: Arc<SrtpWriterFuture>,
    //pub(crate) rtcp_interceptor: Arc<dyn RTCPReader + Send + Sync>,
    pub(crate) stream_info: StreamInfo,

    pub(crate) ssrc: SSRC,
}
