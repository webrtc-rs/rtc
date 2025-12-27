//pub mod track_local;
pub mod track_remote;

use interceptor::stream_info::StreamInfo;
use track_remote::*;

pub(crate) const RTP_OUTBOUND_MTU: usize = 1200;
pub(crate) const RTP_PAYLOAD_TYPE_BITMASK: u8 = 0x7F;

#[derive(Clone)]
pub(crate) struct TrackStream {
    pub(crate) stream_info: Option<StreamInfo>,
}

/// TrackStreams maintains a mapping of RTP/RTCP streams to a specific track
/// a RTPReceiver may contain multiple streams if we are dealing with Simulcast
#[derive(Clone)]
pub(crate) struct TrackStreams {
    pub(crate) track: TrackRemote,
    pub(crate) stream: TrackStream,
    pub(crate) repair_stream: TrackStream,
}
