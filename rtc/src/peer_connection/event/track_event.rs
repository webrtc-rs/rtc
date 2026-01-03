use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrackId;
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverId};

#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub struct RTCTrackEventInit {
    pub receiver_id: RTCRtpReceiverId,
    pub track_id: MediaStreamTrackId,
    pub stream_ids: Vec<MediaStreamId>,
    pub transceiver_id: RTCRtpTransceiverId,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum RTCTrackEvent {
    OnOpen(RTCTrackEventInit),
    OnError(MediaStreamTrackId),
    OnClosing(MediaStreamTrackId),
    OnClose(MediaStreamTrackId),
}

impl Default for RTCTrackEvent {
    fn default() -> Self {
        Self::OnOpen(Default::default())
    }
}
