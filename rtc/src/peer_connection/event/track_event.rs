use crate::media_stream::track::MediaStreamTrackId;
use crate::media_stream::MediaStreamId;
//use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
//use crate::rtp_transceiver::RTCRtpTransceiver;

#[derive(Default, Debug, Clone)]
pub(crate) struct RTCTrackEventInit {
    //TODO: receiver: RTCRtpReceiver,
    track_id: MediaStreamTrackId,
    stream_ids: Vec<MediaStreamId>,
    //TODO: transceiver: RTCRtpTransceiver,
}

#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub struct RTCTrackEvent {
    //TODO: receiver: RTCRtpReceiver,
    pub track_id: MediaStreamTrackId,
    pub stream_ids: Vec<MediaStreamId>,
    //TODO: transceiver: RTCRtpTransceiver,
}
