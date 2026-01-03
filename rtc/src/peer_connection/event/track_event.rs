use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrackId;
use crate::rtp_transceiver::RTCRtpReceiverId;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub struct RTCTrackEvent {
    pub receiver_id: RTCRtpReceiverId,
    pub track_id: MediaStreamTrackId,
    pub stream_ids: Vec<MediaStreamId>,
    pub packet: RTCRtpRtcpPacket,
}

#[derive(Debug, Clone)]
pub enum RTCRtpRtcpPacket {
    Rtp(rtp::Packet),
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
}

impl Default for RTCRtpRtcpPacket {
    fn default() -> Self {
        Self::Rtcp(vec![])
    }
}
