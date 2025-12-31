use crate::media_stream::track::MediaStreamTrackId;
use crate::media_stream::MediaStreamId;
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverId};

#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub struct RTCTrackEvent {
    pub receiver_id: RTCRtpReceiverId,
    pub track_id: MediaStreamTrackId,
    pub stream_ids: Vec<MediaStreamId>,
    pub transceiver_id: RTCRtpTransceiverId,
    pub packet: RTCRtpRtcpPacket,
}

#[derive(Debug, Clone)]
pub enum RTCRtpRtcpPacket {
    Rtp(rtp::packet::Packet),
    Rtcp(Vec<Box<dyn rtcp::packet::Packet>>),
}

impl Default for RTCRtpRtcpPacket {
    fn default() -> Self {
        Self::Rtcp(vec![])
    }
}
