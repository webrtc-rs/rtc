use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::PayloadType;

/// RTPCodecParameters is a sequence containing the media codecs that an RtpSender
/// will choose from, as well as entries for RTX, RED and FEC mechanisms. This also
/// includes the PayloadType that has been negotiated
/// <https://w3c.github.io/webrtc-pc/#rtcrtpcodecparameters>
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpCodecParameters {
    pub rtp_codec: RTCRtpCodec,
    pub payload_type: PayloadType,

    pub stats_id: String, //TODO:
}
