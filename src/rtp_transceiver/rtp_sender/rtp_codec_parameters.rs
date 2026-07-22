use crate::rtp_transceiver::PayloadType;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;

/// RTP codec parameters including negotiated payload type.
///
/// Represents a codec that an RtpSender can use, along with its negotiated
/// payload type and additional metadata.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#rtcrtpcodecparameters)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpCodecParameters {
    /// The codec capability information
    pub rtp_codec: RTCRtpCodec,
    /// The negotiated RTP payload type
    pub payload_type: PayloadType,
}
