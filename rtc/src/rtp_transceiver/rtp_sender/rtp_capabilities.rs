use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;

/// RTPCapabilities represents the capabilities of a transceiver
/// <https://w3c.github.io/webrtc-pc/#rtcrtpcapabilities>
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCapabilities {
    pub codecs: Vec<RTCRtpCodec>,
    pub header_extensions: Vec<RTCRtpHeaderExtensionCapability>,
}
