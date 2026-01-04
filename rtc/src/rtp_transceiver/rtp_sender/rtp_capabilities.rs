use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;

/// RTP capabilities representing available codecs and header extensions.
///
/// Used to describe what a transceiver is capable of sending or receiving.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#rtcrtpcapabilities)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCapabilities {
    /// List of supported codecs
    pub codecs: Vec<RTCRtpCodec>,
    /// List of supported RTP header extensions
    pub header_extensions: Vec<RTCRtpHeaderExtensionCapability>,
}
