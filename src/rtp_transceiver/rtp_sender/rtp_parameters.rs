use crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCRtcpParameters;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;

/// RTP parameters containing negotiated codecs and header extensions.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#dictionary-rtcrtpparameters-members)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpParameters {
    /// Negotiated RTP header extensions
    pub header_extensions: Vec<RTCRtpHeaderExtensionParameters>,
    /// RTCP parameters
    pub rtcp: RTCRtcpParameters,
    /// Negotiated codecs in preference order
    pub codecs: Vec<RTCRtpCodecParameters>,
}
