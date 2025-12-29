use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

/// RTPEncodingParameters provides information relating to both encoding and decoding.
/// This is a subset of the RFC since Pion WebRTC doesn't implement encoding itself
/// <http://draft.ortc.org/#dom-rtcrtpencodingparameters>
#[derive(Default, Debug, Clone)]
pub struct RTCRtpEncodingParameters {
    pub rtp_coding_parameters: RTCRtpCodingParameters,
    pub active: bool,
    pub codec: RTCRtpCodec,
    pub max_bitrate: u32,
    pub max_framerate: Option<f64>,
    pub scale_resolution_down_by: Option<f64>,
}
