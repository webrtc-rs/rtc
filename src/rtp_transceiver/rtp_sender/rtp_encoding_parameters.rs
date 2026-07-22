use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

/// RTP encoding parameters for individual encodings in a simulcast or layered stream.
///
/// This is a subset of the ORTC specification since this implementation
/// doesn't perform encoding directly.
///
/// ## Specifications
///
/// * [ORTC](http://draft.ortc.org/#dom-rtcrtpencodingparameters)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpEncodingParameters {
    /// Base coding parameters (RID, SSRC, RTX, FEC)
    pub rtp_coding_parameters: RTCRtpCodingParameters,
    /// Whether this encoding is actively being transmitted
    pub active: bool,
    /// Codec to use for this encoding
    pub codec: RTCRtpCodec,
    /// Maximum bitrate in bits per second
    pub max_bitrate: u32,
    /// Maximum framerate in frames per second
    pub max_framerate: Option<f64>,
    /// Resolution scaling factor (must be >= 1.0)
    pub scale_resolution_down_by: Option<f64>,
}
