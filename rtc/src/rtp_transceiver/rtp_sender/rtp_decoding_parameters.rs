use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

/// RTP decoding parameters for individual decoding in a simulcast or layered stream.
///
/// This is a subset of the ORTC specification since this implementation
/// doesn't perform decoding directly.
///
/// ## Specifications
///
/// * [ORTC](http://draft.ortc.org/#dom-rtcrtpdecodingparameters)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpDecodingParameters {
    /// Base coding parameters (RID, SSRC, RTX, FEC)
    pub rtp_coding_parameters: RTCRtpCodingParameters,
    /// Codec to use for this encoding
    pub codec: RTCRtpCodec,
}
