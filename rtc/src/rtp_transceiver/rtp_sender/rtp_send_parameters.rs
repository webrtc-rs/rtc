use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;

/// RTP send parameters for configuring senders.
#[derive(Default, Debug, Clone)]
pub struct RTCRtpSendParameters {
    /// The RTP stack settings (codecs, header extensions, RTCP)
    pub rtp_parameters: RTCRtpParameters,
    /// Unique identifier for tracking parameter changes
    pub transaction_id: String,
    /// Encoding parameters for each simulcast/layered stream
    pub encodings: Vec<RTCRtpEncodingParameters>,
}
