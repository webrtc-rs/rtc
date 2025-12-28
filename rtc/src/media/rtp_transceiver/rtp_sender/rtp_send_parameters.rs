use crate::media::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::media::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;

/// RTPSendParameters contains the RTP stack settings used by receivers
#[derive(Default, Debug)]
pub struct RTCRtpSendParameters {
    pub rtp_parameters: RTCRtpParameters,
    pub transaction_id: String,
    pub encodings: Vec<RTCRtpEncodingParameters>,
}
