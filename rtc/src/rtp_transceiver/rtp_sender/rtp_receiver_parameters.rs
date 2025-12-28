use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;

/// RTPReceiveParameters contains the RTP stack settings used by receivers
#[derive(Debug)]
pub struct RTCRtpReceiveParameters {
    pub rtp_parameters: RTCRtpParameters,
}
