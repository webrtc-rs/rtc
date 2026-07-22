use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;

/// RTP receive parameters for configuring receivers.
#[derive(Default, Debug, Clone)]
pub struct RTCRtpReceiveParameters {
    /// The RTP stack settings
    pub rtp_parameters: RTCRtpParameters,
}
