use std::time::Duration;

#[derive(Default, Debug, Clone)]
pub struct RTCRtpContributingSource {
    pub timestamp: Duration,
    pub source: u32,
    pub audio_level: f64,
    pub rtp_timestamp: u32,
}

pub type RTCRtpSynchronizationSource = RTCRtpContributingSource;
