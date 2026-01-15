use super::media::RTCMediaSourceStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCAudioSourceStats {
    pub media_source_stats: RTCMediaSourceStats,

    pub audio_level: f64,
    pub total_audio_energy: f64,
    pub total_samples_duration: f64,
    pub echo_return_loss: f64,
    pub echo_return_loss_enhancement: f64,
}
