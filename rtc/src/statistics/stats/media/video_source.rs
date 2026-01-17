use super::media_source::RTCMediaSourceStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCVideoSourceStats {
    #[serde(flatten)]
    pub media_source_stats: RTCMediaSourceStats,

    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub frames_per_second: f64,
}
