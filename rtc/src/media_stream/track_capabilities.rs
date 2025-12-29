use std::collections::HashSet;

#[derive(Default, Debug, Clone)]
pub struct Range<T> {
    max: T,
    min: T,
}

#[derive(Default, Debug, Clone)]
pub struct MediaTrackCapabilities {
    width: Range<u32>,
    height: Range<u32>,
    aspect_ratio: Range<f64>,
    frame_rate: Range<f64>,
    facing_mode: Vec<String>,
    resize_mode: Vec<String>,
    sample_rate: Range<u32>,
    sample_size: Range<u32>,
    echo_cancellation: HashSet<bool>,
    auto_gain_control: HashSet<bool>,
    noise_suppression: HashSet<bool>,
    latency: Range<f64>,
    channel_count: Range<u32>,
    device_id: String,
    group_id: String,
    background_blur: HashSet<bool>,
}
