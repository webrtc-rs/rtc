#[derive(Default, Debug, Clone)]
pub struct MediaTrackSettings {
    width: u32,
    height: u32,
    aspect_ratio: f64,
    frame_rate: f64,
    facing_mode: String,
    resize_mode: String,
    sample_rate: u32,
    sample_size: u32,
    echo_cancellation: bool,
    auto_gain_control: bool,
    noise_suppression: bool,
    latency: f64,
    channel_count: u32,
    device_id: String,
    group_id: String,
    background_blur: bool,
}
