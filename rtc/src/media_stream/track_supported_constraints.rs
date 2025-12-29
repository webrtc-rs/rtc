#[derive(Default, Debug, Clone)]
pub(crate) struct MediaTrackSupportConstraints {
    width: bool,
    height: bool,
    aspect_ratio: bool,
    frame_rate: bool,
    facing_mode: bool,
    resize_mode: bool,
    sample_rate: bool,
    sample_size: bool,
    echo_cancellation: bool,
    auto_gain_control: bool,
    noise_suppression: bool,
    latency: bool,
    channel_count: bool,
    device_id: bool,
    group_id: bool,
    background_blur: bool,
}
