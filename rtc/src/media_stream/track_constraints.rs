#[derive(Default, Debug, Clone)]
pub struct ConstrainRange<T> {
    max: T,
    min: T,
    exact: T,
    ideal: T,
}

#[derive(Debug, Clone)]
pub enum Constrain<T> {
    Value(T),
    Range(ConstrainRange<T>),
}

#[derive(Debug, Clone)]
pub struct MediaTrackConstraintSet {
    width: Constrain<u32>,
    height: Constrain<u32>,
    aspect_ratio: Constrain<f64>,
    frame_rate: Constrain<f64>,
    facing_mode: Constrain<String>,
    resize_mode: Constrain<String>,
    sample_rate: Constrain<u32>,
    sample_size: Constrain<u32>,
    echo_cancellation: Constrain<bool>,
    auto_gain_control: Constrain<bool>,
    noise_suppression: Constrain<bool>,
    latency: Constrain<f64>,
    channel_count: Constrain<u32>,
    device_id: Constrain<String>,
    group_id: Constrain<String>,
    background_blur: Constrain<bool>,
}

impl Default for MediaTrackConstraintSet {
    fn default() -> Self {
        Self {
            width: Constrain::Value(0),
            height: Constrain::Value(0),
            aspect_ratio: Constrain::Value(0.0),
            frame_rate: Constrain::Value(0.0),
            facing_mode: Constrain::Value("".to_string()),
            resize_mode: Constrain::Value("".to_string()),
            sample_rate: Constrain::Value(0),
            sample_size: Constrain::Value(0),
            echo_cancellation: Constrain::Value(false),
            auto_gain_control: Constrain::Value(false),
            noise_suppression: Constrain::Value(false),
            latency: Constrain::Value(0.0),
            channel_count: Constrain::Value(0),
            device_id: Constrain::Value("".to_string()),
            group_id: Constrain::Value("".to_string()),
            background_blur: Constrain::Value(false),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct MediaTrackConstraints {
    basic: MediaTrackConstraintSet,
    advanced: Vec<MediaTrackConstraintSet>,
}
