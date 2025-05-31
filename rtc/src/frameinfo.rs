use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct FrameInfo {
    pub timestamp: u32,
    pub payload_type: u8,
    pub timestamp_seconds: Option<Duration>,
}

impl FrameInfo {
    pub fn new(timestamp: u32, payload_type: u8, timestamp_seconds: Option<Duration>) -> FrameInfo {
        Self {
            timestamp,
            payload_type,
            timestamp_seconds,
        }
    }
}
