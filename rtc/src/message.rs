use crate::frameinfo::FrameInfo;
use crate::reliability::Reliability;
use std::sync::Arc;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    #[default]
    Binary,
    String,
    Control,
    Reset,
}

#[derive(Debug, Default, Clone)]
pub struct Message {
    pub message_type: MessageType,
    pub stream: usize, // Stream id (SCTP stream or SSRC)
    pub dscp: usize,   // Differentiated Services Code Point
    pub reliability: Arc<Reliability>,
    pub frame_info: Arc<FrameInfo>,
}
