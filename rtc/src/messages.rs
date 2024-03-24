use bytes::BytesMut;
use sctp::ReliabilityType;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum DataChannelMessageType {
    None,
    Control,
    Binary,
    Text,
}

#[derive(Debug)]
pub(crate) struct DataChannelMessageParams {
    pub(crate) unordered: bool,
    pub(crate) reliability_type: ReliabilityType,
    pub(crate) reliability_parameter: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum DataChannelEvent {
    Open,
    Message(BytesMut),
    Close,
}

#[derive(Debug)]
pub struct DataChannelMessage {
    pub(crate) association_handle: usize,
    pub(crate) stream_id: u16,
    pub(crate) data_message_type: DataChannelMessageType,
    pub(crate) params: Option<DataChannelMessageParams>,
    pub(crate) payload: BytesMut,
}

#[derive(Debug)]
pub struct ApplicationMessage {
    pub(crate) association_handle: usize,
    pub(crate) stream_id: u16,
    pub(crate) data_channel_event: DataChannelEvent,
}

#[derive(Debug)]
pub enum STUNMessageEvent {
    Raw(BytesMut),
    Stun(stun::message::Message),
}

#[derive(Debug)]
pub enum DTLSMessageEvent {
    Raw(BytesMut),
    Sctp(DataChannelMessage),
    DataChannel(ApplicationMessage),
}

#[derive(Debug)]
pub enum RTPMessageEvent {
    Raw(BytesMut),
    Rtp(rtp::packet::Packet),
    Rtcp(Vec<Box<dyn rtcp::packet::Packet>>),
}

#[derive(Debug)]
pub enum RTCMessageEvent {
    Raw(BytesMut),
    Stun(STUNMessageEvent),
    Dtls(DTLSMessageEvent),
    Rtp(RTPMessageEvent),
}
