use crate::transport::data_channel::DataChannelEvent;
use crate::transport::dtls_transport::DtlsTransportEvent;
use crate::transport::ice_transport::IceTransportEvent;
use crate::transport::sctp_transport::SctpTransportEvent;
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
pub(crate) enum DataChannelPayload {
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
    pub(crate) data_channel_payload: DataChannelPayload,
}

#[derive(Debug)]
pub enum STUNMessage {
    Raw(BytesMut),
    Stun(stun::message::Message),
}

#[derive(Debug)]
pub enum DTLSMessage {
    Raw(BytesMut),
    Sctp(DataChannelMessage),
    DataChannel(ApplicationMessage),
}

#[derive(Debug)]
pub enum RTPMessage {
    Raw(BytesMut),
    Rtp(rtp::packet::Packet),
    Rtcp(Vec<Box<dyn rtcp::packet::Packet>>),
}

#[derive(Debug)]
pub enum RTCMessage {
    Raw(BytesMut),
    Stun(STUNMessage),
    Dtls(DTLSMessage),
    Rtp(RTPMessage),
}

#[derive(Debug)]
pub enum RTCEvent {
    DataChannelEvent(DataChannelEvent),
    DtlsTransportEvent(DtlsTransportEvent),
    IceTransportEvent(IceTransportEvent),
    SctpTransportEvent(SctpTransportEvent),
}
