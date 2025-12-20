use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::transport::dtls::role::DTLSRole;
use crate::transport::ice::role::RTCIceRole;
use bytes::BytesMut;
use sctp::ReliabilityType;
use shared::TransportContext;
use std::time::Instant;

pub type Mid = String;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum DataChannelMessageType {
    None,
    Control,
    Binary,
    Text,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct DataChannelMessage {
    pub(crate) association_handle: usize,
    pub(crate) stream_id: u16,
    pub(crate) data_message_type: DataChannelMessageType,
    pub(crate) params: Option<DataChannelMessageParams>,
    pub(crate) payload: BytesMut,
}

#[derive(Debug, Clone)]
pub struct ApplicationMessage {
    pub(crate) association_handle: usize,
    pub(crate) stream_id: u16,
    pub(crate) data_channel_event: DataChannelEvent,
}

#[derive(Debug, Clone)]
pub enum STUNMessage {
    Raw(BytesMut),
    Stun(stun::message::Message),
}

#[derive(Debug, Clone)]
pub enum DTLSMessage {
    Raw(BytesMut),
    Sctp(DataChannelMessage),
    DataChannel(ApplicationMessage),
}

#[derive(Debug, Clone)]
pub enum RTPMessage {
    Raw(BytesMut),
    Rtp(rtp::packet::Packet),
    Rtcp(Vec<Box<dyn rtcp::packet::Packet>>),
}

#[derive(Debug, Clone)]
pub enum RTCMessage {
    Raw(BytesMut),
    Stun(STUNMessage),
    Dtls(DTLSMessage),
    Rtp(RTPMessage),
}

pub struct TaggedRTCMessage {
    pub now: Instant,
    pub transport: TransportContext,
    pub message: RTCMessage,
}

#[derive(Debug, Clone)]
pub enum RTCEvent {}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum RTCEventInternal {
    StartRtpSenders,
    StartRtp(bool /*is_renegotiation*/, RTCSessionDescription),
    StartTransports(
        RTCIceRole,
        DTLSRole,
        String, /*remote_ufrag*/
        String, /*remote_pwd*/
        String, /*fingerprint*/
        String, /*fingerprint_hash*/
    ),
    DoNegotiationNeeded,
}
