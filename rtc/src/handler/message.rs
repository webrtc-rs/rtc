use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::RTCDataChannelId;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use ice::candidate::Candidate;
use shared::TransportContext;
use srtp::context::Context;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum DataChannelEvent {
    Open,
    Message(RTCDataChannelMessage),
    Close,
}

#[derive(Debug, Clone)]
pub struct ApplicationMessage {
    pub(crate) data_channel_id: RTCDataChannelId,
    pub(crate) data_channel_event: DataChannelEvent,
}

#[derive(Debug, Clone)]
pub enum STUNMessage {
    Raw(BytesMut),
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

pub(crate) struct TaggedRTCMessage {
    pub now: Instant,
    pub transport: TransportContext,
    pub message: RTCMessage,
}

#[derive(Debug, Clone)]
pub enum RTCEvent {}

#[allow(clippy::large_enum_variant)]
pub(crate) enum RTCEventInternal {
    RTCEvent(RTCEvent),
    RTCPeerConnectionEvent(RTCPeerConnectionEvent),

    // ICE Event
    ICESelectedCandidatePairChange(Box<Candidate>, Box<Candidate>),
    // DTLS Event
    DTLSHandshakeComplete(SocketAddr, Box<Context>, Box<Context>),
    // SCTP Event
    SCTPHandshakeComplete(usize /*AssociationHandle*/),
}
