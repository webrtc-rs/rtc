use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::media_stream::track::MediaStreamTrackId;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use interceptor::Packet;
use shared::TransportContext;
use std::time::Instant;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum DataChannelEvent {
    Open,
    Message(RTCDataChannelMessage),
    Close,
}

#[derive(Debug, Clone)]
pub(crate) struct ApplicationMessage {
    pub(crate) data_channel_id: RTCDataChannelId,
    pub(crate) data_channel_event: DataChannelEvent,
}

#[derive(Debug, Clone)]
pub(crate) struct TrackPacket {
    pub(crate) track_id: MediaStreamTrackId,
    pub(crate) packet: Packet,
}

#[derive(Debug, Clone)]
pub(crate) enum STUNMessage {
    Raw(BytesMut),
}

#[derive(Debug, Clone)]
pub(crate) enum DTLSMessage {
    Raw(BytesMut),
    Sctp(DataChannelMessage),
    DataChannel(ApplicationMessage),
}

#[derive(Debug, Clone)]
pub(crate) enum RTPMessage {
    Raw(BytesMut),
    Packet(Packet),
    TrackPacket(TrackPacket),
}

#[derive(Debug, Clone)]
pub(crate) enum RTCMessageInternal {
    Raw(BytesMut),
    Stun(STUNMessage),
    Dtls(DTLSMessage),
    Rtp(RTPMessage),
}

pub(crate) struct TaggedRTCMessageInternal {
    pub(crate) now: Instant,
    pub(crate) transport: TransportContext,
    pub(crate) message: RTCMessageInternal,
}
