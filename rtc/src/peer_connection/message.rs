use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::media_stream::track::MediaStreamTrackId;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TrackPacket {
    Rtp(rtp::Packet),
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
}

#[derive(Debug, Clone)]
pub(crate) struct TrackMessage {
    pub(crate) track_id: MediaStreamTrackId,
    pub(crate) track_packet: TrackPacket,
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
    Rtp(rtp::Packet),
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
    Track(TrackMessage),
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

/// Messages that can be sent or received through the peer connection.
///
/// This enum represents the different types of messages that can flow through
/// a WebRTC connection, including RTP media packets, RTCP control packets,
/// and data channel messages.
#[derive(Debug, Clone)]
pub enum RTCMessage {
    /// An RTP packet for a specific media track.
    ///
    /// Contains the track ID and the RTP packet data. Used for sending or receiving
    /// media data (audio or video).
    RtpPacket(MediaStreamTrackId, rtp::Packet),
    
    /// An RTCP packet for a specific media track.
    ///
    /// Contains the track ID and one or more RTCP packets. Used for sending or receiving
    /// control information like sender reports, receiver reports, etc.
    RtcpPacket(MediaStreamTrackId, Vec<Box<dyn rtcp::Packet>>),
    
    /// A data channel message.
    ///
    /// Contains the data channel ID and the message data. Used for sending or receiving
    /// application data through a data channel.
    DataChannelMessage(RTCDataChannelId, RTCDataChannelMessage),
}
