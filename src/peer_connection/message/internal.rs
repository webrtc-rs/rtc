use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::event::RTCEventInternal;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use interceptor::Packet;
use shared::TransportContext;
use shared::marshal::MarshalSize;
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
    SctpEvent(SctpEvent),
    DataChannel(ApplicationMessage),
}

/// SCTP lifecycle notifications share the incoming DATA queue. In particular,
/// closing an old use of a stream must reach the channel registry before a new
/// DCEP OPEN for that stream, including when reading releases the old receiver.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SctpEvent {
    Connected(usize),
    Closed(usize, u16),
    BufferReleased(usize, u16, usize),
    BufferedAmountLow(usize, u16),
    BufferedAmountHigh(usize, u16),
}

impl SctpEvent {
    pub(crate) fn into_internal(self) -> RTCEventInternal {
        match self {
            Self::Connected(association) => RTCEventInternal::SCTPHandshakeComplete(association),
            Self::Closed(association, stream) => {
                RTCEventInternal::SCTPStreamClosed(association, stream)
            }
            Self::BufferReleased(association, stream, bytes) => {
                RTCEventInternal::SCTPBufferReleased(association, stream, bytes)
            }
            Self::BufferedAmountLow(association, stream) => {
                RTCEventInternal::SCTPBufferedAmountLow(association, stream)
            }
            Self::BufferedAmountHigh(association, stream) => {
                RTCEventInternal::SCTPBufferedAmountHigh(association, stream)
            }
        }
    }
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

impl RTCMessageInternal {
    /// Returns the size in bytes of the message payload.
    pub(crate) fn len(&self) -> usize {
        match self {
            RTCMessageInternal::Raw(bytes) => bytes.len(),
            RTCMessageInternal::Stun(STUNMessage::Raw(bytes)) => bytes.len(),
            RTCMessageInternal::Dtls(msg) => match msg {
                DTLSMessage::Raw(bytes) => bytes.len(),
                DTLSMessage::Sctp(dcm) => dcm.payload.len(),
                DTLSMessage::SctpEvent(_) => 0,
                DTLSMessage::DataChannel(app_msg) => match &app_msg.data_channel_event {
                    DataChannelEvent::Open | DataChannelEvent::Close => 0,
                    DataChannelEvent::Message(rtc_dcm) => rtc_dcm.data.len(),
                },
            },
            RTCMessageInternal::Rtp(msg) => match msg {
                RTPMessage::Raw(bytes) => bytes.len(),
                RTPMessage::Packet(packet) => match packet {
                    // RTP header is typically 12 bytes + CSRC + extensions
                    Packet::Rtp(rtp) => rtp.marshal_size(),
                    // For RTCP, estimate based on packet count (typically 24-32 bytes per packet)
                    Packet::Rtcp(rtcp_packets) => {
                        let mut rtcp_packet_size = 0;
                        for rtcp_packet in rtcp_packets {
                            rtcp_packet_size += rtcp_packet.marshal_size();
                        }
                        rtcp_packet_size
                    }
                    _ => 0, // Future Packet variants: size unknown; treat as 0 for accounting.
                },
                RTPMessage::TrackPacket(tp) => match &tp.packet {
                    Packet::Rtp(rtp) => rtp.marshal_size(),
                    Packet::Rtcp(rtcp_packets) => {
                        let mut rtcp_packet_size = 0;
                        for rtcp_packet in rtcp_packets {
                            rtcp_packet_size += rtcp_packet.marshal_size();
                        }
                        rtcp_packet_size
                    }
                    _ => 0,
                },
            },
        }
    }
}

pub(crate) struct TaggedRTCMessageInternal {
    pub(crate) now: Instant,
    pub(crate) transport: TransportContext,
    pub(crate) message: RTCMessageInternal,
}
