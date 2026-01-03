use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessage, RTPMessage, TaggedRTCMessage,
};

use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::rtp_transceiver::{PayloadType, RTCRtpReceiverId, RTCRtpTransceiver, SSRC};
use log::{debug, warn};
use shared::TransportContext;
use shared::error::{Error, Result};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct EndpointHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// EndpointHandler implements DataChannel/Media Endpoint handling
/// The transmits queue is now stored in RTCPeerConnection and passed by reference
pub(crate) struct EndpointHandler<'a> {
    ctx: &'a mut EndpointHandlerContext,
    rtp_transceivers: &'a mut Vec<RTCRtpTransceiver>,
}

impl<'a> EndpointHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut EndpointHandlerContext,
        rtp_transceivers: &'a mut Vec<RTCRtpTransceiver>,
    ) -> Self {
        EndpointHandler {
            ctx,
            rtp_transceivers,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "EndpointHandler"
    }
}

// Implement Protocol trait for message processing
impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal>
    for EndpointHandler<'a>
{
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        match msg.message {
            RTCMessage::Dtls(DTLSMessage::DataChannel(message)) => {
                self.handle_dtls_message(msg.now, msg.transport, message)
            }
            RTCMessage::Rtp(RTPMessage::Rtp(message)) => {
                self.handle_rtp_message(msg.now, msg.transport, message)
            }
            RTCMessage::Rtp(RTPMessage::Rtcp(message)) => {
                self.handle_rtcp_message(msg.now, msg.transport, message)
            }
            _ => {
                warn!("drop unsupported message from {}", msg.transport.peer_addr);
                Ok(())
            }
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        self.ctx.write_outs.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> EndpointHandler<'a> {
    fn handle_dtls_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        message: ApplicationMessage,
    ) -> Result<()> {
        match message.data_channel_event {
            DataChannelEvent::Open => {
                self.handle_datachannel_open(now, transport_context, message.data_channel_id)
            }
            DataChannelEvent::Message(data_channel_message) => self.handle_datachannel_message(
                now,
                transport_context,
                message.data_channel_id,
                data_channel_message,
            ),
            DataChannelEvent::Close => {
                self.handle_datachannel_close(now, transport_context, message.data_channel_id)
            }
        }
    }

    fn handle_rtp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        rtp_packet: rtp::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

        if let Some(track_id) =
            self.find_track_id(rtp_packet.header.ssrc, Some(rtp_packet.header.payload_type))
        {
            self.ctx
                .event_outs
                .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnRtpPacket(
                        track_id, rtp_packet,
                    )),
                ));
        } else {
            debug!("drop rtp packet ssrc = {}", rtp_packet.header.ssrc);
        }
        Ok(())
    }

    fn handle_rtcp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        rtcp_packets: Vec<Box<dyn rtcp::Packet>>,
    ) -> Result<()> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);

        let rtcp_ssrc = if let Some(rtcp_packet) = rtcp_packets.first() {
            rtcp_packet.destination_ssrc().first().cloned()
        } else {
            None
        };

        if let Some(rtcp_ssrc) = rtcp_ssrc {
            if let Some(track_id) = self.find_track_id(rtcp_ssrc, None) {
                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnRtcpPacket(
                            track_id,
                            rtcp_packets,
                        )),
                    ));
            } else {
                debug!("drop rtcp packet ssrc = {}", rtcp_ssrc);
            }
        } else {
            debug!("drop rtcp packet due to empty ssrc");
        }

        Ok(())
    }

    fn handle_datachannel_open(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        data_channel_id: u16,
    ) -> Result<()> {
        debug!("data channel is open for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(data_channel_id)),
            ));

        Ok(())
    }

    fn handle_datachannel_close(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        data_channel_id: u16,
    ) -> Result<()> {
        debug!("data channel is close for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(
                    data_channel_id,
                )),
            ));

        Ok(())
    }

    fn handle_datachannel_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        data_channel_id: u16,
        data_channel_message: RTCDataChannelMessage,
    ) -> Result<()> {
        debug!("data channel recv message for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnMessage(
                    data_channel_id,
                    data_channel_message,
                )),
            ));

        Ok(())
    }

    fn find_track_id(
        &mut self,
        ssrc: SSRC,
        payload_type: Option<PayloadType>,
    ) -> Option<MediaStreamTrackId> {
        if let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    if let Some(receiver) = transceiver.receiver() {
                        receiver.get_coding_parameters().iter().any(|coding| {
                            coding.ssrc.is_some_and(|coding_ssrc| coding_ssrc == ssrc)
                        })
                    } else {
                        false
                    }
                })
            && let Some(receiver) = transceiver.receiver_mut()
            && let Some(track) = receiver.tracks().find(|track| track.ssrc() == ssrc)
        {
            let (is_track_codec_empty, track_id) =
                (track.codec().mime_type.is_empty(), track.track_id().clone());

            let track_codec = if is_track_codec_empty
                && let Some(payload_type) = payload_type
                && let Some(codec) = receiver
                    .get_codec_preferences()
                    .iter()
                    .find(|codec| codec.payload_type == payload_type)
            {
                Some(codec.rtp_codec.clone())
            } else {
                None
            };

            if let Some(codec) = track_codec
                && let Some(track) = receiver.track_mut(&track_id)
            {
                // Set valid Codec for track when received the first RTP packet for such ssrc stream
                track.set_codec(codec);

                // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(RTCTrackEventInit {
                            receiver_id: RTCRtpReceiverId(id),
                            track_id: track.track_id().to_owned(),
                            stream_ids: vec![track.stream_id().to_owned()],
                            transceiver_id: id,
                        })),
                    ));
            }

            return Some(track_id);
        }

        None
    }
}
