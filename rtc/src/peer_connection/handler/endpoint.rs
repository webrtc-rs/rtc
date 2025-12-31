use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessage, RTPMessage, TaggedRTCMessage,
};

use crate::peer_connection::event::track_event::{RTCRtpRtcpPacket, RTCTrackEvent};
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiver};
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::TransportContext;
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
        rtp_packet: rtp::packet::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

        if let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter()
                .enumerate()
                .find(|(_, transceiver)| {
                    if let Some(receiver) = transceiver.receiver() {
                        receiver.get_coding_parameters().iter().any(|coding| {
                            coding
                                .ssrc
                                .is_some_and(|ssrc| ssrc == rtp_packet.header.ssrc)
                        })
                    } else {
                        false
                    }
                })
        {
            let (track_id, stream_ids) = if let Some(receiver) = transceiver.receiver() {
                (
                    receiver.track().track_id().to_owned(),
                    vec![receiver.track().stream_id().to_owned()],
                )
            } else {
                ("".to_owned(), vec![])
            };

            self.ctx
                .event_outs
                .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent {
                        receiver_id: RTCRtpReceiverId(id),
                        track_id,
                        stream_ids,
                        packet: RTCRtpRtcpPacket::Rtp(rtp_packet),
                    }),
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
        rtcp_packets: Vec<Box<dyn rtcp::packet::Packet>>,
    ) -> Result<()> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);

        let rtcp_ssrc = if let Some(rtcp_packet) = rtcp_packets.first() {
            rtcp_packet.destination_ssrc().first().cloned()
        } else {
            None
        };

        if let Some(rtcp_ssrc) = rtcp_ssrc {
            if let Some((id, transceiver)) =
                self.rtp_transceivers
                    .iter()
                    .enumerate()
                    .find(|(_, transceiver)| {
                        if let Some(receiver) = transceiver.receiver() {
                            receiver
                                .get_coding_parameters()
                                .iter()
                                .any(|coding| coding.ssrc.is_some_and(|ssrc| ssrc == rtcp_ssrc))
                        } else {
                            false
                        }
                    })
            {
                let (track_id, stream_ids) = if let Some(receiver) = transceiver.receiver() {
                    (
                        receiver.track().track_id().to_owned(),
                        vec![receiver.track().stream_id().to_owned()],
                    )
                } else {
                    ("".to_owned(), vec![])
                };

                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent {
                            receiver_id: RTCRtpReceiverId(id),
                            track_id,
                            stream_ids,
                            packet: RTCRtpRtcpPacket::Rtcp(rtcp_packets),
                        }),
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
}
