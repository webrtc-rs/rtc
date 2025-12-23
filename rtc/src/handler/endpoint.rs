use super::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCEvent, RTCMessage, RTPMessage,
    TaggedRTCMessage,
};
use crate::data_channel::event::RTCDataChannelEvent;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::TransportContext;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct EndpointHandlerContext {
    pub(crate) dtls_handshake_config: ::dtls::config::HandshakeConfig,
    pub(crate) sctp_endpoint_config: ::sctp::EndpointConfig,
    pub(crate) sctp_server_config: ::sctp::ServerConfig,

    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,
}

/// EndpointHandler implements DataChannel/Media Endpoint handling
/// The transmits queue is now stored in RTCPeerConnection and passed by reference
pub(crate) struct EndpointHandler<'a> {
    ctx: &'a mut EndpointHandlerContext,
}

impl<'a> EndpointHandler<'a> {
    pub(crate) fn new(ctx: &'a mut EndpointHandlerContext) -> Self {
        EndpointHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "EndpointHandler"
    }
}

// Implement Protocol trait for message processing
impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEvent> for EndpointHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCPeerConnectionEvent;
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
        self.ctx.write_outs.push_back(TaggedRTCMessage {
            now: Instant::now(),
            transport: TransportContext::default(), //TODO: rewrite transport context
            message: msg.message,
        });
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: RTCEvent) -> Result<()> {
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
            DataChannelEvent::Open => self.handle_datachannel_open(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
            DataChannelEvent::Message(is_string, data) => self.handle_datachannel_message(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
                is_string,
                data,
            ),
            DataChannelEvent::Close => self.handle_datachannel_close(
                now,
                transport_context,
                message.association_handle,
                message.stream_id,
            ),
        }
    }

    fn handle_rtp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _rtp_packet: rtp::packet::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

        Ok(())
    }

    fn handle_rtcp_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _rtcp_packets: Vec<Box<dyn rtcp::packet::Packet>>,
    ) -> Result<()> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);

        Ok(())
    }

    fn handle_datachannel_open(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _association_handle: usize,
        stream_id: u16,
    ) -> Result<()> {
        debug!("data channel is open for {:?}", transport_context);
        //TODO: store association_handle?

        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnOpen(stream_id),
            ));

        Ok(())
    }

    fn handle_datachannel_close(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _association_handle: usize,
        stream_id: u16,
    ) -> Result<()> {
        debug!("data channel is close for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnClose(stream_id),
            ));

        Ok(())
    }

    fn handle_datachannel_message(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        _association_handle: usize,
        stream_id: u16,
        is_string: bool,
        data: BytesMut,
    ) -> Result<()> {
        debug!("data channel recv message for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnMessage(
                    stream_id,
                    RTCDataChannelMessage { is_string, data },
                ),
            ));

        Ok(())
    }
}
