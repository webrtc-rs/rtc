use crate::data_channel::event::RTCDataChannelEvent;
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::RTCDataChannelId;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCEventInternal, RTCMessage,
    TaggedRTCMessage,
};
use log::{debug, warn};
use sctp::PayloadProtocolIdentifier;
use shared::error::{Error, Result};
use shared::TransportContext;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct DataChannelHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// DataChannelHandler implements DataChannel Protocol handling
pub(crate) struct DataChannelHandler<'a> {
    ctx: &'a mut DataChannelHandlerContext,
    data_channels: &'a mut HashMap<RTCDataChannelId, RTCDataChannelInternal>,
}

impl<'a> DataChannelHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut DataChannelHandlerContext,
        data_channels: &'a mut HashMap<RTCDataChannelId, RTCDataChannelInternal>,
    ) -> Self {
        DataChannelHandler { ctx, data_channels }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DataChannelHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal>
    for DataChannelHandler<'a>
{
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "recv SCTP DataChannelMessage from {:?}",
                msg.transport.peer_addr
            );

            let stream_id = message.stream_id;

            if let Some(data_channel_internal) = self.data_channels.get_mut(&stream_id) {
                let data_channel = data_channel_internal
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                data_channel.handle_read(message)?;
            } else {
                let data_channel_internal = RTCDataChannelInternal::accept(
                    message.association_handle,
                    message.stream_id,
                    message.ppi,
                    &message.payload,
                )?;

                self.ctx.read_outs.push_back(TaggedRTCMessage {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                        data_channel_id: message.stream_id,
                        data_channel_event: DataChannelEvent::Open,
                    })),
                });

                self.data_channels
                    .insert(message.stream_id, data_channel_internal);
            }

            let data_channel = self
                .data_channels
                .get_mut(&stream_id)
                .ok_or(Error::ErrDataChannelNotExisted)?
                .data_channel
                .as_mut()
                .ok_or(Error::ErrDataChannelNotExisted)?;

            while let Some(data_channel_message) = data_channel.poll_read() {
                debug!("recv application message {:?}", msg.transport.peer_addr);
                self.ctx.read_outs.push_back(TaggedRTCMessage {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                        data_channel_id: stream_id,
                        data_channel_event: DataChannelEvent::Message(RTCDataChannelMessage {
                            is_string: data_channel_message.ppi
                                == PayloadProtocolIdentifier::String
                                || data_channel_message.ppi
                                    == PayloadProtocolIdentifier::StringEmpty,
                            data: data_channel_message.payload,
                        }),
                    })),
                });
            }

            while let Some(data_channel_message) = data_channel.poll_write() {
                debug!("send data channel message from handle_read");
                self.ctx.write_outs.push_back(TaggedRTCMessage {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: RTCMessage::Dtls(DTLSMessage::Sctp(data_channel_message)),
                });
            }
        } else {
            // Bypass
            debug!("bypass DataChannel read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::DataChannel(message)) = msg.message {
            debug!("send application message {:?}", msg.transport.peer_addr);

            if let DataChannelEvent::Message(RTCDataChannelMessage { is_string, data }) =
                message.data_channel_event
            {
                let data_channel = self
                    .data_channels
                    .get_mut(&message.data_channel_id)
                    .ok_or(Error::ErrDataChannelNotExisted)?
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;

                let data_channel_message =
                    ::datachannel::data_channel::DataChannel::get_data_channel_message(
                        is_string, data,
                    );
                data_channel.handle_write(data_channel_message)?;

                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from handle_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessage {
                        now: Instant::now(),
                        transport: TransportContext::default(),
                        message: RTCMessage::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            } else {
                warn!(
                    "drop unsupported DATACHANNEL message to {}",
                    msg.transport.peer_addr
                );
            }
        } else {
            // Bypass
            debug!("bypass DataChannel write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        for data_channel_internal in self.data_channels.values_mut() {
            if let Some(data_channel) = data_channel_internal.data_channel.as_mut() {
                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from poll_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessage {
                        now: Instant::now(),
                        transport: TransportContext::default(),
                        message: RTCMessage::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        match evt {
            RTCEventInternal::SCTPHandshakeComplete(association_handle) => {
                for data_channel_internal in self.data_channels.values_mut() {
                    if data_channel_internal.ready_state == RTCDataChannelState::Connecting {
                        data_channel_internal.dial(association_handle)?;

                        let data_channel = data_channel_internal
                            .data_channel
                            .as_mut()
                            .ok_or(Error::ErrDataChannelNotExisted)?;

                        self.ctx.read_outs.push_back(TaggedRTCMessage {
                            now: Instant::now(),
                            transport: TransportContext::default(),
                            message: RTCMessage::Dtls(DTLSMessage::DataChannel(
                                ApplicationMessage {
                                    data_channel_id: data_channel_internal.id,
                                    data_channel_event: DataChannelEvent::Open,
                                },
                            )),
                        });

                        while let Some(data_channel_message) = data_channel.poll_write() {
                            debug!("send data channel message from handle_event");
                            self.ctx.write_outs.push_back(TaggedRTCMessage {
                                now: Instant::now(),
                                transport: TransportContext::default(),
                                message: RTCMessage::Dtls(DTLSMessage::Sctp(data_channel_message)),
                            });
                        }
                    }
                }
            }

            RTCEventInternal::SCTPStreamClosed(_association_handle, stream_id) => {
                if self.data_channels.remove(&stream_id).is_some() {
                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(
                                stream_id,
                            )),
                        ));
                }
            }
            _ => {
                self.ctx.event_outs.push_back(evt);
            }
        }
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
