use super::message::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, DataChannelMessage,
    DataChannelMessageParams, DataChannelMessageType, RTCEventInternal, RTCMessage,
    TaggedRTCMessage,
};
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::RTCDataChannelId;
use datachannel::message::{message_channel_ack::*, message_channel_open::*, message_type::*, *};
use log::{debug, error, warn};
use sctp::ReliabilityType;
use shared::error::{Error, Result};
use shared::marshal::*;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct DataChannelHandlerContext {
    pub(crate) association_handle: Option<usize>,
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
            let try_read =
                || -> Result<(Option<ApplicationMessage>, Option<DataChannelMessage>)> {
                    if message.data_message_type == DataChannelMessageType::Control {
                        let mut buf = &message.payload[..];
                        if MessageType::unmarshal(&mut buf)? == MessageType::DataChannelOpen {
                            debug!("DataChannelOpen for association_handle {} and stream_id {} and data_message_type {:?}",
                            message.association_handle,
                            message.stream_id,
                            message.data_message_type);

                            let data_channel_open = DataChannelOpen::unmarshal(&mut buf)?;
                            let (unordered, reliability_type) =
                                get_reliability_params(data_channel_open.channel_type);

                            let params = DataChannelMessageParams {
                                unordered,
                                reliability_type,
                                reliability_parameter: data_channel_open.reliability_parameter,
                            };

                            self.create_data_channel_if_not_existed(
                                &params,
                                message.association_handle,
                                message.stream_id,
                            )?;

                            let payload = Message::DataChannelAck(DataChannelAck {}).marshal()?;
                            Ok((
                                Some(ApplicationMessage {
                                    //association_handle: message.association_handle,
                                    data_channel_id: message.stream_id,
                                    data_channel_event: DataChannelEvent::Open,
                                }),
                                Some(DataChannelMessage {
                                    association_handle: message.association_handle,
                                    stream_id: message.stream_id,
                                    data_message_type: DataChannelMessageType::Control,
                                    params: Some(params),
                                    payload,
                                }),
                            ))
                        } else {
                            Ok((None, None))
                        }
                    } else {
                        Ok((
                            Some(ApplicationMessage {
                                //association_handle: message.association_handle,
                                data_channel_id: message.stream_id,
                                data_channel_event: DataChannelEvent::Message(
                                    RTCDataChannelMessage {
                                        is_string: message.data_message_type
                                            == DataChannelMessageType::Text,
                                        data: message.payload,
                                    },
                                ),
                            }),
                            None,
                        ))
                    }
                };

            match try_read() {
                Ok((inbound_message, outbound_message)) => {
                    // first outbound message
                    if let Some(data_channel_message) = outbound_message {
                        debug!("send DataChannelAck message {:?}", msg.transport.peer_addr);
                        self.ctx.write_outs.push_back(TaggedRTCMessage {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessage::Dtls(DTLSMessage::Sctp(data_channel_message)),
                        });
                    }

                    // then inbound message
                    if let Some(application_message) = inbound_message {
                        debug!("recv application message {:?}", msg.transport.peer_addr);
                        self.ctx.read_outs.push_back(TaggedRTCMessage {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessage::Dtls(DTLSMessage::DataChannel(
                                application_message,
                            )),
                        })
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    return Err(err);
                }
            };
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

            let association_handle =
                if let Some(data_channel) = self.data_channels.get(&message.data_channel_id) {
                    data_channel.association_handle
                } else {
                    return Err(Error::ErrAssociationNotExisted);
                };

            if let DataChannelEvent::Message(data_channel_message) = message.data_channel_event {
                self.ctx.write_outs.push_back(TaggedRTCMessage {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                        association_handle,
                        stream_id: message.data_channel_id,
                        data_message_type: if data_channel_message.is_string {
                            DataChannelMessageType::Text
                        } else {
                            DataChannelMessageType::Binary
                        },
                        params: None,
                        payload: data_channel_message.data,
                    })),
                });
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
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        if let RTCEventInternal::SCTPHandshakeComplete(association_handle) = evt {
            self.ctx.association_handle = Some(association_handle);
        } else {
            self.ctx.event_outs.push_back(evt);
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

fn get_reliability_params(channel_type: ChannelType) -> (bool, ReliabilityType) {
    let (unordered, reliability_type) = match channel_type {
        ChannelType::Reliable => (false, ReliabilityType::Reliable),
        ChannelType::ReliableUnordered => (true, ReliabilityType::Reliable),
        ChannelType::PartialReliableRexmit => (false, ReliabilityType::Rexmit),
        ChannelType::PartialReliableRexmitUnordered => (true, ReliabilityType::Rexmit),
        ChannelType::PartialReliableTimed => (false, ReliabilityType::Timed),
        ChannelType::PartialReliableTimedUnordered => (true, ReliabilityType::Timed),
    };

    (unordered, reliability_type)
}

impl DataChannelHandler<'_> {
    fn create_data_channel_if_not_existed(
        &mut self,
        params: &DataChannelMessageParams,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<()> {
        if let Some(data_channel) = self.data_channels.get_mut(&stream_id) {
            data_channel.association_handle = association_handle;
            data_channel.ready_state = RTCDataChannelState::Open;
        } else {
            let mut data_channel = RTCDataChannelInternal::new(DataChannelParameters {
                ordered: !params.unordered,
                //TODO: fill correctly based on DataChannelMessageParams
                ..Default::default()
            });
            data_channel.association_handle = association_handle;
            data_channel.ready_state = RTCDataChannelState::Open;
            self.data_channels.insert(stream_id, data_channel);
        }
        Ok(())
    }
}
