use crate::messages::{
    ApplicationMessage, DTLSMessageEvent, DataChannelEvent, DataChannelMessage,
    DataChannelMessageParams, DataChannelMessageType, MessageEvent, TaggedMessageEvent,
};
use datachannel::message::{message_channel_ack::*, message_channel_open::*, message_type::*, *};
use log::{debug, error, warn};
use sctp::ReliabilityType;
use shared::error::Result;
use shared::marshal::*;
use shared::{Context, Handler};
use std::collections::VecDeque;

/// DataChannelHandler implements DataChannel Protocol handling
#[derive(Default)]
pub struct DataChannelHandler {
    transmits: VecDeque<TaggedMessageEvent>,
}

impl DataChannelHandler {
    pub fn new() -> Self {
        Self {
            transmits: VecDeque::new(),
        }
    }
}

impl Handler for DataChannelHandler {
    type Rin = TaggedMessageEvent;
    type Rout = Self::Rin;
    type Win = TaggedMessageEvent;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "DataChannelHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
        if let MessageEvent::Dtls(DTLSMessageEvent::Sctp(message)) = msg.message {
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

                            let payload = Message::DataChannelAck(DataChannelAck {}).marshal()?;
                            Ok((
                                Some(ApplicationMessage {
                                    association_handle: message.association_handle,
                                    stream_id: message.stream_id,
                                    data_channel_event: DataChannelEvent::Open,
                                }),
                                Some(DataChannelMessage {
                                    association_handle: message.association_handle,
                                    stream_id: message.stream_id,
                                    data_message_type: DataChannelMessageType::Control,
                                    params: Some(DataChannelMessageParams {
                                        unordered,
                                        reliability_type,
                                        reliability_parameter: data_channel_open
                                            .reliability_parameter,
                                    }),
                                    payload,
                                }),
                            ))
                        } else {
                            Ok((None, None))
                        }
                    } else {
                        Ok((
                            Some(ApplicationMessage {
                                association_handle: message.association_handle,
                                stream_id: message.stream_id,
                                data_channel_event: DataChannelEvent::Message(message.payload),
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
                        self.transmits.push_back(TaggedMessageEvent {
                            now: msg.now,
                            transport: msg.transport,
                            message: MessageEvent::Dtls(DTLSMessageEvent::Sctp(
                                data_channel_message,
                            )),
                        });
                    }

                    // then inbound message
                    if let Some(application_message) = inbound_message {
                        debug!("recv application message {:?}", msg.transport.peer_addr);
                        ctx.fire_handle_read(TaggedMessageEvent {
                            now: msg.now,
                            transport: msg.transport,
                            message: MessageEvent::Dtls(DTLSMessageEvent::DataChannel(
                                application_message,
                            )),
                        })
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    ctx.fire_handle_error(Box::new(err))
                }
            };
        } else {
            // Bypass
            debug!("bypass DataChannel read {:?}", msg.transport.peer_addr);
            ctx.fire_handle_read(msg);
        }
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
            if let MessageEvent::Dtls(DTLSMessageEvent::DataChannel(message)) = msg.message {
                debug!("send application message {:?}", msg.transport.peer_addr);

                if let DataChannelEvent::Message(payload) = message.data_channel_event {
                    self.transmits.push_back(TaggedMessageEvent {
                        now: msg.now,
                        transport: msg.transport,
                        message: MessageEvent::Dtls(DTLSMessageEvent::Sctp(DataChannelMessage {
                            association_handle: message.association_handle,
                            stream_id: message.stream_id,
                            data_message_type: DataChannelMessageType::Text,
                            params: None,
                            payload,
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
                self.transmits.push_back(msg);
            }
        }

        self.transmits.pop_front()
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
