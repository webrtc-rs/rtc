use super::message::{DTLSMessage, RTCEventInternal, RTCMessage, TaggedRTCMessage};
use crate::handler::DEFAULT_TIMEOUT_DURATION;
use crate::transport::sctp::RTCSctpTransport;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message;
use log::{debug, error, warn};
use sctp::{
    AssociationEvent, AssociationHandle, ClientConfig, DatagramEvent, EndpointEvent, Event,
    Payload, PayloadProtocolIdentifier, StreamEvent,
};
use shared::error::{Error, Result};
use shared::marshal::Unmarshal;
use shared::TransportMessage;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SctpHandlerContext {
    pub(crate) sctp_transport: RTCSctpTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

impl SctpHandlerContext {
    pub(crate) fn new(sctp_transport: RTCSctpTransport) -> Self {
        Self {
            sctp_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
        }
    }
}

/// SctpHandler implements SCTP Protocol handling
pub(crate) struct SctpHandler<'a> {
    ctx: &'a mut SctpHandlerContext,
}

impl<'a> SctpHandler<'a> {
    pub(crate) fn new(ctx: &'a mut SctpHandlerContext) -> Self {
        SctpHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "SctpHandler"
    }
}

enum SctpMessage {
    Inbound(DataChannelMessage),
    Outbound(TransportMessage<Payload>),
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal>
    for SctpHandler<'a>
{
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv sctp RAW {:?}", msg.transport.peer_addr);

            if self.ctx.sctp_transport.sctp_endpoint.is_none() {
                warn!(
                    "drop sctp RAW {:?} due to sctp_endpoint is not ready yet",
                    msg.transport.peer_addr
                );
                return Ok(());
            }

            let try_read = || -> Result<Vec<SctpMessage>> {
                let (sctp_endpoint, sctp_associations) = (
                    self.ctx
                        .sctp_transport
                        .sctp_endpoint
                        .as_mut()
                        .ok_or(Error::ErrSCTPNotEstablished)?,
                    &mut self.ctx.sctp_transport.sctp_associations,
                );

                let mut sctp_events: HashMap<AssociationHandle, VecDeque<AssociationEvent>> =
                    HashMap::new();
                if let Some((ch, event)) = sctp_endpoint.handle(
                    msg.now,
                    msg.transport.peer_addr,
                    msg.transport.ecn,
                    dtls_message.freeze(), //TODO: switch API Bytes to BytesMut
                ) {
                    match event {
                        DatagramEvent::NewAssociation(conn) => {
                            sctp_associations.insert(ch, conn);
                        }
                        DatagramEvent::AssociationEvent(event) => {
                            sctp_events.entry(ch).or_default().push_back(event);
                        }
                    }
                }

                let mut messages = vec![];
                {
                    let mut endpoint_events: Vec<(AssociationHandle, EndpointEvent)> = vec![];

                    for (ch, conn) in sctp_associations.iter_mut() {
                        for (event_ch, conn_events) in sctp_events.iter_mut() {
                            if ch == event_ch {
                                for event in conn_events.drain(..) {
                                    debug!("association_handle {} handle_event", ch.0);
                                    conn.handle_event(event);
                                }
                            }
                        }

                        while let Some(event) = conn.poll() {
                            match event {
                                Event::Connected => {
                                    self.ctx
                                        .event_outs
                                        .push_back(RTCEventInternal::SCTPHandshakeComplete(ch.0));
                                }
                                /*Event::Stream(StreamEvent::Opened { id }) => {
                                    self.ctx
                                        .event_outs
                                        .push_back(RTCEventInternal::SCTPStreamOpened(ch.0, id));
                                }*/
                                Event::Stream(StreamEvent::Readable { id }) => {
                                    let mut stream = conn.stream(id)?;
                                    while let Some(chunks) = stream.read_sctp()? {
                                        let n = chunks
                                            .read(&mut self.ctx.sctp_transport.internal_buffer)?;
                                        messages.push(SctpMessage::Inbound(DataChannelMessage {
                                            association_handle: ch.0,
                                            stream_id: id,
                                            ppi: chunks.ppi,
                                            payload: BytesMut::from(
                                                &self.ctx.sctp_transport.internal_buffer[0..n],
                                            ),
                                        }));
                                    }
                                }
                                _ => {}
                            }
                        }

                        while let Some(event) = conn.poll_endpoint_event() {
                            endpoint_events.push((*ch, event));
                        }

                        while let Some(x) = conn.poll_transmit(msg.now) {
                            for transmit in split_transmit(x) {
                                messages.push(SctpMessage::Outbound(transmit));
                            }
                        }
                    }

                    for (ch, event) in endpoint_events {
                        sctp_endpoint.handle_event(ch, event); // handle drain event
                        sctp_associations.remove(&ch);
                    }
                }

                Ok(messages)
            };
            match try_read() {
                Ok(messages) => {
                    for message in messages {
                        match message {
                            SctpMessage::Inbound(message) => {
                                debug!(
                                    "recv sctp data channel message {:?}",
                                    msg.transport.peer_addr
                                );
                                self.ctx.read_outs.push_back(TaggedRTCMessage {
                                    now: msg.now,
                                    transport: msg.transport,
                                    message: RTCMessage::Dtls(DTLSMessage::Sctp(message)),
                                })
                            }
                            SctpMessage::Outbound(transmit) => {
                                if let Payload::RawEncode(raw_data) = transmit.message {
                                    for raw in raw_data {
                                        self.ctx.write_outs.push_back(TaggedRTCMessage {
                                            now: transmit.now,
                                            transport: transmit.transport,
                                            message: RTCMessage::Dtls(DTLSMessage::Raw(
                                                BytesMut::from(&raw[..]),
                                            )),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    return Err(err);
                }
            };
        } else {
            // Bypass
            debug!("bypass sctp read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "send sctp data channel message {:?}",
                msg.transport.peer_addr
            );

            let mut try_write = || -> Result<Vec<TransportMessage<Payload>>> {
                let mut transmits = vec![];
                if message.payload.len() > self.ctx.sctp_transport.internal_buffer.len() {
                    return Err(Error::ErrOutboundPacketTooLarge);
                }

                if let Some(conn) = self
                    .ctx
                    .sctp_transport
                    .sctp_associations
                    .get_mut(&AssociationHandle(message.association_handle))
                {
                    let mut stream = conn.stream(message.stream_id)?;
                    if message.ppi == PayloadProtocolIdentifier::Dcep {
                        let mut data_buf = &message.payload[..];
                        match Message::unmarshal(&mut data_buf)? {
                            Message::DataChannelOpen(data_channel_open) => {
                                let (unordered, reliability_type) = ::datachannel::data_channel::DataChannel::get_reliability_params(data_channel_open.channel_type);
                                stream.set_reliability_params(
                                    unordered,
                                    reliability_type,
                                    data_channel_open.reliability_parameter,
                                )?;
                            }
                            _ => {}
                        }
                    }
                    stream.write_with_ppi(&message.payload, message.ppi)?;

                    while let Some(x) = conn.poll_transmit(msg.now) {
                        transmits.extend(split_transmit(x));
                    }
                } else {
                    return Err(Error::ErrAssociationNotExisted);
                }
                Ok(transmits)
            };
            match try_write() {
                Ok(transmits) => {
                    for transmit in transmits {
                        if let Payload::RawEncode(raw_data) = transmit.message {
                            for raw in raw_data {
                                self.ctx.write_outs.push_back(TaggedRTCMessage {
                                    now: transmit.now,
                                    transport: transmit.transport,
                                    message: RTCMessage::Dtls(DTLSMessage::Raw(BytesMut::from(
                                        &raw[..],
                                    ))),
                                });
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("try_write with error {}", err);
                    return Err(err);
                }
            }
        } else {
            // Bypass
            debug!("Bypass sctp write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        // DTLSHandshakeComplete is not terminated here since SRTP handler needs it
        let remote_addr = if let RTCEventInternal::DTLSHandshakeComplete(remote_addr, _, _) = &evt {
            Some(*remote_addr)
        } else {
            None
        };

        self.ctx.event_outs.push_back(evt);

        if let Some(remote_addr) = remote_addr {
            if let Some(sctp_transport_config) =
                self.ctx.sctp_transport.sctp_transport_config.clone()
            {
                let (sctp_endpoint, sctp_associations) = (
                    self.ctx
                        .sctp_transport
                        .sctp_endpoint
                        .as_mut()
                        .ok_or(Error::ErrSCTPNotEstablished)?,
                    &mut self.ctx.sctp_transport.sctp_associations,
                );

                debug!("sctp endpoint initiates connection for dtls client role");
                let (ch, conn) = sctp_endpoint
                    .connect(ClientConfig::new(sctp_transport_config), remote_addr)
                    .map_err(|e| Error::Other(e.to_string()))?;

                sctp_associations.insert(ch, conn);
            }
        }

        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.ctx.sctp_transport.sctp_endpoint.is_none() {
            return Ok(());
        }

        let mut try_timeout = || -> Result<Vec<TransportMessage<Payload>>> {
            let mut transmits = vec![];

            let (sctp_endpoint, sctp_associations) = (
                self.ctx
                    .sctp_transport
                    .sctp_endpoint
                    .as_mut()
                    .ok_or(Error::ErrSCTPNotEstablished)?,
                &mut self.ctx.sctp_transport.sctp_associations,
            );

            let mut endpoint_events: Vec<(AssociationHandle, EndpointEvent)> = vec![];
            for (ch, conn) in sctp_associations.iter_mut() {
                conn.handle_timeout(now);

                while let Some(event) = conn.poll_endpoint_event() {
                    endpoint_events.push((*ch, event));
                }

                while let Some(x) = conn.poll_transmit(now) {
                    transmits.extend(split_transmit(x));
                }
            }

            for (ch, event) in endpoint_events {
                sctp_endpoint.handle_event(ch, event); // handle drain event
                sctp_associations.remove(&ch);
            }

            Ok(transmits)
        };
        match try_timeout() {
            Ok(transmits) => {
                for transmit in transmits {
                    if let Payload::RawEncode(raw_data) = transmit.message {
                        for raw in raw_data {
                            self.ctx.write_outs.push_back(TaggedRTCMessage {
                                now: transmit.now,
                                transport: transmit.transport,
                                message: RTCMessage::Dtls(DTLSMessage::Raw(BytesMut::from(
                                    &raw[..],
                                ))),
                            });
                        }
                    }
                }
                Ok(())
            }
            Err(err) => {
                error!("try_timeout with error {}", err);
                Err(err)
            }
        }
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let max_eto = Instant::now() + DEFAULT_TIMEOUT_DURATION;
        let mut eto = max_eto;

        for conn in self.ctx.sctp_transport.sctp_associations.values() {
            if let Some(timeout) = conn.poll_timeout() {
                if timeout < eto {
                    eto = timeout;
                }
            }
        }

        if eto != max_eto {
            Some(eto)
        } else {
            None
        }
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

fn split_transmit(transmit: TransportMessage<Payload>) -> Vec<TransportMessage<Payload>> {
    let mut transmits: Vec<TransportMessage<Payload>> = Vec::new();
    if let Payload::RawEncode(contents) = transmit.message {
        for content in contents {
            transmits.push(TransportMessage {
                now: transmit.now,
                transport: transmit.transport,
                message: Payload::RawEncode(vec![content]),
            })
        }
    }

    transmits
}
