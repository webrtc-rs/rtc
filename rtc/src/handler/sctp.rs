use crate::messages::{
    DTLSMessage, DataChannelMessage, DataChannelMessageParams, DataChannelMessageType, RTCEvent,
    RTCMessage,
};
use crate::transport::sctp_transport::RTCSctpTransport;
use bytes::BytesMut;
use log::{debug, error};
use sctp::{
    AssociationEvent, AssociationHandle, DatagramEvent, EndpointEvent, Event, Payload,
    PayloadProtocolIdentifier, StreamEvent,
};
use shared::error::{Error, Result};
use shared::handler::RTCHandler;
use shared::Transmit;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

enum SctpMessage {
    Inbound(DataChannelMessage),
    Outbound(Transmit<sctp::Payload>),
}

impl RTCHandler for RTCSctpTransport {
    fn handle_transmit(&mut self, msg: Transmit<RTCMessage>) -> Vec<Transmit<RTCMessage>> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv sctp RAW {:?}", msg.transport.peer_addr);

            let try_read = || -> Result<Vec<SctpMessage>> {
                let (sctp_endpoint, sctp_associations) = (
                    self.sctp_endpoint
                        .as_mut()
                        .ok_or(Error::ErrSCTPNotEstablished)?,
                    &mut self.sctp_associations,
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
                            if let Event::Stream(StreamEvent::Readable { id }) = event {
                                let mut stream = conn.stream(id)?;
                                while let Some(chunks) = stream.read_sctp()? {
                                    let n = chunks.read(&mut self.internal_buffer)?;
                                    messages.push(SctpMessage::Inbound(DataChannelMessage {
                                        association_handle: ch.0,
                                        stream_id: id,
                                        data_message_type: to_data_message_type(chunks.ppi),
                                        params: None,
                                        payload: BytesMut::from(&self.internal_buffer[0..n]),
                                    }));
                                }
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

            let mut next_msgs = vec![];
            match try_read() {
                Ok(messages) => {
                    for message in messages {
                        match message {
                            SctpMessage::Inbound(message) => {
                                debug!(
                                    "recv sctp data channel message {:?}",
                                    msg.transport.peer_addr
                                );
                                next_msgs.push(Transmit {
                                    now: msg.now,
                                    transport: msg.transport,
                                    message: RTCMessage::Dtls(DTLSMessage::Sctp(message)),
                                })
                            }
                            SctpMessage::Outbound(transmit) => {
                                if let Payload::RawEncode(raw_data) = transmit.message {
                                    for raw in raw_data {
                                        self.transmits.push_back(Transmit {
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
                    self.handle_error(err);
                }
            }
            next_msgs
        } else {
            // Bypass
            debug!("bypass sctp read {:?}", msg.transport.peer_addr);
            vec![msg]
        }
    }

    fn poll_transmit(&mut self, msg: Option<Transmit<RTCMessage>>) -> Option<Transmit<RTCMessage>> {
        if let Some(msg) = msg {
            if let RTCMessage::Dtls(DTLSMessage::Sctp(message)) = msg.message {
                debug!(
                    "send sctp data channel message {:?}",
                    msg.transport.peer_addr
                );

                let mut try_write = || -> Result<Vec<Transmit<Payload>>> {
                    let mut transmits = vec![];

                    let max_message_size = self.max_message_size;
                    if message.payload.len() > max_message_size {
                        return Err(Error::ErrOutboundPacketTooLarge);
                    }

                    if let Some(conn) = self
                        .sctp_associations
                        .get_mut(&AssociationHandle(message.association_handle))
                    {
                        let mut stream = conn.stream(message.stream_id)?;
                        if let Some(DataChannelMessageParams {
                            unordered,
                            reliability_type,
                            reliability_parameter,
                        }) = message.params
                        {
                            stream.set_reliability_params(
                                unordered,
                                reliability_type,
                                reliability_parameter,
                            )?;
                        }
                        stream.write_with_ppi(
                            &message.payload,
                            to_ppid(message.data_message_type, message.payload.len()),
                        )?;

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
                                    self.transmits.push_back(Transmit {
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
                    Err(err) => {
                        error!("try_write with error {}", err);
                        self.handle_error(err);
                    }
                }
            } else {
                // Bypass
                debug!("Bypass sctp write {:?}", msg.transport.peer_addr);
                self.transmits.push_back(msg);
            }
        }

        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<RTCEvent> {
        self.events.pop_front().map(RTCEvent::SctpTransportEvent)
    }

    fn handle_timeout(&mut self, now: Instant) {
        let mut try_timeout = || -> Result<Vec<Transmit<Payload>>> {
            let mut transmits = vec![];

            let (sctp_endpoint, sctp_associations) = (
                self.sctp_endpoint
                    .as_mut()
                    .ok_or(Error::ErrSCTPNotEstablished)?,
                &mut self.sctp_associations,
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
                            self.transmits.push_back(Transmit {
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
                error!("try_timeout with error {}", err);
                self.handle_error(err);
            }
        }
    }

    fn poll_timeout(&mut self, eto: &mut Instant) {
        for conn in self.sctp_associations.values() {
            if let Some(timeout) = conn.poll_timeout() {
                if timeout < *eto {
                    *eto = timeout;
                }
            }
        }
    }
}

fn split_transmit(transmit: Transmit<Payload>) -> Vec<Transmit<Payload>> {
    let mut transmits = Vec::new();
    if let Payload::RawEncode(contents) = transmit.message {
        for content in contents {
            transmits.push(Transmit {
                now: transmit.now,
                transport: transmit.transport,
                message: Payload::RawEncode(vec![content]),
            });
        }
    }

    transmits
}

fn to_data_message_type(ppid: PayloadProtocolIdentifier) -> DataChannelMessageType {
    match ppid {
        PayloadProtocolIdentifier::Dcep => DataChannelMessageType::Control,
        PayloadProtocolIdentifier::String | PayloadProtocolIdentifier::StringEmpty => {
            DataChannelMessageType::Text
        }
        PayloadProtocolIdentifier::Binary | PayloadProtocolIdentifier::BinaryEmpty => {
            DataChannelMessageType::Binary
        }
        _ => DataChannelMessageType::None,
    }
}

fn to_ppid(message_type: DataChannelMessageType, length: usize) -> PayloadProtocolIdentifier {
    match message_type {
        DataChannelMessageType::Text => {
            if length > 0 {
                PayloadProtocolIdentifier::String
            } else {
                PayloadProtocolIdentifier::StringEmpty
            }
        }
        DataChannelMessageType::Binary => {
            if length > 0 {
                PayloadProtocolIdentifier::Binary
            } else {
                PayloadProtocolIdentifier::BinaryEmpty
            }
        }
        _ => PayloadProtocolIdentifier::Dcep,
    }
}
