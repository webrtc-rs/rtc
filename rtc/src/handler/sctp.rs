use super::message::{
    DTLSMessage, DataChannelMessage, DataChannelMessageType, RTCMessage, TaggedRTCMessage,
};
use crate::transport::sctp::RTCSctpTransport;
use log::debug;
use sctp::{Payload, PayloadProtocolIdentifier};
use shared::error::{Error, Result};
use shared::TransportMessage;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SctpHandlerContext {
    pub(crate) sctp_transport: RTCSctpTransport,

    //local_addr: SocketAddr,
    //server_states: Rc<RefCell<ServerStates>>,
    pub(crate) internal_buffer: Vec<u8>,
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
}

impl SctpHandlerContext {
    pub(crate) fn new(sctp_transport: RTCSctpTransport) -> Self {
        let max_message_size = sctp_transport.max_message_size.as_usize();
        Self {
            sctp_transport,
            internal_buffer: vec![0u8; max_message_size],
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
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

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, ()> for SctpHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(_dtls_message)) = msg.message {
            debug!("recv sctp RAW {:?}", msg.transport.peer_addr);
            todo!()
            /*
            let four_tuple = (&msg.transport).into();

            let try_read = || -> Result<Vec<SctpMessage>> {
                let mut server_states = self.server_states.borrow_mut();
                let transport = server_states.get_mut_transport(&four_tuple)?;
                let (sctp_endpoint, sctp_associations) =
                    transport.get_mut_sctp_endpoint_associations();

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
                                    let n = chunks.read(&mut self.ctx.internal_buffer)?;
                                    messages.push(SctpMessage::Inbound(DataChannelMessage {
                                        association_handle: ch.0,
                                        stream_id: id,
                                        data_message_type: to_data_message_type(chunks.ppi),
                                        params: None,
                                        payload: BytesMut::from(&self.ctx.internal_buffer[0..n]),
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
                                            transport: TransportContext {
                                                local_addr: self.local_addr,
                                                peer_addr: transmit.transport.peer_addr,
                                                transport_protocol: TransportProtocol::UDP,
                                                ecn: transmit.transport.ecn,
                                            },
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
            };*/
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
        if let RTCMessage::Dtls(DTLSMessage::Sctp(_message)) = msg.message {
            debug!(
                "send sctp data channel message {:?}",
                msg.transport.peer_addr
            );
            /*
            let four_tuple = (&msg.transport).into();

            let try_write = || -> Result<Vec<TransportMessage<Payload>>> {
                let mut transmits = vec![];
                let mut server_states = self.server_states.borrow_mut();
                let max_message_size = {
                    server_states
                        .server_config()
                        .sctp_server_config
                        .transport
                        .max_message_size() as usize
                };
                if message.payload.len() > max_message_size {
                    return Err(Error::ErrOutboundPacketTooLarge);
                }

                let transport = server_states.get_mut_transport(&four_tuple)?;
                let sctp_associations = transport.get_mut_sctp_associations();
                if let Some(conn) =
                    sctp_associations.get_mut(&AssociationHandle(message.association_handle))
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
                                self.ctx.write_outs.push_back(TaggedRTCMessage {
                                    now: transmit.now,
                                    transport: TransportContext {
                                        local_addr: self.local_addr,
                                        peer_addr: transmit.transport.peer_addr,
                                        transport_protocol: TransportProtocol::UDP,
                                        ecn: transmit.transport.ecn,
                                    },
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
                    return Err(err);
                }
            }*/
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

    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        /*TODO:
        let try_timeout = || -> Result<Vec<TransportMessage<Payload>>> {
            let mut transmits = vec![];
            let mut server_states = self.server_states.borrow_mut();

            for session in server_states.get_mut_sessions().values_mut() {
                for endpoint in session.get_mut_endpoints().values_mut() {
                    for transport in endpoint.get_mut_transports().values_mut() {
                        let (sctp_endpoint, sctp_associations) =
                            transport.get_mut_sctp_endpoint_associations();

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
                    }
                }
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
                                transport: TransportContext {
                                    local_addr: self.local_addr,
                                    peer_addr: transmit.transport.peer_addr,
                                    transport_protocol: TransportProtocol::UDP,
                                    ecn: transmit.transport.ecn,
                                },
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
                return Err(err);
            }
        }*/

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        /*TODO:
        {
            let server_states = self.server_states.borrow();
            for session in server_states.get_sessions().values() {
                for endpoint in session.get_endpoints().values() {
                    for transport in endpoint.get_transports().values() {
                        let sctp_associations = transport.get_sctp_associations();
                        for conn in sctp_associations.values() {
                            if let Some(timeout) = conn.poll_timeout() {
                                if timeout < *eto {
                                    *eto = timeout;
                                }
                            }
                        }
                    }
                }
            }
        }*/
        None
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
