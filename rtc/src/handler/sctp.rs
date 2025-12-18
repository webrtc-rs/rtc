use super::message::{
    DTLSMessage, DataChannelMessage, DataChannelMessageType, RTCMessage, TaggedRTCMessage,
};
use log::debug;
use sctp::{Payload, PayloadProtocolIdentifier};
use shared::{Context, Handler, TransportMessage};
use std::collections::VecDeque;
use std::time::Instant;

/// SctpHandler implements SCTP Protocol handling
pub struct SctpHandler {
    //local_addr: SocketAddr,
    //server_states: Rc<RefCell<ServerStates>>,
    internal_buffer: Vec<u8>,
    transmits: VecDeque<TaggedRTCMessage>,
}

enum SctpMessage {
    Inbound(DataChannelMessage),
    Outbound(TransportMessage<Payload>),
}

impl SctpHandler {
    pub fn new(
        /*local_addr: SocketAddr, server_states: Rc<RefCell<ServerStates>>*/
        max_message_size: usize,
    ) -> Self {
        SctpHandler {
            //local_addr,
            //server_states: Rc::clone(&server_states),
            internal_buffer: vec![0u8; max_message_size],
            transmits: VecDeque::new(),
        }
    }
}

impl Handler for SctpHandler {
    type Rin = TaggedRTCMessage;
    type Rout = Self::Rin;
    type Win = TaggedRTCMessage;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "SctpHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
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
            match try_read() {
                Ok(messages) => {
                    for message in messages {
                        match message {
                            SctpMessage::Inbound(message) => {
                                debug!(
                                    "recv sctp data channel message {:?}",
                                    msg.transport.peer_addr
                                );
                                ctx.fire_handle_read(TaggedRTCMessage {
                                    now: msg.now,
                                    transport: msg.transport,
                                    message: RTCMessage::Dtls(DTLSMessage::Sctp(message)),
                                })
                            }
                            SctpMessage::Outbound(transmit) => {
                                if let Payload::RawEncode(raw_data) = transmit.message {
                                    for raw in raw_data {
                                        self.transmits.push_back(TaggedRTCMessage {
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
                    ctx.fire_handle_error(Box::new(err))
                }
            };*/
        } else {
            // Bypass
            debug!("bypass sctp read {:?}", msg.transport.peer_addr);
            ctx.fire_handle_read(msg);
        }
    }

    fn handle_timeout(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        now: Instant,
    ) {
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
                            self.transmits.push_back(TaggedRTCMessage {
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
                ctx.fire_handle_error(Box::new(err));
            }
        }*/

        ctx.fire_handle_timeout(now);
    }

    fn poll_timeout(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        eto: &mut Instant,
    ) {
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
        ctx.fire_poll_timeout(eto);
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
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
                                    self.transmits.push_back(TaggedRTCMessage {
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
                        ctx.fire_handle_error(Box::new(err));
                    }
                }*/
            } else {
                // Bypass
                debug!("Bypass sctp write {:?}", msg.transport.peer_addr);
                self.transmits.push_back(msg);
            }
        }

        self.transmits.pop_front()
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
