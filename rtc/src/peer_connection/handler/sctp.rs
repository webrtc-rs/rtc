use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::handler::DEFAULT_TIMEOUT_DURATION;
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::sctp::RTCSctpTransport;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message;
use datachannel::message::message_channel_threshold::DataChannelThreshold;
use log::{debug, warn};
use sctp::{
    AssociationEvent, AssociationHandle, ClientConfig, DatagramEvent, EndpointEvent, Event,
    Payload, PayloadProtocolIdentifier, StreamEvent,
};
use shared::error::{Error, Result};
use shared::marshal::Unmarshal;
use shared::{TransportContext, TransportMessage};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SctpHandlerContext {
    pub(crate) sctp_transport: RTCSctpTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
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

impl<'a> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for SctpHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv sctp RAW {:?}", msg.transport.peer_addr);

            if self.ctx.sctp_transport.sctp_endpoint.is_none() {
                warn!(
                    "drop sctp RAW {:?} due to sctp_endpoint is not ready yet",
                    msg.transport.peer_addr
                );
                return Ok(());
            }

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
                                debug!(
                                    "association_handle {} handle_event for Datagram from {}",
                                    ch.0, msg.transport.peer_addr
                                );
                                conn.handle_event(event);
                            }
                        }
                    }

                    while let Some(event) = conn.poll() {
                        match event {
                            Event::HandshakeFailed { reason } => {
                                debug!(
                                    "association_handle {} handshake failed due to {}",
                                    ch.0, reason
                                );
                                //TODO: put it into event_outs?
                            }
                            Event::Connected => {
                                debug!("association_handle {} is connected", ch.0);
                                self.ctx
                                    .event_outs
                                    .push_back(RTCEventInternal::SCTPHandshakeComplete(ch.0));
                            }
                            Event::AssociationLost { reason, id } => {
                                debug!("association_handle {} is closed due to {}", ch.0, reason);
                                self.ctx
                                    .event_outs
                                    .push_back(RTCEventInternal::SCTPStreamClosed(ch.0, id));
                            }
                            Event::Stream(StreamEvent::Readable { id }) => {
                                let mut stream = conn.stream(id)?;
                                while let Some(chunks) = stream.read_sctp()? {
                                    let n = chunks
                                        .read(&mut self.ctx.sctp_transport.internal_buffer)?;
                                    messages.push(SctpMessage::Inbound(DataChannelMessage::new(
                                        ch.0,
                                        id,
                                        chunks.ppi,
                                        BytesMut::from(
                                            &self.ctx.sctp_transport.internal_buffer[0..n],
                                        ),
                                        false,
                                    )));
                                }
                            }
                            Event::Stream(StreamEvent::BufferedAmountLow { id }) => {
                                debug!(
                                    "association_handle {} stream id {} is buffered amount low",
                                    ch.0, id
                                );
                                self.ctx.event_outs.push_back(
                                    RTCEventInternal::RTCPeerConnectionEvent(
                                        RTCPeerConnectionEvent::OnDataChannel(
                                            RTCDataChannelEvent::OnBufferedAmountLow(id),
                                        ),
                                    ),
                                );
                            }
                            Event::Stream(StreamEvent::BufferedAmountHigh { id }) => {
                                debug!(
                                    "association_handle {} stream id {} is buffered amount high",
                                    ch.0, id
                                );
                                self.ctx.event_outs.push_back(
                                    RTCEventInternal::RTCPeerConnectionEvent(
                                        RTCPeerConnectionEvent::OnDataChannel(
                                            RTCDataChannelEvent::OnBufferedAmountHigh(id),
                                        ),
                                    ),
                                );
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

            for message in messages {
                match message {
                    SctpMessage::Inbound(message) => {
                        debug!(
                            "recv sctp data channel message {:?}",
                            msg.transport.peer_addr
                        );
                        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                        })
                    }
                    SctpMessage::Outbound(transmit) => {
                        if let Payload::RawEncode(raw_data) = transmit.message {
                            for raw in raw_data {
                                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                    now: transmit.now,
                                    transport: transmit.transport,
                                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(
                                        BytesMut::from(&raw[..]),
                                    )),
                                });
                            }
                        }
                    }
                }
            }
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

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "send sctp data channel message to {:?}",
                msg.transport.peer_addr
            );

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
                let mut is_dcep_internal_control_message = false;
                if message.ppi == PayloadProtocolIdentifier::Dcep {
                    let mut data_buf = &message.payload[..];
                    let dcep_message = Message::unmarshal(&mut data_buf)?;
                    match dcep_message {
                        Message::DataChannelOpen(data_channel_open) => {
                            debug!(
                                "sctp data channel open {:?} for stream id {}",
                                data_channel_open, message.stream_id
                            );
                            let (unordered, reliability_type) =
                                ::datachannel::data_channel::DataChannel::get_reliability_params(
                                    data_channel_open.channel_type,
                                );
                            let mut stream = conn.open_stream(message.stream_id, message.ppi)?;
                            stream.set_reliability_params(
                                unordered,
                                reliability_type,
                                data_channel_open.reliability_parameter,
                            )?;
                            // Pre-negotiated channels must not announce
                            // themselves in-band; suppress the wire write.
                            if message.negotiated {
                                is_dcep_internal_control_message = true;
                            }
                        }
                        Message::DataChannelClose(_) => {
                            is_dcep_internal_control_message = true;
                            debug!(
                                "sctp data channel close for stream id {}",
                                message.stream_id
                            );
                            let mut stream = conn.stream(message.stream_id)?;
                            stream.close()?;

                            self.ctx
                                .event_outs
                                .push_back(RTCEventInternal::SCTPStreamClosed(
                                    message.association_handle,
                                    message.stream_id,
                                ));
                        }
                        Message::DataChannelThreshold(data_channel_threshold) => {
                            is_dcep_internal_control_message = true;
                            debug!(
                                "sctp data channel set threshold {:?} for stream id {}",
                                data_channel_threshold, message.stream_id
                            );
                            let mut stream = conn.stream(message.stream_id)?;
                            match data_channel_threshold {
                                DataChannelThreshold::Low(threshold) => {
                                    stream.set_buffered_amount_low_threshold(threshold as usize)?;
                                }
                                DataChannelThreshold::High(threshold) => {
                                    stream
                                        .set_buffered_amount_high_threshold(threshold as usize)?;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let mut stream = conn.stream(message.stream_id)?;
                if !is_dcep_internal_control_message && stream.is_writable() {
                    stream.write_with_ppi(&message.payload, message.ppi)?;
                }

                while let Some(x) = conn.poll_transmit(msg.now) {
                    transmits.extend(split_transmit(x));
                }
            } else {
                return Err(Error::ErrAssociationNotExisted);
            }

            for transmit in transmits {
                if let Payload::RawEncode(raw_data) = transmit.message {
                    for raw in raw_data {
                        self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                            now: transmit.now,
                            transport: transmit.transport,
                            message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(
                                &raw[..],
                            ))),
                        });
                    }
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
        if let RTCEventInternal::DTLSHandshakeComplete(_, _) = &evt {
            debug!("sctp recv dtls handshake complete");

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
                    .connect(
                        ClientConfig::new(sctp_transport_config),
                        TransportContext::default().peer_addr,
                    )
                    .map_err(|e| Error::Other(e.to_string()))?;

                sctp_associations.insert(ch, conn);
            }
        }

        self.ctx.event_outs.push_back(evt);

        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.ctx.sctp_transport.sctp_endpoint.is_none() {
            return Ok(());
        }

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

        for transmit in transmits {
            if let Payload::RawEncode(raw_data) = transmit.message {
                for raw in raw_data {
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: transmit.now,
                        transport: transmit.transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(
                            &raw[..],
                        ))),
                    });
                }
            }
        }

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let max_eto = Instant::now() + DEFAULT_TIMEOUT_DURATION;
        let mut eto = max_eto;

        for conn in self.ctx.sctp_transport.sctp_associations.values() {
            if let Some(timeout) = conn.poll_timeout()
                && timeout < eto
            {
                eto = timeout;
            }
        }

        if eto != max_eto { Some(eto) } else { None }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
    use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
    use datachannel::message::message_channel_open::DataChannelOpen;
    use sansio::Protocol;
    use shared::marshal::Marshal;

    /// Build a `SctpHandlerContext` whose SCTP endpoint has exactly one
    /// association so that `handle_write` can reach the DCEP dispatch code.
    fn make_ctx_with_association() -> (SctpHandlerContext, usize) {
        let mut sctp_transport = RTCSctpTransport::new(
            crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize::default(),
        );
        sctp_transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 65536,
                },
                5000,
                5000,
            )
            .expect("start sctp transport");

        // Trigger a client-side connect to create an association.
        let endpoint = sctp_transport.sctp_endpoint.as_mut().unwrap();
        let config = sctp_transport.sctp_transport_config.clone().unwrap();
        let (ch, conn) = endpoint
            .connect(
                sctp::ClientConfig::new(config),
                TransportContext::default().peer_addr,
            )
            .expect("connect");
        let association_handle = ch.0;
        sctp_transport.sctp_associations.insert(ch, conn);

        (SctpHandlerContext::new(sctp_transport), association_handle)
    }

    /// Build a serialised DCEP DataChannelOpen payload.
    fn make_dcep_open_payload() -> BytesMut {
        let msg = Message::DataChannelOpen(DataChannelOpen {
            channel_type: datachannel::message::message_channel_open::ChannelType::Reliable,
            priority: 0,
            reliability_parameter: 0,
            label: b"test-label".to_vec(),
            protocol: b"".to_vec(),
        });
        msg.marshal().expect("marshal DataChannelOpen")
    }

    /// A negotiated (pre-negotiated / out-of-band) DataChannelOpen must set
    /// `is_dcep_internal_control_message = true` so the SCTP handler does NOT
    /// forward the DCEP payload over the wire.
    ///
    /// With a not-yet-established association the stream is writable (default
    /// `ReadWritable` state) but `send_payload_data` would fail with
    /// `ErrPayloadDataStateNotExist` if the handler tried to write the DCEP
    /// payload.  The fact that `handle_write` returns `Ok(())` proves the
    /// negotiated branch suppressed the wire write.
    #[test]
    fn negotiated_datachannel_open_suppresses_wire_write() {
        let (mut ctx, association_handle) = make_ctx_with_association();
        let payload = make_dcep_open_payload();

        let msg = TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage::new(
                association_handle,
                42,
                PayloadProtocolIdentifier::Dcep,
                payload,
                true,
            ))),
        };

        let mut handler = SctpHandler::new(&mut ctx);
        handler
            .handle_write(msg)
            .expect("handle_write must succeed for negotiated channel (wire write suppressed)");
    }

    /// A non-negotiated (in-band) DataChannelOpen does NOT suppress the wire
    /// write. Because the stream defaults to `ReadWritable`, `write_with_ppi`
    /// is attempted but fails with `ErrPayloadDataStateNotExist` since the
    /// SCTP association has not completed its handshake.
    ///
    /// This confirms that the `negotiated` flag is the deciding factor: the
    /// negotiated test above succeeds precisely because the write is suppressed.
    #[test]
    fn non_negotiated_datachannel_open_attempts_wire_write() {
        let (mut ctx, association_handle) = make_ctx_with_association();
        let payload = make_dcep_open_payload();

        let msg = TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage::new(
                association_handle,
                43,
                PayloadProtocolIdentifier::Dcep,
                payload,
                false,
            ))),
        };

        let mut handler = SctpHandler::new(&mut ctx);
        let result = handler.handle_write(msg);

        // The non-negotiated path tries to write the DCEP payload over the
        // wire, which fails because the association is not yet established.
        match result {
            Err(err) => {
                let debug = format!("{err:?}");
                assert!(
                    debug.contains("ErrPayloadDataStateNotExist"),
                    "expected ErrPayloadDataStateNotExist from attempted wire write, got: {debug}"
                );
            }
            Ok(()) => {
                panic!(
                    "in-band DataChannelOpen should attempt a wire write and fail on a non-established association"
                );
            }
        }
    }

    /// When both peers open the same negotiated stream, the second
    /// `open_stream` call must fail with `ErrStreamAlreadyExist`.  This
    /// exercises the peer-race scenario described in RFC 8832 where both
    /// sides send `DATA_CHANNEL_OPEN` for the same pre-negotiated stream ID.
    #[test]
    fn negotiated_dial_duplicate_stream_returns_already_exist() {
        let (mut ctx, association_handle) = make_ctx_with_association();
        let payload = make_dcep_open_payload();

        // First dial: opens stream 50 successfully.
        let msg1 = TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage::new(
                association_handle,
                50,
                PayloadProtocolIdentifier::Dcep,
                payload.clone(),
                true,
            ))),
        };

        let mut handler = SctpHandler::new(&mut ctx);
        handler
            .handle_write(msg1)
            .expect("first negotiated open must succeed");

        // Second dial on the same stream ID: simulates the peer race where
        // both sides send DATA_CHANNEL_OPEN for the same negotiated channel.
        let msg2 = TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage::new(
                association_handle,
                50,
                PayloadProtocolIdentifier::Dcep,
                payload,
                true,
            ))),
        };

        let mut handler = SctpHandler::new(&mut ctx);
        let result = handler.handle_write(msg2);

        match result {
            Err(err) => {
                let debug = format!("{err:?}");
                assert!(
                    debug.contains("ErrStreamAlreadyExist"),
                    "expected ErrStreamAlreadyExist for duplicate negotiated stream, got: {debug}"
                );
            }
            Ok(()) => {
                panic!(
                    "duplicate open_stream on the same stream ID should fail with ErrStreamAlreadyExist"
                );
            }
        }
    }
}
