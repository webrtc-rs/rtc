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

    // Batch-drain state: handle_read/handle_write/handle_timeout only INGEST (set
    // `flush_dirty`); the single transmit flush runs in poll_write, once per driver
    // event-loop iteration. Paired with the driver's burst-read, N received DATA
    // chunks are processed before one flush, so the ack machine coalesces them into
    // ONE SACK (1st arms Delay, 2nd+ stay Immediate until flushed) instead of one
    // SACK per two packets — cutting sendto/recvfrom and amortizing per-iteration
    // cost. `last_now` carries the newest timestamp seen into that flush.
    flush_dirty: bool,
    last_now: Option<Instant>,
}

impl SctpHandlerContext {
    pub(crate) fn new(sctp_transport: RTCSctpTransport) -> Self {
        Self {
            sctp_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            flush_dirty: false,
            last_now: None,
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

    /// Batch-drain flush: gather every association's pending outbound in one pass
    /// into `write_outs`. Called once per event-loop iteration from poll_write when
    /// `flush_dirty` is set, after a burst of inbound packets has been ingested, so
    /// their SACKs coalesce into a single datagram.
    fn flush_transmits(&mut self, now: Instant) {
        for (_ch, conn) in self.ctx.sctp_transport.sctp_associations.iter_mut() {
            while let Some(x) = conn.poll_transmit(now) {
                for transmit in split_transmit(x) {
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
        let now = msg.now;
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
                                    // Reassemble straight into the delivered buffer:
                                    // one copy instead of the scratch-buffer round-trip
                                    // (`internal_buffer.len()` preserves the max-message
                                    // -size bound `read()` enforced via `ErrShortBuffer`).
                                    let max_len = self.ctx.sctp_transport.internal_buffer.len();
                                    let payload = chunks.to_payload(max_len)?;
                                    messages.push(SctpMessage::Inbound(DataChannelMessage {
                                        association_handle: ch.0,
                                        stream_id: id,
                                        ppi: chunks.ppi,
                                        payload,
                                        negotiated: false,
                                    }));
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
                    // Transmit flush is deferred to poll_write (batch-drain) so a
                    // burst of inbound DATA coalesces into one SACK.
                }

                // Teardown safety: if any association is about to be removed
                // (drain/shutdown), flush all pending outbound now — the deferred
                // poll_write flush runs after removal and would drop the
                // association's final packets. Only fires when there IS a removal,
                // so steady-state SACK coalescing is unaffected.
                if !endpoint_events.is_empty() {
                    for (_ch, conn) in sctp_associations.iter_mut() {
                        while let Some(x) = conn.poll_transmit(now) {
                            for transmit in split_transmit(x) {
                                messages.push(SctpMessage::Outbound(transmit));
                            }
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

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.last_now = Some(now);
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
        let now = msg.now;
        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(mut message)) = msg.message {
            debug!(
                "send sctp data channel message to {:?}",
                msg.transport.peer_addr
            );

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

                            // Out-of-band negotiated channels (W3C WebRTC
                            // `RTCDataChannelInit.negotiated`) only open the SCTP
                            // stream locally; the DCEP handshake must not be sent
                            // to the peer, which already created its own channel
                            // with the pre-agreed stream id.
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
                    // The payload is owned end-to-end (the DataChannel `send` API
                    // takes the buffer by value), so hand it to SCTP zero-copy:
                    // `freeze()` is O(1) and the enqueued chunks are refcounted
                    // slices, eliminating a per-message alloc + full-payload memcpy.
                    let payload = std::mem::take(&mut message.payload).freeze();
                    stream.write_chunk_with_ppi(&payload, message.ppi)?;
                }

                // Transmit flush is deferred to poll_write (batch-drain).
            } else {
                return Err(Error::ErrAssociationNotExisted);
            }

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.last_now = Some(now);
        } else {
            // Bypass
            debug!("Bypass sctp write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        // Batch-drain: run the single deferred transmit flush for this event-loop
        // iteration before serving queued outbound.
        if self.ctx.flush_dirty {
            self.ctx.flush_dirty = false;
            let now = self.ctx.last_now.unwrap_or_else(Instant::now);
            self.flush_transmits(now);
        }
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        // DTLSHandshakeComplete is not terminated here since SRTP handler needs it
        let dtls_complete = matches!(&evt, RTCEventInternal::DTLSHandshakeComplete(_, _));
        if dtls_complete {
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

                // `connect` queued the client INIT. Mark dirty so poll_write emits
                // it at the next flush instead of waiting for a later handle_* (the
                // deferred flush is now the only transmit path).
                self.ctx.flush_dirty = true;
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
            // Transmit flush is deferred to poll_write (batch-drain).
        }

        // Teardown safety (see handle_read): flush before removal so a drained
        // association's final packets aren't dropped by the deferred flush.
        if !endpoint_events.is_empty() {
            for (_ch, conn) in sctp_associations.iter_mut() {
                while let Some(x) = conn.poll_transmit(now) {
                    transmits.extend(split_transmit(x));
                }
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

        // Timer processed — mark dirty so poll_write runs the single flush.
        self.ctx.flush_dirty = true;
        self.ctx.last_now = Some(now);

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
    //! Coverage for the batch-drain teardown-safety flush.
    //!
    //! `handle_read` / `handle_timeout` normally only INGEST and defer the transmit
    //! flush to `poll_write`. But when an association drains (graceful shutdown) it is
    //! removed in that same call — so its final packet (SHUTDOWN / SHUTDOWN_COMPLETE)
    //! would be dropped by a flush that runs *after* removal, and the peer would hang
    //! waiting for it. The teardown-safety block flushes pending outbound *before*
    //! removal. These tests drive a real client<->server SCTP handshake through the
    //! public `sctp` API (no DTLS/ICE), then verify the draining association's final
    //! packet reaches `write_outs` instead of being lost.

    use super::*;
    use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    use bytes::Bytes;
    use sansio::Protocol;
    use sctp::{Association, Endpoint, EndpointConfig, ServerConfig, TransportConfig};
    use shared::TransportProtocol;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn client_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444)
    }

    fn server_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555)
    }

    /// An established client<->server SCTP association pair, driven purely through the
    /// public `sctp` API so a handler test can operate on a real, connected
    /// association without standing up the full peer-connection stack.
    struct Established {
        client_ep: Endpoint,
        client_ch: AssociationHandle,
        client_conn: Association,
        server_ep: Endpoint,
        server_ch: AssociationHandle,
        server_conn: Association,
    }

    /// Drain every datagram an association currently wants to transmit.
    fn drain_transmits(conn: &mut Association, now: Instant) -> Vec<Bytes> {
        let mut out = vec![];
        while let Some(t) = conn.poll_transmit(now) {
            if let Payload::RawEncode(contents) = t.message {
                out.extend(contents);
            }
        }
        out
    }

    /// Run the SCTP handshake to completion and return the established pair. The
    /// shuttle plays the role the ICE handler plays in production: it rewrites each
    /// datagram's source address for the receiving endpoint.
    fn establish() -> Established {
        let now = Instant::now();

        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let mut server_ep = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );

        let (client_ch, mut client_conn) = client_ep
            .connect(ClientConfig::new(TransportConfig::default()), server_addr())
            .expect("client connect");

        let mut server_conns: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut connected = false;

        for _ in 0..50 {
            // client -> server
            let c_out = drain_transmits(&mut client_conn, now);
            let mut moved = !c_out.is_empty();
            for dgram in c_out {
                if let Some((ch, event)) = server_ep.handle(now, client_addr(), None, dgram) {
                    match event {
                        DatagramEvent::NewAssociation(conn) => {
                            server_conns.insert(ch, conn);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(sc) = server_conns.get_mut(&ch) {
                                sc.handle_event(e);
                            }
                        }
                    }
                }
            }

            // server -> client
            let mut s_out = vec![];
            for sc in server_conns.values_mut() {
                while sc.poll().is_some() {}
                s_out.extend(drain_transmits(sc, now));
            }
            moved |= !s_out.is_empty();
            for dgram in s_out {
                if let Some((_ch, DatagramEvent::AssociationEvent(e))) =
                    client_ep.handle(now, server_addr(), None, dgram)
                {
                    client_conn.handle_event(e);
                }
            }

            while let Some(event) = client_conn.poll() {
                if let Event::Connected = event {
                    connected = true;
                }
            }

            if connected && !moved {
                break;
            }
        }

        assert!(connected, "SCTP handshake did not complete");
        assert_eq!(server_conns.len(), 1, "exactly one server association");
        let (server_ch, server_conn) = server_conns.into_iter().next().unwrap();

        Established {
            client_ep,
            client_ch,
            client_conn,
            server_ep,
            server_ch,
            server_conn,
        }
    }

    /// Wrap an established client endpoint + association in a handler context.
    fn client_ctx(
        client_ep: Endpoint,
        ch: AssociationHandle,
        conn: Association,
    ) -> SctpHandlerContext {
        let mut transport = RTCSctpTransport::new(SctpMaxMessageSize::default());
        transport
            .internal_buffer
            .resize(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize, 0);
        transport.sctp_endpoint = Some(client_ep);
        transport.sctp_associations.insert(ch, conn);
        SctpHandlerContext::new(transport)
    }

    // First-chunk types we assert on (RFC 4960 §3.2). The `sctp` crate keeps its
    // `CT_*` constants crate-private, so we decode the wire format directly.
    const CT_SHUTDOWN: u8 = 7;
    const CT_SHUTDOWN_COMPLETE: u8 = 14;

    /// First SCTP chunk type of every datagram flushed into `write_outs`. The SCTP
    /// common header is a fixed 12 bytes (RFC 4960 §3.1), so the first chunk's type
    /// field is byte 12.
    fn flushed_chunk_types(ctx: &SctpHandlerContext) -> Vec<u8> {
        ctx.write_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) if raw.len() > 12 => Some(raw[12]),
                _ => None,
            })
            .collect()
    }

    // handle_timeout teardown-safety block: a graceful shutdown queues both the
    // `Drained` endpoint event AND the final SHUTDOWN datagram. handle_timeout
    // collects the drain (removing the association) and must flush the SHUTDOWN
    // *before* removal, or the peer would never learn the association closed.
    #[test]
    fn handle_timeout_flushes_final_packet_before_drain() {
        let e = establish();
        let mut client_conn = e.client_conn;
        client_conn
            .shutdown()
            .expect("shutdown from Established queues Drained + SHUTDOWN");

        let mut ctx = client_ctx(e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);

        {
            let mut handler = SctpHandler::new(&mut ctx);
            handler
                .handle_timeout(Instant::now())
                .expect("handle_timeout");
        }

        assert!(
            ctx.sctp_transport.sctp_associations.is_empty(),
            "draining association must be removed"
        );
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN),
            "the final SHUTDOWN must be flushed before removal, not dropped \
             (flushed chunk types: {flushed:?})"
        );
    }

    // handle_read teardown-safety block (+ the SctpMessage::Outbound arm): when the
    // client, mid graceful-shutdown, receives the peer's SHUTDOWN_ACK it must emit a
    // SHUTDOWN_COMPLETE. That inbound arrives via handle_read, which collects the
    // Drained and removes the association — so the SHUTDOWN_COMPLETE has to be flushed
    // in the same call.
    #[test]
    fn handle_read_flushes_final_packet_before_drain() {
        let e = establish();
        let mut client_conn = e.client_conn;
        let mut server_ep = e.server_ep;
        let mut server_conn = e.server_conn;
        let server_ch = e.server_ch;
        let now = Instant::now();

        // Client initiates graceful shutdown -> emits SHUTDOWN.
        client_conn.shutdown().expect("shutdown");
        let shutdown_dgrams = drain_transmits(&mut client_conn, now);
        assert!(!shutdown_dgrams.is_empty(), "shutdown emits SHUTDOWN");

        // Server processes SHUTDOWN -> replies SHUTDOWN_ACK.
        for d in shutdown_dgrams {
            if let Some((ch, DatagramEvent::AssociationEvent(ev))) =
                server_ep.handle(now, client_addr(), None, d)
            {
                assert_eq!(ch, server_ch);
                server_conn.handle_event(ev);
            }
        }
        while server_conn.poll().is_some() {}
        let ack_dgrams = drain_transmits(&mut server_conn, now);
        assert!(!ack_dgrams.is_empty(), "server replies SHUTDOWN_ACK");

        // Feed SHUTDOWN_ACK to the client HANDLER via handle_read.
        let mut ctx = client_ctx(e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);
        {
            let mut handler = SctpHandler::new(&mut ctx);
            for d in ack_dgrams {
                let msg = TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext {
                        local_addr: client_addr(),
                        peer_addr: server_addr(),
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&d[..]))),
                };
                handler.handle_read(msg).expect("handle_read");
            }
        }

        assert!(
            ctx.sctp_transport.sctp_associations.is_empty(),
            "draining association must be removed"
        );
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN_COMPLETE),
            "the final SHUTDOWN_COMPLETE must be flushed before removal, not dropped \
             (flushed chunk types: {flushed:?})"
        );
    }
}
