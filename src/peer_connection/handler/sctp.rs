use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, SctpEvent, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::sctp::SctpTransport;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message;
use datachannel::message::message_channel_threshold::DataChannelThreshold;
use log::{debug, warn};
use sctp::{
    Association, AssociationEvent, AssociationHandle, ClientConfig, DatagramEvent, EndpointEvent,
    Event, Payload, PayloadProtocolIdentifier, StreamEvent, StreamId,
};
use shared::error::{Error, Result};
use shared::marshal::Unmarshal;
use shared::{TransportContext, TransportMessage};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

pub(crate) struct SctpHandlerContext {
    pub(crate) sctp_transport: SctpTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    // Batch-drain state: handle_read/handle_write/handle_timeout only INGEST (set
    // `flush_dirty`); the single transmit flush runs in poll_write, once per driver
    // event-loop iteration. Paired with the driver's burst-read, N received DATA
    // chunks are processed before one flush, so the ack machine coalesces them into
    // ONE SACK (1st arms Delay, 2nd+ stay Immediate until flushed) instead of one
    // SACK per two packets — cutting sendto/recvfrom and amortizing per-iteration
    // cost. `now` carries the newest timestamp seen into that flush.
    flush_dirty: bool,

    /// Streams left with unread data because the pipeline backlog was over its bound.
    ///
    /// This set is what makes bounded draining safe. `StreamEvent::Readable` is
    /// **edge-triggered** — `association/mod.rs` emits it from `handle_data` when a *new* DATA
    /// chunk arrives, and from ForwardTSN; it is never re-emitted merely because unread data
    /// remains. So a handler that stops mid-stream gets no further notification, and the
    /// moment back-pressure works the peer stops sending, so no new chunk arrives, so no new
    /// `Readable` fires: **the stream would deadlock exactly when the feature engages.**
    /// Remembering the stream here, and retrying from `handle_read`/`handle_timeout`, is the
    /// level-triggered re-arm that closes that hole.
    pending_readable: HashSet<(AssociationHandle, StreamId)>,

    /// Transport context of the most recent inbound datagram, **per association**.
    ///
    /// A resumed drain has no triggering packet to copy this from. A single `last_transport`
    /// would be wrong the moment the endpoint carries more than one association — and it can:
    /// `sctp_associations` is a map, and `establish_two()` in the tests builds exactly that
    /// case. Messages resumed for association A would then be stamped with B's peer address.
    ///
    /// Keyed by association because the 5-tuple is a property of the association, not of the
    /// stream. An association with no entry has never received a datagram, so it cannot have
    /// parked data either.
    association_transport: HashMap<AssociationHandle, TransportContext>,

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// This is the one place in the core that genuinely needs a retained instant: the flush is
    /// armed by a `handle_*` but executed by the next `poll_write`, and `flush_transmits` does
    /// real time-dependent work there — retransmit timers, congestion window, SACK scheduling.
    /// It was `Option<Instant>` with an `unwrap_or_else(Instant::now)` fallback only because
    /// nothing seeded it; that fallback was taken on **every client connection**, for the flush
    /// that emits the INIT chunk. Seeding at construction makes the `Option` unnecessary.
    now: Instant,
}

impl SctpHandlerContext {
    pub(crate) fn new(now: Instant, sctp_transport: SctpTransport) -> Self {
        Self {
            sctp_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            flush_dirty: false,
            pending_readable: HashSet::new(),
            association_transport: HashMap::new(),
            now,
        }
    }

    /// Records the newest instant a caller has supplied.
    ///
    /// `max` rather than assignment, and without a monotonicity assert: an outbound message
    /// carries the instant of the input that *caused* it, so `handle_write` can legitimately be
    /// handed one older than the newest seen. See the design's §9.3.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }
}

/// How many undelivered inbound messages the pipeline may hold before this handler stops
/// draining SCTP's reassembly queues.
///
/// Draining unconditionally is what defeats SCTP's own flow control: bytes left in a
/// reassembly queue are what `get_my_receiver_window_credit()` subtracts from
/// `max_receive_buffer_size`, and that credit is advertised as `a_rwnd` in every SACK. Empty
/// the queue on arrival and `a_rwnd` never falls, so the peer is never told to slow down and
/// the backlog reappears — unbounded — further up the pipeline. Leaving messages in the
/// reassembly queue is not a leak; it is the mechanism.
///
/// The bound is a message count, so the bytes held depend on message size; SCTP's own
/// `max_receive_buffer_size` (1 MiB by default, `SettingEngineBuilder::with_sctp_max_receive_buffer_size`)
/// is the byte-denominated bound underneath it and is what the peer actually sees.
pub(crate) const SCTP_PIPELINE_READ_BACKLOG_LIMIT: usize = 256;

/// SctpHandler implements SCTP Protocol handling
pub(crate) struct SctpHandler<'a> {
    ctx: &'a mut SctpHandlerContext,
    /// Undelivered messages already sitting in `pipeline_context.read_outs`.
    ///
    /// Passed in rather than read from `ctx` because **this handler's own `read_outs` is not
    /// where the backlog forms**: the pipeline drains it into `intermediate_routs` inside the
    /// same `handle_read` call, so it is empty again by the time anything could observe it.
    /// Bounding against it would be a no-op. The queue that actually grows when the
    /// application stops consuming is the pipeline's, one hop downstream.
    downstream_backlog: usize,
}

impl<'a> SctpHandler<'a> {
    pub(crate) fn new(ctx: &'a mut SctpHandlerContext, downstream_backlog: usize) -> Self {
        SctpHandler {
            ctx,
            downstream_backlog,
        }
    }

    /// How many more messages may be pulled out of SCTP before the pipeline is over its bound.
    fn read_budget(&self) -> usize {
        SCTP_PIPELINE_READ_BACKLOG_LIMIT
            .saturating_sub(self.downstream_backlog)
            .saturating_sub(self.ctx.read_outs.len())
    }

    /// Drain one stream while budget allows, recording it as pending if data is left behind.
    ///
    /// Returns the messages read. The budget is checked **before** each `read_sctp()` because
    /// that call consumes a message: testing afterwards would mean having already taken the
    /// thing there was no room for.
    fn drain_stream(
        ctx_pending: &mut HashSet<(AssociationHandle, StreamId)>,
        conn: &mut Association,
        ch: AssociationHandle,
        id: StreamId,
        max_len: usize,
        budget: &mut usize,
        messages: &mut Vec<SctpMessage>,
    ) -> Result<()> {
        // An SCTP DATA chunk may arrive in the same flight as the tail of the
        // association handshake.  Do not expose that chunk to the DataChannel
        // handler while the association is still in COOKIE-WAIT/COOKIE-ECHOED:
        // doing so can announce `OnOpen` before the underlying data transport is
        // established, and an immediate application send cannot be transmitted
        // reliably.  Keep the chunk in SCTP's reassembly queue and let the
        // level-triggered pending path retry it after Event::Connected.
        if conn.is_handshaking() {
            ctx_pending.insert((ch, id));
            return Ok(());
        }

        loop {
            if *budget == 0 {
                // Leave the rest in the reassembly queue: that is what shrinks `a_rwnd`.
                ctx_pending.insert((ch, id));
                return Ok(());
            }
            // A read can retire this API receiver and publish the next use of
            // its SID. Reacquire the stream after draining its lifecycle events
            // so the close fence precedes any DATA from that next use.
            let received = match conn.stream(id) {
                Ok(mut stream) => stream.read_sctp(),
                Err(err) => Err(err),
            };
            let chunks = match received {
                Ok(chunks) => chunks,
                Err(Error::ErrStreamClosed | Error::ErrStreamNotExisted) => None,
                Err(err) => return Err(err),
            };
            let Some(chunks) = chunks else {
                ctx_pending.remove(&(ch, id));
                while let Some(readable) = Self::poll_association_events(conn, ch, messages) {
                    ctx_pending.insert((ch, readable));
                }
                return Ok(());
            };
            // Reassemble straight into the delivered buffer: one copy instead of the
            // scratch-buffer round-trip (`max_len` preserves the max-message-size bound
            // `read()` enforced via `ErrShortBuffer`).
            let payload = chunks.to_payload(max_len)?;
            messages.push(SctpMessage::Inbound(DataChannelMessage {
                association_handle: ch.0,
                stream_id: id,
                ppi: chunks.ppi,
                payload,
                negotiated: false,
            }));
            *budget -= 1;

            while let Some(readable) = Self::poll_association_events(conn, ch, messages) {
                ctx_pending.insert((ch, readable));
            }
        }
    }

    /// Retry streams parked by a full pipeline. The level-triggered half of the drain.
    fn resume_pending_reads(&mut self, now: Instant) -> Result<()> {
        if self.ctx.pending_readable.is_empty() {
            return Ok(());
        }
        let mut budget = self.read_budget();
        if budget == 0 {
            return Ok(());
        }

        let max_len = self.ctx.sctp_transport.internal_buffer.len();
        let mut pending: Vec<(AssociationHandle, StreamId)> =
            self.ctx.pending_readable.iter().copied().collect();
        pending.sort_unstable();

        let mut drained_any = false;
        for (ch, id) in pending {
            if budget == 0 {
                break;
            }
            let Some(transport) = self.ctx.association_transport.get(&ch).copied() else {
                // Never received a datagram, so it cannot have parked data.
                self.ctx.pending_readable.remove(&(ch, id));
                continue;
            };
            let Some(conn) = self.ctx.sctp_transport.sctp_associations.get_mut(&ch) else {
                // The association went away while parked; nothing to resume. Unreachable in
                // practice — the two sites that remove an association clear both maps with it
                // — so this drops the transport entry too rather than leaving the one map to
                // outlive the other.
                self.ctx.pending_readable.remove(&(ch, id));
                self.ctx.association_transport.remove(&ch);
                continue;
            };

            // Drained per association, and stamped with *that* association's 5-tuple: a
            // shared batch would let one association's messages inherit another's transport.
            let mut messages = vec![];
            Self::drain_stream(
                &mut self.ctx.pending_readable,
                conn,
                ch,
                id,
                max_len,
                &mut budget,
                &mut messages,
            )?;

            drained_any |= !messages.is_empty();
            Self::enqueue_messages(
                messages,
                now,
                transport,
                &mut self.ctx.read_outs,
                &mut self.ctx.write_outs,
            );
        }

        if drained_any {
            // Reading drops bytes out of the reassembly queue, which raises the
            // receiver-window credit — the peer only learns that from a SACK, so flush.
            self.ctx.flush_dirty = true;
        }
        Ok(())
    }

    pub(crate) fn name(&self) -> &'static str {
        "SctpHandler"
    }

    /// Forward association events until a readable stream needs attention.
    /// The caller drains or parks that stream, then calls again until None.
    /// This also processes events produced by reading (such as a deferred reset),
    /// while preserving the caller's read budget and transport context.
    fn poll_association_events(
        conn: &mut Association,
        ch: AssociationHandle,
        messages: &mut Vec<SctpMessage>,
    ) -> Option<StreamId> {
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
                    messages.push(SctpMessage::Event(SctpEvent::Connected(ch.0)));
                }
                Event::AssociationLost { reason, id } => {
                    debug!("association_handle {} is closed due to {}", ch.0, reason);
                    messages.push(SctpMessage::Event(SctpEvent::Closed(ch.0, id)));
                }
                Event::Stream(StreamEvent::Readable { id }) => {
                    return Some(id);
                }
                Event::Stream(StreamEvent::BufferedAmountLow { id }) => {
                    debug!(
                        "association_handle {} stream id {} is buffered amount low",
                        ch.0, id
                    );
                    messages.push(SctpMessage::Event(SctpEvent::BufferedAmountLow(ch.0, id)));
                }
                Event::Stream(StreamEvent::BufferedAmountHigh { id }) => {
                    debug!(
                        "association_handle {} stream id {} is buffered amount high",
                        ch.0, id
                    );
                    messages.push(SctpMessage::Event(SctpEvent::BufferedAmountHigh(ch.0, id)));
                }
                Event::Stream(StreamEvent::BufferedAmountReleased { id, n_bytes }) => {
                    // Forward the exact released byte count so the data
                    // channel handler can decrement its synchronous
                    // send back-pressure counter (see DataChannelHandler).
                    messages.push(SctpMessage::Event(SctpEvent::BufferReleased(
                        ch.0, id, n_bytes,
                    )));
                }
                _ => {}
            }
        }
        None
    }

    fn enqueue_messages(
        messages: Vec<SctpMessage>,
        now: Instant,
        transport: TransportContext,
        read_outs: &mut VecDeque<TaggedRTCMessageInternal>,
        write_outs: &mut VecDeque<TaggedRTCMessageInternal>,
    ) {
        for message in messages {
            let message = match message {
                SctpMessage::Inbound(message) => DTLSMessage::Sctp(message),
                SctpMessage::Event(event) => DTLSMessage::SctpEvent(event),
                SctpMessage::Outbound(transmit) => {
                    if let Payload::RawEncode(raw_data) = transmit.message {
                        for raw in raw_data {
                            write_outs.push_back(TaggedRTCMessageInternal {
                                now: transmit.now,
                                transport: transmit.transport,
                                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(
                                    BytesMut::from(&raw[..]),
                                )),
                            });
                        }
                    }
                    continue;
                }
            };
            read_outs.push_back(TaggedRTCMessageInternal {
                now,
                transport,
                message: RTCMessageInternal::Dtls(message),
            });
        }
    }

    /// Batch-drain flush: gather every association's pending outbound in one pass
    /// into `write_outs`. Called once per event-loop iteration from poll_write when
    /// `flush_dirty` is set, after a burst of inbound packets has been ingested, so
    /// their SACKs coalesce into a single datagram.
    fn flush_transmits(&mut self, now: Instant) {
        for (ch, conn) in self.ctx.sctp_transport.sctp_associations.iter_mut() {
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
            let mut messages = vec![];
            while let Some(id) = Self::poll_association_events(conn, *ch, &mut messages) {
                self.ctx.pending_readable.insert((*ch, id));
            }
            Self::enqueue_messages(
                messages,
                now,
                self.ctx
                    .association_transport
                    .get(ch)
                    .copied()
                    .unwrap_or_default(),
                &mut self.ctx.read_outs,
                &mut self.ctx.write_outs,
            );
        }
    }
}

enum SctpMessage {
    Inbound(DataChannelMessage),
    Event(SctpEvent),
    Outbound(TransportMessage<Payload>),
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for SctpHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
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

            // Both are read before `sctp_transport` is split up below, which would otherwise
            // conflict with the borrow of `sctp_associations`.
            let max_len = self.ctx.sctp_transport.internal_buffer.len();
            let mut budget = self.read_budget();
            let mut inbound_transport = None;

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
                // `ch` is the association this datagram belongs to — the only safe key for
                // remembering its 5-tuple.
                inbound_transport = Some((ch, msg.transport));
                match event {
                    DatagramEvent::NewAssociation(conn) => {
                        sctp_associations.insert(ch, conn);
                    }
                    DatagramEvent::AssociationEvent(event) => {
                        sctp_events.entry(ch).or_default().push_back(event);
                    }
                    _ => {}
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

                    while let Some(id) = Self::poll_association_events(conn, *ch, &mut messages) {
                        Self::drain_stream(
                            &mut self.ctx.pending_readable,
                            conn,
                            *ch,
                            id,
                            max_len,
                            &mut budget,
                            &mut messages,
                        )?;
                    }

                    while let Some(event) = conn.poll_endpoint_event() {
                        endpoint_events.push((*ch, event));
                    }
                    // Transmit flush is deferred to poll_write (batch-drain) so a
                    // burst of inbound DATA coalesces into one SACK.
                }

                // Teardown safety: each association that emitted an endpoint event
                // is about to be removed below (drain/shutdown). Flush ITS pending
                // outbound now — the deferred poll_write flush runs after removal and
                // would drop its final packets. Only the draining associations are
                // touched, so non-draining ones keep coalescing and still flush
                // normally in poll_write.
                for (drained_ch, _event) in &endpoint_events {
                    if let Some(conn) = sctp_associations.get_mut(drained_ch) {
                        while let Some(x) = conn.poll_transmit(now) {
                            for transmit in split_transmit(x) {
                                messages.push(SctpMessage::Outbound(transmit));
                            }
                        }
                        while Self::poll_association_events(conn, *drained_ch, &mut messages)
                            .is_some()
                        {}
                    }
                }

                for (ch, event) in endpoint_events {
                    sctp_endpoint.handle_event(ch, event); // handle drain event
                    sctp_associations.remove(&ch);
                    // Drop the per-association bookkeeping with it, or a long-lived endpoint
                    // accumulates entries for associations that no longer exist.
                    self.ctx.association_transport.remove(&ch);
                    self.ctx.pending_readable.retain(|(pch, _)| *pch != ch);
                }
            }

            Self::enqueue_messages(
                messages,
                msg.now,
                msg.transport,
                &mut self.ctx.read_outs,
                &mut self.ctx.write_outs,
            );

            if let Some((ch, transport)) = inbound_transport
                && self.ctx.sctp_transport.sctp_associations.contains_key(&ch)
            {
                self.ctx.association_transport.insert(ch, transport);
            }

            // The application may have drained while this packet was in flight, so retry
            // anything parked before giving up until the retry timer.
            self.resume_pending_reads(now)?;

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.observe(now);
        } else {
            // Bypass
            debug!("bypass sctp read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        // Top up from streams parked by back-pressure. This is exactly when capacity has
        // appeared — somebody is asking for data, so the pipeline ahead has drained — and it
        // needs no timer, no invented interval and no influence on `poll_timeout`.
        //
        // It is also the level-triggered half of the bounded drain. `StreamEvent::Readable`
        // is edge-triggered: it fires on a *new* DATA chunk, never because unread data
        // remains. The moment back-pressure works the peer stops sending, so nothing arrives
        // to re-trigger the drain — without this the stream would deadlock precisely when the
        // feature engages.
        if self.ctx.read_outs.is_empty() && !self.ctx.pending_readable.is_empty() {
            let now = self.ctx.now;
            if let Err(err) = self.resume_pending_reads(now) {
                warn!("failed to resume parked SCTP streams: {}", err);
            }
        }
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
                            stream.close(now)?;
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

                if !is_dcep_internal_control_message {
                    let mut stream = conn.stream(message.stream_id)?;
                    if stream.is_writable() {
                        // The payload is owned end-to-end (the DataChannel `send` API
                        // takes the buffer by value), so hand it to SCTP zero-copy:
                        // `freeze()` is O(1) and the enqueued chunks are refcounted
                        // slices, eliminating a per-message alloc + full-payload memcpy.
                        let payload = std::mem::take(&mut message.payload).freeze();
                        stream.write_chunk_with_ppi(now, &payload, message.ppi)?;
                    }
                }

                // Transmit flush is deferred to poll_write (batch-drain).
            } else {
                return Err(Error::ErrAssociationNotExisted);
            }

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.observe(now);
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
            self.flush_transmits(self.ctx.now);
        }
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        // The event's instant arms the deferred flush below, so `poll_write` can stamp the
        // client INIT with the time the handshake completed rather than the wall clock.
        let now = evt.now;
        self.ctx.observe(now);

        // DTLSHandshakeComplete is not terminated here since SRTP handler needs it
        let dtls_complete = matches!(&evt.event, RTCEventInternal::DTLSHandshakeComplete(_, _));
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
                        now,
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
        if let Some(event) = self.ctx.event_outs.pop_front() {
            return Some(event);
        }
        // A timeout or transmit flush can release bytes with no incoming DATA
        // to drive the read pipeline. Such lifecycle events may also leave via
        // poll_event, but only from the head of the same FIFO: they must never
        // pass older DATA, and are removed exactly once through either route.
        if let Some(TaggedRTCMessageInternal {
            message: RTCMessageInternal::Dtls(DTLSMessage::SctpEvent(event)),
            now,
            ..
        }) = self.ctx.read_outs.front()
        {
            let event = TaggedRTCEventInternal {
                now: *now,
                event: event.into_internal(),
            };
            self.ctx.read_outs.pop_front();
            return Some(event);
        }
        None
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
            let mut messages = vec![];
            while let Some(id) = Self::poll_association_events(conn, *ch, &mut messages) {
                self.ctx.pending_readable.insert((*ch, id));
            }
            Self::enqueue_messages(
                messages,
                now,
                self.ctx
                    .association_transport
                    .get(ch)
                    .copied()
                    .unwrap_or_default(),
                &mut self.ctx.read_outs,
                &mut self.ctx.write_outs,
            );

            while let Some(event) = conn.poll_endpoint_event() {
                endpoint_events.push((*ch, event));
            }
            // Transmit flush is deferred to poll_write (batch-drain).
        }

        // Teardown safety (see handle_read): flush each draining association's final
        // packets before it is removed below, so the deferred flush doesn't drop
        // them. Non-draining associations flush normally in poll_write.
        for (drained_ch, _event) in &endpoint_events {
            if let Some(conn) = sctp_associations.get_mut(drained_ch) {
                while let Some(x) = conn.poll_transmit(now) {
                    transmits.extend(split_transmit(x));
                }
                let mut messages = vec![];
                while Self::poll_association_events(conn, *drained_ch, &mut messages).is_some() {}
                Self::enqueue_messages(
                    messages,
                    now,
                    self.ctx
                        .association_transport
                        .get(drained_ch)
                        .copied()
                        .unwrap_or_default(),
                    &mut self.ctx.read_outs,
                    &mut self.ctx.write_outs,
                );
            }
        }

        for (ch, event) in endpoint_events {
            sctp_endpoint.handle_event(ch, event); // handle drain event
            sctp_associations.remove(&ch);
            self.ctx.association_transport.remove(&ch);
            self.ctx.pending_readable.retain(|(pch, _)| *pch != ch);
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
        self.ctx.observe(now);

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let mut eto = None;

        for conn in self.ctx.sctp_transport.sctp_associations.values() {
            if let Some(timeout) = conn.poll_timeout() {
                eto = Some(eto.map_or(timeout, |e: Instant| e.min(timeout)));
            }
        }

        eto
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
    use crate::data_channel::registry::DataChannelRegistry;
    use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    use crate::peer_connection::handler::datachannel::{
        DataChannelHandler, DataChannelHandlerContext,
    };
    use crate::peer_connection::message::internal::DataChannelEvent;
    use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::Bytes;
    use datachannel::message::message_channel_open::{
        CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
    };
    use sansio::Protocol;
    use sctp::{Association, Endpoint, EndpointConfig, ServerConfig, TransportConfig};
    use shared::{TransportProtocol, marshal::Marshal};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[test]
    fn reused_sid_survives_delayed_reset_response_and_handler_event_order() {
        fn pump(
            ctx: &mut SctpHandlerContext,
            dcctx: &mut DataChannelHandlerContext,
            registry: &mut DataChannelRegistry,
            stats: &mut RTCStatsAccumulator,
        ) {
            // The production pipeline routes handle_read output first, then
            // processes the SCTP lifecycle notifications on poll_event.
            let mut handler =
                DataChannelHandler::new(dcctx, registry, stats, None, RTCDtlsRole::Client, None);
            for msg in ctx.read_outs.drain(..) {
                handler.handle_read(msg).unwrap();
            }
            for event in ctx.event_outs.drain(..) {
                handler.handle_event(event).unwrap();
            }
        }
        let mut e = establish();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Dcep;
        let dcep = |label: &[u8]| {
            Bytes::from(
                Message::DataChannelOpen(DataChannelOpen {
                    channel_type: ChannelType::Reliable,
                    priority: CHANNEL_PRIORITY_NORMAL,
                    reliability_parameter: 0,
                    label: label.to_vec(),
                    protocol: vec![],
                })
                .marshal()
                .unwrap(),
            )
        };
        let mut data_channel_ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        DataChannelHandler::new(
            &mut data_channel_ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Client,
            None,
        )
        .handle_read(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                association_handle: e.client_ch.0,
                stream_id: 1,
                ppi,
                payload: BytesMut::from(dcep(b"old").as_ref()),
                negotiated: false,
            })),
        })
        .unwrap();
        data_channel_ctx.read_outs.clear();
        data_channel_ctx.write_outs.clear();
        data_channel_ctx.event_outs.clear();
        data_channels.get_by_stream_mut(&1).unwrap().ready_state =
            crate::data_channel::state::RTCDataChannelState::Closing;

        e.client_conn
            .open_stream(1, ppi)
            .unwrap()
            .close(now)
            .unwrap();
        e.server_conn.open_stream(1, ppi).unwrap();
        for dgram in drain_transmits(&mut e.client_conn, now) {
            if let Some((_, DatagramEvent::AssociationEvent(event))) =
                e.server_ep.handle(now, client_addr(), None, dgram)
            {
                e.server_conn.handle_event(event);
            }
        }
        let server_reset_packets = drain_transmits(&mut e.server_conn, now);
        let mut delayed_response = None;
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        for dgram in server_reset_packets {
            if dgram.len() > 18 && dgram[12] == 130 && dgram[16..18] == [0, 16] {
                delayed_response = Some(dgram);
            } else {
                SctpHandler::new(&mut ctx, 0)
                    .handle_read(raw_read(now, dgram))
                    .unwrap();
                pump(
                    &mut ctx,
                    &mut data_channel_ctx,
                    &mut data_channels,
                    &mut stats,
                );
            }
        }
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            while let Some(out) = handler.poll_write() {
                if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = out.message {
                    if let Some((_, DatagramEvent::AssociationEvent(event))) =
                        e.server_ep.handle(now, client_addr(), None, raw.freeze())
                    {
                        e.server_conn.handle_event(event);
                    }
                }
            }
        }
        assert!(
            e.server_conn.stream(1).is_err(),
            "peer has completed both resets"
        );
        e.server_conn
            .open_stream(1, ppi)
            .unwrap()
            .write_sctp(now, &dcep(b"new"), ppi)
            .unwrap();
        for dgram in drain_transmits(&mut e.server_conn, now) {
            SctpHandler::new(&mut ctx, 0)
                .handle_read(raw_read(now, dgram))
                .unwrap();
            pump(
                &mut ctx,
                &mut data_channel_ctx,
                &mut data_channels,
                &mut stats,
            );
        }
        SctpHandler::new(&mut ctx, 0)
            .handle_read(raw_read(now, delayed_response.unwrap()))
            .unwrap();
        pump(
            &mut ctx,
            &mut data_channel_ctx,
            &mut data_channels,
            &mut stats,
        );
        let reopened = data_channels
            .get_by_stream_mut(&1)
            .expect("reused SID must have a new channel after processing the old close");
        assert_eq!("new", reopened.label);
    }

    #[test]
    fn timed_abandonment_releases_buffers_without_inbound_packets() {
        for size in [4, 12000] {
            let mut e = establish();
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = e.client_conn.open_stream(1, ppi).unwrap();
            stream
                .set_reliability_params(false, sctp::ReliabilityType::Timed, 100)
                .unwrap();
            stream
                .write_sctp(now, &Bytes::from(vec![0x55; size]), ppi)
                .unwrap();
            assert!(!drain_transmits(&mut e.client_conn, now).is_empty());
            while e.client_conn.poll().is_some() {}
            // Expiration can happen either in T3 or while flushing a pending tail.
            let at = if size == 4 {
                e.client_conn.poll_timeout().unwrap()
            } else {
                now + Duration::from_millis(100)
            };
            let ch = e.client_ch;
            let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler.handle_timeout(at).unwrap();
            let mut released = 0;
            let mut low = 0;
            let mut collect = |handler: &mut SctpHandler<'_>| {
                while let Some(event) = handler.poll_event() {
                    assert_eq!(at, event.now);
                    match event.event {
                        RTCEventInternal::SCTPBufferReleased(association, 1, n_bytes) => {
                            assert_eq!(ch.0, association);
                            released += n_bytes;
                        }
                        RTCEventInternal::SCTPBufferedAmountLow(association, 1) => {
                            assert_eq!(ch.0, association);
                            low += 1;
                        }
                        _ => {}
                    }
                }
            };
            collect(&mut handler);
            while handler.poll_write().is_some() {}
            collect(&mut handler);
            assert_eq!(size, released);
            assert_eq!(1, low);
            handler
                .handle_timeout(at + Duration::from_millis(1))
                .unwrap();
            while handler.poll_write().is_some() {}
            assert!(handler.poll_event().is_none());
            assert_eq!(
                0,
                ctx.sctp_transport
                    .sctp_associations
                    .get_mut(&ch)
                    .unwrap()
                    .stream(1)
                    .unwrap()
                    .buffered_amount()
                    .unwrap()
            );
        }
    }

    #[test]
    fn draining_saved_messages_preserves_the_reset_close_fence() {
        let mut e = establish();
        let now = Instant::now();
        let ch = e.client_ch;
        let data = server_datagrams_carrying(&mut e, 1, 2, now);
        e.server_conn.stream(1).unwrap().stop(now).unwrap();
        let resets = drain_transmits(&mut e.server_conn, now);
        assert!(!resets.is_empty());
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for packet in data.into_iter().chain(resets) {
                handler.handle_read(raw_read(now, packet)).unwrap();
            }
        }
        assert!(
            ctx.read_outs.is_empty(),
            "the two old messages remain in SCTP"
        );
        assert!(ctx.pending_readable.contains(&(ch, 1)));

        let mut handler = SctpHandler::new(&mut ctx, 0);
        for expected in [0, 1] {
            assert!(
                handler.poll_event().is_none(),
                "the close fence cannot overtake an old message"
            );
            let read = handler
                .poll_read()
                .expect("saved message must survive the reset");
            assert!(matches!(
                read.message,
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(message))
                    if message.stream_id == 1 && message.payload == vec![expected; 64]
            ));
        }
        // The last read may retire the Stream object. The following read is
        // EOF, not an error that discards the already collected messages.
        let close = handler.poll_read().expect("old receiver's close fence");
        assert!(matches!(
            close.message,
            RTCMessageInternal::Dtls(DTLSMessage::SctpEvent(SctpEvent::Closed(_, 1)))
        ));
        assert!(handler.poll_read().is_none());
        assert!(
            handler.poll_event().is_none(),
            "a fence has only one delivery route"
        );
    }

    #[test]
    fn public_peer_reads_resume_saved_data_and_reset_without_network_input() {
        use crate::data_channel::message::RTCDataChannelMessage;
        use crate::peer_connection::RTCPeerConnectionBuilder;
        use crate::peer_connection::event::RTCPeerConnectionEvent;
        use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
        use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};

        fn dcep(label: &[u8]) -> Bytes {
            Message::DataChannelOpen(DataChannelOpen {
                channel_type: ChannelType::Reliable,
                priority: CHANNEL_PRIORITY_NORMAL,
                reliability_parameter: 0,
                label: label.to_vec(),
                protocol: vec![],
            })
            .marshal()
            .unwrap()
            .into()
        }

        // Complete the wire exchange while the application backlog remains full.
        // No network delivery or timer callback occurs during the public read phase.
        fn settle(
            ctx: &mut SctpHandlerContext,
            peer_ep: &mut Endpoint,
            peer: &mut Association,
            now: &mut Instant,
        ) {
            for _ in 0..1000 {
                let mut moved = false;
                {
                    let mut handler = SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
                    while let Some(out) = handler.poll_write() {
                        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = out.message {
                            moved = true;
                            if let Some((_, DatagramEvent::AssociationEvent(event))) =
                                peer_ep.handle(*now, client_addr(), None, raw.freeze())
                            {
                                peer.handle_event(event);
                            }
                        }
                    }
                }
                for packet in drain_transmits(peer, *now) {
                    moved = true;
                    SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .handle_read(raw_read(*now, packet))
                        .unwrap();
                }
                while peer.poll().is_some() {}
                if !moved {
                    let next = SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .poll_timeout()
                        .into_iter()
                        .chain(peer.poll_timeout())
                        .min();
                    let Some(next) = next else { return };
                    *now = next.max(*now);
                    SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .handle_timeout(*now)
                        .unwrap();
                    peer.handle_timeout(*now);
                }
            }
            panic!("wire reset failed to reach quiescence");
        }

        for split_read in [false, true] {
            let mut e = establish();
            let mut now = Instant::now();
            let ch = e.client_ch;
            let old_count = SCTP_PIPELINE_READ_BACKLOG_LIMIT + 44;
            let data = server_datagrams_carrying(&mut e, 1, old_count, now);
            e.server_conn.stream(1).unwrap().stop(now).unwrap();
            let resets = drain_transmits(&mut e.server_conn, now);
            let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
            for packet in data.into_iter().chain(resets) {
                SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                    .handle_read(raw_read(now, packet))
                    .unwrap();
            }
            settle(&mut ctx, &mut e.server_ep, &mut e.server_conn, &mut now);
            assert!(
                e.server_conn.stream(1).is_err(),
                "both reset directions completed"
            );
            assert!(ctx.read_outs.is_empty());
            assert!(ctx.pending_readable.contains(&(ch, 1)));

            let mut stream = e
                .server_conn
                .open_stream(1, PayloadProtocolIdentifier::Dcep)
                .unwrap();
            stream
                .write_sctp(now, &dcep(b"new"), PayloadProtocolIdentifier::Dcep)
                .unwrap();
            stream
                .write_sctp(
                    now,
                    &Bytes::from_static(b"new-data"),
                    PayloadProtocolIdentifier::Binary,
                )
                .unwrap();
            settle(&mut ctx, &mut e.server_ep, &mut e.server_conn, &mut now);

            let mut pc = RTCPeerConnectionBuilder::new().build(now).unwrap();
            pc.pipeline_context.sctp_handler_context = ctx;
            // Model the channel that was already open when the application stalled.
            pc.get_datachannel_handler()
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: Default::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                        association_handle: ch.0,
                        stream_id: 1,
                        ppi: PayloadProtocolIdentifier::Dcep,
                        payload: BytesMut::from(dcep(b"old").as_ref()),
                        negotiated: false,
                    })),
                })
                .unwrap();
            let old_id = pc.data_channels.handle_of_stream(&1).unwrap();
            pc.pipeline_context
                .datachannel_handler_context
                .read_outs
                .clear();
            pc.pipeline_context
                .datachannel_handler_context
                .write_outs
                .clear();
            pc.pipeline_context
                .datachannel_handler_context
                .event_outs
                .clear();
            for _ in 0..SCTP_PIPELINE_READ_BACKLOG_LIMIT {
                pc.pipeline_context
                    .data_read_outs
                    .push_back(TaggedRTCMessage {
                        now,
                        message: RTCMessage::DataChannelMessage(
                            old_id,
                            RTCDataChannelMessage::default(),
                        ),
                    });
            }
            let read = |pc: &mut crate::peer_connection::RTCPeerConnection| {
                if split_read {
                    pc.poll_data_read()
                } else {
                    pc.poll_read()
                }
            };
            for _ in 0..SCTP_PIPELINE_READ_BACKLOG_LIMIT {
                assert!(matches!(read(&mut pc).unwrap().message,
                    RTCMessage::DataChannelMessage(id, message) if id == old_id && message.data.is_empty()));
            }
            for index in 0..old_count {
                let out = read(&mut pc).expect("public read must resume the parked SCTP receiver");
                assert!(matches!(out.message,
                    RTCMessage::DataChannelMessage(id, message)
                        if id == old_id && message.data == vec![index as u8; 64]));
                assert!(
                    pc.pipeline_context.data_read_outs.len() < SCTP_PIPELINE_READ_BACKLOG_LIMIT
                );
                if index == 0 {
                    assert!(
                        pc.pipeline_context
                            .sctp_handler_context
                            .pending_readable
                            .contains(&(ch, 1)),
                        "one public read must not drain every saved SCTP message past the backlog bound"
                    );
                }
            }
            let new_id = pc
                .data_channels
                .handle_of_stream(&1)
                .expect("new DCEP registers the reused SID");
            assert_ne!(old_id, new_id);
            assert_eq!(pc.data_channels.get_by_stream_mut(&1).unwrap().label, "new");
            assert!(matches!(read(&mut pc).unwrap().message,
                RTCMessage::DataChannelMessage(id, message) if id == new_id && message.data == b"new-data"[..]));
            assert!(read(&mut pc).is_none());
            assert!(
                pc.pipeline_context
                    .sctp_handler_context
                    .pending_readable
                    .is_empty()
            );
            let mut lifecycle = vec![];
            while let Some(event) = pc.poll_event() {
                if let RTCPeerConnectionEvent::OnDataChannel(event) = event {
                    lifecycle.push(event);
                }
            }
            assert!(
                matches!(lifecycle.as_slice(),
                [RTCDataChannelEvent::OnClose(old), RTCDataChannelEvent::OnOpen(new)]
                    if *old == old_id && *new == new_id),
                "lifecycle order: {lifecycle:?}"
            );
        }
    }

    #[test]
    fn old_dcep_ack_cannot_complete_new_fragmented_open() {
        use crate::peer_connection::RTCPeerConnectionBuilder;
        use datachannel::data_channel::{DataChannel, DataChannelConfig};

        fn settle(
            ctx: &mut SctpHandlerContext,
            peer_ep: &mut Endpoint,
            peer: &mut Association,
            now: &mut Instant,
        ) {
            for _ in 0..1000 {
                let mut moved = false;
                {
                    let mut handler = SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
                    while let Some(out) = handler.poll_write() {
                        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = out.message {
                            moved = true;
                            if let Some((_, DatagramEvent::AssociationEvent(event))) =
                                peer_ep.handle(*now, client_addr(), None, raw.freeze())
                            {
                                peer.handle_event(event);
                            }
                        }
                    }
                }
                for packet in drain_transmits(peer, *now) {
                    moved = true;
                    SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .handle_read(raw_read(*now, packet))
                        .unwrap();
                }
                while peer.poll().is_some() {}
                if !moved {
                    let next = SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .poll_timeout()
                        .into_iter()
                        .chain(peer.poll_timeout())
                        .min();
                    let Some(next) = next else { return };
                    *now = next.max(*now);
                    SctpHandler::new(ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                        .handle_timeout(*now)
                        .unwrap();
                    peer.handle_timeout(*now);
                }
            }
            panic!("wire reset failed to reach quiescence");
        }

        let mut e = establish();
        let mut now = Instant::now();
        let ch = e.client_ch;
        let ppi = PayloadProtocolIdentifier::Dcep;
        let old_open: Bytes = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: b"already closed".to_vec(),
            protocol: vec![],
        })
        .marshal()
        .unwrap()
        .into();
        let mut stream = e.server_conn.open_stream(1, ppi).unwrap();
        stream.write_sctp(now, &old_open, ppi).unwrap();
        stream.stop(now).unwrap();
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        settle(&mut ctx, &mut e.server_ep, &mut e.server_conn, &mut now);
        assert!(
            e.server_conn.stream(1).is_err(),
            "both old protocol resets completed"
        );
        assert!(ctx.read_outs.is_empty(), "old OPEN remains parked in SCTP");

        let mut pc = RTCPeerConnectionBuilder::new().build(now).unwrap();
        pc.pipeline_context.sctp_handler_context = ctx;
        assert!(pc.poll_read().is_none(), "DCEP has no application payload");
        assert!(
            pc.data_channels.handle_of_stream(&1).is_none(),
            "old Open/Close lifecycle completed"
        );
        assert_eq!(
            pc.pipeline_context
                .datachannel_handler_context
                .write_outs
                .len(),
            1,
            "the old OPEN queued its DCEP ACK before its close fence"
        );

        // Reuse is now valid. Only the first fragment of the new OPEN arrives;
        // its complete message, and therefore its parameters, are still unknown.
        let mut opener = DataChannel::dial(
            DataChannelConfig {
                channel_type: ChannelType::ReliableUnordered,
                priority: CHANNEL_PRIORITY_NORMAL,
                label: "x".repeat(4000),
                ..Default::default()
            },
            e.server_ch.0,
            1,
        )
        .unwrap();
        let new_open = opener.poll_write().unwrap();
        assert!(!opener.is_handshake_complete());
        e.server_conn
            .open_stream(1, ppi)
            .unwrap()
            .write_sctp(now, &new_open.payload.freeze(), ppi)
            .unwrap();
        let packets = drain_transmits(&mut e.server_conn, now);
        assert!(packets.len() >= 2, "new OPEN is fragmented");
        let first = packets
            .into_iter()
            .find(|p| p.len() >= 29 && p[12] == 0 && p[13] & 1 == 0)
            .unwrap();
        pc.get_sctp_handler()
            .handle_read(raw_read(now, first))
            .unwrap();
        assert!(pc.poll_read().is_none());
        assert!(
            pc.data_channels.handle_of_stream(&1).is_none(),
            "new OPEN was not reassembled or accepted"
        );

        // The caller may poll writes after ingesting the next datagram. The old
        // pending ACK must not attach to the newly created API stream for SID 1.
        while let Some(out) = pc.get_datachannel_handler().poll_write() {
            pc.get_sctp_handler().handle_write(out).unwrap();
        }
        while let Some(out) = pc.get_sctp_handler().poll_write() {
            if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = out.message {
                if let Some((_, DatagramEvent::AssociationEvent(event))) =
                    e.server_ep.handle(now, client_addr(), None, raw.freeze())
                {
                    e.server_conn.handle_event(event);
                }
            }
        }
        if let Some(chunks) = e.server_conn.stream(1).unwrap().read_sctp().unwrap() {
            opener
                .handle_read(DataChannelMessage {
                    association_handle: e.server_ch.0,
                    stream_id: 1,
                    ppi: chunks.ppi,
                    payload: chunks.to_payload(8192).unwrap(),
                    negotiated: false,
                })
                .unwrap();
        }
        assert!(
            !opener.is_handshake_complete(),
            "ACK of an already reset channel completed a new handshake whose OPEN is incomplete at the receiver"
        );
    }

    #[test]
    fn lifecycle_event_poll_cannot_overtake_data_in_the_shared_queue() {
        let e = establish();
        let now = Instant::now();
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        SctpHandler::enqueue_messages(
            vec![
                SctpMessage::Inbound(DataChannelMessage {
                    association_handle: ch.0,
                    stream_id: 1,
                    ppi: PayloadProtocolIdentifier::Binary,
                    payload: BytesMut::from(&b"old"[..]),
                    negotiated: false,
                }),
                SctpMessage::Event(SctpEvent::BufferReleased(ch.0, 1, 3)),
                SctpMessage::Event(SctpEvent::Closed(ch.0, 1)),
            ],
            now,
            TransportContext::default(),
            &mut ctx.read_outs,
            &mut ctx.write_outs,
        );
        let mut handler = SctpHandler::new(&mut ctx, 0);
        assert!(handler.poll_event().is_none());
        assert!(matches!(handler.poll_read().unwrap().message,
            RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) if message.payload == b"old"[..]));
        assert!(matches!(
            handler.poll_event().unwrap().event,
            RTCEventInternal::SCTPBufferReleased(_, 1, 3)
        ));
        assert!(matches!(
            handler.poll_read().unwrap().message,
            RTCMessageInternal::Dtls(DTLSMessage::SctpEvent(SctpEvent::Closed(_, 1)))
        ));
        assert!(handler.poll_read().is_none());
        assert!(handler.poll_event().is_none());
    }

    #[test]
    fn old_message_close_and_reused_sid_open_keep_their_pipeline_order() {
        fn forward_to_channels(
            ctx: &mut SctpHandlerContext,
            dcctx: &mut DataChannelHandlerContext,
            registry: &mut DataChannelRegistry,
            stats: &mut RTCStatsAccumulator,
        ) {
            let mut sctp = SctpHandler::new(ctx, 0);
            let mut channels =
                DataChannelHandler::new(dcctx, registry, stats, None, RTCDtlsRole::Client, None);
            while let Some(message) = sctp.poll_read() {
                channels.handle_read(message).unwrap();
            }
            assert!(
                sctp.poll_event().is_none(),
                "lifecycle was consumed exactly once"
            );
        }
        let dcep = |label: &[u8]| {
            Bytes::from(
                Message::DataChannelOpen(DataChannelOpen {
                    channel_type: ChannelType::Reliable,
                    priority: CHANNEL_PRIORITY_NORMAL,
                    reliability_parameter: 0,
                    label: label.to_vec(),
                    protocol: vec![],
                })
                .marshal()
                .unwrap(),
            )
        };
        let mut e = establish();
        let now = Instant::now();
        e.server_conn
            .open_stream(1, PayloadProtocolIdentifier::Dcep)
            .unwrap()
            .write_sctp(now, &dcep(b"old"), PayloadProtocolIdentifier::Dcep)
            .unwrap();
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        for packet in drain_transmits(&mut e.server_conn, now) {
            SctpHandler::new(&mut ctx, 0)
                .handle_read(raw_read(now, packet))
                .unwrap();
        }
        let mut dcctx = DataChannelHandlerContext::new(now);
        let mut registry = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        forward_to_channels(&mut ctx, &mut dcctx, &mut registry, &mut stats);
        let old_id = registry.handle_of_stream(&1).unwrap();
        dcctx.read_outs.clear();
        dcctx.write_outs.clear();
        dcctx.event_outs.clear();

        e.server_conn
            .stream(1)
            .unwrap()
            .write_sctp(
                now,
                &Bytes::from_static(b"last old message"),
                PayloadProtocolIdentifier::Binary,
            )
            .unwrap();
        for packet in drain_transmits(&mut e.server_conn, now) {
            SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                .handle_read(raw_read(now, packet))
                .unwrap();
        }
        e.server_conn.stream(1).unwrap().stop(now).unwrap();
        // Finish both protocol resets while the old application message remains
        // unread. No loss or fabricated RSN is needed to expose the EOF fence.
        for _ in 0..4 {
            for packet in drain_transmits(&mut e.server_conn, now) {
                SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                    .handle_read(raw_read(now, packet))
                    .unwrap();
            }
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            while let Some(packet) = handler.poll_write() {
                if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = packet.message
                    && let Some((_, DatagramEvent::AssociationEvent(event))) =
                        e.server_ep.handle(now, client_addr(), None, raw.freeze())
                {
                    e.server_conn.handle_event(event);
                }
            }
        }
        assert!(ctx.read_outs.is_empty(), "the old message is still parked");
        e.server_conn
            .open_stream(1, PayloadProtocolIdentifier::Dcep)
            .expect("peer may reuse SID after both protocol resets")
            .write_sctp(now, &dcep(b"new"), PayloadProtocolIdentifier::Dcep)
            .unwrap();
        for packet in drain_transmits(&mut e.server_conn, now) {
            SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
                .handle_read(raw_read(now, packet))
                .unwrap();
        }

        forward_to_channels(&mut ctx, &mut dcctx, &mut registry, &mut stats);
        let new_id = registry.handle_of_stream(&1).unwrap();
        assert_ne!(old_id, new_id);
        assert_eq!(registry.get(&new_id).unwrap().label, "new");
        let messages: Vec<_> = dcctx
            .read_outs
            .drain(..)
            .map(|message| {
                let RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app)) = message.message
                else {
                    panic!("unexpected pipeline message");
                };
                (app.data_channel_id, app.data_channel_event)
            })
            .collect();
        assert!(matches!(messages.as_slice(), [
            (old_message_id, DataChannelEvent::Message(message)),
            (closed_id, DataChannelEvent::Close),
            (opened_id, DataChannelEvent::Open),
        ] if *old_message_id == old_id && *closed_id == old_id && *opened_id == new_id
            && message.data == b"last old message"[..]));
        assert!(
            dcctx.event_outs.is_empty(),
            "close stays with the ordered read pipeline"
        );
        assert_eq!(stats.peer_connection.data_channels_closed, 1);

        use crate::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
        use crate::peer_connection::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
        use crate::peer_connection::message::internal::ApplicationMessage;
        let mut endpoint_ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![];
        let mut endpoint = EndpointHandler::new(&mut endpoint_ctx, &mut transceivers, &mut stats);
        for (data_channel_id, data_channel_event) in messages {
            endpoint
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                        ApplicationMessage {
                            data_channel_id,
                            data_channel_event,
                        },
                    )),
                })
                .unwrap();
        }
        assert!(
            endpoint.poll_read().is_some(),
            "old application payload remains available"
        );
        assert!(matches!(endpoint.poll_event().unwrap().event,
            RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnClose(id))) if id == old_id));
        assert!(matches!(endpoint.poll_event().unwrap().event,
            RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnOpen(id))) if id == new_id));
        assert!(endpoint.poll_event().is_none());
    }

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }

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
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_addr(),
            )
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
                        _ => {}
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

    /// Build a client association that has sent COOKIE-ECHO but has not yet received COOKIE-ACK,
    /// then create one DATA datagram from the already-established server.  This is the ordering
    /// that can occur when a peer opens a DataChannel in the same flight as the final SCTP
    /// handshake packet.
    fn client_with_data_before_cookie_ack() -> (SctpHandlerContext, Vec<Bytes>, Vec<Bytes>) {
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
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_addr(),
            )
            .expect("client connect");

        // Client INIT -> server association.
        let init = drain_transmits(&mut client_conn, now);
        let (server_ch, mut server_conn) = init
            .into_iter()
            .find_map(|dgram| {
                server_ep.handle(now, client_addr(), None, dgram).and_then(
                    |(ch, event)| match event {
                        DatagramEvent::NewAssociation(conn) => Some((ch, conn)),
                        _ => None,
                    },
                )
            })
            .expect("server association");

        // Server INIT-ACK -> client COOKIE-ECHO.
        let init_ack = drain_transmits(&mut server_conn, now);
        for dgram in init_ack {
            if let Some((ch, DatagramEvent::AssociationEvent(event))) =
                client_ep.handle(now, server_addr(), None, dgram)
            {
                assert_eq!(ch, client_ch);
                client_conn.handle_event(event);
            }
        }
        let cookie_echo = drain_transmits(&mut client_conn, now);

        // Server processes COOKIE-ECHO and becomes established, producing COOKIE-ACK.
        for dgram in cookie_echo {
            if let Some((ch, DatagramEvent::AssociationEvent(event))) =
                server_ep.handle(now, client_addr(), None, dgram)
            {
                assert_eq!(ch, server_ch);
                server_conn.handle_event(event);
            }
        }
        while server_conn.poll().is_some() {}
        let cookie_ack = drain_transmits(&mut server_conn, now);
        assert!(!cookie_ack.is_empty(), "server must produce COOKIE-ACK");

        // Send a DCEP OPEN before the client receives COOKIE-ACK.
        let dcep_open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: b"early-channel".to_vec(),
            protocol: Vec::new(),
        })
        .marshal()
        .expect("DCEP OPEN");
        {
            let mut stream = server_conn
                .open_stream(1, PayloadProtocolIdentifier::Dcep)
                .expect("open server stream");
            stream
                .write_sctp(
                    now,
                    &Bytes::from(dcep_open),
                    PayloadProtocolIdentifier::Dcep,
                )
                .expect("server data");
        }
        let early_data = drain_transmits(&mut server_conn, now);
        assert!(!early_data.is_empty(), "server must produce DCEP DATA");

        (
            client_ctx(now, client_ep, client_ch, client_conn),
            cookie_ack,
            early_data,
        )
    }

    /// Establish TWO independent associations on a single client endpoint (each to
    /// its own server), so a handler test can drain one while the other stays live.
    fn establish_two() -> (
        Endpoint,
        AssociationHandle,
        Association,
        AssociationHandle,
        Association,
    ) {
        let now = Instant::now();
        let server_a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555);
        let server_b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6666);

        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let mut server_a = Endpoint::new(
            server_a_addr,
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );
        let mut server_b = Endpoint::new(
            server_b_addr,
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );

        let (ch_a, mut conn_a) = client_ep
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_a_addr,
            )
            .expect("connect A");
        let (ch_b, mut conn_b) = client_ep
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_b_addr,
            )
            .expect("connect B");

        let mut sa: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut sb: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut a_up = false;
        let mut b_up = false;

        for _ in 0..100 {
            let mut moved = false;

            // client A -> server A, client B -> server B
            for d in drain_transmits(&mut conn_a, now) {
                moved = true;
                if let Some((ch, ev)) = server_a.handle(now, client_addr(), None, d) {
                    match ev {
                        DatagramEvent::NewAssociation(c) => {
                            sa.insert(ch, c);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(c) = sa.get_mut(&ch) {
                                c.handle_event(e);
                            }
                        }
                        _ => {}
                    }
                }
            }
            for d in drain_transmits(&mut conn_b, now) {
                moved = true;
                if let Some((ch, ev)) = server_b.handle(now, client_addr(), None, d) {
                    match ev {
                        DatagramEvent::NewAssociation(c) => {
                            sb.insert(ch, c);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(c) = sb.get_mut(&ch) {
                                c.handle_event(e);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // servers -> client (client_ep routes back by verification tag)
            let mut back = vec![];
            for c in sa.values_mut() {
                while c.poll().is_some() {}
                for d in drain_transmits(c, now) {
                    back.push((server_a_addr, d));
                }
            }
            for c in sb.values_mut() {
                while c.poll().is_some() {}
                for d in drain_transmits(c, now) {
                    back.push((server_b_addr, d));
                }
            }
            for (from, d) in back {
                moved = true;
                if let Some((ch, DatagramEvent::AssociationEvent(e))) =
                    client_ep.handle(now, from, None, d)
                {
                    if ch == ch_a {
                        conn_a.handle_event(e);
                    } else if ch == ch_b {
                        conn_b.handle_event(e);
                    }
                }
            }

            while let Some(ev) = conn_a.poll() {
                if let Event::Connected = ev {
                    a_up = true;
                }
            }
            while let Some(ev) = conn_b.poll() {
                if let Event::Connected = ev {
                    b_up = true;
                }
            }

            if a_up && b_up && !moved {
                break;
            }
        }

        assert!(a_up && b_up, "both associations must connect");
        (client_ep, ch_a, conn_a, ch_b, conn_b)
    }

    /// Wrap an established client endpoint + association in a handler context.
    fn client_ctx(
        now: Instant,
        client_ep: Endpoint,
        ch: AssociationHandle,
        conn: Association,
    ) -> SctpHandlerContext {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .internal_buffer
            .resize(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize, 0);
        transport.sctp_endpoint = Some(client_ep);
        transport.sctp_associations.insert(ch, conn);
        SctpHandlerContext::new(now, transport)
    }

    // First-chunk types we assert on (RFC 9260 §3.2). The `sctp` crate keeps its
    // `CT_*` constants crate-private, so we decode the wire format directly.
    const CT_PAYLOAD_DATA: u8 = 0;
    const CT_SHUTDOWN: u8 = 7;
    const CT_SHUTDOWN_COMPLETE: u8 = 14;

    /// First SCTP chunk type of every datagram flushed into `write_outs`. The SCTP
    /// common header is a fixed 12 bytes (RFC 9260 §3.1), so the first chunk's type
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

    const CT_SACK: u8 = 3;

    /// The advertised receiver window (`a_rwnd`) from the first flushed SACK.
    ///
    /// Asserting on the wire rather than on the association's internal credit: `a_rwnd` is
    /// what the peer actually reads, and `get_my_receiver_window_credit()` is `pub(crate)` to
    /// the `sctp` crate anyway. Layout is RFC 9260 §3.3.4 — 12-byte common header, then the
    /// 4-byte chunk header, then a 4-byte Cumulative TSN Ack, then `a_rwnd`.
    fn flushed_sack_a_rwnd(flushed: &[TaggedRTCMessageInternal]) -> Option<u32> {
        flushed.iter().find_map(|m| match &m.message {
            RTCMessageInternal::Dtls(DTLSMessage::Raw(raw))
                if raw.len() >= 24 && raw[12] == CT_SACK =>
            {
                Some(u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]))
            }
            _ => None,
        })
    }

    /// Feed `dgrams` to a client handler with the given downstream backlog, flush, and return
    /// the resulting context.
    fn run_client(
        now: Instant,
        e: Established,
        dgrams: Vec<Bytes>,
        backlog: usize,
    ) -> (SctpHandlerContext, Vec<TaggedRTCMessageInternal>) {
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        let mut flushed = vec![];
        let mut handler = SctpHandler::new(&mut ctx, backlog);
        for dgram in dgrams {
            handler.handle_read(raw_read(now, dgram)).expect("read");
        }
        // The first DATA arms a *delayed* ack, so without letting that timer expire there is
        // no SACK to read `a_rwnd` from. Harmless in the parked case: the backlog is still
        // over the bound there, so the resume finds no budget and changes nothing.
        handler
            .handle_timeout(now + Duration::from_millis(500))
            .expect("delayed-ack timer");
        // `poll_write` *pops*: collect, or the evidence is thrown away.
        while let Some(m) = handler.poll_write() {
            flushed.push(m);
        }
        (ctx, flushed)
    }

    /// Push `count` messages from the server onto `stream_id` and return the datagrams the
    /// client must receive. Returns raw wire bytes so the test drives the real
    /// `handle_read` path rather than poking handler internals.
    fn server_datagrams_carrying(
        e: &mut Established,
        stream_id: StreamId,
        count: usize,
        now: Instant,
    ) -> Vec<Bytes> {
        {
            let mut stream = e
                .server_conn
                .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
                .expect("open server stream");
            for i in 0..count {
                stream
                    .write_sctp(
                        now,
                        &Bytes::from(vec![i as u8; 64]),
                        PayloadProtocolIdentifier::Binary,
                    )
                    .expect("server write");
            }
        }
        while e.server_conn.poll().is_some() {}
        drain_transmits(&mut e.server_conn, now)
    }

    fn raw_read(now: Instant, dgram: Bytes) -> TaggedRTCMessageInternal {
        TaggedRTCMessageInternal {
            now,
            transport: TransportContext {
                local_addr: client_addr(),
                peer_addr: server_addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&dgram[..]))),
        }
    }

    /// An SCTP DATA message received before COOKIE-ACK must stay in the association's receive
    /// queue.  Once COOKIE-ACK establishes the association, the same message is delivered exactly
    /// once, allowing the DataChannel handler to announce `OnOpen` only after SCTP is ready.
    #[test]
    fn inbound_data_waits_for_sctp_handshake() {
        let now = Instant::now();
        let (mut ctx, cookie_ack, early_data) = client_with_data_before_cookie_ack();

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for dgram in early_data {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("early DATA");
            }
        }

        assert!(
            ctx.read_outs.is_empty(),
            "handshaking SCTP data must not reach the DataChannel handler"
        );
        assert_eq!(
            ctx.pending_readable.len(),
            1,
            "the readable stream must be retried after SCTP connects"
        );

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for dgram in cookie_ack {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("COOKIE-ACK");
            }
        }

        assert!(
            ctx.pending_readable.is_empty(),
            "the stream must be drained after SCTP becomes established"
        );
        assert_eq!(
            ctx.read_outs.len(),
            2,
            "establishment must precede the single DCEP"
        );
        let connected = ctx.read_outs.pop_front().expect("establishment event");
        assert!(matches!(
            connected.message,
            RTCMessageInternal::Dtls(DTLSMessage::SctpEvent(SctpEvent::Connected(_)))
        ));
        let inbound = ctx.read_outs.pop_front().expect("delivered DCEP");
        assert!(matches!(
            &inbound.message,
            RTCMessageInternal::Dtls(DTLSMessage::Sctp(data))
                if data.ppi == PayloadProtocolIdentifier::Dcep
        ));

        // The DataChannel handler now sees the DCEP message only after SCTP has become
        // established. It can therefore accept the channel, emit Open, and queue its ACK
        // without attempting a write in CookieEchoed.
        let mut data_channel_ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        {
            let mut handler = DataChannelHandler::new(
                &mut data_channel_ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Client,
                None,
            );
            handler.handle_read(connected).expect("SCTP establishment");
            handler
                .handle_read(inbound)
                .expect("accept DCEP after SCTP handshake");
        }
        assert!(
            data_channel_ctx.read_outs.iter().any(|message| matches!(
                &message.message,
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open)
            )),
            "the DataChannel Open event must follow SCTP establishment"
        );
    }

    /// With the pipeline already at its bound, inbound DATA must be left in the reassembly
    /// queue rather than pulled into the pipeline — and the peer must be *told*, by the only
    /// channel SCTP has for saying so: a smaller `a_rwnd` in the SACK.
    ///
    /// Draining unconditionally is exactly what defeats this. The bytes sitting in the
    /// reassembly queue are what `max_receive_buffer_size` is measured against, so emptying
    /// it on arrival keeps `a_rwnd` pinned at maximum however far behind the application is.
    #[test]
    fn a_full_pipeline_parks_the_stream_and_shrinks_the_advertised_window() {
        let now = Instant::now();

        // Same traffic, two identical associations: one allowed to drain, one at the bound.
        let mut e_free = establish();
        let free_dgrams = server_datagrams_carrying(&mut e_free, 1, 8, now);
        let mut e_full = establish();
        let full_dgrams = server_datagrams_carrying(&mut e_full, 1, 8, now);
        assert!(!full_dgrams.is_empty(), "server produced no DATA");

        let (ctx_free, flushed_free) = run_client(now, e_free, free_dgrams, 0);
        let (ctx_full, flushed_full) =
            run_client(now, e_full, full_dgrams, SCTP_PIPELINE_READ_BACKLOG_LIMIT);

        assert!(
            !ctx_free.read_outs.is_empty(),
            "control: an empty pipeline must receive the messages"
        );
        assert!(
            ctx_free.pending_readable.is_empty(),
            "control: nothing should be parked when there is room"
        );

        assert!(
            ctx_full.read_outs.is_empty(),
            "a full pipeline must not be handed more messages, got {}",
            ctx_full.read_outs.len()
        );
        assert!(
            !ctx_full.pending_readable.is_empty(),
            "the stream must be remembered, or the edge-triggered Readable is lost forever"
        );

        let free = flushed_sack_a_rwnd(&flushed_free).expect("control flushed no SACK");
        let full = flushed_sack_a_rwnd(&flushed_full).expect("parked run flushed no SACK");
        assert!(
            full < free,
            "undrained bytes must shrink the window advertised to the peer: \
             parked a_rwnd {full} should be below drained a_rwnd {free}"
        );
    }

    /// **The deadlock this feature would otherwise create.**
    ///
    /// `StreamEvent::Readable` is edge-triggered: `association/mod.rs` emits it when a *new*
    /// DATA chunk arrives, never because unread data remains. So the moment back-pressure
    /// works — the peer throttled, no new chunk coming — a stream parked mid-drain would
    /// never be revisited, and the connection would stall exactly when the feature engaged.
    ///
    /// This drives `handle_timeout` with **no new inbound datagram** and requires the parked
    /// data to come through anyway.
    #[test]
    fn a_parked_stream_resumes_without_a_new_inbound_chunk() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 8, now);

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in dgrams {
                handler.handle_read(raw_read(now, dgram)).expect("read");
            }
        }
        assert!(ctx.read_outs.is_empty(), "precondition: nothing drained");
        assert!(!ctx.pending_readable.is_empty(), "precondition: parked");

        // The application drains, so the pipeline has room again. Nothing else happens: no
        // packet arrives, and the peer — correctly throttled — sends nothing. The only call
        // is the one the pipeline makes when it wants data.
        let resumed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler.poll_read()
        };

        assert!(
            resumed.is_some(),
            "parked stream never resumed — this is the edge-triggered Readable deadlock: \
             the peer is throttled so no new chunk will arrive to re-trigger the drain"
        );
        assert!(
            ctx.pending_readable.is_empty(),
            "a fully drained stream must stop being remembered"
        );
    }

    /// A resumed drain must be stamped with **its own** association's 5-tuple.
    ///
    /// The first version of this kept a single `last_transport` — the most recent inbound
    /// datagram's context — and reused it for every resumed message. With more than one
    /// association on the endpoint (which `sctp_associations` being a map allows, and
    /// `establish_two` exercises) that hands association A's messages association B's peer
    /// address, because whichever datagram arrived last wins.
    #[test]
    fn a_resumed_drain_uses_its_own_associations_transport() {
        let now = Instant::now();

        // Two associations to two different peers, each carrying parked data.
        let mut e_a = establish();
        let a_dgrams = server_datagrams_carrying(&mut e_a, 1, 4, now);
        let mut e_b = establish();
        let b_dgrams = server_datagrams_carrying(&mut e_b, 1, 4, now);

        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7001);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7002);

        let mut ctx = client_ctx(now, e_a.client_ep, e_a.client_ch, e_a.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in a_dgrams {
                let mut msg = raw_read(now, dgram);
                msg.transport.peer_addr = peer_a;
                handler.handle_read(msg).expect("read A");
            }
        }
        assert!(!ctx.pending_readable.is_empty(), "A must be parked");

        // A datagram from a *different* peer arrives afterwards. Under the old single
        // `last_transport` this is the value A's resumed messages would inherit.
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in b_dgrams {
                let mut msg = raw_read(now, dgram);
                msg.transport.peer_addr = peer_b;
                // Belongs to no association on this endpoint; under the old single
                // `last_transport` it would still have overwritten it.
                let _ = handler.handle_read(msg);
            }
        }

        // Now let A resume, through the path that actually resumes it.
        let mut resumed = vec![];
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            while let Some(msg) = handler.poll_read() {
                resumed.push(msg);
            }
        }

        assert!(!resumed.is_empty(), "A never resumed");
        for msg in &resumed {
            assert_eq!(
                msg.transport.peer_addr, peer_a,
                "a resumed message must carry its own association's peer address, not \
                 whichever datagram happened to arrive most recently"
            );
        }
    }

    /// `poll_timeout` must stay silent about parked streams.
    ///
    /// Reporting a deadline for them was tried and reverted. The only instant available here
    /// is the *retained* one, which is always in the past relative to the caller's clock, and
    /// a caller that computes `deadline - now` gets zero. `tests/ice_tcp_active_passive.rs`
    /// treats a zero delay as "handle the timeout and `continue`", skipping its socket reads
    /// — so a past deadline starved the connection of I/O for the test's full 30 s budget and
    /// no data-channel message was ever delivered.
    #[test]
    fn poll_timeout_reports_nothing_for_a_parked_stream() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 8, now);

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in dgrams {
                handler.handle_read(raw_read(now, dgram)).expect("read");
            }
        }
        assert!(!ctx.pending_readable.is_empty(), "precondition: parked");

        // With room, and with none: neither may produce a deadline at or before `now`.
        for backlog in [0, SCTP_PIPELINE_READ_BACKLOG_LIMIT] {
            let mut handler = SctpHandler::new(&mut ctx, backlog);
            if let Some(eto) = handler.poll_timeout() {
                assert!(
                    eto > now,
                    "a parked stream must not put a past deadline in front of the caller \
                     (backlog {backlog}): callers read that as zero delay and skip their I/O"
                );
            }
        }
    }

    // handle_timeout teardown-safety block: a graceful shutdown queues both the
    // `Drained` endpoint event AND the final SHUTDOWN datagram. handle_timeout
    // collects the drain (removing the association) and must flush the SHUTDOWN
    // *before* removal, or the peer would never learn the association closed.
    #[test]
    fn handle_timeout_flushes_final_packet_before_drain() {
        let now = Instant::now();
        let e = establish();
        let mut client_conn = e.client_conn;
        client_conn
            .shutdown()
            .expect("shutdown from Established queues Drained + SHUTDOWN");

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
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
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
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

    // The teardown-safety flush must touch ONLY the draining association. With two
    // live associations, draining A must flush A's final SHUTDOWN and remove A while
    // leaving B — and B's queued DATA — untouched (B keeps coalescing and is flushed
    // later in poll_write). The over-broad "flush every association" form would drain
    // B's DATA here too; this test rejects that.
    #[test]
    fn teardown_flush_targets_only_the_draining_association() {
        let now = Instant::now();
        let (client_ep, ch_a, mut conn_a, ch_b, mut conn_b) = establish_two();

        // A: graceful shutdown -> Drained + a pending SHUTDOWN.
        conn_a.shutdown().expect("shutdown A");
        // B: queue DATA that is NOT yet flushed (stays pending in the association).
        conn_b
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .and_then(|mut s| {
                s.write_chunk_with_ppi(
                    now,
                    &Bytes::from_static(b"pending payload on B"),
                    PayloadProtocolIdentifier::Binary,
                )
            })
            .expect("queue DATA on B");

        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .internal_buffer
            .resize(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize, 0);
        transport.sctp_endpoint = Some(client_ep);
        transport.sctp_associations.insert(ch_a, conn_a);
        transport.sctp_associations.insert(ch_b, conn_b);
        let mut ctx = SctpHandlerContext::new(now, transport);

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler
                .handle_timeout(Instant::now())
                .expect("handle_timeout");
        }

        // A (draining) removed; B (live) retained.
        assert!(
            !ctx.sctp_transport.sctp_associations.contains_key(&ch_a),
            "draining association A must be removed"
        );
        assert!(
            ctx.sctp_transport.sctp_associations.contains_key(&ch_b),
            "live association B must be retained"
        );

        // Only A's SHUTDOWN was flushed; B's DATA was NOT.
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN),
            "A's final SHUTDOWN must be flushed (flushed chunk types: {flushed:?})"
        );
        assert!(
            !flushed.contains(&CT_PAYLOAD_DATA),
            "B's DATA must NOT be flushed by A's teardown (flushed chunk types: {flushed:?})"
        );

        // ...and B's DATA is still pending in the association, ready for poll_write.
        let b = ctx
            .sctp_transport
            .sctp_associations
            .get_mut(&ch_b)
            .expect("B present");
        assert!(
            b.poll_transmit(Instant::now()).is_some(),
            "B's queued DATA must remain pending, not consumed by A's teardown"
        );
    }

    // Design §3.7's worked example. The client INIT is queued by `connect` inside
    // `handle_event` and emitted by the *next* `poll_write` — so before C3-01 gave the event
    // channel a timestamp, the retained instant was still unset at that point and the flush
    // fell back to `Instant::now()`. That was not a defensive branch: it was the path taken on
    // every client connection. Now the INIT is stamped from the event that armed it.
    #[test]
    fn client_init_flush_is_stamped_from_the_event_that_armed_it() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .internal_buffer
            .resize(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize, 0);
        transport.sctp_endpoint = Some(Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        ));
        transport.sctp_transport_config = Some(TransportConfig::default());
        let mut ctx = SctpHandlerContext::new(t(0), transport);

        // No inbound SCTP has been seen, so nothing but the event has moved the retained
        // instant off its construction seed.
        assert_eq!(ctx.now, t(0));

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now: t(7),
                    event: RTCEventInternal::DTLSHandshakeComplete(None, None),
                })
                .expect("handle_event");
        }
        assert_eq!(
            ctx.now,
            t(7),
            "the event's instant must arm the deferred flush"
        );

        let flushed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            let mut out = vec![];
            while let Some(msg) = handler.poll_write() {
                out.push(msg);
            }
            out
        };

        assert!(!flushed.is_empty(), "poll_write must emit the client INIT");
        for msg in &flushed {
            assert_eq!(
                msg.now,
                t(7),
                "the INIT carries the instant of the event that caused it, not the wall clock"
            );
        }
    }

    // C4-04 replaced `last_now: Option<Instant>` + `unwrap_or_else(Instant::now)` with a
    // construction-seeded `now: Instant`. The *point* of the deferred flush is batching — N
    // inbound DATA chunks ingested before one flush, so the ack machine coalesces them into a
    // single SACK instead of one per two packets. Nothing in the suite pinned that invariant,
    // and the workspace has no SCTP throughput benchmark to measure it with, so this asserts it
    // structurally: a burst of reads must arm the flush once and produce one flush's worth of
    // output, not one per packet.
    #[test]
    fn a_burst_of_reads_produces_one_flush_not_one_per_packet() {
        let base = Instant::now();
        let t = |millis| base + Duration::from_millis(millis);

        let e = establish();
        let mut server_conn = e.server_conn;
        let server_ch = e.server_ch;
        let mut ctx = client_ctx(t(0), e.client_ep, e.client_ch, e.client_conn);

        // Server sends several DATA chunks; each becomes its own inbound datagram.
        let mut stream = server_conn
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .expect("open stream");
        for i in 0..4u8 {
            stream
                .write_chunk_with_ppi(
                    base,
                    &Bytes::from(vec![i; 1024]),
                    PayloadProtocolIdentifier::Binary,
                )
                .expect("queue DATA");
        }
        let dgrams = drain_transmits(&mut server_conn, t(0));
        assert!(
            dgrams.len() >= 2,
            "the burst must be more than one datagram to be worth batching, got {}",
            dgrams.len()
        );
        let _ = server_ch;

        // Ingest the whole burst. Every read arms the flush; none performs it.
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for (i, d) in dgrams.iter().enumerate() {
                handler
                    .handle_read(TaggedRTCMessageInternal {
                        now: t(i as u64),
                        transport: TransportContext {
                            local_addr: client_addr(),
                            peer_addr: server_addr(),
                            transport_protocol: TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&d[..]))),
                    })
                    .expect("handle_read");
            }
        }
        assert!(
            ctx.write_outs.is_empty(),
            "ingest must not flush: that is what makes the SACKs coalesce"
        );
        assert_eq!(
            ctx.now,
            t(dgrams.len() as u64 - 1),
            "the retained instant is the newest of the burst, which is what stamps the flush"
        );

        // One poll_write runs the single flush for the whole burst.
        let flushed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            let mut out = vec![];
            while let Some(msg) = handler.poll_write() {
                out.push(msg);
            }
            out
        };
        assert!(
            !flushed.is_empty(),
            "the flush must emit the coalesced SACK"
        );
        assert!(
            flushed.len() < dgrams.len(),
            "batching must emit fewer datagrams than it ingested ({} in, {} out)",
            dgrams.len(),
            flushed.len()
        );
    }
}
