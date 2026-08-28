use crate::data_channel::RTCDataChannelHandle;
use crate::data_channel::RTCDataChannelId;
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::state::RTCDataChannelState;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::{
    RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::RTCDtlsRole;
use crate::peer_connection::transport::sctp::SCTP_MAX_CHANNELS;
use crate::statistics::accumulator::RTCStatsAccumulator;
use log::{debug, warn};
use sctp::PayloadProtocolIdentifier;
use shared::TransportContext;
use shared::error::{Error, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub(crate) struct DataChannelHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// `poll_write` drains each channel's outbound queue, and a message can still be sitting
    /// there from an earlier `handle_*` — the datachannel layer buffers when SCTP back-pressures
    /// it. Stamping those with the instant of the input that caused them is the right answer;
    /// this field is what a `poll_*` has instead of a parameter.
    now: Instant,
}

impl DataChannelHandlerContext {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            now,
        }
    }

    /// Records the newest instant a caller has supplied. See the design's §9.3 for why there is
    /// no monotonicity assert alongside the `max`.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }
}

/// DataChannelHandler implements DataChannel Protocol handling
pub(crate) struct DataChannelHandler<'a> {
    ctx: &'a mut DataChannelHandlerContext,
    data_channels: &'a mut HashMap<RTCDataChannelHandle, RTCDataChannelInternal>,
    /// Handles of locally-created channels whose stream id is still unassigned (DTLS role not yet
    /// resolved / SCTP not connected), in creation order.
    pending_handles: &'a mut Vec<RTCDataChannelHandle>,
    /// Reverse lookup stream id -> handle, for channels that have been assigned a stream id.
    data_channel_ids: &'a mut HashMap<RTCDataChannelId, RTCDataChannelHandle>,
    /// Handle allocator, shared with `RTCPeerConnection`, so accepted (remote) channels get a
    /// distinct handle.
    handle_allocator: &'a mut usize,
    stats: &'a mut RTCStatsAccumulator,
    /// Configured DCEP handshake timeout for in-band channels. `None` disables it.
    dcep_handshake_timeout: Option<Duration>,
    /// The local DTLS role, resolved once the remote description has been applied.
    dtls_role: RTCDtlsRole,
    /// The negotiated SCTP channel cap, known once the SCTP association is connected.
    max_channels: Option<u16>,
}

impl<'a> DataChannelHandler<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ctx: &'a mut DataChannelHandlerContext,
        data_channels: &'a mut HashMap<RTCDataChannelHandle, RTCDataChannelInternal>,
        pending_handles: &'a mut Vec<RTCDataChannelHandle>,
        data_channel_ids: &'a mut HashMap<RTCDataChannelId, RTCDataChannelHandle>,
        handle_allocator: &'a mut usize,
        stats: &'a mut RTCStatsAccumulator,
        dcep_handshake_timeout: Option<Duration>,
        dtls_role: RTCDtlsRole,
        max_channels: Option<u16>,
    ) -> Self {
        DataChannelHandler {
            ctx,
            data_channels,
            pending_handles,
            data_channel_ids,
            handle_allocator,
            stats,
            dcep_handshake_timeout,
            dtls_role,
            max_channels,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DataChannelHandler"
    }

    /// Emit the `DataChannelEvent::Open` application message and record the
    /// corresponding peer-connection and per-channel statistics.
    ///
    /// The caller must have already ensured the channel's `ready_state` is `Open`.
    fn emit_data_channel_opened(
        &mut self,
        now: Instant,
        transport: TransportContext,
        handle: RTCDataChannelHandle,
    ) -> Result<()> {
        let dc = self
            .data_channels
            .get(&handle)
            .ok_or(Error::ErrDataChannelNotExisted)?;
        // A channel only opens once its stream id has been assigned (on the connected
        // procedure), so the event always carries a stream id.
        let stream_id = dc.stream_id.ok_or(Error::ErrDataChannelNotExisted)?;

        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport,
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id: stream_id,
                data_channel_event: DataChannelEvent::Open,
            })),
        });

        self.stats.peer_connection.on_data_channel_opened();
        self.stats
            .get_or_create_data_channel(stream_id, &dc.label, &dc.protocol)
            .on_state_changed(RTCDataChannelState::Open);
        Ok(())
    }

    /// Assign stream ids to pending local channels once the DTLS role is resolved.
    ///
    /// Implements W3C WebRTC section 6.1.1.3 step 4.2 / RFC 8832 section 6.
    /// Channels that cannot be assigned an id are closed and the application is notified.
    fn assign_pending_ids(&mut self, now: Instant) {
        let pending = std::mem::take(self.pending_handles);
        // `max` is a count of streams, so valid ids span `0..max` and the top id (`max - 1`)
        // is usable.
        let max = self.max_channels.unwrap_or(SCTP_MAX_CHANNELS);
        let mut used: HashSet<RTCDataChannelId> = self.data_channel_ids.keys().copied().collect();
        let mut closed = Vec::new();
        for handle in pending {
            // Closed channels cannot be dialed, so they must not consume a stream id.
            if let Some(dc) = self.data_channels.get(&handle)
                && (dc.ready_state == RTCDataChannelState::Closed
                    || dc.ready_state == RTCDataChannelState::Closing)
            {
                continue;
            }
            let mut id = 0u16;
            if self.dtls_role == RTCDtlsRole::Server {
                id += 1;
            }
            let mut found = None;
            while id < max {
                if !used.contains(&id) {
                    found = Some(id);
                    break;
                }
                id += 2;
            }
            match found {
                Some(stream_id) => {
                    if let Some(dc) = self.data_channels.get_mut(&handle) {
                        dc.stream_id = Some(stream_id);
                        self.data_channel_ids.insert(stream_id, handle);
                        // Reserve the id for later handles in this batch, so two pending
                        // channels cannot be assigned the same stream id.
                        used.insert(stream_id);
                    }
                }
                None => {
                    closed.push(handle);
                }
            }
        }
        for handle in closed {
            if let Some(mut dc) = self.data_channels.remove(&handle) {
                let _ = dc.close();
                // The channel never received a stream id, so it cannot be keyed by one.
                // Notify the application with the stable handle so the event routes to the right
                // channel rather than via the defaulted stream id 0. Error first, then close
                // (W3C section 6.2.7).
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(
                            RTCDataChannelEvent::OnErrorByHandle(handle),
                        ),
                    ),
                });
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(
                            RTCDataChannelEvent::OnCloseByHandle(handle),
                        ),
                    ),
                });
            }
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DataChannelHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "recv SCTP DataChannelMessage from {:?}",
                msg.transport.peer_addr
            );

            // Defensive assignment in case DATA_CHANNEL_ACK arrives before SCTPHandshakeComplete.
            self.assign_pending_ids(now);

            let stream_id = message.stream_id;
            let transport = msg.transport;

            let handle = self.data_channel_ids.get(&stream_id).copied();

            let (handle, opened) = if let Some(handle) = handle {
                let data_channel_internal = self
                    .data_channels
                    .get_mut(&handle)
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                // A closed channel is terminal: ignore any late DCEP or user data.
                if data_channel_internal.ready_state == RTCDataChannelState::Closed {
                    return Ok(());
                }

                // Process the inbound message, then check whether a still-connecting
                // in-band channel just completed its DCEP handshake (initiator side).
                // If so, promote it to Open and emit the open event.
                let mut opened = false;
                let data_channel = data_channel_internal
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                data_channel.handle_read(message)?;
                if data_channel.is_handshake_complete()
                    && data_channel_internal.ready_state == RTCDataChannelState::Connecting
                {
                    data_channel_internal.ready_state = RTCDataChannelState::Open;
                    data_channel_internal.handshake_deadline = None;
                    opened = true;
                }
                (handle, opened)
            } else {
                // Incoming (remote) channel: assign a fresh handle and record its stream id.
                let handle = RTCDataChannelHandle::new(*self.handle_allocator);
                *self.handle_allocator += 1;
                let data_channel_internal = RTCDataChannelInternal::accept(
                    handle,
                    message.association_handle,
                    stream_id,
                    message.ppi,
                    &message.payload,
                )?;

                self.data_channels.insert(handle, data_channel_internal);
                self.data_channel_ids.insert(stream_id, handle);
                (handle, true)
            };

            if opened {
                self.emit_data_channel_opened(now, transport, handle)?;
            }

            // Get label/protocol before taking mutable borrow for the loop
            let (label, protocol) = {
                let dc = self
                    .data_channels
                    .get(&handle)
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                (dc.label.clone(), dc.protocol.clone())
            };

            // Only deliver application messages once the channel is Open. Messages that
            // arrive while it is still Connecting stay buffered in the underlying
            // DataChannel's read queue; they drain once the channel opens, or are
            // discarded on close/timeout.
            let is_open = self
                .data_channels
                .get(&handle)
                .is_some_and(|dc| dc.ready_state == RTCDataChannelState::Open);

            let data_channel = self
                .data_channels
                .get_mut(&handle)
                .ok_or(Error::ErrDataChannelNotExisted)?
                .data_channel
                .as_mut()
                .ok_or(Error::ErrDataChannelNotExisted)?;

            if is_open {
                while let Some(data_channel_message) = data_channel.poll_read() {
                    let payload_len = data_channel_message.payload.len();
                    debug!("recv application message {:?}", msg.transport.peer_addr);

                    // Track received message stats
                    self.stats
                        .get_or_create_data_channel(stream_id, &label, &protocol)
                        .on_message_received(payload_len);

                    // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-12#section-6.6
                    // When receiving an SCTP user message with one of these [Empty]
                    // PPIDs, the receiver MUST ignore the SCTP user message and
                    // process it as an empty message.
                    let message_data = if matches!(
                        data_channel_message.ppi,
                        PayloadProtocolIdentifier::StringEmpty
                            | PayloadProtocolIdentifier::BinaryEmpty
                    ) {
                        Default::default()
                    } else {
                        data_channel_message.payload
                    };

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id: stream_id,
                                data_channel_event: DataChannelEvent::Message(
                                    RTCDataChannelMessage {
                                        is_string: matches!(
                                            data_channel_message.ppi,
                                            PayloadProtocolIdentifier::String
                                                | PayloadProtocolIdentifier::StringEmpty
                                        ),
                                        data: message_data,
                                    },
                                ),
                            },
                        )),
                    });
                }
            }

            while let Some(data_channel_message) = data_channel.poll_write() {
                debug!("send data channel message from handle_read");
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
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

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::DataChannel(message)) = msg.message {
            debug!("send application message {:?}", msg.transport.peer_addr);

            if let DataChannelEvent::Message(RTCDataChannelMessage { is_string, data }) =
                message.data_channel_event
            {
                let data_len = data.len();
                let channel_id = message.data_channel_id;
                let handle = self
                    .data_channel_ids
                    .get(&channel_id)
                    .copied()
                    .ok_or(Error::ErrDataChannelNotExisted)?;

                // Get label/protocol before taking mutable borrow
                let dc_internal = self
                    .data_channels
                    .get(&handle)
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                let label = dc_internal.label.clone();
                let protocol = dc_internal.protocol.clone();

                let data_channel = self
                    .data_channels
                    .get_mut(&handle)
                    .ok_or(Error::ErrDataChannelNotExisted)?
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;

                let data_channel_message =
                    ::datachannel::data_channel::DataChannel::get_data_channel_message(
                        is_string, data,
                    );
                data_channel.handle_write(data_channel_message)?;

                // Track sent message stats
                self.stats
                    .get_or_create_data_channel(channel_id, &label, &protocol)
                    .on_message_sent(data_len);

                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from handle_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
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
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: self.ctx.now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        let now = evt.now;
        match evt.event {
            RTCEventInternal::SCTPHandshakeComplete(association_handle) => {
                // Assign stream ids before dialing (W3C section 6.1.1.3).
                self.assign_pending_ids(now);

                // Out-of-band negotiated channels have no DCEP handshake, so they are
                // open immediately and fire the open event here. In-band channels stay
                // connecting until their `DATA_CHANNEL_ACK` arrives in `handle_read`.
                let mut opened = Vec::new();
                for data_channel_internal in self.data_channels.values_mut() {
                    // Only dial channels that have not been dialed yet. An in-band channel stays
                    // Connecting after dialing, so the ready_state guard alone does not
                    // exclude it from a second SCTPHandshakeComplete.
                    if data_channel_internal.ready_state == RTCDataChannelState::Connecting
                        && data_channel_internal.data_channel.is_none()
                    {
                        // A channel can only be dialed once its stream id is assigned.
                        let _stream_id = data_channel_internal
                            .stream_id
                            .ok_or(Error::ErrDataChannelNotExisted)?;
                        data_channel_internal.dial(association_handle)?;

                        if data_channel_internal.negotiated {
                            opened.push(data_channel_internal.handle);
                        } else {
                            // In-band channels have a DCEP handshake to complete; arm a
                            // deadline so a lost ACK cannot leave them Connecting forever.
                            data_channel_internal.handshake_deadline =
                                self.dcep_handshake_timeout.map(|timeout| now + timeout);
                        }

                        let data_channel = data_channel_internal
                            .data_channel
                            .as_mut()
                            .ok_or(Error::ErrDataChannelNotExisted)?;

                        while let Some(data_channel_message) = data_channel.poll_write() {
                            debug!("send data channel message from handle_event");
                            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                now,
                                transport: TransportContext::default(),
                                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(
                                    data_channel_message,
                                )),
                            });
                        }
                    }
                }

                for handle in opened {
                    self.emit_data_channel_opened(now, TransportContext::default(), handle)?;
                }
            }

            RTCEventInternal::SCTPStreamClosed(_association_handle, stream_id) => {
                if let Some(handle) = self.data_channel_ids.remove(&stream_id)
                    && let Some(dc) = self.data_channels.remove(&handle)
                {
                    // A channel already closed by handshake timeout has already fired OnClose
                    // and been counted; do not emit or count it twice.
                    if !dc.close_emitted {
                        // Track data channel closed
                        self.stats.peer_connection.on_data_channel_closed();
                        if let Some(dc_stats) = self.stats.data_channels.get_mut(&stream_id) {
                            dc_stats.on_state_changed(RTCDataChannelState::Closed);
                        }

                        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                            now,
                            event: RTCEventInternal::RTCPeerConnectionEvent(
                                RTCPeerConnectionEvent::OnDataChannel(
                                    RTCDataChannelEvent::OnClose(stream_id),
                                ),
                            ),
                        });
                    }
                }
            }

            RTCEventInternal::SCTPBufferReleased(_association_handle, stream_id, n_bytes) => {
                // Pure accounting: SCTP released (acked or abandoned) `n_bytes` of
                // this channel's outgoing buffer. Decrement the synchronous send
                // back-pressure counter; do NOT forward the event further.
                if let Some(handle) = self.data_channel_ids.get(&stream_id).copied()
                    && let Some(dc) = self.data_channels.get_mut(&handle)
                {
                    dc.outstanding_bytes = dc.outstanding_bytes.saturating_sub(n_bytes);
                }
            }
            // Events propagate rather than being re-stamped: the forwarded event keeps the
            // instant at which its condition was observed, not the instant this hop ran.
            event => {
                self.ctx
                    .event_outs
                    .push_back(TaggedRTCEventInternal { now, event });
            }
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.observe(now);

        // Close in-band channels whose DCEP handshake did not complete in time.
        let mut timed_out = Vec::new();
        for dc in self.data_channels.values() {
            if let Some(deadline) = dc.handshake_deadline
                && dc.ready_state == RTCDataChannelState::Connecting
                && deadline <= now
            {
                timed_out.push(dc.handle);
            }
        }

        for handle in timed_out {
            if let Some(dc) = self.data_channels.get_mut(&handle) {
                let stream_id = dc.stream_id;
                dc.handshake_deadline = None;
                dc.ready_state = RTCDataChannelState::Closed;
                if let Some(data_channel) = dc.data_channel.as_mut() {
                    data_channel.close()?;
                }

                self.stats.peer_connection.on_data_channel_closed();
                if let Some(stream_id) = stream_id {
                    self.stats
                        .get_or_create_data_channel(stream_id, &dc.label, &dc.protocol)
                        .on_state_changed(RTCDataChannelState::Closed);
                }

                dc.close_emitted = true;
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(
                            stream_id.unwrap_or(0),
                        )),
                    ),
                });
            }
        }

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.data_channels
            .values()
            .filter_map(|dc| {
                if dc.ready_state == RTCDataChannelState::Connecting {
                    dc.handshake_deadline
                } else {
                    None
                }
            })
            .min()
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Timing contract for the DCEP handshake-complete signal and for the connected-procedure
    //! id assignment.
    //!
    //! These drive `DataChannelHandler` directly and pin
    //! *when* the open event fires and `ready_state` flips, which the integration
    //! tests cannot see: they only require the open event to fire *eventually*, so
    //! they pass whether the channel is promoted at dial time or on the ACK.

    use super::*;
    use crate::data_channel::parameters::DataChannelParameters;
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::BytesMut;
    use datachannel::data_channel::DataChannelMessage;
    use datachannel::message::Message;
    use datachannel::message::message_channel_ack::DataChannelAck;
    use sansio::Protocol;
    use shared::marshal::Marshal;

    /// Test harness, mimicking the `RTCPeerConnection`-owned fields that `DataChannelHandler`
    /// borrows. `handler()` returns a short-lived `DataChannelHandler` borrowing the harness.
    struct Harness {
        ctx: DataChannelHandlerContext,
        data_channels: HashMap<RTCDataChannelHandle, RTCDataChannelInternal>,
        pending: Vec<RTCDataChannelHandle>,
        ids: HashMap<RTCDataChannelId, RTCDataChannelHandle>,
        allocator: usize,
        stats: RTCStatsAccumulator,
        dtls_role: RTCDtlsRole,
        max_channels: Option<u16>,
    }

    impl Harness {
        fn new() -> Self {
            let now = Instant::now();
            Self {
                ctx: DataChannelHandlerContext::new(now),
                data_channels: HashMap::new(),
                pending: Vec::new(),
                ids: HashMap::new(),
                allocator: 100,
                stats: RTCStatsAccumulator::new(),
                dtls_role: RTCDtlsRole::Client,
                max_channels: None,
            }
        }

        fn add(&mut self, handle: usize, stream_id: u16) {
            assert!(
                self.data_channels
                    .insert(
                        RTCDataChannelHandle::new(handle),
                        in_band_channel(handle, stream_id),
                    )
                    .is_none()
            );
            self.ids
                .insert(stream_id, RTCDataChannelHandle::new(handle));
        }

        fn handler(&mut self, timeout: Option<Duration>) -> DataChannelHandler<'_> {
            DataChannelHandler::new(
                &mut self.ctx,
                &mut self.data_channels,
                &mut self.pending,
                &mut self.ids,
                &mut self.allocator,
                &mut self.stats,
                timeout,
                self.dtls_role,
                self.max_channels,
            )
        }
    }

    fn in_band_channel(handle: usize, stream_id: u16) -> RTCDataChannelInternal {
        let mut dc = RTCDataChannelInternal::new(
            RTCDataChannelHandle::new(handle),
            DataChannelParameters {
                label: "timing-test".to_string(),
                protocol: String::new(),
                ordered: true,
                max_packet_life_time: None,
                max_retransmits: None,
                negotiated: None,
            },
        );
        dc.stream_id = Some(stream_id);
        dc
    }

    fn negotiated_channel(handle: usize, stream_id: u16) -> RTCDataChannelInternal {
        let mut dc = RTCDataChannelInternal::new(
            RTCDataChannelHandle::new(handle),
            DataChannelParameters {
                label: "timing-test".to_string(),
                protocol: String::new(),
                ordered: true,
                max_packet_life_time: None,
                max_retransmits: None,
                negotiated: Some(stream_id),
            },
        );
        dc.stream_id = Some(stream_id);
        dc
    }

    fn ack(association_handle: usize, stream_id: u16) -> DataChannelMessage {
        let ack = Message::DataChannelAck(DataChannelAck {})
            .marshal()
            .unwrap();
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: BytesMut::from(&ack[..]),
            negotiated: false,
        }
    }

    fn data_message(association_handle: usize, stream_id: u16, data: &[u8]) -> DataChannelMessage {
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::String,
            payload: BytesMut::from(data),
            negotiated: false,
        }
    }

    fn message_events(ctx: &DataChannelHandlerContext) -> Vec<DataChannelEvent> {
        ctx.read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app)) => {
                    Some(app.data_channel_event.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// The open events emitted so far, as stream ids (the public-facing identity).
    fn open_ids(ctx: &DataChannelHandlerContext) -> Vec<RTCDataChannelId> {
        ctx.read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open) =>
                {
                    Some(app.data_channel_id)
                }
                _ => None,
            })
            .collect()
    }

    /// An in-band channel is dialed at `SCTPHandshakeComplete` but stays
    /// `Connecting` with no open event; the open event fires exactly once, and
    /// `ready_state` flips to `Open`, only when the peer's `DATA_CHANNEL_ACK`
    /// is processed.
    #[test]
    fn in_band_channel_fires_open_only_when_ack_is_processed() {
        let mut h = Harness::new();
        let now = Instant::now();
        h.add(1, 1);

        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        let dc = h.data_channels.get(&RTCDataChannelHandle::new(1)).unwrap();
        assert!(
            dc.data_channel.is_some(),
            "SCTPHandshakeComplete must dial the in-band channel"
        );
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Connecting,
            "an in-band channel must stay Connecting after the SCTP handshake"
        );
        assert!(
            h.ctx.read_outs.iter().all(|m| !matches!(
                &m.message,
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open)
            )),
            "no open event may fire at SCTPHandshakeComplete time"
        );

        {
            let mut handler = h.handler(None);
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        assert_eq!(
            h.data_channels
                .get(&RTCDataChannelHandle::new(1))
                .unwrap()
                .ready_state,
            RTCDataChannelState::Open,
            "ready_state flips to Open exactly when the ACK is processed"
        );

        assert_eq!(
            open_ids(&h.ctx),
            vec![1],
            "exactly one open event, fired on the ACK"
        );
        assert_eq!(
            h.stats.peer_connection.data_channels_opened, 1,
            "open stats recorded exactly once"
        );
    }

    /// A negotiated (out-of-band) channel has no DCEP handshake: it dials open
    /// immediately and fires the open event at `SCTPHandshakeComplete`.
    #[test]
    fn negotiated_channel_fires_open_at_handshake_complete() {
        let mut h = Harness::new();
        let now = Instant::now();
        h.data_channels
            .insert(RTCDataChannelHandle::new(1), negotiated_channel(1, 1));
        h.ids.insert(1, RTCDataChannelHandle::new(1));

        let mut handler = h.handler(None);
        handler
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            })
            .unwrap();

        let dc = h.data_channels.get(&RTCDataChannelHandle::new(1)).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Open,
            "a negotiated channel is open immediately at SCTPHandshakeComplete"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "a negotiated channel has no DCEP handshake deadline"
        );

        assert_eq!(
            open_ids(&h.ctx),
            vec![1],
            "exactly one open event at SCTPHandshakeComplete for a negotiated channel"
        );
        assert_eq!(
            h.stats.peer_connection.data_channels_opened, 1,
            "open stats recorded for the negotiated channel"
        );
    }

    /// `emit_data_channel_opened` returns an error when the channel does not exist.
    #[test]
    fn emit_data_channel_opened_missing_channel_returns_error() {
        let mut h = Harness::new();
        let now = Instant::now();

        let mut handler = h.handler(None);
        let err = handler
            .emit_data_channel_opened(
                now,
                TransportContext::default(),
                RTCDataChannelHandle::new(99),
            )
            .unwrap_err();
        assert_eq!(err, Error::ErrDataChannelNotExisted);
    }

    /// A second `SCTPHandshakeComplete` must not re-dial an already-dialed
    /// in-band channel: it stays Connecting after dialing, so the
    /// `data_channel.is_none()` guard is what excludes it.
    #[test]
    fn sctp_handshake_complete_does_not_redial() {
        let mut h = Harness::new();
        let now = Instant::now();
        h.add(1, 1);

        // Fire SCTPHandshakeComplete once; this dials the channel and queues its OPEN.
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        let first_writes = h.ctx.write_outs.len();
        assert!(
            first_writes >= 1,
            "dialing must queue the DATA_CHANNEL_OPEN"
        );
        h.ctx.write_outs.clear();

        // Fire it again: no new dial, so nothing new is queued.
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        assert_eq!(
            h.ctx.write_outs.len(),
            0,
            "a second SCTPHandshakeComplete must not re-dial the channel"
        );
    }

    /// A straggler `DATA_CHANNEL_ACK` on a channel that has already been closed
    /// must be ignored: it must not flip state or emit an open event.
    #[test]
    fn ack_on_closed_channel_is_ignored() {
        let mut h = Harness::new();
        let now = Instant::now();
        let mut dc = in_band_channel(1, 1);
        dc.ready_state = RTCDataChannelState::Closed;
        h.data_channels.insert(RTCDataChannelHandle::new(1), dc);
        h.ids.insert(1, RTCDataChannelHandle::new(1));

        let mut handler = h.handler(None);
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
            })
            .unwrap();

        assert_eq!(
            h.data_channels
                .get(&RTCDataChannelHandle::new(1))
                .unwrap()
                .ready_state,
            RTCDataChannelState::Closed,
            "a closed channel must ignore a late ACK"
        );
        assert!(
            !message_events(&h.ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event may fire for a closed channel"
        );
    }

    /// An in-band channel whose ACK never arrives must time out: it transitions
    /// to Closed, fires OnClose and is counted exactly once (closed without opened).
    #[test]
    fn in_band_channel_times_out_without_ack() {
        let mut h = Harness::new();
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        h.add(1, 1);

        // Dial the in-band channel and arm a deadline.
        {
            let mut handler = h.handler(Some(timeout));
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A deadline must be reported.
        {
            let mut handler = h.handler(Some(timeout));
            let deadline = handler
                .poll_timeout()
                .expect("a dialed in-band channel must have a deadline");
            assert!(deadline <= now + timeout);
        }

        // Advance past the deadline and let handle_timeout fire.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = h.handler(Some(timeout));
            handler.handle_timeout(later).unwrap();
        }

        let dc = h.data_channels.get(&RTCDataChannelHandle::new(1)).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Closed,
            "a timed-out channel must be Closed"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "timeout must clear the deadline"
        );
        assert!(
            !message_events(&h.ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event for a timed-out channel"
        );

        let closes = h
            .ctx
            .event_outs
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(1))
                    )
                )
            })
            .count();
        assert_eq!(closes, 1, "exactly one OnClose for the timed-out channel");

        assert_eq!(h.stats.peer_connection.data_channels_opened, 0);
        assert_eq!(h.stats.peer_connection.data_channels_closed, 1);

        // No further deadlines remain.
        {
            let mut handler = h.handler(Some(timeout));
            assert!(
                handler.poll_timeout().is_none(),
                "no deadline after the timeout fired"
            );
        }
    }

    /// A user message arriving before the ACK is buffered and delivered only
    /// after the channel opens, with the open event first.
    #[test]
    fn pre_open_data_is_buffered_until_open() {
        let mut h = Harness::new();
        let now = Instant::now();
        h.add(1, 1);

        // Dial first.
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A user data message arrives while the channel is still Connecting.
        {
            let mut handler = h.handler(None);
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"hello",
                    ))),
                })
                .unwrap();
        }

        // No message event yet.
        assert!(
            !message_events(&h.ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "no message may be delivered before the channel is open"
        );

        // The ACK arrives: the channel opens and the buffered message is delivered,
        // with the open event first.
        {
            let mut handler = h.handler(None);
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        let events = message_events(&h.ctx);
        assert!(
            matches!(events.first(), Some(DataChannelEvent::Open)),
            "open event must fire first"
        );
        assert!(
            matches!(events.get(1), Some(DataChannelEvent::Message(_))),
            "the buffered message must be delivered after the open event"
        );
    }

    /// A user message buffered before the ACK is discarded if the channel times
    /// out: it must never be delivered to the application.
    #[test]
    fn pre_open_data_is_dropped_on_timeout() {
        let mut h = Harness::new();
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        h.add(1, 1);

        {
            let mut handler = h.handler(Some(timeout));
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // Buffer a user message while Connecting.
        {
            let mut handler = h.handler(Some(timeout));
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"bye",
                    ))),
                })
                .unwrap();
        }

        // Time out; the channel closes and the buffered message must not be delivered.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = h.handler(Some(timeout));
            handler.handle_timeout(later).unwrap();
        }

        assert!(
            !message_events(&h.ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "a buffered message must never be delivered after the timeout"
        );
    }

    /// Pending (pre-connection) local channels are assigned ids in creation order at the
    /// connected procedure, using the resolved DTLS role's parity, and channels that cannot be
    /// assigned an id (the negotiated max channel count is exhausted) are closed.
    ///
    /// The stream cap is a count of streams, so `max = 4` admits ids `0..3`; server parity (odd)
    /// admits `1` and `3`, exercising the top usable id (`max - 1 = 3`).
    #[test]
    fn assign_pending_ids_respects_max_channels_and_closes_overflow() {
        let mut h = Harness::new();
        h.dtls_role = RTCDtlsRole::Server;
        h.max_channels = Some(4);

        // Three in-band channels created while the DTLS role was still Auto: no stream id yet.
        let first = RTCDataChannelHandle::new(1);
        let second = RTCDataChannelHandle::new(2);
        let third = RTCDataChannelHandle::new(3);
        for handle in [first, second, third] {
            h.data_channels.insert(
                handle,
                RTCDataChannelInternal::new(
                    handle,
                    DataChannelParameters {
                        label: "deferred".to_string(),
                        protocol: String::new(),
                        ordered: true,
                        max_packet_life_time: None,
                        max_retransmits: None,
                        negotiated: None,
                    },
                ),
            );
        }
        h.pending = vec![first, second, third];

        let now = Instant::now();
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // Server parity (odd) with a cap of 4 streams admits two ids: 1 and 3. The first two
        // pending channels get them; the third has no id left and is closed and removed.
        assert_eq!(
            h.data_channels.get(&first).unwrap().stream_id,
            Some(1),
            "the first pending channel gets the server-parity id 1"
        );
        assert_eq!(
            h.data_channels.get(&second).unwrap().stream_id,
            Some(3),
            "the second pending channel gets the top server-parity id 3 (max - 1)"
        );
        assert!(
            h.data_channels.get(&third).is_none(),
            "the third pending channel is closed when the id space is exhausted"
        );
        assert!(h.pending.is_empty(), "pending handles are consumed");
        assert_eq!(
            h.ids.get(&1),
            Some(&first),
            "the first assigned id is registered in the reverse map"
        );
        assert_eq!(
            h.ids.get(&3),
            Some(&second),
            "the top assigned id is registered in the reverse map"
        );
    }

    /// Two pending channels must never be handed the same stream id, even when both share the
    /// role's parity: the first reserves its id and the second takes the next free one.
    #[test]
    fn assign_pending_ids_assigns_distinct_ids_across_a_batch() {
        let mut h = Harness::new();
        h.dtls_role = RTCDtlsRole::Client;
        h.max_channels = Some(8);

        let first = RTCDataChannelHandle::new(1);
        let second = RTCDataChannelHandle::new(2);
        for handle in [first, second] {
            h.data_channels.insert(
                handle,
                RTCDataChannelInternal::new(
                    handle,
                    DataChannelParameters {
                        label: "deferred".to_string(),
                        protocol: String::new(),
                        ordered: true,
                        max_packet_life_time: None,
                        max_retransmits: None,
                        negotiated: None,
                    },
                ),
            );
        }
        h.pending = vec![first, second];

        let now = Instant::now();
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        let first_id = h.data_channels.get(&first).unwrap().stream_id;
        let second_id = h.data_channels.get(&second).unwrap().stream_id;
        assert_eq!(first_id, Some(0), "client parity starts at even id 0");
        assert_eq!(
            second_id,
            Some(2),
            "the second pending channel gets the next even id"
        );
        assert_ne!(
            first_id, second_id,
            "two pending channels must not share a stream id"
        );
    }

    /// Closed pending channels do not consume a stream id.
    #[test]
    fn closed_pending_channel_skipped_by_assign_pending_ids() {
        let mut h = Harness::new();
        h.dtls_role = RTCDtlsRole::Client;
        let closed = RTCDataChannelHandle::new(1);
        let live = RTCDataChannelHandle::new(2);
        for handle in [closed, live] {
            h.data_channels.insert(
                handle,
                RTCDataChannelInternal::new(
                    handle,
                    DataChannelParameters {
                        label: "deferred".to_string(),
                        protocol: String::new(),
                        ordered: true,
                        max_packet_life_time: None,
                        max_retransmits: None,
                        negotiated: None,
                    },
                ),
            );
        }
        // Close the first channel before SCTPHandshakeComplete.
        h.data_channels.get_mut(&closed).unwrap().close().unwrap();
        assert_eq!(
            h.data_channels.get(&closed).unwrap().ready_state,
            RTCDataChannelState::Closed
        );
        h.pending = vec![closed, live];

        let now = Instant::now();
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        assert!(h.pending.is_empty());
        assert_eq!(h.data_channels.get(&closed).unwrap().stream_id, None);
        assert_eq!(h.data_channels.get(&live).unwrap().stream_id, Some(0));
        assert!(!h.ids.values().any(|handle| *handle == closed));
        assert_eq!(h.ids.get(&0), Some(&live));
    }

    /// An id-exhausted pending channel is closed and the application receives OnError then OnClose.
    #[test]
    fn assign_pending_ids_overflow_fires_error_and_close() {
        let mut h = Harness::new();
        h.dtls_role = RTCDtlsRole::Client;
        // A cap of 2 streams admits one client-parity id (0); the second channel overflows.
        h.max_channels = Some(2);

        let first = RTCDataChannelHandle::new(1);
        let second = RTCDataChannelHandle::new(2);
        for handle in [first, second] {
            h.data_channels.insert(
                handle,
                RTCDataChannelInternal::new(
                    handle,
                    DataChannelParameters {
                        label: "overflow".to_string(),
                        protocol: String::new(),
                        ordered: true,
                        max_packet_life_time: None,
                        max_retransmits: None,
                        negotiated: None,
                    },
                ),
            );
        }
        h.pending = vec![first, second];

        let now = Instant::now();
        {
            let mut handler = h.handler(None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        assert_eq!(h.data_channels.get(&first).unwrap().stream_id, Some(0));
        assert!(h.data_channels.get(&second).is_none());

        let errors = h
            .ctx
            .event_outs
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(
                            RTCDataChannelEvent::OnErrorByHandle(_)
                        )
                    )
                )
            })
            .count();
        let closes = h
            .ctx
            .event_outs
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(
                            RTCDataChannelEvent::OnCloseByHandle(_)
                        )
                    )
                )
            })
            .count();
        assert_eq!(errors, 1);
        assert_eq!(closes, 1);

        // OnErrorByHandle must precede OnCloseByHandle (section 6.2.7).
        let events: Vec<_> = h
            .ctx
            .event_outs
            .iter()
            .filter_map(|e| match &e.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnDataChannel(dc_event),
                ) => Some(dc_event.clone()),
                _ => None,
            })
            .collect();
        assert!(
            matches!(
                events.first(),
                Some(RTCDataChannelEvent::OnErrorByHandle(_))
            ),
            "OnErrorByHandle must precede OnCloseByHandle"
        );
    }
}
