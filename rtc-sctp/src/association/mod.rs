use crate::association::{
    state::{AckMode, AckState, AssociationState},
    stats::AssociationStats,
};
use crate::chunk::chunk_header::CHUNK_HEADER_SIZE;
use crate::chunk::{
    Chunk, ErrorCauseUnrecognizedChunkType, USER_INITIATED_ABORT,
    chunk_abort::ChunkAbort,
    chunk_cookie_ack::ChunkCookieAck,
    chunk_cookie_echo::ChunkCookieEcho,
    chunk_error::ChunkError,
    chunk_forward_tsn::ChunkForwardTsn,
    chunk_forward_tsn::ChunkForwardTsnStream,
    chunk_heartbeat::ChunkHeartbeat,
    chunk_heartbeat_ack::ChunkHeartbeatAck,
    chunk_init::ChunkInit,
    chunk_init::ChunkInitAck,
    chunk_payload_data::ChunkPayloadData,
    chunk_payload_data::PayloadProtocolIdentifier,
    chunk_payload_data::{MessageId, MessageReliability},
    chunk_reconfig::ChunkReconfig,
    chunk_selective_ack::ChunkSelectiveAck,
    chunk_shutdown::ChunkShutdown,
    chunk_shutdown_ack::ChunkShutdownAck,
    chunk_shutdown_complete::ChunkShutdownComplete,
    chunk_type::{CT_FORWARD_TSN, CT_RECONFIG},
};
use crate::config::{COMMON_HEADER_SIZE, DATA_CHUNK_HEADER_SIZE, ServerConfig, TransportConfig};
use crate::packet::{CommonHeader, Packet};
use crate::param::{
    Param,
    param_forward_tsn_supported::ParamForwardTsnSupported,
    param_heartbeat_info::ParamHeartbeatInfo,
    param_outgoing_reset_request::ParamOutgoingResetRequest,
    param_reconfig_response::{ParamReconfigResponse, ReconfigResult},
    param_state_cookie::ParamStateCookie,
    param_supported_extensions::ParamSupportedExtensions,
};
use crate::queue::{
    payload_queue::PayloadQueue,
    pending_queue::{PendingQueue, ResetMarker},
    receive_queue::{DeferredReceive, ReceiveQueue},
};
use crate::shared::{AssociationEventInner, AssociationId, EndpointEvent, EndpointEventInner};
use crate::util::{constant_time_eq, sna16lt, sna32gt, sna32gte, sna32lt, sna32lte};
use crate::{AssociationEvent, Payload, Side};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use stream::{Stream, StreamEvent, StreamId, StreamState};
use timer::{ACK_INTERVAL, RtoManager, Timer, TimerTable};

use crate::association::stream::RecvSendState;
use bytes::{Bytes, BytesMut};
use log::{debug, error, trace, warn};
use rand::random;
use rustc_hash::FxHashMap;
use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

mod reset;
mod reset_receive;
use reset_receive::{IncomingResetQueue, ReceiveResetAction};
pub(crate) mod state;
pub(crate) mod stats;
pub(crate) mod stream;
pub(crate) mod timer;
mod transmit;
use reset::OutgoingReset;

#[cfg(test)]
mod association_test;
#[cfg(test)]
mod model_test;

/// Reasons why an association might be lost
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum AssociationError {
    /// Handshake failed
    #[error("handshake failed due to {0}")]
    HandshakeFailed(String),
    /// The peer violated the QUIC specification as understood by this implementation
    #[error("transport error")]
    TransportError,
    /// The peer's QUIC stack aborted the association automatically
    #[error("aborted by peer")]
    AssociationClosed,
    /// The peer closed the association
    #[error("closed by peer")]
    ApplicationClosed,
    /// The peer is unable to continue processing this association, usually due to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated idle timeout
    ///
    /// If neither side is sending keep-alives, an association will time out after a long enough idle
    /// period even if the peer is still reachable
    #[error("timed out")]
    TimedOut,
    /// The local application closed the association
    #[error("closed")]
    LocallyClosed,
}

/// Events of interest to the application
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// Handshake was failed
    HandshakeFailed {
        /// Reason that the association was closed
        reason: AssociationError,
    },

    /// The association was successfully established
    Connected,
    /// The association was lost
    ///
    /// Emitted if the peer closes the association or an error is encountered.
    AssociationLost {
        /// Reason that the association was closed
        reason: AssociationError,
        /// The stream the loss was reported against.
        id: StreamId,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
}

/// Effects of one validated SACK, keeping buffer release, delivery credit and
/// advisory acknowledgments distinct.
struct SackProgress {
    bytes_acked_per_stream: FxHashMap<u16, i64>,
    total_bytes_acked: i64,
    htna: u32,
    // Serial TSN order, so recovery can merge these with its normal prefix.
    revoked: Vec<u32>,
}

/// Selection is stable even after fragments leave either queue.
#[derive(Debug, Copy, Clone)]
struct MessageToAbandon {
    id: MessageId,
    // A whole message is already identified by its candidate TSN. Fragmented
    // messages still use the group index, including when selected in pending.
    sent_tsn: Option<u32>,
}

///Association represents an SCTP association
//13.2.  Parameters Necessary per Association (i.e., the TCB)
//Peer : Tag value to be sent in every packet and is received
//Verification: in the INIT or INIT ACK chunk.
//Tag :
//
//My : Tag expected in every inbound packet and sent in the
//Verification: INIT or INIT ACK chunk.
//
//Tag :
//State : A state variable indicating what state the association
// : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
// : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
// : SHUTDOWN-ACK-SENT.
//
// No Closed state is illustrated since if a
// association is Closed its TCB SHOULD be removed.
pub struct Association {
    side: Side,
    state: AssociationState,
    handshake_completed: bool,
    max_message_size: u32,
    inflight_queue_length: usize,
    will_send_shutdown: bool,
    bytes_received: usize,
    bytes_sent: usize,

    pub(crate) peer_verification_tag: u32,
    my_verification_tag: u32,
    pub(crate) my_next_tsn: u32,
    peer_last_tsn: u32,
    // for RTT measurement
    min_tsn2measure_rtt: u32,
    will_send_forward_tsn: bool,
    will_retransmit_fast: bool,
    will_retransmit_reconfig: bool,
    /// True only while the in-flight queue may still hold chunks flagged for
    /// T3-rtx retransmission (set when the timer marks them, cleared once the
    /// scan has re-sent them all). Lets `gather_outbound` skip the O(in-flight)
    /// retransmit scan entirely in the steady state, where nothing is ever
    /// marked — that scan was the single hottest function in the send profile.
    t3_retransmit_pending: bool,

    will_send_shutdown_ack: bool,
    will_send_shutdown_complete: bool,

    // Reconfig
    my_next_rsn: u32,
    next_stream_generation: u64,
    next_message_id: u64,
    transmit_streams: FxHashMap<StreamId, transmit::TransmitStream>,
    pub(crate) receive_streams: FxHashMap<StreamId, ReceiveQueue>,
    receive_buffered_bytes: usize,
    pending_receivers: BTreeSet<StreamId>,
    peer_supports_reconfig: bool,
    outgoing_reset: Option<OutgoingReset>,
    incoming_resets: IncomingResetQueue,
    // Non-RFC internal data
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,

    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    my_max_num_inbound_streams: u16,
    my_max_num_outbound_streams: u16,
    my_cookie: Option<ParamStateCookie>,

    pub(crate) payload_queue: PayloadQueue,
    inflight_queue: PayloadQueue,
    /// Absolute, inclusive ranges from the last validated SACK. Comparing
    /// ranges detects reneging without visiting every outstanding DATA chunk.
    peer_gap_ack_ranges: Vec<(u32, u32)>,
    pending_queue: PendingQueue,
    control_queue: VecDeque<Packet>,
    stream_queue: VecDeque<u16>,

    pub(crate) mtu: u32,
    // max DATA chunk payload size
    max_payload_size: u32,
    cumulative_tsn_ack_point: u32,
    advanced_peer_tsn_ack_point: u32,
    use_forward_tsn: bool,
    /// Max stream-sequence-number per *ordered* stream among abandoned chunks
    /// currently in the forward-TSN window `(cumulative_tsn_ack_point,
    /// advanced_peer_tsn_ack_point]`. Maintained incrementally as chunks are
    /// abandoned (the RFC 3758 C2 walk) so that `create_forward_tsn` is
    /// O(streams) instead of rescanning the whole in-flight window — which, for
    /// PR-SCTP data channels, ran ~1000 hashmap probes per FORWARD-TSN and was
    /// ~9% of send CPU in profiles. Unordered chunks are omitted: the receiver
    /// ignores the per-stream list for them (it advances by `new_cumulative_tsn`
    /// alone), so reporting them was pure waste.
    fwd_tsn_stream_map: FxHashMap<u16, u16>,
    /// Successful outgoing resets retire SSNs through their last assigned TSN.
    /// Keep these bounds only while old DATA can remain locally in flight.
    confirmed_reset_tsns: FxHashMap<u16, u32>,
    /// Successful reset bounds in TSN order, even if results arrived out of order.
    reset_tsn_ack_queue: VecDeque<(u32, Vec<u16>)>,

    pub(crate) rto_mgr: RtoManager,
    timers: TimerTable,

    // Congestion control parameters
    max_receive_buffer_size: u32,
    // my congestion window size
    pub(crate) cwnd: u32,
    // calculated peer's receiver windows size
    rwnd: u32,
    zero_window_probe: Option<u32>,
    // slow start threshold
    pub(crate) ssthresh: u32,
    partial_bytes_acked: u32,
    pub(crate) in_fast_recovery: bool,
    fast_recover_exit_point: u32,

    // Chunks stored for retransmission
    stored_init: Option<ChunkInit>,
    stored_cookie_echo: Option<ChunkCookieEcho>,
    /// Per-chunk lookups on the receive path; SIDs are bounded by the
    /// negotiated stream count, so the faster non-SipHash hasher is safe.
    pub(crate) streams: FxHashMap<StreamId, StreamState>,

    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    error: Option<AssociationError>,

    // per inbound packet context
    delayed_ack_triggered: bool,
    immediate_ack_triggered: bool,

    pub(crate) stats: AssociationStats,
    ack_state: AckState,

    // for testing
    pub(crate) ack_mode: AckMode,
}

impl Default for Association {
    fn default() -> Self {
        Association {
            side: Side::default(),
            state: AssociationState::default(),
            handshake_completed: false,
            max_message_size: 0,
            inflight_queue_length: 0,
            will_send_shutdown: false,
            bytes_received: 0,
            bytes_sent: 0,

            peer_verification_tag: 0,
            my_verification_tag: 0,
            my_next_tsn: 0,
            peer_last_tsn: 0,
            // for RTT measurement
            min_tsn2measure_rtt: 0,
            will_send_forward_tsn: false,
            will_retransmit_fast: false,
            will_retransmit_reconfig: false,
            t3_retransmit_pending: false,

            will_send_shutdown_ack: false,
            will_send_shutdown_complete: false,

            // Reconfig
            my_next_rsn: 0,
            next_stream_generation: 0,
            next_message_id: 0,
            transmit_streams: FxHashMap::default(),
            receive_streams: FxHashMap::default(),
            receive_buffered_bytes: 0,
            pending_receivers: BTreeSet::new(),
            peer_supports_reconfig: false,
            outgoing_reset: None,
            incoming_resets: IncomingResetQueue::new(0),

            // Non-RFC internal data
            remote_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            local_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            transport_protocol: TransportProtocol::UDP,

            source_port: 0,
            destination_port: 0,
            my_max_num_inbound_streams: 0,
            my_max_num_outbound_streams: 0,
            my_cookie: None,

            payload_queue: PayloadQueue::default(),
            inflight_queue: PayloadQueue::default(),
            peer_gap_ack_ranges: Vec::new(),
            pending_queue: PendingQueue::default(),
            control_queue: VecDeque::default(),
            stream_queue: VecDeque::default(),

            mtu: 0,
            // max DATA chunk payload size
            max_payload_size: 0,
            cumulative_tsn_ack_point: 0,
            advanced_peer_tsn_ack_point: 0,
            use_forward_tsn: false,
            fwd_tsn_stream_map: FxHashMap::default(),
            confirmed_reset_tsns: FxHashMap::default(),
            reset_tsn_ack_queue: VecDeque::default(),

            rto_mgr: RtoManager::default(),
            timers: TimerTable::default(),

            // Congestion control parameters
            max_receive_buffer_size: 0,
            // my congestion window size
            cwnd: 0,
            // calculated peer's receiver windows size
            rwnd: 0,
            zero_window_probe: None,
            // slow start threshold
            ssthresh: 0,
            partial_bytes_acked: 0,
            in_fast_recovery: false,
            fast_recover_exit_point: 0,

            // Chunks stored for retransmission
            stored_init: None,
            stored_cookie_echo: None,
            streams: FxHashMap::default(),

            events: VecDeque::default(),
            endpoint_events: VecDeque::default(),
            error: None,

            // per inbound packet context
            delayed_ack_triggered: false,
            immediate_ack_triggered: false,

            stats: AssociationStats::default(),
            ack_state: AckState::default(),

            // for testing
            ack_mode: AckMode::default(),
        }
    }
}

impl Association {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_config: Option<Arc<ServerConfig>>,
        config: Arc<TransportConfig>,
        max_payload_size: u32,
        local_aid: AssociationId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        protocol: TransportProtocol,
        now: Instant,
    ) -> Self {
        let side = if server_config.is_some() {
            Side::Server
        } else {
            Side::Client
        };

        // It's a bit strange, but we're going backwards from the calculation in
        // config.rs to get max_payload_size from INITIAL_MTU.
        let mtu = max_payload_size.saturating_add(COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);

        // RFC 4960 Sec 7.2.1
        // The initial cwnd before DATA transmission or after a sufficiently
        // long idle period MUST be set to min(4*MTU, max (2*MTU, 4380bytes)).
        // Written in total form: the previous `(2 * mtu).clamp(4380, 4 * mtu)`
        // panicked for effective MTUs below ~1095 (`Ord::clamp` with
        // min > max) and overflowed near `u32::MAX`, both reachable through
        // `EndpointConfig::max_payload_size` and MTU-derived payload budgets.
        let cwnd = mtu.saturating_mul(2).max(4380).min(mtu.saturating_mul(4));
        // RFC 4960 requires an unpredictable initial TSN. SCTP remains usable without an RTC
        // crypto provider, so this deliberately uses `rand`'s thread-local CSPRNG.
        let mut tsn = random::<u32>();
        if tsn == 0 {
            tsn += 1;
        }

        let mut this = Association {
            side,
            handshake_completed: false,
            max_receive_buffer_size: config.max_receive_buffer_size(),
            max_message_size: config.max_message_size(),
            my_max_num_outbound_streams: config.max_num_outbound_streams(),
            my_max_num_inbound_streams: config.max_num_inbound_streams(),
            max_payload_size,

            rto_mgr: RtoManager::new(),
            timers: TimerTable::new(config.timer_config()),

            mtu,
            cwnd,
            remote_addr,
            local_addr,
            transport_protocol: protocol,

            my_verification_tag: local_aid,
            my_next_tsn: tsn,
            my_next_rsn: tsn,
            min_tsn2measure_rtt: tsn,
            cumulative_tsn_ack_point: tsn - 1,
            advanced_peer_tsn_ack_point: tsn - 1,
            error: None,

            ..Default::default()
        };

        if side.is_client() {
            let mut init = ChunkInit {
                initial_tsn: this.my_next_tsn,
                num_outbound_streams: this.my_max_num_outbound_streams,
                num_inbound_streams: this.my_max_num_inbound_streams,
                initiate_tag: this.my_verification_tag,
                advertised_receiver_window_credit: this.max_receive_buffer_size,
                ..Default::default()
            };
            init.set_supported_extensions();

            this.set_state(AssociationState::CookieWait);
            this.stored_init = Some(init);
            let _ = this.send_init();
            this.timers
                .start(Timer::T1Init, now, this.rto_mgr.get_rto());
        }

        this
    }

    /// Returns application-facing event
    ///
    /// Associations should be polled for events after:
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    /// - a call was made to `poll_transmit`, which can abandon expired messages
    #[must_use]
    pub fn poll(&mut self) -> Option<Event> {
        self.publish_ready_streams();
        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        /*TODO: if let Some(event) = self.streams.poll() {
            return Some(Event::Stream(event));
        }*/

        if let Some(err) = self.error.take() {
            return Some(Event::HandshakeFailed { reason: err });
        }

        None
    }

    /// Return endpoint-facing event
    #[must_use]
    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the association
    /// - a call was made to `handle_transmit`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.timers
            .next_timeout()
            .into_iter()
            .chain(self.next_reconfig_result_retry().map(|(_, at)| at))
            .min()
    }

    /// Returns packets to transmit
    ///
    /// Associations should be polled for transmit after:
    /// - the application performed some I/O on the Association
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<TransportMessage<Payload>> {
        let (contents, _) = self.gather_outbound(now);
        if contents.is_empty() {
            None
        } else {
            trace!(
                "[{}] sending {} bytes (total {} datagrams)",
                self.side,
                contents.iter().fold(0, |l, c| l + c.len()),
                contents.len()
            );
            Some(TransportMessage {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: self.remote_addr,
                    ecn: None,
                    transport_protocol: Default::default(),
                },
                message: Payload::RawEncode(contents),
            })
        }
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    ///
    /// It is most efficient to call this immediately after the system clock reaches the latest
    /// `Instant` that was output by `poll_timeout`; however spurious extra calls will simply
    /// no-op and therefore are safe.
    pub fn handle_timeout(&mut self, now: Instant) {
        for &timer in &Timer::VALUES {
            let (expired, failure, n_rtos) = self.timers.is_expired(timer, now);
            if !expired {
                continue;
            }
            self.timers.set(timer, None);
            //trace!("{:?} timeout", timer);

            if timer == Timer::Ack {
                self.on_ack_timeout();
            } else if failure {
                self.on_retransmission_failure(timer);
            } else {
                self.on_retransmission_timeout(timer, n_rtos, now);
                self.timers.start(timer, now, self.rto_mgr.get_rto());
            }
        }
    }

    /// Process `AssociationEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of an association event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: AssociationEvent) {
        match event.0 {
            AssociationEventInner::Datagram(transmit) => {
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                /*TODO:if remote != self.remote && self.server_config.as_ref().map_or(true, |x| !x.migration)
                {
                    trace!("discarding packet from unrecognized peer {}", remote);
                    return;
                }*/

                if let Payload::PartialDecode(partial_decode) = transmit.message {
                    debug!(
                        "[{}] recving {} bytes",
                        self.side,
                        COMMON_HEADER_SIZE as usize + partial_decode.remaining.len()
                    );

                    let pkt = match partial_decode.finish() {
                        Ok(p) => p,
                        Err(err) => {
                            warn!("[{}] unable to parse SCTP packet {}", self.side, err);
                            return;
                        }
                    };

                    if let Err(err) = self.handle_inbound(pkt, transmit.now) {
                        error!("handle_inbound got err: {}", err);
                        let _ = self.close(AssociationError::TransportError);
                    }
                } else {
                    trace!("discarding invalid partial_decode");
                }
            } //TODO:
        }
    }

    /// Returns Association statistics
    pub fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Whether the Association is in the process of being established
    ///
    /// If this returns `false`, the Association may be either established or closed, signaled by the
    /// emission of a `Connected` or `AssociationLost` message respectively.
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_completed
    }

    /// The number of streams negotiated for this association: the smaller of the inbound and
    /// outbound counts the two endpoints agreed on in INIT/INIT ACK.
    ///
    /// `None` while the association is still handshaking. Before the peer's INIT (or INIT ACK) has
    /// been processed, the two counts still hold this endpoint's *configured* limits rather than
    /// anything agreed, so reporting them would overstate what the association can carry.
    ///
    /// This is what [RFC 8831] data channels are limited by, and what W3C
    /// `RTCSctpTransport.maxChannels` reports.
    ///
    /// [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
    pub fn negotiated_max_streams(&self) -> Option<u16> {
        if self.is_handshaking() {
            None
        } else {
            Some(
                self.my_max_num_inbound_streams
                    .min(self.my_max_num_outbound_streams),
            )
        }
    }

    /// Whether the Association is closed
    ///
    /// Closed Associations cannot transport any further data. An association becomes closed when
    /// either peer application intentionally closes it, or when either transport layer detects an
    /// error such as a time-out or certificate validation failure.
    ///
    /// A `AssociationLost` event is emitted with details when the association becomes closed.
    pub fn is_closed(&self) -> bool {
        self.state == AssociationState::Closed
    }

    /// Whether there is no longer any need to keep the association around
    ///
    /// Closed associations become drained after a brief timeout to absorb any remaining in-flight
    /// packets from the peer. All drained associations have been closed.
    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// Look up whether we're the client or server of this Association
    pub fn side(&self) -> Side {
        self.side
    }

    /// The latest socket address for this Association's peer
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Current best estimate of this Association's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        Duration::from_millis(self.rto_mgr.get_rto())
    }

    /// The local IP address which was used when the peer established
    /// the association
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown initiates the shutdown sequence. The method blocks until the
    /// shutdown sequence is completed and the association is closed, or until the
    /// passed context is done, in which case the context's error is returned.
    pub fn shutdown(&mut self) -> Result<()> {
        debug!("[{}] closing association..", self.side);

        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrShutdownNonEstablished);
        }

        // Attempt a graceful shutdown.
        self.set_state(AssociationState::ShutdownPending);

        if self.inflight_queue_length == 0 {
            // No more outstanding, send shutdown.
            self.will_send_shutdown = true;
            self.awake_write_loop();
            self.set_state(AssociationState::ShutdownSent);
        }

        self.endpoint_events.push_back(EndpointEventInner::Drained);

        Ok(())
    }

    /// Close ends the SCTP Association and cleans up any state
    pub fn close(&mut self, reason: AssociationError) -> Result<()> {
        if self.state() != AssociationState::Closed {
            self.set_state(AssociationState::Closed);

            debug!("[{}] closing association..", self.side);

            self.close_all_timers();
            self.outgoing_reset = None;

            for si in self.streams.keys().cloned().collect::<Vec<u16>>() {
                self.unregister_stream(si, reason.clone());
            }

            self.receive_streams.clear();
            self.receive_buffered_bytes = 0;
            self.pending_receivers.clear();
            self.transmit_streams.clear();
            self.pending_queue = PendingQueue::new();
            self.inflight_queue = PayloadQueue::default();
            self.payload_queue = PayloadQueue::default();
            self.incoming_resets = IncomingResetQueue::new(0);
            self.fwd_tsn_stream_map.clear();
            self.confirmed_reset_tsns.clear();
            self.reset_tsn_ack_queue.clear();
            self.control_queue.clear();
            debug!("[{}] association closed", self.side);
            debug!(
                "[{}] stats nDATAs (in) : {}",
                self.side,
                self.stats.get_num_datas()
            );
            debug!(
                "[{}] stats nSACKs (in) : {}",
                self.side,
                self.stats.get_num_sacks()
            );
            debug!(
                "[{}] stats nT3Timeouts : {}",
                self.side,
                self.stats.get_num_t3timeouts()
            );
            debug!(
                "[{}] stats nAckTimeouts: {}",
                self.side,
                self.stats.get_num_ack_timeouts()
            );
            debug!(
                "[{}] stats nFastRetrans: {}",
                self.side,
                self.stats.get_num_fast_retrans()
            );
        }

        Ok(())
    }

    /// open_stream opens a stream
    pub fn open_stream(
        &mut self,
        stream_identifier: StreamId,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<Stream<'_>> {
        self.publish_ready_streams();
        if self.streams.contains_key(&stream_identifier) {
            return Err(Error::ErrStreamAlreadyExist);
        }

        if let Some(s) = self.create_stream(stream_identifier, false, default_payload_type) {
            Ok(s)
        } else {
            Err(Error::ErrStreamCreateFailed)
        }
    }

    /// accept_stream accepts a stream
    pub fn accept_stream(&mut self) -> Option<Stream<'_>> {
        self.publish_ready_streams();
        self.stream_queue
            .pop_front()
            .map(move |stream_identifier| Stream {
                stream_identifier,
                association: self,
            })
    }

    /// stream returns a stream
    pub fn stream(&mut self, stream_identifier: StreamId) -> Result<Stream<'_>> {
        self.publish_ready_streams();
        if !self.streams.contains_key(&stream_identifier) {
            Err(Error::ErrStreamNotExisted)
        } else {
            Ok(Stream {
                stream_identifier,
                association: self,
            })
        }
    }

    /// The identifiers of every stream currently open on this association.
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.keys().cloned().collect()
    }

    /// bytes_sent returns the number of bytes sent
    pub(crate) fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// bytes_received returns the number of bytes received
    pub(crate) fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// max_message_size returns the maximum message size you can send.
    pub(crate) fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    /// set_max_message_size sets the maximum message size you can send.
    pub(crate) fn set_max_message_size(&mut self, max_message_size: u32) {
        self.max_message_size = max_message_size;
    }

    /// unregister_stream un-registers a stream from the association
    /// The caller should hold the association write lock.
    fn unregister_stream(&mut self, stream_identifier: StreamId, reason: AssociationError) {
        if self.streams.remove(&stream_identifier).is_some() {
            debug!("[{}] unregister_stream {}", self.side, stream_identifier);
            self.events.push_back(Event::AssociationLost {
                reason,
                id: stream_identifier,
            });
            self.stream_queue.retain(|id| *id != stream_identifier);
        }
    }

    /// Retire the API receiver only after its saved messages have been read.
    pub(crate) fn finish_stream_delivery(&mut self, id: StreamId) {
        let Some(received) = self.receive_streams.get_mut(&id) else {
            return;
        };
        if !received.finish_delivery() {
            return;
        }
        if received.is_readable() {
            self.pending_receivers.insert(id);
        }
        self.unregister_stream(id, AssociationError::Reset);
    }

    /// Account every payload mutation at the RX ownership boundary. Complete
    /// delivery, incomplete reassembly and deferred future DATA share rwnd.
    /// Lifecycle-only changes do not change this charge.
    pub(crate) fn with_receive_queue<R>(
        &mut self,
        id: StreamId,
        update: impl FnOnce(&mut ReceiveQueue) -> R,
    ) -> R {
        let received = self
            .receive_streams
            .entry(id)
            .or_insert_with(|| ReceiveQueue::new(id));
        let before = received.get_num_bytes();
        let result = update(received);
        self.receive_buffered_bytes =
            self.receive_buffered_bytes - before + received.get_num_bytes();
        result
    }

    fn publish_ready_streams(&mut self) {
        // Only retiring a saved delivery can expose another receiver without
        // incoming DATA creating it. Avoid scanning every retained SID for
        // every event; old close events remain ahead of the new publication.
        while let Some(id) = self.pending_receivers.pop_first() {
            if !self.streams.contains_key(&id)
                && self
                    .receive_streams
                    .get(&id)
                    .is_some_and(ReceiveQueue::is_readable)
            {
                self.create_stream(id, true, PayloadProtocolIdentifier::default());
                self.events
                    .push_back(Event::Stream(StreamEvent::Readable { id }));
            }
        }
    }

    /// set_state atomically sets the state of the Association.
    fn set_state(&mut self, new_state: AssociationState) {
        if new_state != self.state {
            debug!(
                "[{}] state change: '{}' => '{}'",
                self.side, self.state, new_state,
            );
        }
        self.state = new_state;
    }

    /// state atomically returns the state of the Association.
    pub(crate) fn state(&self) -> AssociationState {
        self.state
    }

    /// caller must hold self.lock
    fn send_init(&mut self) -> Result<()> {
        if let Some(stored_init) = &self.stored_init {
            debug!("[{}] sending INIT", self.side);

            self.source_port = 5000; // Spec??
            self.destination_port = 5000; // Spec??

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_init.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrInitNotStoredToSend)
        }
    }

    /// caller must hold self.lock
    fn send_cookie_echo(&mut self) -> Result<()> {
        if let Some(stored_cookie_echo) = &self.stored_cookie_echo {
            debug!("[{}] sending COOKIE-ECHO", self.side);

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_cookie_echo.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrCookieEchoNotStoredToSend)
        }
    }

    /// handle_inbound parses incoming raw packets
    fn handle_inbound(&mut self, p: Packet, now: Instant) -> Result<()> {
        if let Err(err) = p.check_packet() {
            warn!("[{}] failed validating packet {}", self.side, err);
            return Ok(());
        }

        self.handle_chunk_start();

        for c in &p.chunks {
            self.handle_chunk(&p, c, now)?;
        }

        self.handle_chunk_end(now);

        Ok(())
    }

    fn handle_chunk_start(&mut self) {
        self.delayed_ack_triggered = false;
        self.immediate_ack_triggered = false;
    }

    fn handle_chunk_end(&mut self, now: Instant) {
        if self.immediate_ack_triggered {
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
        } else if self.delayed_ack_triggered {
            // Will send delayed ack in the next ack timeout
            self.ack_state = AckState::Delay;
            self.timers.start(Timer::Ack, now, ACK_INTERVAL);
        }
    }

    #[allow(clippy::borrowed_box)]
    fn handle_chunk(&mut self, p: &Packet, chunk: &Box<dyn Chunk>, now: Instant) -> Result<()> {
        chunk.check()?;
        let chunk_any = chunk.as_any();
        let packets = if let Some(c) = chunk_any.downcast_ref::<ChunkInit>() {
            if c.is_ack {
                self.handle_init_ack(p, c, now)?
            } else {
                self.handle_init(p, c)?
            }
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkAbort>() {
            let mut err_str = String::new();
            for e in &c.error_causes {
                if matches!(e.code, USER_INITIATED_ABORT) {
                    debug!("User initiated abort received");
                    let _ = self.close(AssociationError::Reset);
                    return Ok(());
                }
                err_str += &format!("({})", e);
            }
            return Err(Error::ErrAbortChunk(err_str));
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkError>() {
            let mut err_str = String::new();
            for e in &c.error_causes {
                err_str += &format!("({})", e);
            }
            return Err(Error::ErrAbortChunk(err_str));
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkHeartbeat>() {
            self.handle_heartbeat(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkCookieEcho>() {
            self.handle_cookie_echo(c)?
        } else if chunk_any.downcast_ref::<ChunkCookieAck>().is_some() {
            self.handle_cookie_ack()?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkPayloadData>() {
            self.handle_data(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkSelectiveAck>() {
            self.handle_sack(c, now)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkReconfig>() {
            self.handle_reconfig(now, c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkForwardTsn>() {
            self.handle_forward_tsn(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdown>() {
            self.handle_shutdown(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownAck>() {
            self.handle_shutdown_ack(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownComplete>() {
            self.handle_shutdown_complete(c)?
        } else {
            return Err(Error::ErrChunkTypeUnhandled);
        };

        if !packets.is_empty() {
            let mut buf: VecDeque<_> = packets.into_iter().collect();
            self.control_queue.append(&mut buf);
            self.awake_write_loop();
        }

        Ok(())
    }

    fn handle_init(&mut self, p: &Packet, i: &ChunkInit) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInit received in state '{}'", self.side, state);

        // https://tools.ietf.org/html/rfc4960#section-5.2.1
        // Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
        // respond with an INIT ACK using the same parameters it sent in its
        // original INIT chunk (including its Initiate Tag, unchanged).  When
        // responding, the endpoint MUST send the INIT ACK back to the same
        // address that the original INIT (sent by this endpoint) was sent.

        if state != AssociationState::Closed
            && state != AssociationState::CookieWait
            && state != AssociationState::CookieEchoed
        {
            // 5.2.2.  Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
            //        COOKIE-WAIT, and SHUTDOWN-ACK-SENT
            return Err(Error::ErrHandleInitState);
        }

        // Should we be setting any of these permanently until we've ACKed further?
        self.my_max_num_inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.my_max_num_inbound_streams);
        self.my_max_num_outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.my_max_num_outbound_streams);
        self.peer_verification_tag = i.initiate_tag;
        self.source_port = p.common_header.destination_port;
        self.destination_port = p.common_header.source_port;

        // 13.2 This is the last TSN received in sequence.  This value
        // is set initially by taking the peer's initial TSN,
        // received in the INIT or INIT ACK chunk, and
        // subtracting one from it.
        self.incoming_resets = IncomingResetQueue::new(i.initial_tsn);
        self.peer_last_tsn = if i.initial_tsn == 0 {
            u32::MAX
        } else {
            i.initial_tsn - 1
        };

        // Adopt the peer's advertised receive window and seed ssthresh from it,
        // mirroring handle_init_ack (and Pion's shared init path). RFC 4960
        // §7.2.1 (Slow-Start) permits initialising ssthresh to the advertised
        // receiver window; without this the answerer keeps ssthresh at its
        // initial 0, so cwnd never starts below it, slow-start never runs, and
        // cwnd only grows linearly under congestion avoidance (§7.2.2).
        self.rwnd = i.advertised_receiver_window_credit;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);
        self.ssthresh = self.rwnd;

        self.negotiate_extensions(&i.params);

        let mut outbound = Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![],
        };

        let mut init_ack = ChunkInit {
            is_ack: true,
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: self.my_max_num_outbound_streams,
            num_inbound_streams: self.my_max_num_inbound_streams,
            initiate_tag: self.my_verification_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            ..Default::default()
        };

        if self.my_cookie.is_none() {
            self.my_cookie = Some(ParamStateCookie::new());
        }

        if let Some(my_cookie) = &self.my_cookie {
            init_ack.params = vec![Box::new(my_cookie.clone())];
        }

        init_ack.set_supported_extensions();

        outbound.chunks = vec![Box::new(init_ack)];

        Ok(vec![outbound])
    }

    fn handle_init_ack(
        &mut self,
        p: &Packet,
        i: &ChunkInitAck,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInitAck received in state '{}'", self.side, state);
        if state != AssociationState::CookieWait {
            // RFC 4960
            // 5.2.3.  Unexpected INIT ACK
            //   If an INIT ACK is received by an endpoint in any state other than the
            //   COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
            //   An unexpected INIT ACK usually indicates the processing of an old or
            //   duplicated INIT chunk.
            return Ok(vec![]);
        }

        self.my_max_num_inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.my_max_num_inbound_streams);
        self.my_max_num_outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.my_max_num_outbound_streams);
        self.peer_verification_tag = i.initiate_tag;
        self.incoming_resets = IncomingResetQueue::new(i.initial_tsn);
        self.peer_last_tsn = if i.initial_tsn == 0 {
            u32::MAX
        } else {
            i.initial_tsn - 1
        };
        if self.source_port != p.common_header.destination_port
            || self.destination_port != p.common_header.source_port
        {
            warn!("[{}] handle_init_ack: port mismatch", self.side);
            return Ok(vec![]);
        }

        self.rwnd = i.advertised_receiver_window_credit;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);

        // RFC 4690 Sec 7.2.1
        //  o  The initial value of ssthresh MAY be arbitrarily high (for
        //     example, implementations MAY use the size of the receiver
        //     advertised window).
        self.ssthresh = self.rwnd;
        trace!(
            "[{}] updated cwnd={} ssthresh={} inflight={} (INI)",
            self.side,
            self.cwnd,
            self.ssthresh,
            self.inflight_queue.outstanding_bytes()
        );

        self.timers.stop(Timer::T1Init);
        self.stored_init = None;

        self.negotiate_extensions(&i.params);
        let cookie_param = i
            .params
            .iter()
            .find_map(|param| param.as_any().downcast_ref::<ParamStateCookie>());

        if let Some(v) = cookie_param {
            self.stored_cookie_echo = Some(ChunkCookieEcho {
                cookie: v.cookie.clone(),
            });

            self.send_cookie_echo()?;

            self.timers
                .start(Timer::T1Cookie, now, self.rto_mgr.get_rto());

            self.set_state(AssociationState::CookieEchoed);

            Ok(vec![])
        } else {
            Err(Error::ErrInitAckNoCookie)
        }
    }

    fn negotiate_extensions(&mut self, params: &[Box<dyn Param>]) {
        self.use_forward_tsn = false;
        self.peer_supports_reconfig = false;
        for param in params {
            if param.as_any().is::<ParamForwardTsnSupported>() {
                // RFC 3758 3.3: the original PR-SCTP advertisement remains
                // valid independently of the newer supported-chunk list.
                self.use_forward_tsn = true;
            } else if let Some(ext) = param.as_any().downcast_ref::<ParamSupportedExtensions>() {
                self.use_forward_tsn |= ext.chunk_types.contains(&CT_FORWARD_TSN);
                self.peer_supports_reconfig |= ext.chunk_types.contains(&CT_RECONFIG);
            }
        }
    }

    fn handle_heartbeat(&self, c: &ChunkHeartbeat) -> Result<Vec<Packet>> {
        trace!("[{}] chunkHeartbeat", self.side);
        if let Some(p) = c.params.first() {
            if let Some(hbi) = p.as_any().downcast_ref::<ParamHeartbeatInfo>() {
                return Ok(vec![Packet {
                    common_header: CommonHeader {
                        verification_tag: self.peer_verification_tag,
                        source_port: self.source_port,
                        destination_port: self.destination_port,
                    },
                    chunks: vec![Box::new(ChunkHeartbeatAck {
                        params: vec![Box::new(ParamHeartbeatInfo {
                            heartbeat_information: hbi.heartbeat_information.clone(),
                        })],
                    })],
                }]);
            } else {
                warn!(
                    "[{}] failed to handle Heartbeat, no ParamHeartbeatInfo",
                    self.side,
                );
            }
        }

        Ok(vec![])
    }

    fn handle_cookie_echo(&mut self, c: &ChunkCookieEcho) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ECHO received in state '{}'", self.side, state);

        if let Some(my_cookie) = &self.my_cookie {
            match state {
                AssociationState::Established => {
                    if !constant_time_eq(&my_cookie.cookie, &c.cookie) {
                        return Ok(vec![]);
                    }
                }
                AssociationState::Closed
                | AssociationState::CookieWait
                | AssociationState::CookieEchoed => {
                    if !constant_time_eq(&my_cookie.cookie, &c.cookie) {
                        return Ok(vec![]);
                    }

                    self.timers.stop(Timer::T1Init);
                    self.stored_init = None;

                    self.timers.stop(Timer::T1Cookie);
                    self.stored_cookie_echo = None;

                    self.events.push_back(Event::Connected);
                    self.set_state(AssociationState::Established);
                    self.handshake_completed = true;
                }
                _ => return Ok(vec![]),
            };
        } else {
            debug!("[{}] COOKIE-ECHO received before initialization", self.side);
            return Ok(vec![]);
        }

        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkCookieAck {})],
        }])
    }

    fn handle_cookie_ack(&mut self) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ACK received in state '{}'", self.side, state);
        if state != AssociationState::CookieEchoed {
            // RFC 4960
            // 5.2.5.  Handle Duplicate COOKIE-ACK.
            //   At any state other than COOKIE-ECHOED, an endpoint should silently
            //   discard a received COOKIE ACK chunk.
            return Ok(vec![]);
        }

        self.timers.stop(Timer::T1Cookie);
        self.stored_cookie_echo = None;

        self.events.push_back(Event::Connected);
        self.set_state(AssociationState::Established);
        self.handshake_completed = true;

        Ok(vec![])
    }

    fn handle_data(&mut self, d: &ChunkPayloadData) -> Result<Vec<Packet>> {
        debug!(
            "[{}] DATA: tsn={} peer_last_tsn={} immediateSack={} len={}, unordered={}",
            self.side,
            d.tsn,
            self.peer_last_tsn,
            d.immediate_sack,
            d.user_data.len(),
            d.unordered,
        );
        self.stats.inc_datas();

        let can_push = self.payload_queue.can_push(d, self.peer_last_tsn);
        let mut stream_handle_data = false;
        if can_push {
            if d.stream_identifier < self.my_max_num_inbound_streams {
                if self.get_my_receiver_window_credit() > 0 {
                    // Pass the new chunk to stream level as soon as it arrives
                    self.payload_queue.push(d.clone(), self.peer_last_tsn);
                    stream_handle_data = true;
                } else {
                    // Receive buffer is full. Two kinds of chunk are still worth taking,
                    // because refusing them is not something the application can relieve by
                    // draining.
                    //
                    // The first fills a gap below the highest TSN already queued.
                    let fills_gap = self
                        .payload_queue
                        .get_last_tsn_received()
                        .is_some_and(|last_tsn| sna32lt(d.tsn, *last_tsn));

                    // The second is the next in-sequence chunk when nothing is readable at
                    // all, and it is what keeps a full buffer from becoming permanent. Bytes
                    // are released only when the application reads; `is_readable()` is
                    // head-of-line blocked by an incomplete chunk set; and the chunk that
                    // would complete that set is exactly `peer_last_tsn + 1`. Dropping it
                    // leaves the window at zero with no way to reopen — every retransmission
                    // is refused for the same reason, forever.
                    // See <https://github.com/webrtc-rs/webrtc/issues/822>.
                    //
                    // Guarded on nothing being readable so this stays an escape from deadlock
                    // rather than a licence to overrun the bound. A merely slow receiver has
                    // data to take and must be made to take it. Without the guard, the chunk
                    // accepted here is `peer_last_tsn + 1` — precisely the one that advances
                    // the cumulative ack — so every chunk would qualify and
                    // `max_receive_buffer_size` would stop bounding anything.
                    let unblocks_reassembly =
                        d.tsn == self.peer_last_tsn.wrapping_add(1) && !self.has_readable_data();

                    if fills_gap || unblocks_reassembly {
                        debug!(
                            "[{}] receive buffer full, but accepted {} with tsn={} ssn={}",
                            self.side,
                            if fills_gap {
                                "as this is a missing chunk"
                            } else {
                                "as the in-sequence chunk that unblocks reassembly"
                            },
                            d.tsn,
                            d.stream_sequence_number
                        );
                        self.payload_queue.push(d.clone(), self.peer_last_tsn);
                        stream_handle_data = true;
                    } else {
                        debug!(
                            "[{}] receive buffer full. dropping DATA with tsn={} ssn={}",
                            self.side, d.tsn, d.stream_sequence_number
                        );
                    }
                }
            } else {
                // silently discard the data. (sender will retry on T3-rtx timeout)
                debug!("[{}] discard {}", self.side, d.stream_sequence_number);
                return Ok(vec![]);
            }
        }

        let immediate_sack = d.immediate_sack;

        if stream_handle_data {
            self.events.push_back(Event::DatagramReceived);
            self.deliver_received_data(d.clone());
        }

        self.handle_peer_last_tsn_and_acknowledgement(immediate_sack)
    }

    fn handle_sack(&mut self, d: &ChunkSelectiveAck, now: Instant) -> Result<Vec<Packet>> {
        trace!(
            "[{}] {}, SACK: cumTSN={} a_rwnd={}",
            self.side,
            self.cumulative_tsn_ack_point,
            d.cumulative_tsn_ack,
            d.advertised_receiver_window_credit
        );
        let state = self.state();
        if state != AssociationState::Established
            && state != AssociationState::ShutdownPending
            && state != AssociationState::ShutdownReceived
        {
            return Ok(vec![]);
        }

        self.stats.inc_sacks();

        if sna32gt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            // RFC 4960 sec 6.2.1.  Processing a Received SACK
            // D)
            //   i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
            //      Point, then drop the SACK.  Since Cumulative TSN Ack is
            //      monotonically increasing, a SACK whose Cumulative TSN Ack is
            //      less than the Cumulative TSN Ack Point indicates an out-of-
            //      order SACK.

            debug!(
                "[{}] SACK Cumulative ACK {} is older than ACK point {}",
                self.side, d.cumulative_tsn_ack, self.cumulative_tsn_ack_point
            );

            return Ok(vec![]);
        }

        // Process selective ack
        let SackProgress {
            bytes_acked_per_stream,
            total_bytes_acked,
            htna,
            revoked,
        } = self.process_selective_ack(d, now)?;

        let mut cum_tsn_ack_point_advanced = false;
        if sna32lt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            trace!(
                "[{}] SACK: cumTSN advanced: {} -> {}",
                self.side, self.cumulative_tsn_ack_point, d.cumulative_tsn_ack
            );

            self.cumulative_tsn_ack_point = d.cumulative_tsn_ack;
            while self
                .reset_tsn_ack_queue
                .front()
                .is_some_and(|(tsn, _)| sna32lte(*tsn, d.cumulative_tsn_ack))
            {
                let (tsn, streams) = self.reset_tsn_ack_queue.pop_front().unwrap();
                for si in streams {
                    if self.confirmed_reset_tsns.get(&si) == Some(&tsn) {
                        self.confirmed_reset_tsns.remove(&si);
                    }
                }
            }
            cum_tsn_ack_point_advanced = true;
            self.on_cumulative_tsn_ack_point_advanced(total_bytes_acked, now);
        }

        self.release_stream_buffers(&bytes_acked_per_stream);

        // New rwnd value
        // RFC 4960 sec 6.2.1.  Processing a Received SACK
        // D)
        //   ii) Set rwnd equal to the newly received a_rwnd minus the number
        //       of bytes still outstanding after processing the Cumulative
        //       TSN Ack and the Gap Ack Blocks.

        // acknowledged payload bytes were already released from the in-flight queue
        let bytes_outstanding = self.inflight_queue.outstanding_bytes() as u32;
        if bytes_outstanding >= d.advertised_receiver_window_credit {
            self.rwnd = 0;
        } else {
            self.rwnd = d.advertised_receiver_window_credit - bytes_outstanding;
        }

        if let Some(probe) = self.zero_window_probe {
            let window_still_closed = self.inflight_queue.get(probe).is_some_and(|chunk| {
                chunk.is_outstanding()
                    && (d.advertised_receiver_window_credit as usize) < chunk.user_data.len()
            });
            if !window_still_closed {
                self.zero_window_probe = None;
            } else {
                // RFC 9260 6.1 A: a reader may keep its window shut indefinitely
                // while its SACKs demonstrate that the path is still alive.
                // Positive credit smaller than the probe is also insufficient.
                self.timers.reset_retrans(Timer::T3RTX);
            }
        }

        self.process_fast_retransmission(
            d.cumulative_tsn_ack,
            htna,
            cum_tsn_ack_point_advanced,
            &revoked,
        )?;

        if self.use_forward_tsn {
            // RFC 3758 Sec 3.5 C1
            if sna32lt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                self.advanced_peer_tsn_ack_point = self.cumulative_tsn_ack_point;
                // Window reset: everything previously tracked is now at/below
                // the cumulative ack point, so start the stream map fresh.
                self.fwd_tsn_stream_map.clear();
            }

            self.advance_peer_ack_point();
            self.awake_write_loop();
        }

        self.postprocess_sack(state, cum_tsn_ack_point_advanced, now);

        Ok(vec![])
    }

    fn handle_reconfig(&mut self, now: Instant, c: &ChunkReconfig) -> Result<Vec<Packet>> {
        trace!("[{}] handle_reconfig", self.side);

        // RFC 6525 3.1: validate the whole supported parameter combination
        // before applying either half. In particular, two outgoing requests
        // cannot smuggle a second state transition into one RE-CONFIG.
        let kind = |p: &dyn Param| {
            if p.as_any().is::<ParamReconfigResponse>() {
                0
            } else if p.as_any().is::<ParamOutgoingResetRequest>() {
                1
            } else {
                2
            }
        };
        let combination = (
            c.param_a.as_deref().map(kind),
            c.param_b.as_deref().map(kind),
        );
        if !matches!(combination, (Some(0 | 1), None) | (Some(0), Some(0 | 1))) {
            return Ok(vec![]);
        }
        let mut pp = vec![];

        if let Some(param_a) = &c.param_a {
            self.handle_reconfig_param(now, param_a, &mut pp)?;
        }

        if let Some(param_b) = &c.param_b {
            self.handle_reconfig_param(now, param_b, &mut pp)?;
        }

        Ok(pp)
    }

    fn handle_forward_tsn(&mut self, c: &ChunkForwardTsn) -> Result<Vec<Packet>> {
        trace!("[{}] FwdTSN: {}", self.side, c);

        if !self.use_forward_tsn {
            warn!("[{}] received FwdTSN but not enabled", self.side);
            // Return an error chunk
            let cerr = ChunkError {
                error_causes: vec![ErrorCauseUnrecognizedChunkType::default()],
            };

            let outbound = Packet {
                common_header: CommonHeader {
                    verification_tag: self.peer_verification_tag,
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                },
                chunks: vec![Box::new(cerr)],
            };
            return Ok(vec![outbound]);
        }

        // From RFC 3758 Sec 3.6:
        //   Note, if the "New Cumulative TSN" value carried in the arrived
        //   FORWARD TSN chunk is found to be behind or at the current cumulative
        //   TSN point, the data receiver MUST treat this FORWARD TSN as out-of-
        //   date and MUST NOT update its Cumulative TSN.  The receiver SHOULD
        //   send a SACK to its peer (the sender of the FORWARD TSN) since such a
        //   duplicate may indicate the previous SACK was lost in the network.

        trace!(
            "[{}] should send ack? newCumTSN={} peer_last_tsn={}",
            self.side, c.new_cumulative_tsn, self.peer_last_tsn
        );
        if sna32lte(c.new_cumulative_tsn, self.peer_last_tsn) {
            trace!("[{}] sending ack on Forward TSN", self.side);
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
            return Ok(vec![]);
        }

        // From RFC 3758 Sec 3.6:
        //   the receiver MUST perform the same TSN handling, including duplicate
        //   detection, gap detection, SACK generation, cumulative TSN
        //   advancement, etc. as defined in RFC 2960 [2]---with the following
        //   exceptions and additions.

        //   When a FORWARD TSN chunk arrives, the data receiver MUST first update
        //   its cumulative TSN point to the value carried in the FORWARD TSN
        //   chunk,

        // Advance peer_last_tsn
        while let Some(&tsn) = self.payload_queue.sorted.front()
            && sna32lte(tsn, c.new_cumulative_tsn)
        {
            self.payload_queue.pop(tsn);
        }
        self.peer_last_tsn = c.new_cumulative_tsn;

        // RX sequence state exists independently of API stream registration.
        // An abandoned first message may precede the first DATA we ever receive.
        for forwarded in &c.streams {
            if forwarded.identifier >= self.my_max_num_inbound_streams {
                continue;
            }
            self.incoming_resets.observe_stream(forwarded.identifier);
            self.with_receive_queue(forwarded.identifier, |received| {
                received.forward_tsn_for_ordered(forwarded.sequence)
            });
        }
        let receive_ids: Vec<_> = self.receive_streams.keys().copied().collect();
        for id in receive_ids {
            self.forward_unordered_receive(id, c.new_cumulative_tsn);
        }

        self.handle_peer_last_tsn_and_acknowledgement(false)
    }

    fn handle_shutdown(&mut self, _: &ChunkShutdown) -> Result<Vec<Packet>> {
        let state = self.state();

        if state == AssociationState::Established {
            if !self.inflight_queue.is_empty() {
                self.set_state(AssociationState::ShutdownReceived);
            } else {
                // No more outstanding, send shutdown ack.
                self.will_send_shutdown_ack = true;
                self.set_state(AssociationState::ShutdownAckSent);

                self.awake_write_loop();
            }
        } else if state == AssociationState::ShutdownSent {
            // self.cumulative_tsn_ack_point = c.cumulative_tsn_ack

            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    fn handle_shutdown_ack(&mut self, _: &ChunkShutdownAck) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownSent || state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.will_send_shutdown_complete = true;

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    fn handle_shutdown_complete(&mut self, _: &ChunkShutdownComplete) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.close(AssociationError::AssociationClosed)?;
        }

        Ok(vec![])
    }

    /// A common routine for handle_data and handle_forward_tsn routines
    fn handle_peer_last_tsn_and_acknowledgement(
        &mut self,
        sack_immediately: bool,
    ) -> Result<Vec<Packet>> {
        let mut reply = vec![];

        // Try to advance peer_last_tsn

        // From RFC 3758 Sec 3.6:
        //   .. and then MUST further advance its cumulative TSN point locally
        //   if possible
        // Meaning, if peer_last_tsn+1 points to a chunk that is received,
        // advance peer_last_tsn until peer_last_tsn+1 points to unreceived chunk.
        //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        while self
            .payload_queue
            .pop(self.peer_last_tsn.wrapping_add(1))
            .is_some()
        {
            self.peer_last_tsn = self.peer_last_tsn.wrapping_add(1);
            //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        }

        // RFC 6525 5.2.2 E2-E5 also applies when FORWARD TSN filled the gap.
        let sequences = self.incoming_resets.ready(self.peer_last_tsn);
        for sequence in sequences {
            self.retry_incoming_reset(sequence, &mut reply)?;
        }

        let has_packet_loss = !self.payload_queue.is_empty();
        if has_packet_loss {
            trace!(
                "[{}] packetloss: {}",
                self.side,
                self.payload_queue
                    .get_gap_ack_blocks_string(self.peer_last_tsn)
            );
        }

        if (self.ack_state != AckState::Immediate
            && !sack_immediately
            && !has_packet_loss
            && self.ack_mode == AckMode::Normal)
            || self.ack_mode == AckMode::AlwaysDelay
        {
            if self.ack_state == AckState::Idle {
                self.delayed_ack_triggered = true;
            } else {
                self.immediate_ack_triggered = true;
            }
        } else {
            self.immediate_ack_triggered = true;
        }

        Ok(reply)
    }

    #[allow(clippy::borrowed_box)]
    fn handle_reconfig_param(
        &mut self,
        now: Instant,
        raw: &Box<dyn Param>,
        reply: &mut Vec<Packet>,
    ) -> Result<()> {
        if let Some(p) = raw.as_any().downcast_ref::<ParamOutgoingResetRequest>() {
            let action = self.incoming_resets.accept(
                p,
                self.receive_streams
                    .keys()
                    .chain(self.streams.keys())
                    .copied(),
                self.my_max_num_inbound_streams,
            );
            // E1 is part of accepting the request, not an unchecked way to stop
            // another procedure's timer using an invalid/reused sequence number.
            if !matches!(
                action,
                ReceiveResetAction::Reply(
                    ReconfigResult::ErrorBadSequenceNumber | ReconfigResult::Denied
                )
            ) {
                self.acknowledge_reconfig(p.reconfig_response_sequence_number, now);
            }
            let sequence = p.reconfig_request_sequence_number;
            match action {
                ReceiveResetAction::Reply(result) => {
                    reply.push(self.reconfig_response_packet(sequence, result))
                }
                ReceiveResetAction::New | ReceiveResetAction::Pending => {
                    self.retry_incoming_reset(sequence, reply)?
                }
            }
            self.immediate_ack_triggered = true;
            Ok(())
        } else if let Some(p) = raw.as_any().downcast_ref::<ParamReconfigResponse>() {
            self.handle_reset_response(now, p);
            Ok(())
        } else {
            Err(Error::ErrParameterType)
        }
    }

    fn process_selective_ack(
        &mut self,
        d: &ChunkSelectiveAck,
        now: Instant,
    ) -> Result<SackProgress> {
        // Reject acknowledgments for unassigned TSNs before modifying queues.
        if sna32gte(d.cumulative_tsn_ack, self.my_next_tsn) {
            return Err(Error::ErrTsnRequestNotExist);
        }
        let mut last_end = 0;
        for gap in &d.gap_ack_blocks {
            if gap.start == 0
                || gap.start <= last_end
                || gap.end < gap.start
                || sna32gte(
                    d.cumulative_tsn_ack.wrapping_add(gap.end as u32),
                    self.my_next_tsn,
                )
            {
                return Err(Error::ErrTsnRequestNotExist);
            }
            last_end = gap.end;
        }
        let mut bytes_acked_per_stream = FxHashMap::default();
        let mut total_bytes_acked = 0;
        let mut newly_acked_data = false;
        // Abandoned DATA can precede the earliest outstanding TSN. RFC 9260
        // 6.3.2 R3 applies to that outstanding DATA, including gap acknowledgments.
        let earliest_outstanding = self.inflight_queue.sorted.iter().copied().find(|tsn| {
            self.inflight_queue
                .get(*tsn)
                .is_some_and(ChunkPayloadData::is_outstanding)
        });

        // New ack point, so pop all ACKed packets from inflight_queue
        // We add 1 because the "currentAckPoint" has already been popped from the inflight queue
        // For the first SACK we take care of this by setting the ackpoint to cumAck - 1
        let mut i = self.cumulative_tsn_ack_point.wrapping_add(1);
        //log::debug!("[{}] i={} d={}", self.name, i, d.cumulative_tsn_ack);
        while sna32lte(i, d.cumulative_tsn_ack) {
            if let Some(mut c) = self.inflight_queue.pop(i) {
                if c.acknowledge() {
                    newly_acked_data |= c.nsent > 0;

                    let n_bytes_acked = c.release_buffer() as i64;
                    total_bytes_acked += c.take_delivery_credit() as i64;
                    // A late SACK for a retired stream must not release bytes
                    // belonging to a new channel that reused its SID.
                    if self.is_current_stream_data(&c) {
                        *bytes_acked_per_stream
                            .entry(c.stream_identifier)
                            .or_default() += n_bytes_acked;
                    }

                    // RFC 4960 sec 6.3.1.  RTO Calculation
                    //   C4)  When data is in flight and when allowed by rule C5 below, a new
                    //        RTT measurement MUST be made each round trip.  Furthermore, new
                    //        RTT measurements SHOULD be made no more than once per round trip
                    //        for a given destination transport address.
                    //   C5)  Karn's algorithm: RTT measurements MUST NOT be made using
                    //        packets that were retransmitted (and thus for which it is
                    //        ambiguous whether the reply was for the first instance of the
                    //        chunk or for a later instance)
                    if !c.abandoned() && c.nsent == 1 && sna32gte(c.tsn, self.min_tsn2measure_rtt) {
                        self.min_tsn2measure_rtt = self.my_next_tsn;
                        if let Some(since) = &c.since {
                            let rtt = now.duration_since(*since);
                            let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                            trace!(
                                "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                self.side,
                                rtt.as_millis(),
                                srtt,
                                self.rto_mgr.get_rto()
                            );
                        } else {
                            error!("[{}] invalid c.since", self.side);
                        }
                    }
                }

                if self.in_fast_recovery && c.tsn == self.fast_recover_exit_point {
                    debug!("[{}] exit fast-recovery", self.side);
                    self.in_fast_recovery = false;
                }
            } else {
                return Err(Error::ErrInflightQueueTsnPop);
            }

            i = i.wrapping_add(1);
        }

        let revoked = self.revoke_missing_gap_acks(d);

        let mut htna = d.cumulative_tsn_ack;

        // Record peer acknowledgments independently of local payload release.
        for g in &d.gap_ack_blocks {
            for i in g.start..=g.end {
                let tsn = d.cumulative_tsn_ack.wrapping_add(i as u32);

                let newly_acknowledged = self.inflight_queue.acknowledge(tsn);
                let n_bytes_acked = if newly_acknowledged {
                    self.inflight_queue.release_buffer(tsn) as i64
                } else {
                    0
                };

                let delivery_credit = self
                    .inflight_queue
                    .get_mut(tsn)
                    .map_or(0, ChunkPayloadData::take_delivery_credit)
                    as i64;
                if let Some(c) = self.inflight_queue.get(tsn) {
                    if newly_acknowledged {
                        newly_acked_data |= c.nsent > 0;
                        total_bytes_acked += delivery_credit;
                        if self.is_current_stream_data(c) {
                            *bytes_acked_per_stream
                                .entry(c.stream_identifier)
                                .or_default() += n_bytes_acked;
                        }

                        trace!("[{}] tsn={} has been sacked", self.side, c.tsn);

                        if !c.abandoned() && c.nsent == 1 {
                            self.min_tsn2measure_rtt = self.my_next_tsn;
                            if let Some(since) = &c.since {
                                let rtt = now.duration_since(*since);
                                let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                                trace!(
                                    "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                    self.side,
                                    rtt.as_millis(),
                                    srtt,
                                    self.rto_mgr.get_rto()
                                );
                            } else {
                                error!("[{}] invalid c.since", self.side);
                            }
                        }

                        if sna32lt(htna, tsn) {
                            htna = tsn;
                        }
                    }
                } else {
                    return Err(Error::ErrTsnRequestNotExist);
                }
            }
        }

        // RFC 9260 8.1-8.2: an acknowledgment of new DATA clears the error
        // counter, including a late SACK after local abandonment. Payload
        // release does not acknowledge DATA; duplicates and never-sent TSNs
        // assigned only for FORWARD TSN do not count as newly acknowledged DATA.
        if newly_acked_data {
            self.timers.reset_retrans(Timer::T3RTX);
        }
        if earliest_outstanding.is_some_and(|tsn| {
            sna32lte(tsn, d.cumulative_tsn_ack)
                || self.inflight_queue.get(tsn).is_some_and(|c| c.acknowledged)
        }) {
            // Postprocessing restarts T3 with the current RTO if DATA/FORWARD
            // TSN remains outstanding.
            self.timers.set(Timer::T3RTX, None);
        }
        Ok(SackProgress {
            bytes_acked_per_stream,
            total_bytes_acked,
            htna,
            revoked,
        })
    }

    /// RFC 9260 6.2.1 D(iii): a disappearing gap returns its DATA to recovery.
    /// Diff the two ordered sets of ranges, visiting chunks only in the removed
    /// portions. Ordinary cumulative SACKs need no inflight scan or allocation.
    fn revoke_missing_gap_acks(&mut self, d: &ChunkSelectiveAck) -> Vec<u32> {
        let mut revoked = Vec::new();
        let mut gap_index = 0;
        for &(start_tsn, end_tsn) in &self.peer_gap_ack_ranges {
            if sna32lte(end_tsn, d.cumulative_tsn_ack) {
                continue; // The cumulative ACK already removed this whole range.
            }
            let mut offset = if sna32lte(start_tsn, d.cumulative_tsn_ack) {
                1
            } else {
                start_tsn.wrapping_sub(d.cumulative_tsn_ack)
            };
            let end = end_tsn.wrapping_sub(d.cumulative_tsn_ack);
            while offset <= end {
                while gap_index < d.gap_ack_blocks.len()
                    && (d.gap_ack_blocks[gap_index].end as u32) < offset
                {
                    gap_index += 1;
                }
                let next_gap = d.gap_ack_blocks.get(gap_index);
                if let Some(gap) = next_gap
                    && gap.start as u32 <= offset
                {
                    offset = gap.end as u32 + 1;
                    continue;
                }
                let missing_end = next_gap.map_or(end, |gap| end.min(gap.start as u32 - 1));
                for missing in offset..=missing_end {
                    let tsn = d.cumulative_tsn_ack.wrapping_add(missing);
                    // Local abandonment may already have retired this payload.
                    if self.inflight_queue.revoke_gap_ack(tsn) {
                        revoked.push(tsn);
                    }
                }
                offset = missing_end + 1;
            }
        }
        self.peer_gap_ack_ranges.clear();
        self.peer_gap_ack_ranges
            .extend(d.gap_ack_blocks.iter().map(|gap| {
                (
                    d.cumulative_tsn_ack.wrapping_add(gap.start as u32),
                    d.cumulative_tsn_ack.wrapping_add(gap.end as u32),
                )
            }));
        revoked
    }

    fn on_cumulative_tsn_ack_point_advanced(&mut self, total_bytes_acked: i64, now: Instant) {
        // RFC 4096, sec 6.3.2.  Retransmission Timer Rules
        //   R2)  Whenever all outstanding data sent to an address have been
        //        acknowledged, turn off the T3-rtx timer of that address.
        if self.inflight_queue.is_empty() {
            trace!(
                "[{}] SACK: no more packet in-flight (pending={})",
                self.side,
                self.pending_queue.len()
            );
            self.timers.stop(Timer::T3RTX);
        } else {
            trace!("[{}] T3-rtx timer start (pt2)", self.side);
            self.timers
                .restart_if_stale(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }

        // Update congestion control parameters
        if self.cwnd <= self.ssthresh {
            // RFC 4096, sec 7.2.1.  Slow-Start
            //   o  When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
            //		use the slow-start algorithm to increase cwnd only if the current
            //      congestion window is being fully utilized, an incoming SACK
            //      advances the Cumulative TSN Ack Point, and the data sender is not
            //      in Fast Recovery.  Only when these three conditions are met can
            //      the cwnd be increased; otherwise, the cwnd MUST not be increased.
            //		If these conditions are met, then cwnd MUST be increased by, at
            //      most, the lesser of 1) the total size of the previously
            //      outstanding DATA chunk(s) acknowledged, and 2) the destination's
            //      path MTU.
            if !self.in_fast_recovery && !self.pending_queue.is_empty() {
                self.cwnd += std::cmp::min(total_bytes_acked as u32, self.cwnd); // TCP way
                // self.cwnd += min32(uint32(total_bytes_acked), self.mtu) // SCTP way (slow)
                trace!(
                    "[{}] updated cwnd={} ssthresh={} acked={} (SS)",
                    self.side, self.cwnd, self.ssthresh, total_bytes_acked
                );
            } else {
                trace!(
                    "[{}] cwnd did not grow: cwnd={} ssthresh={} acked={} FR={} pending={}",
                    self.side,
                    self.cwnd,
                    self.ssthresh,
                    total_bytes_acked,
                    self.in_fast_recovery,
                    self.pending_queue.len()
                );
            }
        } else {
            // RFC 4096, sec 7.2.2.  Congestion Avoidance
            //   o  Whenever cwnd is greater than ssthresh, upon each SACK arrival
            //      that advances the Cumulative TSN Ack Point, increase
            //      partial_bytes_acked by the total number of bytes of all new chunks
            //      acknowledged in that SACK including chunks acknowledged by the new
            //      Cumulative TSN Ack and by Gap Ack Blocks.
            self.partial_bytes_acked += total_bytes_acked as u32;

            //   o  When partial_bytes_acked is equal to or greater than cwnd and
            //      before the arrival of the SACK the sender had cwnd or more bytes
            //      of data outstanding (i.e., before arrival of the SACK, flight size
            //      was greater than or equal to cwnd), increase cwnd by MTU, and
            //      reset partial_bytes_acked to (partial_bytes_acked - cwnd).
            if self.partial_bytes_acked >= self.cwnd && !self.pending_queue.is_empty() {
                self.partial_bytes_acked -= self.cwnd;
                self.cwnd += self.mtu;
                trace!(
                    "[{}] updated cwnd={} ssthresh={} acked={} (CA)",
                    self.side, self.cwnd, self.ssthresh, total_bytes_acked
                );
            }
        }
    }

    fn process_fast_retransmission(
        &mut self,
        cum_tsn_ack_point: u32,
        htna: u32,
        cum_tsn_ack_point_advanced: bool,
        revoked: &[u32],
    ) -> Result<()> {
        // HTNA algorithm - RFC 4960 Sec 7.2.4
        // Increment missIndicator of each chunks that the SACK reported missing
        // when either of the following is met:
        // a)  Not in fast-recovery
        //     miss indications are incremented only for missing TSNs prior to the
        //     highest TSN newly acknowledged in the SACK.
        // b)  In fast-recovery AND the Cumulative TSN Ack Point advanced
        //     the miss indications are incremented for all TSNs reported missing
        //     in the SACK.
        if !self.in_fast_recovery || cum_tsn_ack_point_advanced || !revoked.is_empty() {
            let normal_reports = !self.in_fast_recovery || cum_tsn_ack_point_advanced;
            let max_tsn = if !self.in_fast_recovery {
                // a) increment only for missing TSNs prior to the HTNA
                htna
            } else {
                // b) increment for all TSNs reported missing
                cum_tsn_ack_point
                    .wrapping_add(self.inflight_queue.len() as u32)
                    .wrapping_add(1)
            };

            // Capture the normal range before a missing chunk can enter fast
            // recovery. Revoked TSNs are already in serial order; append only
            // those beyond that range, reporting an overlapping TSN once.
            let normal_end = if normal_reports {
                max_tsn
                    .wrapping_sub(cum_tsn_ack_point)
                    .min(self.inflight_queue.len() as u32 + 1)
            } else {
                0
            };
            let normal = (1..normal_end).map(|offset| cum_tsn_ack_point.wrapping_add(offset));
            let additional = revoked
                .iter()
                .copied()
                .filter(|tsn| tsn.wrapping_sub(cum_tsn_ack_point) >= normal_end);
            for tsn in normal.chain(additional) {
                if let Some(c) = self.inflight_queue.get_mut(tsn) {
                    if c.is_outstanding() && c.miss_indicator < 3 {
                        c.miss_indicator += 1;
                        if c.miss_indicator == 3 && !self.in_fast_recovery {
                            // 2)  If not in Fast Recovery, adjust the ssthresh and cwnd of the
                            //     destination address(es) to which the missing DATA chunks were
                            //     last sent, according to the formula described in Section 7.2.3.
                            self.in_fast_recovery = true;
                            self.fast_recover_exit_point = htna;
                            self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
                            self.cwnd = self.ssthresh;
                            self.partial_bytes_acked = 0;
                            self.will_retransmit_fast = true;

                            trace!(
                                "[{}] updated cwnd={} ssthresh={} inflight={} (FR)",
                                self.side,
                                self.cwnd,
                                self.ssthresh,
                                self.inflight_queue.outstanding_bytes()
                            );
                        }
                    }
                } else {
                    return Err(Error::ErrTsnRequestNotExist);
                }
            }
        }

        if self.in_fast_recovery && cum_tsn_ack_point_advanced {
            self.will_retransmit_fast = true;
        }

        Ok(())
    }

    /// The caller must hold the lock. This method was only added because the
    /// linter was complaining about the "cognitive complexity" of handle_sack.
    fn postprocess_sack(
        &mut self,
        state: AssociationState,
        mut should_awake_write_loop: bool,
        now: Instant,
    ) {
        if !self.inflight_queue.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt3)", self.side);
            self.timers
                .restart_if_stale(Timer::T3RTX, now, self.rto_mgr.get_rto());
        } else if state == AssociationState::ShutdownPending {
            // No more outstanding, send shutdown.
            should_awake_write_loop = true;
            self.will_send_shutdown = true;
            self.set_state(AssociationState::ShutdownSent);
        } else if state == AssociationState::ShutdownReceived {
            // No more outstanding, send shutdown ack.
            should_awake_write_loop = true;
            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);
        }

        if should_awake_write_loop {
            self.awake_write_loop();
        }
    }

    fn retry_incoming_reset(&mut self, sequence: u32, reply: &mut Vec<Packet>) -> Result<()> {
        if self.incoming_resets.get(sequence).is_none() {
            return Ok(());
        }
        if !self.incoming_resets.is_ready(sequence, self.peer_last_tsn) {
            reply.push(self.reconfig_response_packet(sequence, ReconfigResult::InProgress));
            return Ok(());
        }
        let streams = self
            .incoming_resets
            .complete(sequence, ReconfigResult::SuccessPerformed)
            .unwrap();
        for &id in streams.iter() {
            // RFC 8831 6.7 closes each reused wire channel in both directions.
            // An unread API receiver may still describe an earlier RX epoch.
            let reciprocal = self
                .receive_streams
                .get(&id)
                .is_some_and(ReceiveQueue::needs_reciprocal_reset);
            if let Some(s) = self.streams.get_mut(&id) {
                s.incoming_reset = true;
                s.state = ((s.state as u8) & 1).into();
            }
            if reciprocal {
                self.queue_reset_request(id);
            }
            let awaiting_outgoing = self.pending_queue.is_resetting(id);
            self.with_receive_queue(id, |received| {
                if awaiting_outgoing {
                    received.require_outgoing_reset();
                }
                received.reset();
            });
            self.finish_stream_delivery(id);
        }
        // E4 replays received DATA after this boundary's RX mutation. A second
        // accepted reset can retain part of the same stream's future queue.
        for &id in streams.iter() {
            let actions = self.with_receive_queue(id, ReceiveQueue::take_deferred);
            for action in actions {
                match action {
                    DeferredReceive::Data(data) => self.deliver_received_data(data),
                    DeferredReceive::ForwardUnordered(tsn) => {
                        self.forward_unordered_receive(id, tsn)
                    }
                }
            }
        }
        reply.push(self.reconfig_response_packet(sequence, ReconfigResult::SuccessPerformed));
        Ok(())
    }

    fn deliver_received_data(&mut self, data: ChunkPayloadData) {
        let id = data.stream_identifier;
        self.incoming_resets.observe_stream(id);
        let deferred = self
            .incoming_resets
            .boundary(id)
            .is_some_and(|boundary| sna32gt(data.tsn, boundary));
        if deferred {
            self.with_receive_queue(id, |received| received.defer(DeferredReceive::Data(data)));
        } else {
            self.get_or_create_stream(id);
            if self.with_receive_queue(id, |received| received.push(data)) {
                self.events
                    .push_back(Event::Stream(StreamEvent::Readable { id }));
            }
        }
    }

    fn forward_unordered_receive(&mut self, id: StreamId, tsn: u32) {
        let boundary = self.incoming_resets.boundary(id);
        if self.receive_streams.contains_key(&id) {
            let readable = self.with_receive_queue(id, |received| {
                if let Some(boundary) = boundary
                    && sna32gt(tsn, boundary)
                {
                    received.forward_tsn_for_unordered(boundary);
                    received.defer(DeferredReceive::ForwardUnordered(tsn));
                } else {
                    received.forward_tsn_for_unordered(tsn);
                }
                received.is_readable()
            });
            if readable && self.streams.contains_key(&id) {
                self.events
                    .push_back(Event::Stream(StreamEvent::Readable { id }));
            }
        }
    }

    fn reconfig_response_packet(&self, sequence: u32, result: ReconfigResult) -> Packet {
        self.create_packet(vec![Box::new(ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: sequence,
                result,
            })),
            param_b: None,
        })])
    }

    /// create_packet wraps chunks in a packet.
    /// The caller should hold the read lock.
    pub(crate) fn create_packet(&self, chunks: Vec<Box<dyn Chunk>>) -> Packet {
        Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks,
        }
    }

    /// Marshal a single control chunk into one SCTP packet, bypassing the
    /// `Vec<Box<dyn Chunk>>` + `Packet` allocations of `create_packet(..).marshal()`.
    /// Feeds the borrowed chunk straight to the shared framing path
    /// ([`Packet::write_framed`]). Used on the hot SACK / FORWARD-TSN send path
    /// (a SACK is emitted roughly every 1-2 inbound DATA chunks). The caller holds
    /// the lock.
    fn marshal_control_chunk(&self, chunk: &dyn Chunk) -> Result<Bytes> {
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };
        // common header + chunk header + value + up to 3 bytes of trailing padding.
        let mut buf = BytesMut::with_capacity(
            COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + chunk.value_length() + 3,
        );
        Packet::write_framed(&common_header, std::iter::once(chunk), &mut buf)?;
        Ok(buf.freeze())
    }

    /// create_stream creates a stream. The caller should hold the lock and check no stream exists for this id.
    fn create_stream(
        &mut self,
        stream_identifier: StreamId,
        accept: bool,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Option<Stream<'_>> {
        let limit = if accept {
            self.my_max_num_inbound_streams
        } else {
            self.my_max_num_outbound_streams
        };
        if stream_identifier >= limit {
            return None;
        }
        let mut s = StreamState::new(
            self.side,
            stream_identifier,
            self.max_payload_size,
            default_payload_type,
        );
        s.generation = self.next_stream_generation;
        self.next_stream_generation = self.next_stream_generation.wrapping_add(1);

        if accept {
            self.stream_queue.push_back(stream_identifier);
            self.events.push_back(Event::Stream(StreamEvent::Opened {
                id: stream_identifier,
            }));
        }

        let received = self
            .receive_streams
            .entry(stream_identifier)
            .or_insert_with(|| ReceiveQueue::new(stream_identifier));
        if !accept {
            received.open();
        } else if received.delivery_closed() {
            // Saved messages can be published after their wire reset already
            // finished. Stopping this receiver must not reset a newer channel.
            s.incoming_reset = true;
            s.state = RecvSendState::Readable;
        }
        self.streams.insert(stream_identifier, s);

        Some(Stream {
            stream_identifier,
            association: self,
        })
    }

    /// get_or_create_stream gets or creates a stream. The caller should hold the lock.
    fn get_or_create_stream(&mut self, stream_identifier: StreamId) -> Option<Stream<'_>> {
        if self.streams.contains_key(&stream_identifier) {
            Some(Stream {
                stream_identifier,
                association: self,
            })
        } else {
            self.create_stream(
                stream_identifier,
                true,
                PayloadProtocolIdentifier::default(),
            )
        }
    }

    /// Whether any stream currently holds a complete message the application could read.
    ///
    /// Distinguishes a receiver that is merely slow — it has data to take, and back-pressure
    /// should make it take it — from one wedged behind an incomplete chunk set, which cannot
    /// drain anything however attentive it is. Only the second justifies accepting a chunk
    /// into a full receive buffer.
    fn has_readable_data(&self) -> bool {
        self.receive_streams.values().any(ReceiveQueue::is_readable)
    }

    pub(crate) fn get_my_receiver_window_credit(&self) -> u32 {
        self.max_receive_buffer_size
            .saturating_sub(self.receive_buffered_bytes.min(u32::MAX as usize) as u32)
    }

    #[cfg(any(test, fuzzing, feature = "bench"))]
    pub(crate) fn assert_receive_accounting(&self) {
        assert_eq!(
            self.receive_buffered_bytes,
            self.receive_streams
                .values()
                .map(ReceiveQueue::get_num_bytes)
                .sum::<usize>(),
            "receive credit differs from retained payload ownership"
        );
    }

    /// gather_outbound gathers outgoing packets. The returned bool value set to
    /// false means the association should be closed down after the final send.
    fn gather_outbound(&mut self, now: Instant) -> (Vec<Bytes>, bool) {
        let mut raw_packets = vec![];
        let state = self.state();
        let sack_allowed = matches!(
            state,
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownSent
                | AssociationState::ShutdownReceived
        );
        let mut pending_sack = None;
        while let Some(packet) = self.control_queue.pop_front() {
            // RFC 6525 §5.2 recommends bundling the SACK with a reset response.
            // Keep other control chunks' framing rules unchanged and never grow
            // this packet beyond the same MTU limit used for DATA bundling.
            if sack_allowed
                && self.ack_state == AckState::Immediate
                && packet.chunks.len() == 1
                && packet.chunks[0].as_any().is::<ChunkReconfig>()
            {
                let sack = pending_sack.get_or_insert_with(|| self.create_selective_ack_chunk());
                let wire_size = COMMON_HEADER_SIZE as usize
                    + (CHUNK_HEADER_SIZE + packet.chunks[0].value_length()).next_multiple_of(4)
                    + (CHUNK_HEADER_SIZE + sack.value_length()).next_multiple_of(4);
                if wire_size <= self.mtu as usize {
                    let mut buf = BytesMut::with_capacity(wire_size);
                    if Packet::write_framed(
                        &packet.common_header,
                        [packet.chunks[0].as_ref(), sack as &dyn Chunk].into_iter(),
                        &mut buf,
                    )
                    .is_ok()
                    {
                        raw_packets.push(buf.freeze());
                        self.ack_state = AckState::Idle;
                        pending_sack = None;
                        continue;
                    }
                }
            }
            if let Ok(raw) = packet.marshal() {
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a control packet", self.side);
            }
        }
        if let Some(sack) = pending_sack {
            // The complete gap/duplicate report did not fit beside RE-CONFIG.
            // Send that already prepared SACK separately, without losing it or
            // consuming duplicate TSNs a second time.
            if let Ok(raw) = self.marshal_control_chunk(&sack) {
                raw_packets.push(raw);
                self.ack_state = AckState::Idle;
            } else {
                warn!("[{}] failed to serialize a SACK packet", self.side);
            }
        }
        match state {
            AssociationState::Established => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                raw_packets = self.gather_outbound_data_and_reconfig_packets(raw_packets, now);
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                (raw_packets, true)
            }
            AssociationState::ShutdownPending
            | AssociationState::ShutdownSent
            | AssociationState::ShutdownReceived => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            AssociationState::ShutdownAckSent => {
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            _ => (raw_packets, true),
        }
    }

    fn gather_data_packets_to_retransmit(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        // Nothing is ever flagged for T3-rtx in the steady state, so skip the
        // full in-flight scan unless the T3-rtx timer has actually marked chunks.
        if self.t3_retransmit_pending {
            self.get_data_packets_to_retransmit(now, &mut raw_packets);
        }
        raw_packets
    }

    fn gather_outbound_data_and_reconfig_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        self.resume_reset_query(now);
        // Pop unsent data chunks from the pending queue to send as much as
        // cwnd and rwnd allow.
        let (chunks, sis_to_reset) = self.pop_pending_data_chunks_to_send(now);
        if !chunks.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt1)", self.side);
            self.timers
                .restart_if_stale(Timer::T3RTX, now, self.rto_mgr.get_rto());

            self.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
        }

        self.emit_reconfig(now, &mut raw_packets);
        if !sis_to_reset.is_empty() {
            self.start_reconfig(now, sis_to_reset, &mut raw_packets);
        }

        raw_packets
    }

    fn gather_outbound_fast_retransmission_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        if self.will_retransmit_fast {
            self.will_retransmit_fast = false;
            self.abandon_unretransmittable_messages(
                now,
                ChunkPayloadData::is_fast_retransmit_candidate,
            );

            let mut to_fast_retrans: Vec<Box<dyn Chunk>> = vec![];
            let mut fast_retrans_size = COMMON_HEADER_SIZE;

            let mut i = 0;
            loop {
                let tsn = self
                    .cumulative_tsn_ack_point
                    .wrapping_add(i)
                    .wrapping_add(1);
                if let Some(c) = self.inflight_queue.get_mut(tsn) {
                    if !c.is_fast_retransmit_candidate() {
                        i += 1;
                        continue;
                    }

                    // RFC 4960 Sec 7.2.4 Fast Retransmit on Gap Reports
                    //  3)  Determine how many of the earliest (i.e., lowest TSN) DATA chunks
                    //      marked for retransmission will fit into a single packet, subject
                    //      to constraint of the path MTU of the destination transport
                    //      address to which the packet is being sent.  Call this value K.
                    //      Retransmit those K DATA chunks in a single packet.  When a Fast
                    //      Retransmit is being performed, the sender SHOULD ignore the value
                    //      of cwnd and SHOULD NOT delay retransmission for this single
                    //		packet.

                    // Padded wire size, the same accounting
                    // bundle_data_chunks_into_packets uses for bundle
                    // decisions.
                    let data_chunk_size =
                        (DATA_CHUNK_HEADER_SIZE + c.user_data.len() as u32).next_multiple_of(4);
                    if self.mtu < fast_retrans_size + data_chunk_size {
                        break;
                    }

                    fast_retrans_size += data_chunk_size;
                    self.stats.inc_fast_retrans();
                    c.nsent += 1;
                } else {
                    break; // end of pending data
                }

                if let Some(c) = self.inflight_queue.get_mut(tsn) {
                    to_fast_retrans.push(Box::new(c.clone()));
                    trace!(
                        "[{}] fast-retransmit: tsn={} sent={} htna={}",
                        self.side, c.tsn, c.nsent, self.fast_recover_exit_point
                    );
                }
                i += 1;
            }

            if !to_fast_retrans.is_empty() {
                if let Ok(raw) = self.create_packet(to_fast_retrans).marshal() {
                    raw_packets.push(raw);
                } else {
                    warn!(
                        "[{}] failed to serialize a DATA packet to be fast-retransmitted",
                        self.side
                    );
                }
            }
        }

        raw_packets
    }

    fn gather_outbound_sack_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        if self.ack_state == AckState::Immediate {
            self.ack_state = AckState::Idle;
            let sack = self.create_selective_ack_chunk();
            debug!("[{}] sending SACK: {}", self.side, sack);
            if let Ok(raw) = self.marshal_control_chunk(&sack) {
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a SACK packet", self.side);
            }
        }

        raw_packets
    }

    fn gather_outbound_forward_tsn_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        /*log::debug!(
            "[{}] gatherOutboundForwardTSNPackets {}",
            self.name,
            self.will_send_forward_tsn
        );*/
        if self.will_send_forward_tsn {
            self.will_send_forward_tsn = false;
            if sna32gt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                let fwd_tsn = self.create_forward_tsn();
                if let Ok(raw) = self.marshal_control_chunk(&fwd_tsn) {
                    raw_packets.push(raw);
                } else {
                    warn!("[{}] failed to serialize a Forward TSN packet", self.side);
                }
            }
        }

        raw_packets
    }

    fn gather_outbound_shutdown_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> (Vec<Bytes>, bool) {
        let mut ok = true;

        if self.will_send_shutdown {
            self.will_send_shutdown = false;

            let shutdown = ChunkShutdown {
                cumulative_tsn_ack: self.cumulative_tsn_ack_point,
            };

            if let Ok(raw) = self.create_packet(vec![Box::new(shutdown)]).marshal() {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a Shutdown packet", self.side);
            }
        } else if self.will_send_shutdown_ack {
            self.will_send_shutdown_ack = false;

            let shutdown_ack = ChunkShutdownAck {};

            if let Ok(raw) = self.create_packet(vec![Box::new(shutdown_ack)]).marshal() {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a ShutdownAck packet", self.side);
            }
        } else if self.will_send_shutdown_complete {
            self.will_send_shutdown_complete = false;

            let shutdown_complete = ChunkShutdownComplete {};

            if let Ok(raw) = self
                .create_packet(vec![Box::new(shutdown_complete)])
                .marshal()
            {
                raw_packets.push(raw);
                ok = false;
            } else {
                warn!(
                    "[{}] failed to serialize a ShutdownComplete packet",
                    self.side
                );
            }
        }

        (raw_packets, ok)
    }

    /// get_data_packets_to_retransmit is called when T3-rtx is timed out and retransmit outstanding data chunks
    /// that are not acked or abandoned yet.
    fn get_data_packets_to_retransmit(&mut self, now: Instant, raw_packets: &mut Vec<Bytes>) {
        // T3 may have marked this DATA before its lifetime elapsed, while the
        // send window deferred the actual retransmission (RFC 3758 TR4).
        self.abandon_unretransmittable_messages(now, |c| c.retransmit);
        let awnd = std::cmp::min(self.cwnd, self.rwnd);
        let mut chunks = vec![];
        let mut bytes_to_send = 0;
        let mut done = false;
        let mut i = 0;
        // Assume we will re-send every flagged chunk; flip back on if we stop
        // early (a marked chunk that doesn't fit awnd, or a zero-window probe)
        // so the next gather_outbound still scans.
        let mut chunks_remaining = false;
        while !done {
            let tsn = self
                .cumulative_tsn_ack_point
                .wrapping_add(i)
                .wrapping_add(1);
            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                if !c.retransmit {
                    i += 1;
                    continue;
                }

                if i == 0 && self.rwnd < c.user_data.len() as u32 {
                    // Send it as a zero window probe
                    done = true;
                    chunks_remaining = true;
                } else if bytes_to_send + c.user_data.len() > awnd as usize {
                    chunks_remaining = true;
                    break;
                }

                // reset the retransmit flag not to retransmit again before the next
                // t3-rtx timer fires
                c.retransmit = false;
                bytes_to_send += c.user_data.len();

                c.nsent += 1;
            } else {
                break; // end of pending data
            }

            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                trace!(
                    "[{}] retransmitting tsn={} ssn={} sent={}",
                    self.side, c.tsn, c.stream_sequence_number, c.nsent
                );

                chunks.push(c.clone());
            }
            i += 1;
        }

        // Cleared once the whole in-flight window has been rescanned with nothing
        // left flagged; kept set while awnd/zero-window left chunks behind.
        self.t3_retransmit_pending = chunks_remaining;

        self.bundle_data_chunks_into_packets(chunks, raw_packets);
    }

    fn release_stream_buffers(&mut self, bytes_acked_per_stream: &FxHashMap<u16, i64>) {
        for (si, n_bytes_acked) in bytes_acked_per_stream {
            if *n_bytes_acked > 0 {
                // Report the exact bytes released for this stream (acknowledged OR
                // abandoned — both funnel through bytes_acked_per_stream) so upper
                // layers can decrement their own send-buffer accounting. Unlike the
                // edge-triggered BufferedAmountLow advisory below, this fires on
                // every release with the byte delta.
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountReleased {
                        id: *si,
                        n_bytes: *n_bytes_acked as usize,
                    }));
            }
            if let Some(s) = self.streams.get_mut(si)
                && s.on_buffer_released(*n_bytes_acked)
            {
                trace!("StreamEvent::BufferedAmountLow");
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountLow { id: *si }))
            }
        }
    }

    /// RFC 3758 section 3.5 C2-C4. Retain the stream map until the peer catches up.
    fn advance_peer_ack_point(&mut self) {
        let mut tsn = self.advanced_peer_tsn_ack_point.wrapping_add(1);
        while let Some(c) = self.inflight_queue.get(tsn) {
            // A late FORWARD-TSN carrying old SSNs must be stale after RX reset.
            // Bound its global TSN until the reset result retires those SSNs;
            // unrelated DATA still flows. Otherwise another stream's TSN can
            // make the old control chunk look new in a reused SID's SSN space.
            if self
                .outgoing_reset
                .as_ref()
                .is_some_and(|reset| sna32gt(tsn, reset.request.sender_last_tsn))
            {
                break;
            }
            if !c.abandoned() {
                break;
            }
            let (unordered, si, ssn) = (c.unordered, c.stream_identifier, c.stream_sequence_number);
            // Local SID reuse says nothing about the peer's SSN space. Old
            // SSNs remain necessary until its outgoing reset is confirmed.
            let current_ssn_space = self
                .confirmed_reset_tsns
                .get(&si)
                .is_none_or(|last_reset_tsn| sna32gt(tsn, *last_reset_tsn));
            self.advanced_peer_tsn_ack_point = tsn;
            if current_ssn_space {
                self.note_abandoned_for_forward_tsn(unordered, si, ssn);
            }
            tsn = tsn.wrapping_add(1);
        }
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.will_send_forward_tsn = true;
        } else {
            self.fwd_tsn_stream_map.clear();
        }
    }

    fn timed_data_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        self.use_forward_tsn
            && c.reliability
                .deadline()
                .is_some_and(|deadline| now >= deadline)
    }

    fn is_current_stream_data(&self, c: &ChunkPayloadData) -> bool {
        self.streams
            .get(&c.stream_identifier)
            .is_some_and(|s| s.generation == c.stream_generation)
    }

    /// A positive deadline can expire at any time. Timed(0) and Rexmit limits
    /// instead apply when this particular DATA is considered for retransmission.
    fn retransmission_policy_exhausted(
        &self,
        c: &ChunkPayloadData,
        now: Instant,
        is_candidate: bool,
    ) -> bool {
        if !self.use_forward_tsn {
            return false;
        }
        match c.reliability {
            MessageReliability::Reliable => false,
            MessageReliability::Timed { deadline } => now >= deadline,
            // RFC 7496 3.1: the limit excludes the first transmission and counts
            // both fast and timer-based retries. nsent includes that first send.
            MessageReliability::Rexmit { max_retransmits } => {
                is_candidate && c.nsent > max_retransmits
            }
        }
    }

    /// Select identities without changing ACK, retry or buffer state. Only a
    /// fragment selected for recovery can exhaust that message's retry budget.
    fn unretransmittable_messages(
        &self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) -> Vec<MessageToAbandon> {
        let mut messages = vec![];
        let mut selected = rustc_hash::FxHashSet::default();
        for &tsn in &self.inflight_queue.sorted {
            let c = self.inflight_queue.get(tsn).unwrap();
            if c.is_outstanding()
                && self.retransmission_policy_exhausted(c, now, is_candidate(c))
                && let Some(id) = c.message_id
                && selected.insert(id)
            {
                messages.push(MessageToAbandon {
                    id,
                    sent_tsn: Some(tsn),
                });
            }
        }
        messages
    }

    /// RFC 3758 A2/A3: abandon all fragments by identity, including Gap-ACKed
    /// siblings and an unsent tail. Each payload is released at most once.
    /// FORWARD TSN and timers are updated after the complete operation.
    fn abandon_message(&mut self, message: MessageToAbandon) -> bool {
        let whole_tsn = message.sent_tsn.filter(|&tsn| {
            self.inflight_queue.get(tsn).is_some_and(|c| {
                c.message_id == Some(message.id) && c.beginning_fragment && c.ending_fragment
            })
        });
        let mut inflight = whole_tsn.map_or_else(
            || self.inflight_queue.message_tsns(message.id),
            |tsn| vec![tsn],
        );
        let mut released_per_stream = FxHashMap::default();
        let mut changed = false;
        let tail = self.pending_queue.drain_message(message.id);
        // If a sent prefix was cumulatively acknowledged, merely forwarding its
        // old TSN is ineffective (RFC 3758 3.6). Reserve one terminal TSN for the
        // entire unsent tail so FORWARD TSN discards any incomplete peer state.
        // This is bookkeeping only: abandoned DATA is never marshalled.
        if let Some(first) = tail.first().filter(|c| !c.beginning_fragment) {
            let mut terminal = first.clone();
            terminal.stream_sequence_number = self
                .transmit_streams
                .get_mut(&first.stream_identifier)
                .unwrap()
                .abandon_tail(message.id);
            terminal.tsn = self.generate_next_tsn();
            terminal.ending_fragment = true;
            terminal.user_data = Bytes::new();
            terminal.buffer_released = true;
            terminal.mark_abandoned();
            inflight.push(terminal.tsn);
            self.inflight_queue.push_no_check(terminal);
        }
        for c in tail {
            if self.is_current_stream_data(&c) {
                *released_per_stream.entry(c.stream_identifier).or_default() +=
                    c.user_data.len() as i64;
            }
            changed = true;
        }
        for tsn in inflight {
            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                let (si, generation) = (c.stream_identifier, c.stream_generation);
                let (abandoned, released) = self.inflight_queue.abandon(tsn);
                changed |= abandoned;
                let released = released as i64;
                if released > 0
                    && self
                        .streams
                        .get(&si)
                        .is_some_and(|s| s.generation == generation)
                {
                    *released_per_stream.entry(si).or_default() += released;
                }
            }
        }
        self.release_stream_buffers(&released_per_stream);
        changed
    }

    fn on_messages_abandoned(&mut self, now: Instant) {
        self.advance_peer_ack_point();
        // RFC 3758 C5: recovery must continue even with no DATA left to retry.
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.timers
                .restart_if_stale(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
    }

    fn abandon_unretransmittable_messages(
        &mut self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) {
        let mut changed = false;
        for message in self.unretransmittable_messages(now, is_candidate) {
            changed |= self.abandon_message(message);
        }
        if changed {
            self.on_messages_abandoned(now);
        }
    }

    /// An unstarted message has consumed neither SSN nor TSN. Timed(0) is
    /// captured as Rexmit(0), preserving its first-transmission API contract.
    fn pending_message_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        self.timed_data_expired(c, now)
    }

    fn pending_message_to_abandon(&self) -> MessageToAbandon {
        MessageToAbandon {
            id: self
                .pending_queue
                .peek()
                .and_then(|c| c.message_id)
                .expect("outbound DATA has a message identity"),
            sent_tsn: None,
        }
    }

    /// pop_pending_data_chunks_to_send pops chunks from the pending queues as many as
    /// the cwnd and rwnd allows to send.
    fn pop_pending_data_chunks_to_send(
        &mut self,
        now: Instant,
    ) -> (Vec<ChunkPayloadData>, Vec<ResetMarker>) {
        let mut chunks = vec![];
        let mut sis_to_reset = vec![]; // stream identifiers to reset
        if !self.pending_queue.is_empty() {
            // No reconfiguration result can arrive during this queue drain.
            // Evaluate recovery gates once, not once per DATA fragment.
            // Common header + RE-CONFIG header + fixed outgoing-reset parameter.
            // Round the variable SID list down to a multiple of four wire bytes.
            let max_reset_streams = (self
                .mtu
                .min(COMMON_HEADER_SIZE + u16::MAX as u32)
                .saturating_sub(COMMON_HEADER_SIZE + 20)
                / 4
                * 2)
            .max(1) as usize;
            let can_start_reconfig = self.can_start_reconfig();
            // RFC 4960 sec 6.1.  Transmission of DATA Chunks
            //   A) At any given time, the data sender MUST NOT transmit new data to
            //      any destination transport address if its peer's rwnd indicates
            //      that the peer has no buffer space (i.e., rwnd is 0; see Section
            //      6.2.1).  However, regardless of the value of rwnd (including if it
            //      is 0), the data sender can always have one DATA chunk in flight to
            //      the receiver if allowed by cwnd (see rule B, below).

            loop {
                // RFC 6525 5.1.1: only one request may be in flight. Reset
                // markers live outside DATA queues, so other streams can send.
                if can_start_reconfig {
                    while sis_to_reset.len() < max_reset_streams {
                        let Some(reset) = self.pending_queue.pop_ready_reset() else {
                            break;
                        };
                        sis_to_reset.push(reset);
                    }
                }
                // Freeze Sender's Last Assigned TSN before any later DATA,
                // including a zero-window probe (RFC 6525 5.1.2 A3).
                if !sis_to_reset.is_empty() {
                    break;
                }
                let Some(c) = self.pending_queue.peek() else {
                    break;
                };
                let (beginning_fragment, unordered, data_len) =
                    (c.beginning_fragment, c.unordered, c.user_data.len());

                // RFC 3758 timed reliability: a message whose lifetime has run
                // out must be abandoned even if it was never transmitted. Doing
                // this here, ahead of the window checks and before a TSN is
                // allocated, means there is no gap for the peer to reconcile and
                // no ForwardTSN to send.
                if self.pending_message_expired(c, now) {
                    let message = self.pending_message_to_abandon();
                    if self.abandon_message(message) {
                        self.on_messages_abandoned(now);
                    }
                    continue;
                }

                if self.inflight_queue.outstanding_bytes() + data_len > self.cwnd as usize {
                    break; // would exceeds cwnd
                }

                if data_len > self.rwnd as usize {
                    break; // no more rwnd
                }

                self.rwnd -= data_len as u32;

                if let Some(chunk) = self.move_pending_data_chunk_to_inflight_queue(
                    beginning_fragment,
                    unordered,
                    now,
                ) {
                    chunks.push(chunk);
                }
            }

            // the data sender can always have one DATA chunk in flight to the receiver
            if chunks.is_empty() && sis_to_reset.is_empty() && self.inflight_queue.is_empty() {
                // Send zero window probe
                if let Some(c) = self.pending_queue.peek() {
                    let (beginning_fragment, unordered) = (c.beginning_fragment, c.unordered);

                    if let Some(chunk) = self.move_pending_data_chunk_to_inflight_queue(
                        beginning_fragment,
                        unordered,
                        now,
                    ) {
                        self.zero_window_probe = Some(chunk.tsn);
                        chunks.push(chunk);
                    }
                }
            }
        }

        (chunks, sis_to_reset)
    }

    /// bundle_data_chunks_into_packets packs DATA chunks into packets. It tries to bundle
    /// DATA chunks into a packet so long as the resulting packet size does not exceed
    /// the path MTU.
    fn bundle_data_chunks_into_packets(
        &self,
        chunks: Vec<ChunkPayloadData>,
        raw_packets: &mut Vec<Bytes>,
    ) {
        // RFC 4960 sec 6.1.  Transmission of DATA Chunks
        //   Multiple DATA chunks committed for transmission MAY be bundled in a
        //   single packet.  Furthermore, DATA chunks being retransmitted MAY be
        //   bundled with new DATA chunks, as long as the resulting packet size
        //   does not exceed the path MTU.
        //
        // Marshal each bundle straight into `raw_packets` from the borrowed
        // chunks: no intermediate `Vec<Packet>`, no `Box<dyn Chunk>` per chunk.
        // The chunks are already retained in the in-flight queue, so this send
        // copy is throwaway.
        if chunks.is_empty() {
            return;
        }
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };

        // First pass: split the chunks into MTU-bounded datagrams and total up
        // their marshalled (4-byte-padded) length. The whole burst is then
        // written into ONE buffer and `split_to` hands out each datagram as a
        // zero-copy `Bytes` view sharing that single allocation — one malloc per
        // burst instead of one per packet on the hot send path. The bundle
        // boundaries are computed once here and reused below, so the MTU-split
        // rule lives in exactly one place.
        let hdr = COMMON_HEADER_SIZE as usize;
        let mut bundles: Vec<(usize, usize)> = Vec::new();
        let mut total_len = 0usize;
        let mut bundle_start = 0;
        let mut bundle_len = hdr;
        for (i, chunk) in chunks.iter().enumerate() {
            // Marshalled chunk size: header + payload, padded up to the SCTP
            // 4-byte boundary. Bundle decisions must use this wire size —
            // deciding on raw payload sizes admitted bundles that marshalled
            // past the MTU (e.g. payloads of 1147 + 16 pass a payload-only
            // check at an MTU of 1191 but serialize to a 1208-byte packet).
            let wire =
                (DATA_CHUNK_HEADER_SIZE as usize + chunk.user_data.len()).next_multiple_of(4);
            // Close the current bundle before a chunk whose padded wire size
            // would push the datagram past the MTU.
            if bundle_len + wire > self.mtu as usize && i > bundle_start {
                bundles.push((bundle_start, i));
                total_len += bundle_len;
                bundle_start = i;
                bundle_len = hdr;
            }
            bundle_len += wire;
        }
        bundles.push((bundle_start, chunks.len()));
        total_len += bundle_len;

        // Second pass: marshal each datagram into the shared buffer.
        let mut buf = BytesMut::with_capacity(total_len);
        for (start, end) in bundles {
            match Packet::write_framed(
                &common_header,
                chunks[start..end].iter().map(|c| c as &dyn Chunk),
                &mut buf,
            ) {
                Ok(_) => {
                    let plen = buf.len();
                    raw_packets.push(buf.split_to(plen).freeze());
                }
                Err(_) => {
                    warn!("[{}] failed to serialize a DATA packet", self.side);
                    buf.clear();
                }
            }
        }
    }

    /// generate_next_tsn returns the my_next_tsn and increases it. The caller should hold the lock.
    fn generate_next_tsn(&mut self) -> u32 {
        let tsn = self.my_next_tsn;
        self.my_next_tsn = self.my_next_tsn.wrapping_add(1);
        tsn
    }

    /// generate_next_rsn returns the my_next_rsn and increases it. The caller should hold the lock.
    fn generate_next_rsn(&mut self) -> u32 {
        let rsn = self.my_next_rsn;
        self.my_next_rsn = self.my_next_rsn.wrapping_add(1);
        rsn
    }

    fn create_selective_ack_chunk(&mut self) -> ChunkSelectiveAck {
        ChunkSelectiveAck {
            cumulative_tsn_ack: self.peer_last_tsn,
            advertised_receiver_window_credit: self.get_my_receiver_window_credit(),
            gap_ack_blocks: self.payload_queue.get_gap_ack_blocks(self.peer_last_tsn),
            duplicate_tsn: self.payload_queue.pop_duplicates(),
        }
    }

    /// Record an abandoned chunk into the forward-TSN stream map (RFC 3758 C4),
    /// called from the C2 walk as `advanced_peer_tsn_ack_point` advances
    /// over each newly-abandoned in-flight chunk. Only *ordered* streams are
    /// tracked: the receiver ignores the per-stream SSN list for unordered
    /// chunks (it advances purely by `new_cumulative_tsn`). Keeps the greatest
    /// SSN seen per stream, which is the value RFC 3758 C4 requires to report.
    ///
    /// A stream's entry may briefly outlive the chunk that set it (until the
    /// window closes and the map is cleared), so a stale SSN can be re-reported;
    /// that is safe because the receiver only advances a stream forward and the
    /// SSN always corresponds to a really-abandoned chunk. The `u16` SSN compare
    /// (`sna16lt`) is sound because the window span is bounded by rwnd — a
    /// stream cannot lap the full 65536-sequence space before the window closes.
    fn note_abandoned_for_forward_tsn(&mut self, unordered: bool, si: u16, ssn: u16) {
        if unordered {
            return;
        }
        self.fwd_tsn_stream_map
            .entry(si)
            .and_modify(|cur| {
                if sna16lt(*cur, ssn) {
                    *cur = ssn;
                }
            })
            .or_insert(ssn);
    }

    /// Test-only observer for the incremental forward-TSN stream map, so the
    /// endpoint tests can assert it is cleared once the forward-TSN window
    /// closes (the C1/C3 clear paths, which the unit tests can't reach).
    #[cfg(test)]
    pub(crate) fn fwd_tsn_stream_map_is_empty(&self) -> bool {
        self.fwd_tsn_stream_map.is_empty()
    }

    /// create_forward_tsn generates ForwardTSN chunk.
    /// This method will be be called if use_forward_tsn is set to false.
    fn create_forward_tsn(&self) -> ChunkForwardTsn {
        // RFC 3758 Sec 3.5 C4: report, once per ordered stream, the greatest
        // stream-sequence-number among abandoned chunks in the forward-TSN
        // window. This is maintained incrementally in `fwd_tsn_stream_map` (see
        // its declaration and the C2 walk that feeds it), so we no longer
        // rescan `(cumulative_tsn_ack_point, advanced_peer_tsn_ack_point]` with
        // a per-TSN hashmap probe on every FORWARD-TSN — that scan was O(rwnd)
        // (~1000 probes/call for a 1 MB window) and dominated the send profile.
        let mut fwd_tsn = ChunkForwardTsn {
            new_cumulative_tsn: self.advanced_peer_tsn_ack_point,
            streams: Vec::with_capacity(self.fwd_tsn_stream_map.len()),
        };
        for (si, ssn) in &self.fwd_tsn_stream_map {
            fwd_tsn.streams.push(ChunkForwardTsnStream {
                identifier: *si,
                sequence: *ssn,
            });
        }
        // `trace!` evaluates its arguments lazily, so the stream list is only
        // formatted when trace logging is enabled -- no per-FORWARD-TSN string
        // allocation on the hot send path (this fires often for PR-SCTP data
        // channels, which is exactly where it was showing up in profiles).
        trace!(
            "[{}] building fwd_tsn: newCumulativeTSN={} cumTSN={} streams={:?}",
            self.side, fwd_tsn.new_cumulative_tsn, self.cumulative_tsn_ack_point, fwd_tsn.streams
        );

        fwd_tsn
    }

    /// Move the chunk peeked with self.pending_queue.peek() to the inflight_queue.
    fn move_pending_data_chunk_to_inflight_queue(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
        now: Instant,
    ) -> Option<ChunkPayloadData> {
        if let Some(mut c) = self.pending_queue.pop(beginning_fragment, unordered) {
            self.transmit_streams
                .entry(c.stream_identifier)
                .or_default()
                .assign_ssn(&mut c);
            c.tsn = self.generate_next_tsn();

            // RTT baseline only; the message's reliability deadline is immutable.
            c.since = Some(now);
            c.nsent = 1; // being sent for the first time

            trace!(
                "[{}] sending ppi={} tsn={} ssn={} sent={} len={} ({},{})",
                self.side,
                c.payload_type as u32,
                c.tsn,
                c.stream_sequence_number,
                c.nsent,
                c.user_data.len(),
                c.beginning_fragment,
                c.ending_fragment
            );

            self.inflight_queue.push_no_check(c.clone());

            Some(c)
        } else {
            error!("[{}] failed to pop from pending queue", self.side);
            None
        }
    }

    /// Queues the outgoing stream-reset chunk (RFC 6525).
    ///
    /// Reset markers carry a stream boundary and RX epoch; their timer starts when the
    /// immutable request is actually emitted by poll_transmit.
    pub(crate) fn send_reset_request(
        &mut self,
        _now: Instant,
        stream_identifier: StreamId,
    ) -> Result<()> {
        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrResetPacketInStateNotExist);
        }
        if !self.peer_supports_reconfig {
            return Err(Error::Other(
                "peer does not support SCTP stream reconfiguration".into(),
            ));
        }

        self.queue_reset_request(stream_identifier);
        Ok(())
    }

    fn queue_reset_request(&mut self, stream_identifier: StreamId) {
        if !self.peer_supports_reconfig {
            return;
        }
        let receive_epoch = self
            .receive_streams
            .entry(stream_identifier)
            .or_insert_with(|| ReceiveQueue::new(stream_identifier))
            .note_outgoing_reset();
        self.pending_queue.push_reset(ResetMarker {
            stream_identifier,
            receive_epoch,
        });
        self.awake_write_loop();
    }

    /// send_payload_data sends the data chunks.
    ///
    /// The queueing instant is already recorded on each chunk by `Stream::packetize`, so this
    /// does not need one of its own.
    pub(crate) fn send_payload_data(&mut self, chunks: Vec<ChunkPayloadData>) -> Result<()> {
        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrPayloadDataStateNotExist);
        }

        let id = MessageId::new(self.next_message_id);
        self.next_message_id = self
            .next_message_id
            .checked_add(1)
            .expect("association message identity exhausted");
        for mut c in chunks {
            c.message_id = Some(id);
            self.pending_queue.push(c);
        }

        self.awake_write_loop();
        Ok(())
    }

    /// buffered_amount returns total amount (in bytes) of currently buffered user data.
    /// This is used only by testing.
    pub(crate) fn buffered_amount(&self) -> usize {
        self.pending_queue.get_num_bytes() + self.inflight_queue.buffered_bytes()
    }

    fn awake_write_loop(&self) {
        // No Op on Purpose
    }

    fn close_all_timers(&mut self) {
        // Close all retransmission & ack timers
        for timer in Timer::VALUES {
            self.timers.stop(timer);
        }
    }

    fn on_ack_timeout(&mut self) {
        trace!(
            "[{}] ack timed out (ack_state: {})",
            self.side, self.ack_state
        );
        self.stats.inc_ack_timeouts();
        self.ack_state = AckState::Immediate;
        self.awake_write_loop();
    }

    fn on_retransmission_timeout(&mut self, timer_id: Timer, n_rtos: usize, now: Instant) {
        match timer_id {
            Timer::T1Init => {
                if let Err(err) = self.send_init() {
                    debug!(
                        "[{}] failed to retransmit init (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T1Cookie => {
                if let Err(err) = self.send_cookie_echo() {
                    debug!(
                        "[{}] failed to retransmit cookie-echo (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T2Shutdown => {
                debug!(
                    "[{}] retransmission of shutdown timeout (n_rtos={})",
                    self.side, n_rtos
                );
                let state = self.state();
                match state {
                    AssociationState::ShutdownSent => {
                        self.will_send_shutdown = true;
                        self.awake_write_loop();
                    }
                    AssociationState::ShutdownAckSent => {
                        self.will_send_shutdown_ack = true;
                        self.awake_write_loop();
                    }
                    _ => {}
                }
            }

            Timer::T3RTX => {
                self.stats.inc_t3timeouts();
                self.rto_mgr.backoff();
                // Refresh before C2 or mark_all_to_retrasmit reads abandoned().
                self.abandon_unretransmittable_messages(now, ChunkPayloadData::is_outstanding);

                // RFC 4960 sec 6.3.3
                //  E1)  For the destination address for which the timer expires, adjust
                //       its ssthresh with rules defined in Section 7.2.3 and set the
                //       cwnd <- MTU.
                // RFC 4960 sec 7.2.3
                //   When the T3-rtx timer expires on an address, SCTP should perform slow
                //   start by:
                //      ssthresh = max(cwnd/2, 4*MTU)
                //      cwnd = 1*MTU

                if self.zero_window_probe.is_none() {
                    self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
                    self.cwnd = self.mtu;
                }
                trace!(
                    "[{}] updated cwnd={} ssthresh={} inflight={} (RTO)",
                    self.side,
                    self.cwnd,
                    self.ssthresh,
                    self.inflight_queue.outstanding_bytes()
                );

                // RFC 3758 sec 3.5
                //  A5) Any time the T3-rtx timer expires, on any destination, the sender
                //  SHOULD try to advance the "Advanced.Peer.Ack.Point" by following
                //  the procedures outlined in C2 - C5.
                if self.use_forward_tsn {
                    self.advance_peer_ack_point();
                }

                debug!(
                    "[{}] T3-rtx timed out: n_rtos={} cwnd={} ssthresh={}",
                    self.side, n_rtos, self.cwnd, self.ssthresh
                );

                self.inflight_queue.mark_all_to_retrasmit();
                self.t3_retransmit_pending = true;
                self.awake_write_loop();
            }

            Timer::Reconfig => {
                self.will_retransmit_reconfig = true;
                self.awake_write_loop();
            }

            _ => {}
        }
    }

    fn on_retransmission_failure(&mut self, id: Timer) {
        match id {
            Timer::T1Init => {
                error!("[{}] retransmission failure: T1-init", self.side);
                self.error = Some(AssociationError::HandshakeFailed(
                    Error::ErrHandshakeInitAck.to_string(),
                ));
            }

            Timer::T1Cookie => {
                error!("[{}] retransmission failure: T1-cookie", self.side);
                self.error = Some(AssociationError::HandshakeFailed(
                    Error::ErrHandshakeCookieEcho.to_string(),
                ));
            }

            Timer::T2Shutdown => {
                error!("[{}] retransmission failure: T2-shutdown", self.side);
            }

            Timer::T3RTX => {
                // A configured finite recovery budget must end the association,
                // not leave reliable DATA stranded with no timer (RFC 9260 8.1).
                error!("[{}] retransmission failure: T3-rtx (DATA)", self.side);
                let _ = self.close(AssociationError::TimedOut);
            }

            Timer::Reconfig => {
                error!("[{}] retransmission failure: RE-CONFIG", self.side);
                // A request without a timer would block all subsequent resets.
                self.outgoing_reset = None;
                self.will_retransmit_reconfig = false;
                let _ = self.close(AssociationError::TimedOut);
            }

            _ => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn expected_reset_sequence(&self) -> u32 {
        self.incoming_resets.next_expected_rsn()
    }

    /// Whether no timers are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        self.poll_timeout().is_none()
    }
}
