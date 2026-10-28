use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, STUNMessage, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::statistics::accumulator::RTCStatsAccumulator;
use crate::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage};
use std::collections::VecDeque;
use std::time::Instant;

pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: IceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// Cached stats key of the currently selected ICE candidate pair
    /// (`RTCIceCandidatePair_<local>_<remote>`), refreshed only when the selected
    /// pair changes. The per-packet read/write path looks the pair's stats
    /// accumulator up with this key instead of re-`format!`ing it on every packet
    /// — that formatting was a heap allocation on the hot path in both directions.
    pub(crate) selected_pair_key: Option<String>,
}

impl IceHandlerContext {
    pub(crate) fn new(ice_transport: IceTransport) -> Self {
        Self {
            ice_transport,

            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),

            selected_pair_key: None,
        }
    }
}

/// IceHandler implements ICE Protocol handling
pub(crate) struct IceHandler<'a> {
    ctx: &'a mut IceHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> IceHandler<'a> {
    pub(crate) fn new(ctx: &'a mut IceHandlerContext, stats: &'a mut RTCStatsAccumulator) -> Self {
        IceHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "IceHandler"
    }
}

/// Where the ICE agent has the selected candidate pair send from and to.
#[derive(Clone, Copy)]
struct Route {
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    transport_protocol: shared::TransportProtocol,
}

impl super::WriteBypass for IceHandler<'_> {
    fn write_in_place(&mut self, pending: &mut VecDeque<TaggedRTCMessageInternal>) -> bool {
        if !self.ctx.write_outs.is_empty() {
            return false;
        }
        match self.selected_route() {
            Some(route) => {
                for msg in pending.iter_mut() {
                    self.stamp(msg, route);
                }
            }
            None => {
                for msg in pending.drain(..) {
                    trace!(
                        "drop message from {:?} to {:?} before ICE connection is connected",
                        msg.transport.local_addr, msg.transport.peer_addr,
                    );
                }
            }
        }
        self.queue_agent_transmits(pending);
        true
    }
}

impl IceHandler<'_> {
    fn selected_route(&self) -> Option<Route> {
        let (local, remote) = self.ctx.ice_transport.agent.get_selected_candidate_pair()?;
        // Use the local candidate's base address: for (server/peer-)
        // reflexive candidates the candidate address is the NAT mapping,
        // not a bound local socket (RFC 8445 §5.1.1).
        Some(Route {
            local_addr: local.base_addr(),
            peer_addr: remote.addr(),
            transport_protocol: local.network_type().to_protocol(),
        })
    }

    /// Addresses `msg` with the selected candidate pair and counts it.
    ///
    /// The pair replaces local/peer addr and transport protocol: DTLS/SCTP endpoints run on
    /// placeholder transport contexts, so without the protocol rewrite their transmits stay
    /// stamped UDP even when the selected pair is TCP, and consumers routing poll_write() output by
    /// transport_protocol send every non-STUN packet down the wrong transport.
    fn stamp(&mut self, msg: &mut TaggedRTCMessageInternal, route: Route) {
        msg.transport.local_addr = route.local_addr;
        msg.transport.peer_addr = route.peer_addr;
        msg.transport.transport_protocol = route.transport_protocol;
        debug!("Bypass ice write {:?}", msg.transport.peer_addr);

        // Track packets/bytes sent on the selected candidate pair. Look the
        // accumulator up via the cached key to avoid allocating it per packet.
        let bytes = msg.message.len();
        if let Some(key) = &self.ctx.selected_pair_key
            && let Some(pair) = self.stats.ice_candidate_pairs.get_mut(key)
        {
            pair.on_packet_sent(bytes, msg.now);
        }
    }

    /// Puts what the agent has to send at the front of `queue`, in its own order.
    ///
    /// Control-plane first. The agent's transmits — an ICE nomination, a consent check
    /// — must reach the peer before any data-plane packet the pipeline already queued
    /// ahead of this call. The one that matters: the first DTLS ClientHello is queued
    /// the instant the controlling side selects (its own nomination's success
    /// response), and if it overtakes the nomination's USE-CANDIDATE request on the
    /// wire, the peer has not set its selected pair yet and drops it — a full
    /// retransmit cycle of otherwise-dead connect latency. Front-insertion keeps the
    /// agent's traffic first while preserving its own order.
    fn queue_agent_transmits(&mut self, queue: &mut VecDeque<TaggedRTCMessageInternal>) {
        use sansio::Protocol;

        let mut agent_transmits = Vec::new();
        while let Some(transmit) = self.ctx.ice_transport.agent.poll_write() {
            agent_transmits.push(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Stun(STUNMessage::Raw(transmit.message)),
            });
        }
        for message in agent_transmits.into_iter().rev() {
            queue.push_front(message);
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for IceHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Stun(STUNMessage::Raw(message)) = msg.message {
            self.ctx.ice_transport.agent.handle_read(TransportMessage {
                now: msg.now,
                transport: msg.transport,
                message,
            })?;
        } else if self
            .ctx
            .ice_transport
            .agent
            .get_selected_candidate_pair()
            .is_some()
        {
            // only ICE connection is ready and bypass it
            debug!("bypass ice read {:?}", msg.transport.peer_addr);

            // Track packets/bytes received on the selected candidate pair. Look
            // the accumulator up via the cached key (set on the last
            // SelectedCandidatePairChange) to avoid allocating the key per packet.
            let bytes = msg.message.len();
            if let Some(key) = &self.ctx.selected_pair_key
                && let Some(pair) = self.stats.ice_candidate_pairs.get_mut(key)
            {
                pair.on_packet_received(bytes, msg.now);
            }

            // When ICE restarts and the selected candidate pair changes,
            // WebRTC treats this as a path migration, and DTLS continues unchanged, bound to the ICE transport, not to a fixed 5-tuple.
            // Use default for transport to make DTLS tunneled
            msg.transport = TransportContext::default();
            self.ctx.read_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.peer_addr, msg.transport.local_addr
            );
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        match self.selected_route() {
            Some(route) => {
                self.stamp(&mut msg, route);
                self.ctx.write_outs.push_back(msg);
            }
            None => trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.local_addr, msg.transport.peer_addr,
            ),
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        let mut write_outs = std::mem::take(&mut self.ctx.write_outs);
        self.queue_agent_transmits(&mut write_outs);
        self.ctx.write_outs = write_outs;
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        if let Some(evt) = self.ctx.ice_transport.agent.poll_event() {
            // The agent stamps its own events, so this drain *propagates* that instant rather
            // than retaining one: the condition was observed when the agent saw it, not when
            // the pipeline got round to polling for it.
            let now = evt.now;
            match evt.event {
                ::ice::Event::ConnectionStateChange(state) => {
                    let ice_connection_state = state.into();
                    self.ctx.ice_transport.ice_connection_state = ice_connection_state;

                    // Update transport stats for ICE state change
                    // Use the original ice state which converts to RTCIceTransportState
                    self.stats.transport.on_ice_state_changed(state.into());

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                                ice_connection_state,
                            ),
                        ),
                    });
                }
                ::ice::Event::SelectedCandidatePairChange(local, remote) => {
                    debug!(
                        "ice selected candidate pair {:?} <-> {:?}",
                        local.addr(),
                        remote.addr()
                    );

                    // Create/update the candidate pair accumulator
                    let pair = self
                        .stats
                        .get_or_create_candidate_pair(local.id(), remote.id());
                    pair.nominated = true;
                    pair.state = RTCStatsIceCandidatePairState::Succeeded;

                    // Cache the pair's stats key so the per-packet path can look
                    // the accumulator up by borrow instead of re-formatting (and
                    // allocating) the key on every read/write.
                    let key = format!("RTCIceCandidatePair_{}_{}", local.id(), remote.id());
                    self.ctx.selected_pair_key = Some(key.clone());
                    // Update transport stats for selected candidate pair change
                    self.stats.transport.on_selected_candidate_pair_changed(key);

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::ICESelectedCandidatePairChange,
                    });
                }
                ::ice::Event::RoleChange(is_controlling) => {
                    self.stats.transport.on_ice_role_changed(is_controlling);
                }
                _ => {}
            }
        }

        super::pop_event(&mut self.ctx.event_outs)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.ice_transport.agent.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.ctx.ice_transport.agent.poll_timeout()
    }

    fn close(&mut self) -> Result<()> {
        self.ctx.ice_transport.agent.close()
    }
}
