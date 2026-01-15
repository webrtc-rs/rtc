use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, STUNMessage, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::ice::RTCIceTransport;
use crate::statistics::accumulator::RTCStatsAccumulator;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: RTCIceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

impl IceHandlerContext {
    pub(crate) fn new(ice_transport: RTCIceTransport) -> Self {
        Self {
            ice_transport,

            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
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

impl<'a> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for IceHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
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

            // Update transport stats for received packet
            if let RTCMessageInternal::Raw(ref raw) = msg.message {
                self.stats.transport.on_packet_received(raw.len());
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
        if let Some((local, remote)) = self.ctx.ice_transport.agent.get_selected_candidate_pair() {
            // use ICE selected candidate pair to replace local/peer addr
            msg.transport.local_addr = local.addr();
            msg.transport.peer_addr = remote.addr();
            debug!("Bypass ice write {:?}", msg.transport.peer_addr);

            // Update transport stats for sent packet
            if let RTCMessageInternal::Raw(ref raw) = msg.message {
                self.stats.transport.on_packet_sent(raw.len());
            }

            self.ctx.write_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.local_addr, msg.transport.peer_addr,
            );
        }

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        while let Some(transmit) = self.ctx.ice_transport.agent.poll_write() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Stun(STUNMessage::Raw(transmit.message)),
            });
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        if let Some(evt) = self.ctx.ice_transport.agent.poll_event() {
            match evt {
                ::ice::Event::ConnectionStateChange(state) => {
                    let ice_connection_state = state.into();
                    self.ctx.ice_transport.ice_connection_state = ice_connection_state;

                    // Update transport stats for ICE state change
                    // Use the original ice state which converts to RTCIceTransportState
                    self.stats.transport.on_ice_state_changed(state.into());

                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                                ice_connection_state,
                            ),
                        ));
                }
                ::ice::Event::SelectedCandidatePairChange(local, remote) => {
                    debug!(
                        "ice selected candidate pair {:?} <-> {:?}",
                        local.addr(),
                        remote.addr()
                    );

                    // Update transport stats for selected candidate pair change
                    let pair_id = format!("{}_{}", local.foundation(), remote.foundation());
                    self.stats
                        .transport
                        .on_selected_candidate_pair_changed(pair_id);

                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::ICESelectedCandidatePairChange);
                }
            }
        }

        self.ctx.event_outs.pop_front()
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
