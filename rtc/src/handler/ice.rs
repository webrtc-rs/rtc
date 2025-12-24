use std::collections::VecDeque;
use std::time::Instant;

use super::message::{RTCEventInternal, RTCMessage, STUNMessage, TaggedRTCMessage};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::transport::ice::RTCIceTransport;
use crate::transport::TransportStates;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::TransportMessage;

#[derive(Default)]
pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: RTCIceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
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
    transport_states: &'a mut TransportStates,
    ctx: &'a mut IceHandlerContext,
}

impl<'a> IceHandler<'a> {
    pub(crate) fn new(
        transport_states: &'a mut TransportStates,
        ctx: &'a mut IceHandlerContext,
    ) -> Self {
        IceHandler {
            transport_states,
            ctx,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "IceHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal> for IceHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Stun(STUNMessage::Raw(message)) = msg.message {
            self.ctx.ice_transport.agent.handle_read(TransportMessage {
                now: msg.now,
                transport: msg.transport,
                message,
            })?;
        } else {
            // Bypass
            debug!("bypass ice read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedRTCMessage) -> Result<()> {
        let candidate_pair_opt = if let Some((local, remote)) =
            self.ctx.ice_transport.agent.get_selected_candidate_pair()
        {
            Some((local, remote))
        } else if let Some((local, remote)) = self
            .ctx
            .ice_transport
            .agent
            .get_best_available_candidate_pair()
        {
            Some((local, remote))
        } else {
            None
        };

        if let Some((local, remote)) = candidate_pair_opt {
            // use ICE selected or best available candidate pair to replace local/peer addr
            msg.transport.local_addr = local.addr();
            msg.transport.peer_addr = remote.addr();
            debug!("Bypass ice write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.peer_addr,
                msg.transport.local_addr
            );
        }

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        while let Some(transmit) = self.ctx.ice_transport.agent.poll_write() {
            self.ctx.write_outs.push_back(TaggedRTCMessage {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessage::Stun(STUNMessage::Raw(transmit.message)),
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
                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state.into()),
                        ));
                }
                ::ice::Event::SelectedCandidatePairChange(local, remote) => {
                    self.ctx.event_outs.push_back(
                        RTCEventInternal::ICESelectedCandidatePairChange(local, remote),
                    );
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
