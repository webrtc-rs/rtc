use std::collections::VecDeque;
use std::time::Instant;

use super::message::{RTCEventInternal, TaggedRTCMessage};
use crate::transport::ice::RTCIceTransport;
use log::debug;
use shared::error::{Error, Result};

#[derive(Default)]
pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: RTCIceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
}

impl IceHandlerContext {
    pub(crate) fn new(ice_transport: RTCIceTransport) -> Self {
        Self {
            ice_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
        }
    }
}

/// IceHandler implements ICE Protocol handling
pub(crate) struct IceHandler<'a> {
    ctx: &'a mut IceHandlerContext,
}

impl<'a> IceHandler<'a> {
    pub(crate) fn new(ctx: &'a mut IceHandlerContext) -> Self {
        IceHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "IceHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, RTCEventInternal> for IceHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        // Bypass
        debug!("bypass ice read {:?}", msg.transport.peer_addr);
        self.ctx.read_outs.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        // Bypass
        debug!("Bypass ice write {:?}", msg.transport.peer_addr);
        self.ctx.write_outs.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: RTCEventInternal) -> Result<()> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
