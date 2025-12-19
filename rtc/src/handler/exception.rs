use super::message::TaggedRTCMessage;
use log::error;
use shared::{Context, Handler};
use std::error::Error;
use std::time::Instant;

/// ExceptionHandler implements exception handling for inbound or outbound directions
#[derive(Default)]
pub struct ExceptionHandler;

impl ExceptionHandler {
    pub fn new() -> Self {
        ExceptionHandler
    }
}

impl Handler for ExceptionHandler {
    type Rin = TaggedRTCMessage;
    type Rout = TaggedRTCMessage;
    type Win = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;

    fn name(&self) -> &str {
        "ExceptionHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
        ctx.fire_handle_read(msg);
    }

    fn handle_error(
        &mut self,
        _ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        err: Box<dyn Error>,
    ) {
        error!("ExceptionHandler::read_exception {}", err);
        // terminate timeout here, no more ctx.fire_handle_error(err);
    }

    fn handle_timeout(
        &mut self,
        _ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        _now: Instant,
    ) {
        // terminate timeout here, no more ctx.fire_handle_timeout(now);
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        ctx.fire_poll_write()
    }
}
