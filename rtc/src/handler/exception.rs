use crate::messages::TaggedMessageEvent;
use log::error;
use shared::{Context, Handler};
use std::error::Error;

/// ExceptionHandler implements exception handling for inbound or outbound directions
#[derive(Default)]
pub struct ExceptionHandler;

impl ExceptionHandler {
    pub fn new() -> Self {
        ExceptionHandler
    }
}

impl Handler for ExceptionHandler {
    type Rin = TaggedMessageEvent;
    type Rout = TaggedMessageEvent;
    type Win = TaggedMessageEvent;
    type Wout = TaggedMessageEvent;

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
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        err: Box<dyn Error>,
    ) {
        error!("ExceptionHandler::read_exception {}", err);
        ctx.fire_handle_error(err);
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        ctx.fire_poll_write()
    }
}
