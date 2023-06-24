use retty::channel::{Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler};
use retty::transport::TaggedBytesMut;
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;
use std::time::Instant;

use crate::conn::DTLSConn;
use crate::handshaker::HandshakeConfig;
use crate::state::State;

struct DtlsInboundHandler {
    conn: Rc<RefCell<DTLSConn>>,
}
struct DtlsOutboundHandler {
    conn: Rc<RefCell<DTLSConn>>,
}
struct DtlsHandler {
    inbound: DtlsInboundHandler,
    outbound: DtlsOutboundHandler,
}

impl DtlsHandler {
    fn new(
        handshake_config: HandshakeConfig,
        is_client: bool,
        initial_state: Option<State>,
    ) -> Self {
        let conn = Rc::new(RefCell::new(DTLSConn::new(
            handshake_config,
            is_client,
            initial_state,
        )));

        DtlsHandler {
            inbound: DtlsInboundHandler {
                conn: Rc::clone(&conn),
            },
            outbound: DtlsOutboundHandler { conn },
        }
    }
}

impl InboundHandler for DtlsInboundHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn transport_active(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_transport_active();

        let result = {
            let mut conn = self.conn.borrow_mut();
            conn.handshake()
        };
        if let Err(err) = result {
            ctx.fire_read_exception(Box::new(err));
        } //TODO: ctx.fire_write()
    }

    fn transport_inactive(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_transport_inactive();
    }

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        ctx.fire_read(msg);
    }

    fn read_exception(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, err: Box<dyn Error>) {
        ctx.fire_read_exception(err);
    }

    fn read_eof(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_read_eof();
    }

    fn handle_timeout(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, now: Instant) {
        let result = {
            let mut conn = self.conn.borrow_mut();
            if !conn.is_handshake_completed() {
                conn.handshake_timeout(now)
            } else {
                Ok(())
            }
        };
        if let Err(err) = result {
            ctx.fire_read_exception(Box::new(err));
        } //TODO: ctx.fire_write()

        ctx.fire_handle_timeout(now);
    }

    fn poll_timeout(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, eto: &mut Instant) {
        let current_eto = {
            let conn = self.conn.borrow();
            conn.current_retransmit_timer
        };
        if let Some(current_eto) = current_eto {
            if current_eto < *eto {
                *eto = current_eto;
            }
        };
        ctx.fire_poll_timeout(eto);
    }
}

impl OutboundHandler for DtlsOutboundHandler {
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, msg: Self::Win) {
        ctx.fire_write(msg);
    }

    fn write_exception(
        &mut self,
        ctx: &OutboundContext<Self::Win, Self::Wout>,
        err: Box<dyn Error>,
    ) {
        ctx.fire_write_exception(err);
    }

    fn close(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>) {
        ctx.fire_close();
    }
}

impl Handler for DtlsHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "DtlsHandler"
    }

    fn split(
        self,
    ) -> (
        Box<dyn InboundHandler<Rin = Self::Rin, Rout = Self::Rout>>,
        Box<dyn OutboundHandler<Win = Self::Win, Wout = Self::Wout>>,
    ) {
        (Box::new(self.inbound), Box::new(self.outbound))
    }
}
