use retty::channel::{Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler};
use retty::transport::{TaggedBytesMut, TransportContext};
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;
use std::time::Instant;

use crate::conn::DTLSConn;
use crate::handshaker::HandshakeConfig;
use crate::state::State;
use bytes::BytesMut;
use shared::error::Result;

struct DtlsInboundHandler {
    transport: Option<TransportContext>,
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
        client_transport: Option<TransportContext>,
        initial_state: Option<State>,
    ) -> Self {
        let conn = Rc::new(RefCell::new(DTLSConn::new(
            handshake_config,
            is_client,
            initial_state,
        )));

        DtlsHandler {
            inbound: DtlsInboundHandler {
                transport: client_transport,
                conn: Rc::clone(&conn),
            },
            outbound: DtlsOutboundHandler { conn },
        }
    }
}

impl DtlsInboundHandler {
    fn handle_outgoing(&mut self, ctx: &InboundContext<TaggedBytesMut, TaggedBytesMut>) {
        if let Some(transport) = &self.transport {
            let mut outgoing_raw_packets = vec![];
            {
                let mut conn = self.conn.borrow_mut();
                while let Some(pkt) = conn.outgoing_raw_packet() {
                    outgoing_raw_packets.push(pkt);
                }
            };
            for message in outgoing_raw_packets {
                ctx.fire_write(TaggedBytesMut {
                    now: Instant::now(),
                    transport: *transport,
                    message,
                });
            }
        }
    }
}

impl InboundHandler for DtlsInboundHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn transport_active(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        let try_dtls_active = || -> Result<()> {
            let mut conn = self.conn.borrow_mut();
            conn.handshake()
        };
        if let Err(err) = try_dtls_active() {
            ctx.fire_read_exception(Box::new(err));
        }
        self.handle_outgoing(ctx);

        ctx.fire_transport_active();
    }

    fn transport_inactive(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_transport_inactive();
    }

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        if self.transport.is_none() {
            self.transport = Some(msg.transport);
        }

        let try_dtls_read = || -> Result<Vec<BytesMut>> {
            let mut messages = vec![];
            let mut conn = self.conn.borrow_mut();
            conn.read_and_buffer(&msg.message)?;
            if !conn.is_handshake_completed() {
                conn.handshake()?;
                conn.handle_queued_packets()?;
            }
            while let Some(message) = conn.incoming_application_data() {
                messages.push(message);
            }
            Ok(messages)
        };
        match try_dtls_read() {
            Ok(messages) => {
                for message in messages {
                    ctx.fire_read(TaggedBytesMut {
                        now: msg.now,
                        transport: msg.transport,
                        message,
                    })
                }
            }
            Err(err) => ctx.fire_read_exception(Box::new(err)),
        };
        self.handle_outgoing(ctx);
    }

    fn read_exception(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, err: Box<dyn Error>) {
        ctx.fire_read_exception(err);
    }

    fn read_eof(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_read_eof();
    }

    fn handle_timeout(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, now: Instant) {
        let try_dtls_timeout = || -> Result<()> {
            let mut conn = self.conn.borrow_mut();
            if !conn.is_handshake_completed() {
                conn.handshake_timeout(now)?
            }
            Ok(())
        };
        if let Err(err) = try_dtls_timeout() {
            ctx.fire_read_exception(Box::new(err));
        }
        self.handle_outgoing(ctx);

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
