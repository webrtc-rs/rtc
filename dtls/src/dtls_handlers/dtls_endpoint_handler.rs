use retty::channel::{Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler};
use retty::transport::{TaggedBytesMut, TransportContext};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use crate::config::HandshakeConfig;
use crate::endpoint::{Endpoint, EndpointEvent};
use crate::state::State;
use shared::error::{Error, Result};

struct DtlsEndpointInboundHandler {
    local_addr: SocketAddr,
    endpoint: Rc<RefCell<Endpoint>>,

    //Client only
    initial_state: Option<State>,
    client_config: Option<HandshakeConfig>,
    peer_addr: Option<SocketAddr>,
}
struct DtlsEndpointOutboundHandler {
    local_addr: SocketAddr,
    endpoint: Rc<RefCell<Endpoint>>,
}
pub struct DtlsEndpointHandler {
    inbound: DtlsEndpointInboundHandler,
    outbound: DtlsEndpointOutboundHandler,
}

impl DtlsEndpointHandler {
    pub fn new(
        local_addr: SocketAddr,
        handshake_config: HandshakeConfig,
        //Client only
        is_client: bool,
        peer_addr: Option<SocketAddr>,
        initial_state: Option<State>,
    ) -> Self {
        let (endpoint, client_config) = if is_client {
            (Endpoint::new(None), Some(handshake_config))
        } else {
            (Endpoint::new(Some(handshake_config)), None)
        };
        let endpoint = Rc::new(RefCell::new(endpoint));

        DtlsEndpointHandler {
            inbound: DtlsEndpointInboundHandler {
                local_addr,
                endpoint: Rc::clone(&endpoint),

                //Client only
                initial_state,
                client_config,
                peer_addr,
            },
            outbound: DtlsEndpointOutboundHandler {
                local_addr,
                endpoint,
            },
        }
    }
}

impl InboundHandler for DtlsEndpointInboundHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn transport_active(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        if self.client_config.is_some() {
            let mut try_dtls_active = || -> Result<()> {
                let mut endpoint = self.endpoint.borrow_mut();
                endpoint.connect(
                    self.peer_addr
                        .take()
                        .ok_or(Error::ErrClientTransportNotSet)?,
                    self.client_config.take().ok_or(Error::NoClientConfig)?,
                    self.initial_state.take(),
                )?;

                Ok(())
            };
            if let Err(err) = try_dtls_active() {
                ctx.fire_read_exception(Box::new(err));
            }
            handle_outgoing(ctx, &self.endpoint, self.local_addr);
        }

        ctx.fire_transport_active();
    }

    fn transport_inactive(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>) {
        ctx.fire_transport_inactive();
    }

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        let try_dtls_read = || -> Result<Vec<EndpointEvent>> {
            let mut endpoint = self.endpoint.borrow_mut();
            let messages = endpoint.read(
                msg.now,
                msg.transport.peer_addr,
                Some(msg.transport.local_addr.ip()),
                msg.transport.ecn,
                msg.message,
            )?;
            Ok(messages)
        };
        match try_dtls_read() {
            Ok(messages) => {
                for message in messages {
                    match message {
                        EndpointEvent::HandshakeComplete => {}
                        EndpointEvent::ApplicationData(message) => {
                            ctx.fire_read(TaggedBytesMut {
                                now: msg.now,
                                transport: msg.transport,
                                message,
                            });
                        }
                    }
                }
            }
            Err(err) => ctx.fire_read_exception(Box::new(err)),
        };
        handle_outgoing(ctx, &self.endpoint, msg.transport.local_addr);
    }

    fn handle_timeout(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, now: Instant) {
        let try_dtls_timeout = || -> Result<()> {
            let mut endpoint = self.endpoint.borrow_mut();
            let remotes: Vec<SocketAddr> = endpoint.get_connections_keys().copied().collect();
            for remote in remotes {
                let _ = endpoint.handle_timeout(remote, now);
                //TODO: timeout errors
            }
            Ok(())
        };
        if let Err(err) = try_dtls_timeout() {
            ctx.fire_read_exception(Box::new(err));
        }
        handle_outgoing(ctx, &self.endpoint, self.local_addr);

        ctx.fire_handle_timeout(now);
    }

    fn poll_timeout(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, eto: &mut Instant) {
        {
            let endpoint = self.endpoint.borrow();
            let remotes = endpoint.get_connections_keys();
            for remote in remotes {
                let _ = endpoint.poll_timeout(*remote, eto);
            }
        }
        ctx.fire_poll_timeout(eto);
    }
}

impl OutboundHandler for DtlsEndpointOutboundHandler {
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, msg: Self::Win) {
        let try_dtls_write = || -> Result<()> {
            let mut endpoint = self.endpoint.borrow_mut();
            endpoint.write(msg.transport.peer_addr, &msg.message)
        };
        if let Err(err) = try_dtls_write() {
            ctx.fire_write_exception(Box::new(err));
        }
        handle_outgoing(ctx, &self.endpoint, msg.transport.local_addr);
    }

    fn close(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>) {
        {
            let mut endpoint = self.endpoint.borrow_mut();
            let remotes: Vec<SocketAddr> = endpoint.get_connections_keys().copied().collect();
            for remote in remotes {
                let _ = endpoint.close(remote);
            }
        }
        handle_outgoing(ctx, &self.endpoint, self.local_addr);

        ctx.fire_close();
    }
}

impl Handler for DtlsEndpointHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "DtlsEndpointHandler"
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

fn handle_outgoing(
    ctx: &OutboundContext<TaggedBytesMut, TaggedBytesMut>,
    endpoint: &Rc<RefCell<Endpoint>>,
    local_addr: SocketAddr,
) {
    let mut transmits = vec![];
    {
        let mut e = endpoint.borrow_mut();
        while let Some(transmit) = e.poll_transmit() {
            transmits.push(transmit);
        }
    };
    for transmit in transmits {
        ctx.fire_write(TaggedBytesMut {
            now: transmit.now,
            transport: TransportContext {
                local_addr,
                peer_addr: transmit.remote,
                ecn: transmit.ecn,
            },
            message: transmit.payload,
        });
    }
}
