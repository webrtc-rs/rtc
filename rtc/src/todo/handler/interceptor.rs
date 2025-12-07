use crate::interceptor::InterceptorEvent;
use crate::messages::{MessageEvent, RTPMessageEvent, TaggedMessageEvent};
use crate::types::FourTuple;
use crate::ServerStates;
use log::{debug, error};
use shared::error::Result;
use shared::{Context, Handler};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Instant;

/// InterceptorHandler implements RTCP feedback handling
pub struct InterceptorHandler {
    server_states: Rc<RefCell<ServerStates>>,
    transmits: VecDeque<TaggedMessageEvent>,
}

impl InterceptorHandler {
    pub fn new(server_states: Rc<RefCell<ServerStates>>) -> Self {
        Self {
            server_states,
            transmits: VecDeque::new(),
        }
    }
}

impl Handler for InterceptorHandler {
    type Rin = TaggedMessageEvent;
    type Rout = Self::Rin;
    type Win = TaggedMessageEvent;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "InterceptorHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        mut msg: Self::Rin,
    ) {
        if let MessageEvent::Rtp(RTPMessageEvent::Rtp(_))
        | MessageEvent::Rtp(RTPMessageEvent::Rtcp(_)) = &msg.message
        {
            let mut try_read = || -> Result<Vec<InterceptorEvent>> {
                let mut server_states = self.server_states.borrow_mut();
                let four_tuple = (&msg.transport).into();
                let endpoint = server_states.get_mut_endpoint(&four_tuple)?;
                let interceptor = endpoint.get_mut_interceptor();
                Ok(interceptor.read(&mut msg))
            };

            match try_read() {
                Ok(events) => {
                    for event in events {
                        match event {
                            InterceptorEvent::Inbound(inbound) => {
                                debug!("interceptor forward Rtcp {:?}", msg.transport.peer_addr);
                                ctx.fire_handle_read(inbound);
                            }
                            InterceptorEvent::Outbound(outbound) => {
                                self.transmits.push_back(outbound);
                            }
                            InterceptorEvent::Error(err) => {
                                error!("try_read got error {}", err);
                                ctx.fire_handle_error(err);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    ctx.fire_handle_error(Box::new(err))
                }
            };

            if let MessageEvent::Rtp(RTPMessageEvent::Rtcp(_)) = &msg.message {
                // RTCP message read must end here in SFU case. If any rtcp packet needs to be forwarded to other Endpoints,
                // just add a new interceptor to forward it.
                debug!("interceptor terminates Rtcp {:?}", msg.transport.peer_addr);
                return;
            }
        }

        debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
        ctx.fire_handle_read(msg);
    }

    fn handle_timeout(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        now: Instant,
    ) {
        let try_handle_timeout = || -> Result<Vec<InterceptorEvent>> {
            let mut interceptor_events = vec![];

            let mut server_states = self.server_states.borrow_mut();
            let sessions = server_states.get_mut_sessions();
            for session in sessions.values_mut() {
                let endpoints = session.get_mut_endpoints();
                for endpoint in endpoints.values_mut() {
                    #[allow(clippy::map_clone)]
                    let four_tuples: Vec<FourTuple> = endpoint
                        .get_transports()
                        .keys()
                        .map(|four_tuple| *four_tuple)
                        .collect();
                    let interceptor = endpoint.get_mut_interceptor();
                    let mut events = interceptor.handle_timeout(now, &four_tuples);
                    interceptor_events.append(&mut events);
                }
            }

            Ok(interceptor_events)
        };

        match try_handle_timeout() {
            Ok(events) => {
                for event in events {
                    match event {
                        InterceptorEvent::Inbound(_) => {
                            error!("unexpected inbound message from try_handle_timeout");
                        }
                        InterceptorEvent::Outbound(outbound) => {
                            self.transmits.push_back(outbound);
                        }
                        InterceptorEvent::Error(err) => {
                            error!("try_read got error {}", err);
                            ctx.fire_handle_error(err);
                        }
                    }
                }
            }
            Err(err) => {
                error!("try_handle_timeout with error {}", err);
                ctx.fire_handle_error(Box::new(err))
            }
        }

        ctx.fire_handle_timeout(now);
    }

    fn poll_timeout(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        eto: &mut Instant,
    ) {
        {
            let mut server_states = self.server_states.borrow_mut();
            let sessions = server_states.get_mut_sessions();
            for session in sessions.values_mut() {
                let endpoints = session.get_mut_endpoints();
                for endpoint in endpoints.values_mut() {
                    let interceptor = endpoint.get_mut_interceptor();
                    interceptor.poll_timeout(eto)
                }
            }
        }

        ctx.fire_poll_timeout(eto);
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(mut msg) = ctx.fire_poll_write() {
            if let MessageEvent::Rtp(RTPMessageEvent::Rtp(_))
            | MessageEvent::Rtp(RTPMessageEvent::Rtcp(_)) = &msg.message
            {
                let mut try_write = || -> Result<Vec<InterceptorEvent>> {
                    let mut server_states = self.server_states.borrow_mut();
                    let four_tuple = (&msg.transport).into();
                    let endpoint = server_states.get_mut_endpoint(&four_tuple)?;
                    let interceptor = endpoint.get_mut_interceptor();
                    Ok(interceptor.write(&mut msg))
                };

                match try_write() {
                    Ok(events) => {
                        for event in events {
                            match event {
                                InterceptorEvent::Inbound(_) => {
                                    error!("unexpected inbound message from try_write");
                                }
                                InterceptorEvent::Outbound(outbound) => {
                                    self.transmits.push_back(outbound);
                                }
                                InterceptorEvent::Error(err) => {
                                    error!("try_write got error {}", err);
                                    ctx.fire_handle_error(err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("try_write with error {}", err);
                        ctx.fire_handle_error(Box::new(err))
                    }
                };
            }

            debug!("interceptor write {:?}", msg.transport.peer_addr);
            self.transmits.push_back(msg);
        }

        self.transmits.pop_front()
    }
}
