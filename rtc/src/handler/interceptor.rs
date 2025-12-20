use super::message::{RTCMessage, RTPMessage, TaggedRTCMessage};
use log::debug;
use shared::error::{Error, Result};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct InterceptorHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a> {
    ctx: &'a mut InterceptorHandlerContext,
}

impl<'a> InterceptorHandler<'a> {
    pub(crate) fn new(ctx: &'a mut InterceptorHandlerContext) -> Self {
        InterceptorHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "InterceptorHandler"
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, ()> for InterceptorHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Rtp(RTPMessage::Rtp(_)) | RTCMessage::Rtp(RTPMessage::Rtcp(_)) =
            &msg.message
        {
            /*TODO
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
                                self.ctx.read_outs.push_back(inbound);
                            }
                            InterceptorEvent::Outbound(outbound) => {
                                self.ctx.write_outs.push_back(outbound);
                            }
                            InterceptorEvent::Error(err) => {
                                error!("try_read got error {}", err);
                                return Err(err);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    return Err(err);
                }
            };
            */
            if let RTCMessage::Rtp(RTPMessage::Rtcp(_)) = &msg.message {
                // RTCP message read must end here. If any rtcp packet needs to be forwarded to PeerConnection,
                // just add a new interceptor to forward it.
                debug!("interceptor terminates Rtcp {:?}", msg.transport.peer_addr);
                return Ok(());
            }
        }

        debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
        self.ctx.read_outs.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Rtp(RTPMessage::Rtp(_)) | RTCMessage::Rtp(RTPMessage::Rtcp(_)) =
            &msg.message
        {
            /*TODO:
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
                                self.ctx.write_outs.push_back(outbound);
                            }
                            InterceptorEvent::Error(err) => {
                                error!("try_write got error {}", err);
                                return Err(err);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("try_write with error {}", err);
                    return Err(err);
                }
            };*/
        }

        debug!("interceptor write {:?}", msg.transport.peer_addr);
        self.ctx.write_outs.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        /*TODO:
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
                            self.ctx.write_outs.push_back(outbound);
                        }
                        InterceptorEvent::Error(err) => {
                            error!("try_read got error {}", err);
                            return Err(err);
                        }
                    }
                }
            }
            Err(err) => {
                error!("try_handle_timeout with error {}", err);
                return Err(err);
            }
        }*/

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        /*TODO
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
        }*/

        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
