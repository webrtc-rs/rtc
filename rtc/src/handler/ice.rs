use crate::messages::{RTCEvent, RTCMessage, STUNMessage};
use crate::transport::ice_transport::ice_candidate_pair::RTCIceCandidatePair;
use crate::transport::ice_transport::{IceTransportEvent, RTCIceTransport};
use bytes::BytesMut;
use ice::Event;
use log::{debug, error, warn};
use shared::error::Result;
use shared::handler::RTCHandler;
use shared::Transmit;
use std::time::Instant;

impl RTCHandler for RTCIceTransport {
    type Ein = ();
    type Eout = RTCEvent;
    type Rin = RTCMessage;
    type Rout = RTCMessage;
    type Win = RTCMessage;
    type Wout = RTCMessage;

    fn handle_read(&mut self, msg: Transmit<Self::Rin>) -> Result<()> {
        if let RTCMessage::Stun(STUNMessage::Raw(message)) = msg.message {
            let stun_transmit = Transmit {
                now: msg.now,
                transport: msg.transport,
                message,
            };

            let try_read = || -> Result<()> { self.gatherer.agent.handle_read(stun_transmit) };

            if let Err(err) = try_read() {
                warn!("try_read got error {}", err);
                return Err(err);
            }
        } else {
            debug!("bypass StunHandler read for {}", msg.transport.peer_addr);
            self.routs.push_back(msg)
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Transmit<Self::Rout>> {
        self.routs.pop_front()
    }

    fn handle_write(&mut self, msg: Transmit<Self::Win>) -> Result<()> {
        if let RTCMessage::Stun(STUNMessage::Stun(mut stun_message)) = msg.message {
            debug!(
                "StunMessage type {} sent to {}",
                stun_message.typ, msg.transport.peer_addr
            );
            stun_message.encode();
            let message = BytesMut::from(&stun_message.raw[..]);
            self.wouts.push_back(Transmit {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Stun(STUNMessage::Raw(message)),
            });
        } else {
            debug!("bypass StunHandler write for {}", msg.transport.peer_addr);
            self.wouts.push_back(msg);
        }

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Transmit<RTCMessage>> {
        self.wouts.pop_front()
    }

    fn poll_event(&mut self) -> Option<RTCEvent> {
        if let Some(event) = self.gatherer.agent.poll_event() {
            match event {
                Event::ConnectionStateChange(state) => Some(RTCEvent::IceTransportEvent(
                    IceTransportEvent::OnConnectionStateChange(state.into()),
                )),
                Event::SelectedCandidatePairChange(local, remote) => {
                    Some(RTCEvent::IceTransportEvent(
                        IceTransportEvent::OnSelectedCandidatePairChange(Box::new(
                            RTCIceCandidatePair::new((&*local).into(), (&*remote).into()),
                        )),
                    ))
                }
            }
        } else {
            None
        }
    }

    /// Handles a timeout event
    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        let mut try_timeout = || -> Result<()> {
            self.gatherer.agent.handle_timeout(now);
            while let Some(transmit) = self.gatherer.agent.poll_transmit() {
                self.wouts.push_back(Transmit {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessage::Stun(STUNMessage::Raw(transmit.message)),
                });
            }

            Ok(())
        };
        match try_timeout() {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("try_timeout with error {}", err);
                Err(err)
            }
        }
    }

    /// Polls a timeout event
    fn poll_timeout(&mut self) -> Option<Instant> {
        self.gatherer.agent.poll_timeout()
    }
}
