use crate::handlers::RTCHandler;
use crate::messages::{RTCMessageEvent, STUNMessageEvent};
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::Result;
use shared::Transmit;
use stun::message::Message;

/// StunHandler implements STUN Protocol handling
#[derive(Default)]
pub struct StunHandler {
    next: Option<Box<dyn RTCHandler>>,
}

impl StunHandler {
    pub fn new() -> Self {
        StunHandler::default()
    }
}

impl RTCHandler for StunHandler {
    fn chain(mut self: Box<Self>, next: Box<dyn RTCHandler>) -> Box<dyn RTCHandler> {
        self.next = Some(next);
        self
    }

    fn next(&mut self) -> Option<&mut Box<dyn RTCHandler>> {
        self.next.as_mut()
    }

    fn handle_transmit(&mut self, msg: Transmit<RTCMessageEvent>) {
        let next_msg = if let RTCMessageEvent::Stun(STUNMessageEvent::Raw(message)) = msg.message {
            let try_read = || -> Result<Message> {
                let mut stun_message = Message {
                    raw: message.to_vec(),
                    ..Default::default()
                };
                stun_message.decode()?;
                debug!(
                    "StunMessage type {} received from {}",
                    stun_message.typ, msg.transport.peer_addr
                );
                Ok(stun_message)
            };

            match try_read() {
                Ok(stun_message) => Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Stun(STUNMessageEvent::Stun(stun_message)),
                },
                Err(err) => {
                    warn!("try_read got error {}", err);
                    self.handle_error(err);
                    return;
                }
            }
        } else {
            debug!("bypass StunHandler read for {}", msg.transport.peer_addr);
            msg
        };

        if let Some(next) = self.next() {
            next.handle_transmit(next_msg);
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit<RTCMessageEvent>> {
        let transmit = if let Some(next) = self.next() {
            next.poll_transmit()
        } else {
            None
        };

        if let Some(msg) = transmit {
            if let RTCMessageEvent::Stun(STUNMessageEvent::Stun(mut stun_message)) = msg.message {
                debug!(
                    "StunMessage type {} sent to {}",
                    stun_message.typ, msg.transport.peer_addr
                );
                stun_message.encode();
                let message = BytesMut::from(&stun_message.raw[..]);
                Some(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Stun(STUNMessageEvent::Raw(message)),
                })
            } else {
                debug!("bypass StunHandler write for {}", msg.transport.peer_addr);
                Some(msg)
            }
        } else {
            None
        }
    }
}
