use crate::handlers::RTCHandler;
use crate::messages::{RTCMessage, STUNMessage};
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::Result;
use shared::Transmit;
use stun::message::Message;

/// StunHandler implements STUN Protocol handling
#[derive(Default)]
pub struct StunCodec;

impl StunCodec {
    pub fn new() -> Self {
        StunCodec
    }
}

impl RTCHandler for StunCodec {
    fn handle_transmit(&mut self, msg: Transmit<RTCMessage>) -> Vec<Transmit<RTCMessage>> {
        if let RTCMessage::Stun(STUNMessage::Raw(message)) = msg.message {
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
                Ok(stun_message) => vec![Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Stun(STUNMessage::Stun(stun_message)),
                }],
                Err(err) => {
                    warn!("try_read got error {}", err);
                    self.handle_error(err);
                    vec![]
                }
            }
        } else {
            debug!("bypass StunHandler read for {}", msg.transport.peer_addr);
            vec![msg]
        }
    }

    fn poll_transmit(&mut self, msg: Option<Transmit<RTCMessage>>) -> Option<Transmit<RTCMessage>> {
        if let Some(msg) = msg {
            if let RTCMessage::Stun(STUNMessage::Stun(mut stun_message)) = msg.message {
                debug!(
                    "StunMessage type {} sent to {}",
                    stun_message.typ, msg.transport.peer_addr
                );
                stun_message.encode();
                let message = BytesMut::from(&stun_message.raw[..]);
                Some(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Stun(STUNMessage::Raw(message)),
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
