use super::message::{RTCMessage, STUNMessage, TaggedRTCMessage};
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::Result;
use shared::{Context, Handler};
use stun::message::Message;

/// StunHandler implements STUN Protocol handling
#[derive(Default)]
pub struct StunHandler;

impl StunHandler {
    pub fn new() -> Self {
        StunHandler
    }
}

impl Handler for StunHandler {
    type Rin = TaggedRTCMessage;
    type Rout = Self::Rin;
    type Win = TaggedRTCMessage;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "StunHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
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
                Ok(stun_message) => {
                    ctx.fire_handle_read(TaggedRTCMessage {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessage::Stun(STUNMessage::Stun(stun_message)),
                    });
                }
                Err(err) => {
                    warn!("try_read got error {}", err);
                    ctx.fire_handle_error(Box::new(err));
                }
            }
        } else {
            debug!("bypass StunHandler read for {}", msg.transport.peer_addr);
            ctx.fire_handle_read(msg);
        }
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
            if let RTCMessage::Stun(STUNMessage::Stun(mut stun_message)) = msg.message {
                debug!(
                    "StunMessage type {} sent to {}",
                    stun_message.typ, msg.transport.peer_addr
                );
                stun_message.encode();
                let message = BytesMut::from(&stun_message.raw[..]);
                Some(TaggedRTCMessage {
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
