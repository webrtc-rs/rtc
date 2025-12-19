use super::message::{RTCMessage, STUNMessage, TaggedRTCMessage};
use bytes::BytesMut;
use log::{debug, warn};
use shared::error::{Error, Result};
use std::collections::VecDeque;
use std::time::Instant;
use stun::message::Message;

#[derive(Default)]
pub(crate) struct StunHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
}

/// StunHandler implements STUN Protocol handling
pub(crate) struct StunHandler<'a> {
    ctx: &'a mut StunHandlerContext,
}

impl<'a> StunHandler<'a> {
    pub fn new(ctx: &'a mut StunHandlerContext) -> Self {
        StunHandler { ctx }
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, ()> for StunHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
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
                    self.ctx.read_outs.push_back(TaggedRTCMessage {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessage::Stun(STUNMessage::Stun(stun_message)),
                    });
                }
                Err(err) => {
                    warn!("try_read got error {}", err);
                    return Err(err);
                }
            }
        } else {
            debug!("bypass StunHandler read for {}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Stun(STUNMessage::Stun(mut stun_message)) = msg.message {
            debug!(
                "StunMessage type {} sent to {}",
                stun_message.typ, msg.transport.peer_addr
            );
            stun_message.encode();
            let message = BytesMut::from(&stun_message.raw[..]);
            self.ctx.write_outs.push_back(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Stun(STUNMessage::Raw(message)),
            });
        } else {
            debug!("bypass StunHandler write for {}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
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
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
