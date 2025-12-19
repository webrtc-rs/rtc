use super::message::{DTLSMessage, RTCMessage, RTPMessage, STUNMessage, TaggedRTCMessage};

use log::{debug, error};
use shared::{Protocol, TaggedBytesMut};
use std::collections::VecDeque;
use std::time::Instant;

/// match_range is a MatchFunc that accepts packets with the first byte in [lower..upper]
fn match_range(lower: u8, upper: u8, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let b = buf[0];
    b >= lower && b <= upper
}

/// MatchFuncs as described in RFC7983
/// <https://tools.ietf.org/html/rfc7983>
///              +----------------+
///              |        [0..3] -+--> forward to STUN
///              |                |
///              |      [16..19] -+--> forward to ZRTP
///              |                |
///  packet -->  |      [20..63] -+--> forward to DTLS
///              |                |
///              |      [64..79] -+--> forward to TURN Channel
///              |                |
///              |    [128..191] -+--> forward to RTP/RTCP
///              +----------------+
/// match_dtls is a MatchFunc that accepts packets with the first byte in [20..63]
/// as defied in RFC7983
fn match_dtls(b: &[u8]) -> bool {
    match_range(20, 63, b)
}

/// match_srtp is a MatchFunc that accepts packets with the first byte in [128..191]
/// as defied in RFC7983
fn match_srtp(b: &[u8]) -> bool {
    match_range(128, 191, b)
}

#[derive(Default)]
pub(crate) struct DemuxerHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
}

/// DemuxerHandler implements demuxing of STUN/DTLS/RTP/RTCP Protocol packets
pub(crate) struct DemuxerHandler<'a> {
    ctx: &'a mut DemuxerHandlerContext,
}

impl<'a> DemuxerHandler<'a> {
    pub fn new(ctx: &'a mut DemuxerHandlerContext) -> Self {
        DemuxerHandler { ctx }
    }
}

impl<'a> Protocol<TaggedBytesMut, TaggedRTCMessage, ()> for DemuxerHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = ();
    type Error = shared::error::Error;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        if msg.message.is_empty() {
            error!("drop invalid packet due to zero length");
        } else if match_dtls(&msg.message) {
            self.ctx.read_outs.push_back(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Dtls(DTLSMessage::Raw(msg.message)),
            });
        } else if match_srtp(&msg.message) {
            self.ctx.read_outs.push_back(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Rtp(RTPMessage::Raw(msg.message)),
            });
        } else {
            self.ctx.read_outs.push_back(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Stun(STUNMessage::Raw(msg.message)),
            });
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        match msg.message {
            RTCMessage::Stun(STUNMessage::Raw(message))
            | RTCMessage::Dtls(DTLSMessage::Raw(message))
            | RTCMessage::Rtp(RTPMessage::Raw(message)) => {
                self.ctx.write_outs.push_back(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
            _ => {
                debug!("drop non-RAW packet {:?}", msg.message);
            }
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: ()) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
