use super::message::{DTLSMessage, RTCMessage, RTPMessage, STUNMessage, TaggedRTCMessage};

use log::{debug, error};
use shared::{Context, Handler, TaggedBytesMut};

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

/// DemuxerHandler implements demuxing of STUN/DTLS/RTP/RTCP Protocol packets
#[derive(Default)]
pub struct DemuxerHandler;

impl DemuxerHandler {
    pub fn new() -> Self {
        DemuxerHandler
    }
}

impl Handler for DemuxerHandler {
    type Rin = TaggedBytesMut;
    type Rout = TaggedRTCMessage;
    type Win = TaggedRTCMessage;
    type Wout = TaggedBytesMut;

    fn name(&self) -> &str {
        "DemuxerHandler"
    }

    fn handle_read(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
        msg: Self::Rin,
    ) {
        if msg.message.is_empty() {
            error!("drop invalid packet due to zero length");
        } else if match_dtls(&msg.message) {
            ctx.fire_handle_read(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Dtls(DTLSMessage::Raw(msg.message)),
            });
        } else if match_srtp(&msg.message) {
            ctx.fire_handle_read(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Rtp(RTPMessage::Raw(msg.message)),
            });
        } else {
            ctx.fire_handle_read(TaggedRTCMessage {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Stun(STUNMessage::Raw(msg.message)),
            });
        }
    }

    fn poll_write(
        &mut self,
        ctx: &Context<Self::Rin, Self::Rout, Self::Win, Self::Wout>,
    ) -> Option<Self::Wout> {
        if let Some(msg) = ctx.fire_poll_write() {
            match msg.message {
                RTCMessage::Stun(STUNMessage::Raw(message))
                | RTCMessage::Dtls(DTLSMessage::Raw(message))
                | RTCMessage::Rtp(RTPMessage::Raw(message)) => Some(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                }),
                _ => {
                    debug!("drop non-RAW packet {:?}", msg.message);
                    None
                }
            }
        } else {
            None
        }
    }
}
