use crate::handlers::RTCHandler;
use crate::messages::{DTLSMessageEvent, RTCMessageEvent, RTPMessageEvent, STUNMessageEvent};
use log::{debug, error};
use shared::Transmit;

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
pub struct DemuxerHandler {
    next: Option<Box<dyn RTCHandler>>,
}

impl DemuxerHandler {
    pub fn new() -> Self {
        DemuxerHandler::default()
    }
}

impl RTCHandler for DemuxerHandler {
    fn chain(mut self: Box<Self>, next: Box<dyn RTCHandler>) -> Box<dyn RTCHandler> {
        self.next = Some(next);
        self
    }

    fn next(&mut self) -> Option<&mut Box<dyn RTCHandler>> {
        self.next.as_mut()
    }

    fn handle_transmit(&mut self, msg: Transmit<RTCMessageEvent>) {
        if let RTCMessageEvent::Raw(message) = msg.message {
            if message.is_empty() {
                error!("drop invalid packet due to zero length");
                return;
            }

            let next_msg = if match_dtls(&message) {
                Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Dtls(DTLSMessageEvent::Raw(message)),
                }
            } else if match_srtp(&message) {
                Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Rtp(RTPMessageEvent::Raw(message)),
                }
            } else {
                Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Stun(STUNMessageEvent::Raw(message)),
                }
            };

            if let Some(next) = self.next() {
                next.handle_transmit(next_msg);
            }
        } else {
            debug!("drop non-RAW packet {:?}", msg.message);
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit<RTCMessageEvent>> {
        let transmit = if let Some(next) = self.next() {
            next.poll_transmit()
        } else {
            None
        };

        if let Some(msg) = transmit {
            match msg.message {
                RTCMessageEvent::Stun(STUNMessageEvent::Raw(message))
                | RTCMessageEvent::Dtls(DTLSMessageEvent::Raw(message))
                | RTCMessageEvent::Rtp(RTPMessageEvent::Raw(message)) => Some(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageEvent::Raw(message),
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
