use crate::handler::RTCHandler;
use crate::messages::{DTLSMessage, RTCMessage, RTPMessage, STUNMessage};
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
pub struct Demuxer;

impl Demuxer {
    pub fn new() -> Self {
        Demuxer
    }
}

impl RTCHandler for Demuxer {
    fn handle_transmit(&mut self, msg: Transmit<RTCMessage>) -> Vec<Transmit<RTCMessage>> {
        if let RTCMessage::Raw(message) = msg.message {
            if message.is_empty() {
                error!("drop invalid packet due to zero length");
                vec![]
            } else if match_dtls(&message) {
                vec![Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Dtls(DTLSMessage::Raw(message)),
                }]
            } else if match_srtp(&message) {
                vec![Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Rtp(RTPMessage::Raw(message)),
                }]
            } else {
                vec![Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Stun(STUNMessage::Raw(message)),
                }]
            }
        } else {
            debug!("drop non-RAW packet {:?}", msg.message);
            vec![]
        }
    }

    fn poll_transmit(&mut self, msg: Option<Transmit<RTCMessage>>) -> Option<Transmit<RTCMessage>> {
        if let Some(msg) = msg {
            match msg.message {
                RTCMessage::Stun(STUNMessage::Raw(message))
                | RTCMessage::Dtls(DTLSMessage::Raw(message))
                | RTCMessage::Rtp(RTPMessage::Raw(message)) => Some(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Raw(message),
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
