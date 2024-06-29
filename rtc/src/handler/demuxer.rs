use crate::messages::{DTLSMessage, RTCMessage, RTPMessage, STUNMessage};
use log::{debug, error};
use shared::error::Result;
use shared::handler::RTCHandler;
use shared::Transmit;
use std::collections::VecDeque;

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
pub struct Demuxer {
    routs: VecDeque<Transmit<RTCMessage>>,
    wouts: VecDeque<Transmit<RTCMessage>>,
}

impl Demuxer {
    pub fn new() -> Self {
        Self {
            routs: VecDeque::new(),
            wouts: VecDeque::new(),
        }
    }
}

impl RTCHandler for Demuxer {
    type Ein = ();
    type Eout = ();
    type Rin = RTCMessage;
    type Rout = RTCMessage;
    type Win = RTCMessage;
    type Wout = RTCMessage;

    fn handle_read(&mut self, msg: Transmit<Self::Rin>) -> Result<()> {
        if let RTCMessage::Raw(message) = msg.message {
            if message.is_empty() {
                error!("drop invalid packet due to zero length");
            } else if match_dtls(&message) {
                self.routs.push_back(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Dtls(DTLSMessage::Raw(message)),
                });
            } else if match_srtp(&message) {
                self.routs.push_back(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Rtp(RTPMessage::Raw(message)),
                });
            } else {
                self.routs.push_back(Transmit {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessage::Stun(STUNMessage::Raw(message)),
                });
            }
        } else {
            debug!("drop non-RAW packet {:?}", msg.message);
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Transmit<Self::Rout>> {
        self.routs.pop_front()
    }

    fn handle_write(&mut self, msg: Transmit<Self::Win>) -> Result<()> {
        match msg.message {
            RTCMessage::Stun(STUNMessage::Raw(message))
            | RTCMessage::Dtls(DTLSMessage::Raw(message))
            | RTCMessage::Rtp(RTPMessage::Raw(message)) => self.wouts.push_back(Transmit {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessage::Raw(message),
            }),
            _ => {
                debug!("drop non-RAW packet {:?}", msg.message);
            }
        }

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Transmit<RTCMessage>> {
        self.wouts.pop_front()
    }
}
