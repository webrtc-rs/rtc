use crate::peer_connection::event::TaggedRTCEventInternal;
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, RTPMessage, STUNMessage, TaggedRTCMessageInternal,
};

use crate::statistics::accumulator::RTCStatsAccumulator;
use log::{debug, error};
use shared::error::Error;
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
/// <https://datatracker.ietf.org/doc/html/rfc7983>
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
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
}

/// DemuxerHandler implements demuxing of STUN/DTLS/RTP/RTCP Protocol packets
pub(crate) struct DemuxerHandler<'a> {
    ctx: &'a mut DemuxerHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> DemuxerHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut DemuxerHandlerContext,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        DemuxerHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DemuxerHandler"
    }
}

impl super::WriteBypass for DemuxerHandler<'_> {
    fn write_in_place(&mut self, pending: &mut VecDeque<TaggedRTCMessageInternal>) -> bool {
        if !self.ctx.write_outs.is_empty() {
            return false;
        }
        let stats = &mut *self.stats;
        pending.retain_mut(|msg| {
            let bytes = match &mut msg.message {
                RTCMessageInternal::Raw(message) => {
                    stats.transport.on_packet_sent(message.len());
                    return true;
                }
                RTCMessageInternal::Stun(STUNMessage::Raw(message))
                | RTCMessageInternal::Dtls(DTLSMessage::Raw(message))
                | RTCMessageInternal::Rtp(RTPMessage::Raw(message)) => std::mem::take(message),
                other => {
                    debug!("drop non-RAW packet {other:?}");
                    return false;
                }
            };
            stats.transport.on_packet_sent(bytes.len());
            msg.message = RTCMessageInternal::Raw(bytes);
            true
        });
        true
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DemuxerHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<(), Self::Error> {
        if let RTCMessageInternal::Raw(message) = msg.message {
            // Update transport stats for received packet
            self.stats.transport.on_packet_received(message.len());

            if message.is_empty() {
                error!("drop invalid packet due to zero length");
            } else if match_dtls(&message) {
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(message)),
                });
            } else if match_srtp(&message) {
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Raw(message)),
                });
            } else {
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Stun(STUNMessage::Raw(message)),
                });
            }
        } else {
            debug!("drop non-RAW packet {:?}", msg.message);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<(), Self::Error> {
        match msg.message {
            RTCMessageInternal::Raw(message)
            | RTCMessageInternal::Stun(STUNMessage::Raw(message))
            | RTCMessageInternal::Dtls(DTLSMessage::Raw(message))
            | RTCMessageInternal::Rtp(RTPMessage::Raw(message)) => {
                // Update transport stats for sent packet
                self.stats.transport.on_packet_sent(message.len());

                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Raw(message),
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

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> shared::error::Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        super::pop_event(&mut self.ctx.event_outs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::handler::WriteBypass;
    use bytes::BytesMut;
    use interceptor::Packet;
    use sansio::Protocol;

    fn tagged(message: RTCMessageInternal) -> TaggedRTCMessageInternal {
        TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: Default::default(),
            message,
        }
    }

    fn mixed() -> VecDeque<TaggedRTCMessageInternal> {
        let bytes = |b: &[u8]| BytesMut::from(b);
        [
            RTCMessageInternal::Raw(bytes(&[1, 2, 3])),
            RTCMessageInternal::Stun(STUNMessage::Raw(bytes(&[0, 1]))),
            // Not bytes yet: the demuxer has no use for it and drops it.
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(Default::default()))),
            RTCMessageInternal::Dtls(DTLSMessage::Raw(bytes(&[22, 254, 253, 9]))),
            RTCMessageInternal::Rtp(RTPMessage::Raw(bytes(&[128, 96, 0, 1, 7, 7]))),
        ]
        .into_iter()
        .map(tagged)
        .collect()
    }

    fn bytes_of(queue: &VecDeque<TaggedRTCMessageInternal>) -> Vec<Vec<u8>> {
        queue
            .iter()
            .map(|m| match &m.message {
                RTCMessageInternal::Raw(b) => b.to_vec(),
                other => panic!("the demuxer left {other:?} on the belt"),
            })
            .collect()
    }

    /// Passing the belt through in place leaves what queueing each message and polling the queue
    /// would have: the same bytes in the same order, the same drops, the same count.
    #[test]
    fn writing_in_place_leaves_what_queueing_would() {
        let mut queued_ctx = DemuxerHandlerContext::default();
        let mut queued_stats = RTCStatsAccumulator::default();
        let mut queued = VecDeque::new();
        {
            let mut handler = DemuxerHandler::new(&mut queued_ctx, &mut queued_stats);
            for msg in mixed() {
                handler.handle_write(msg).unwrap();
            }
            while let Some(msg) = handler.poll_write() {
                queued.push_back(msg);
            }
        }

        let mut ctx = DemuxerHandlerContext::default();
        let mut stats = RTCStatsAccumulator::default();
        let mut in_place = mixed();
        assert!(DemuxerHandler::new(&mut ctx, &mut stats).write_in_place(&mut in_place));

        assert_eq!(bytes_of(&in_place), bytes_of(&queued));
        assert_eq!(in_place.len(), 4);
        assert_eq!(
            stats.transport.packets_sent,
            queued_stats.transport.packets_sent
        );
        assert_eq!(
            stats.transport.bytes_sent,
            queued_stats.transport.bytes_sent
        );
        assert!(ctx.write_outs.is_empty());
    }

    /// With something already queued in the handler the in-place pass would reorder it, so the
    /// handler declines and the belt is left as it was.
    #[test]
    fn a_handler_with_output_of_its_own_declines() {
        let mut ctx = DemuxerHandlerContext::default();
        ctx.write_outs
            .push_back(tagged(RTCMessageInternal::Raw(BytesMut::from(&[9u8][..]))));
        let mut stats = RTCStatsAccumulator::default();
        let mut belt = mixed();
        assert!(!DemuxerHandler::new(&mut ctx, &mut stats).write_in_place(&mut belt));
        assert_eq!(belt.len(), 5);
    }
}
