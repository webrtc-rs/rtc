//! Delivers keyframe requests to the application.
//!
//! Inbound RTCP stops at the end of the interceptor chain: receiver reports feed the sender
//! statistics, a NACK is answered by the responder, transport-wide feedback drives the bandwidth
//! estimate, and the application is not told. A keyframe request is the exception. It is about a
//! stream this endpoint may only be relaying, so the one party that can act on it is the
//! application, which knows where the stream comes from. An SFU asks its publishers for a keyframe
//! when a subscriber asks it for one.

use crate::{Attribute, Interceptor, Packet, StreamInfo, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// Builds a [`KeyframeRequestForwarderInterceptor`].
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyframeRequestForwarderBuilder;

impl KeyframeRequestForwarderBuilder {
    /// A builder with nothing to configure.
    pub fn new() -> Self {
        Self
    }

    /// The interceptor, to be registered at [`Slot::KeyframeRequests`](crate::Slot::KeyframeRequests).
    pub fn build(self) -> KeyframeRequestForwarderInterceptor {
        KeyframeRequestForwarderInterceptor::default()
    }
}

/// Passes inbound keyframe requests, PLI and FIR, on to the application and lets every other
/// inbound RTCP packet end its journey at the interceptors that act on it.
///
/// # Where it belongs
///
/// **Application-most** ([`Slot::KeyframeRequests`](crate::Slot::KeyframeRequests)), so every
/// interceptor that reads RTCP has seen the whole of it before this one narrows it down.
///
/// What it keeps, it marks with [`Attribute::DeliverToApplication`]: inbound RTCP is dropped at the
/// end of the chain otherwise. Re-emitting a copy would not help, since a packet an interceptor
/// emits rejoins the belt behind it, so no position exists from which to forward past the end of
/// the chain. Marking works because it does not try to: the packet finishes the walk and the end of
/// the chain reads the mark.
///
/// The feedback is tagged with the id of the track it is about, which for a stream this endpoint
/// sends is the sending track, and for one it receives the receiving track.
#[derive(Default)]
pub struct KeyframeRequestForwarderInterceptor {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

/// Whether an RTCP packet asks for a keyframe.
fn is_keyframe_request(packet: &dyn rtcp::Packet) -> bool {
    let any = packet.as_any();
    any.is::<rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication>()
        || any.is::<rtcp::payload_feedbacks::full_intra_request::FullIntraRequest>()
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for KeyframeRequestForwarderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &msg.message.packet {
            let requests: Vec<_> = packets
                .iter()
                .filter(|p| is_keyframe_request(p.as_ref()))
                .cloned()
                .collect();
            if requests.is_empty() {
                // Not the application's business, and the interceptors have already acted on it.
                return Ok(());
            }
            msg.message.packet = Packet::Rtcp(requests);
            msg.message.add(Attribute::DeliverToApplication);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for KeyframeRequestForwarderInterceptor {
    fn writes_pass_through(&self) -> bool {
        true
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributedPacket, Registry, Slot};
    use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
    use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    use rtcp::receiver_report::ReceiverReport;
    use shared::TransportContext;

    fn inbound(packet: Packet) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(packet),
        }
    }

    fn pli(ssrc: u32) -> Box<dyn rtcp::Packet> {
        Box::new(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: ssrc,
        })
    }

    fn chain() -> impl Interceptor {
        Registry::new()
            .with(
                Slot::KeyframeRequests,
                KeyframeRequestForwarderBuilder::new().build(),
            )
            .build()
    }

    #[test]
    fn a_picture_loss_indication_reaches_the_application() {
        let mut chain = chain();
        chain
            .handle_read(inbound(Packet::Rtcp(vec![pli(42)])))
            .unwrap();
        let out = chain.poll_read().expect("delivered");
        let Packet::Rtcp(packets) = &out.message.packet else {
            panic!("not RTCP")
        };
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .as_any()
                .downcast_ref::<PictureLossIndication>()
                .unwrap()
                .media_ssrc,
            42
        );
        assert!(chain.poll_read().is_none());
    }

    #[test]
    fn a_full_intra_request_reaches_the_application() {
        let mut chain = chain();
        let fir = FullIntraRequest {
            sender_ssrc: 1,
            media_ssrc: 0,
            fir: vec![FirEntry {
                ssrc: 7,
                sequence_number: 1,
            }],
        };
        chain
            .handle_read(inbound(Packet::Rtcp(vec![Box::new(fir)])))
            .unwrap();
        assert!(chain.poll_read().is_some());
    }

    #[test]
    fn reports_in_the_same_packet_are_left_to_the_interceptors() {
        let mut chain = chain();
        let rr: Box<dyn rtcp::Packet> = Box::new(ReceiverReport::default());
        chain
            .handle_read(inbound(Packet::Rtcp(vec![rr, pli(5)])))
            .unwrap();
        let out = chain.poll_read().unwrap();
        let Packet::Rtcp(packets) = &out.message.packet else {
            panic!("not RTCP")
        };
        assert_eq!(packets.len(), 1, "only the keyframe request is passed on");
        assert!(packets[0].as_any().is::<PictureLossIndication>());
    }

    #[test]
    fn other_feedback_still_stops_at_the_end_of_the_chain() {
        let mut chain = chain();
        let rr: Box<dyn rtcp::Packet> = Box::new(ReceiverReport::default());
        chain.handle_read(inbound(Packet::Rtcp(vec![rr]))).unwrap();
        assert!(chain.poll_read().is_none());
    }

    #[test]
    fn media_and_outbound_packets_are_untouched() {
        let mut chain = chain();
        chain
            .handle_read(inbound(Packet::Rtp(rtp::Packet::default())))
            .unwrap();
        assert!(chain.poll_read().is_some(), "RTP passes");
        chain
            .handle_write(inbound(Packet::Rtcp(vec![pli(1)])))
            .unwrap();
        assert!(chain.poll_write().is_some(), "outbound RTCP passes");
    }
}
