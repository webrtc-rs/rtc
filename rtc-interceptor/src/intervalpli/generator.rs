//! Periodic Picture Loss Indication for bound remote streams.

use super::stream_supports_pli;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

/// How often a keyframe is requested when no interval is configured.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3);

/// Requests a keyframe from every bound remote stream on a fixed interval.
///
/// # Where this belongs in the chain
///
/// It only generates, and what it generates is RTCP, so its position is fixed by nothing except
/// being on the application side of the pacer — as everything that generates is, so that what it
/// produces is still metered on its way out.
///
/// # Forcing a keyframe
///
/// Send [`InterceptorEvent::ForcePli`] into the chain. Under the nested design this was an
/// inherent method, `force_pli`, which became unreachable the moment anything wrapped this
/// interceptor — it was dead code in practice. A command event walks application-ward to the wire
/// and reaches it wherever it sits.
///
/// Sans-I/O has no clock of its own, so the interval is measured from the first `Instant` the
/// interceptor is handed, whether that arrives via `handle_read`, `handle_timeout` or the event.
pub struct IntervalPliInterceptor {
    interval: Duration,
    /// Bound remote streams that negotiated PLI. Ordered so a tick emits deterministically.
    streams: BTreeSet<u32>,
    /// Streams bound but not yet sent their first request.
    ///
    /// Upstream asks immediately on bind, which needs an instant this interceptor does not have until
    /// one is handed to it; these are flushed at the first opportunity.
    pending_immediate: BTreeSet<u32>,
    next_timeout: Option<Instant>,
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl Default for IntervalPliInterceptor {
    fn default() -> Self {
        Self::new(DEFAULT_INTERVAL)
    }
}

impl IntervalPliInterceptor {
    /// A generator asking every bound stream for a keyframe every `interval`.
    ///
    /// A zero interval disables periodic requests, leaving only [`InterceptorEvent::ForcePli`] —
    /// matching upstream, which creates no ticker when its interval is not positive.
    pub fn new(interval: Duration) -> Self {
        Self {
            read_queue: VecDeque::new(),
            interval,
            streams: BTreeSet::new(),
            pending_immediate: BTreeSet::new(),
            next_timeout: None,
            write_queue: VecDeque::new(),
        }
    }

    /// The streams currently being asked for keyframes.
    pub fn bound_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams.iter().copied()
    }

    /// Queue one RTCP packet carrying a PLI per SSRC.
    ///
    /// One compound packet rather than one datagram each, as upstream does: they are all going to
    /// the same peer at the same instant.
    fn queue_plis(&mut self, now: Instant, ssrcs: &[u32]) {
        if ssrcs.is_empty() {
            return;
        }

        // Asking now satisfies the ask-on-bind these streams were still waiting for, so a forced
        // request does not arrive alongside a duplicate of itself.
        for ssrc in ssrcs {
            self.pending_immediate.remove(ssrc);
        }

        let plis: Vec<Box<dyn rtcp::Packet>> = ssrcs
            .iter()
            .map(|&ssrc| {
                Box::new(
                    rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: ssrc,
                    },
                ) as Box<dyn rtcp::Packet>
            })
            .collect();

        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(plis)),
        });
    }

    /// Arm the interval from the first instant this interceptor is handed, and send the first request
    /// for any stream bound since.
    fn observe(&mut self, now: Instant) {
        if !self.pending_immediate.is_empty() {
            let ssrcs: Vec<u32> = self.pending_immediate.iter().copied().collect();
            self.queue_plis(now, &ssrcs);
        }
        self.arm(now);
    }

    /// Start the interval running, if it is not already and there is anything to ask.
    fn arm(&mut self, now: Instant) {
        if self.next_timeout.is_none() && self.is_periodic() && !self.streams.is_empty() {
            self.next_timeout = Some(now + self.interval);
        }
    }

    fn is_periodic(&self) -> bool {
        !self.interval.is_zero()
    }

    /// SSRCs that are bound, from a request naming some or all of them.
    ///
    /// A PLI for a stream nobody is receiving has no destination, so unbound SSRCs are dropped.
    fn targets(&self, requested: Option<&Vec<u32>>) -> Vec<u32> {
        match requested {
            None => self.streams.iter().copied().collect(),
            Some(ssrcs) => ssrcs
                .iter()
                .copied()
                .filter(|ssrc| self.streams.contains(ssrc))
                .collect(),
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for IntervalPliInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.observe(msg.now);

        // A keyframe request arrives as an attribute on a packet rather than out of band: with no
        // event channel, that is how one interceptor tells another something.
        if let Some(Attribute::ForcePli { ssrcs }) =
            msg.message.get(&Attribute::ForcePli { ssrcs: None })
        {
            let targets = self.targets(ssrcs.as_ref());
            self.queue_plis(msg.now, &targets);
            self.arm(msg.now);
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

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.observe(now);

        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);
            let ssrcs: Vec<u32> = self.streams.iter().copied().collect();
            self.queue_plis(now, &ssrcs);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for IntervalPliInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_pli(info) {
            self.streams.insert(info.ssrc);
            self.pending_immediate.insert(info.ssrc);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.pending_immediate.remove(&info.ssrc);
        if self.streams.is_empty() {
            // Nothing left to ask: stop asking to be woken.
            self.next_timeout = None;
        }
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::InterceptorChain;
    use crate::stream_info::RTCPFeedback;
    use sansio::Protocol;

    fn stream_info(ssrc: u32) -> StreamInfo {
        StreamInfo {
            ssrc,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            }],
            ..Default::default()
        }
    }

    /// A packet carrying a keyframe request. With no event channel, an attribute on a packet is
    /// how one interceptor asks another for something.
    fn force_pli(now: Instant, ssrcs: Option<Vec<u32>>) -> TaggedPacket {
        let mut msg = TaggedPacket {
            now,
            transport: Default::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
        };
        msg.message.add(Attribute::ForcePli { ssrcs });
        msg
    }

    fn plis(chain: &mut InterceptorChain) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(pkt) = chain.poll_write() {
            if let Packet::Rtcp(packets) = &pkt.message.packet {
                for p in packets {
                    if let Some(pli) = p
                        .as_any()
                        .downcast_ref::<rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication>(
                        ) {
                        out.push(pli.media_ssrc);
                    }
                }
            }
        }
        out
    }

    fn chain(interval: Duration) -> InterceptorChain {
        InterceptorChain::new(vec![Box::new(IntervalPliInterceptor::new(interval))])
    }

    #[test]
    fn a_bound_stream_is_asked_immediately() {
        let now = Instant::now();
        let mut chain = chain(Duration::from_secs(3));
        chain.bind_remote_stream(&stream_info(7));

        chain.handle_timeout(now).unwrap();
        assert_eq!(vec![7], plis(&mut chain));
    }

    #[test]
    fn requests_repeat_on_the_interval() {
        let now = Instant::now();
        let mut chain = chain(Duration::from_secs(1));
        chain.bind_remote_stream(&stream_info(7));

        chain.handle_timeout(now).unwrap();
        assert_eq!(vec![7], plis(&mut chain), "the immediate one");

        chain
            .handle_timeout(now + Duration::from_millis(999))
            .unwrap();
        assert!(plis(&mut chain).is_empty(), "not due yet");

        chain.handle_timeout(now + Duration::from_secs(1)).unwrap();
        assert_eq!(vec![7], plis(&mut chain), "due");
    }

    #[test]
    fn an_unbound_stream_stops_being_asked() {
        let now = Instant::now();
        let mut chain = chain(Duration::from_secs(1));
        chain.bind_remote_stream(&stream_info(7));
        chain.handle_timeout(now).unwrap();
        let _ = plis(&mut chain);

        chain.unbind_remote_stream(&stream_info(7));
        chain.handle_timeout(now + Duration::from_secs(5)).unwrap();

        assert!(plis(&mut chain).is_empty());
        assert_eq!(None, chain.poll_timeout(), "and stops asking to be woken");
    }

    // -----------------------------------------------------------------------------------
    // ForcePli — the capability that replaces an unreachable inherent method
    // -----------------------------------------------------------------------------------

    /// The whole point of the event: this reaches the generator **through the chain**, which the
    /// inherent `force_pli` could not do once anything wrapped the interceptor.
    #[test]
    fn force_pli_reaches_the_generator_through_the_chain() {
        let now = Instant::now();
        // Deliberately not the only interceptor, and not the one the application holds: under nesting
        // this arrangement is exactly what made `force_pli` unreachable.
        let mut chain = InterceptorChain::new(vec![
            Box::new(IntervalPliInterceptor::new(Duration::ZERO)),
            Box::new(crate::TwccSenderBuilder::new().build()),
        ]);
        chain.bind_remote_stream(&stream_info(7));
        // A newly bound stream is asked for a keyframe the first time the interceptor is handed a
        // clock, and a carrier packet supplies one — so clear that out first, leaving only what
        // the request itself produces.
        chain.handle_timeout(now).unwrap();
        plis(&mut chain);

        chain
            .handle_read(force_pli(now, None))
            .expect("handle_read");

        assert_eq!(vec![7], plis(&mut chain));
    }

    #[test]
    fn force_pli_can_name_specific_streams() {
        let now = Instant::now();
        let mut chain = chain(Duration::ZERO);
        chain.bind_remote_stream(&stream_info(7));
        chain.bind_remote_stream(&stream_info(8));
        // A newly bound stream is asked for a keyframe the first time the interceptor is handed a
        // clock, and a carrier packet supplies one — so clear that out first, leaving only what
        // the request itself produces.
        chain.handle_timeout(now).unwrap();
        plis(&mut chain);

        chain
            .handle_read(force_pli(now, Some(vec![8])))
            .expect("handle_read");

        assert_eq!(vec![8], plis(&mut chain), "only the one named");
    }

    #[test]
    fn force_pli_ignores_streams_that_are_not_bound() {
        let now = Instant::now();
        let mut chain = chain(Duration::ZERO);
        chain.bind_remote_stream(&stream_info(7));
        // A newly bound stream is asked for a keyframe the first time the interceptor is handed a
        // clock, and a carrier packet supplies one — so clear that out first, leaving only what
        // the request itself produces.
        chain.handle_timeout(now).unwrap();
        plis(&mut chain);

        chain
            .handle_read(force_pli(now, Some(vec![999])))
            .expect("handle_read");

        assert!(
            plis(&mut chain).is_empty(),
            "a PLI for a stream nobody receives has no destination"
        );
    }

    /// A zero interval means no periodic requests, but forcing still works.
    #[test]
    fn a_zero_interval_disables_only_the_periodic_requests() {
        let now = Instant::now();
        let mut chain = chain(Duration::ZERO);
        chain.bind_remote_stream(&stream_info(7));

        chain.handle_timeout(now).unwrap();
        assert_eq!(vec![7], plis(&mut chain), "the immediate one still happens");
        assert_eq!(None, chain.poll_timeout(), "but no interval is armed");

        chain.handle_timeout(now + Duration::from_secs(60)).unwrap();
        assert!(plis(&mut chain).is_empty());

        chain
            .handle_read(force_pli(now, None))
            .expect("handle_read");
        assert_eq!(vec![7], plis(&mut chain), "forcing still works");
    }

    /// A request rides in on a packet and the packet carries on, so anything after this
    /// interceptor sees both the request and the PLI it produced.
    #[test]
    fn a_force_pli_attribute_is_not_consumed() {
        let now = Instant::now();
        let mut chain =
            InterceptorChain::new(vec![Box::new(IntervalPliInterceptor::new(Duration::ZERO))]);
        chain.bind_remote_stream(&stream_info(7));
        // A newly bound stream is asked for a keyframe the first time the interceptor is handed a
        // clock, and a carrier packet supplies one — so clear that out first, leaving only what
        // the request itself produces.
        chain.handle_timeout(now).unwrap();
        plis(&mut chain);

        let mut carrier = TaggedPacket {
            now,
            transport: Default::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
        };
        carrier.message.add(Attribute::ForcePli { ssrcs: None });
        chain.handle_read(carrier).expect("handle_read");

        assert_eq!(vec![7], plis(&mut chain), "the request was acted on");
        assert!(
            chain.poll_read().is_some(),
            "and the packet that carried it carried on"
        );
    }
}
