use crate::interceptors::report::receiver_stream::ReceiverStream;
use crate::interceptors::report::ReportBuilder;
use crate::interceptors::{Interceptor, InterceptorEvent};
use crate::messages::{MessageEvent, RTPMessageEvent, TaggedMessageEvent};
use crate::types::FourTuple;
use retty::transport::TransportContext;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub(crate) struct ReceiverReport {
    pub(super) interval: Duration,
    pub(super) eto: Instant,
    pub(crate) streams: HashMap<u32, ReceiverStream>,
    pub(super) next: Option<Box<dyn Interceptor>>,
}

impl ReceiverReport {
    pub(crate) fn builder() -> ReportBuilder {
        ReportBuilder {
            is_rr: true,
            ..Default::default()
        }
    }
}

impl Interceptor for ReceiverReport {
    fn chain(mut self: Box<Self>, next: Box<dyn Interceptor>) -> Box<dyn Interceptor> {
        self.next = Some(next);
        self
    }

    fn next(&mut self) -> Option<&mut Box<dyn Interceptor>> {
        self.next.as_mut()
    }

    fn read(&mut self, msg: &mut TaggedMessageEvent) -> Vec<InterceptorEvent> {
        if let MessageEvent::Rtp(RTPMessageEvent::Rtcp(rtcp_packets)) = &msg.message {
            for rtcp_packet in rtcp_packets {
                if let Some(sr) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                {
                    if let Some(stream) = self.streams.get_mut(&sr.ssrc) {
                        stream.process_sender_report(msg.now, sr);
                    }
                }
            }
        } else if let MessageEvent::Rtp(RTPMessageEvent::Rtp(rtp_packet)) = &msg.message {
            if let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc) {
                stream.process_rtp(msg.now, rtp_packet);
            }
        }

        if let Some(next) = self.next() {
            next.read(msg)
        } else {
            vec![]
        }
    }

    fn handle_timeout(&mut self, now: Instant, four_tuples: &[FourTuple]) -> Vec<InterceptorEvent> {
        let mut interceptor_events = vec![];

        if self.eto <= now {
            self.eto = now + self.interval;

            for stream in self.streams.values_mut() {
                let rr = stream.generate_report(now);
                for four_tuple in four_tuples {
                    interceptor_events.push(InterceptorEvent::Outbound(TaggedMessageEvent {
                        now,
                        transport: TransportContext {
                            local_addr: four_tuple.local_addr,
                            peer_addr: four_tuple.peer_addr,
                            ecn: None,
                        },
                        message: MessageEvent::Rtp(RTPMessageEvent::Rtcp(vec![Box::new(
                            rr.clone(),
                        )])),
                    }));
                }
            }
        }

        if let Some(next) = self.next() {
            let mut events = next.handle_timeout(now, four_tuples);
            interceptor_events.append(&mut events);
        }
        interceptor_events
    }

    fn poll_timeout(&mut self, eto: &mut Instant) {
        if self.eto < *eto {
            *eto = self.eto
        }

        if let Some(next) = self.next() {
            next.poll_timeout(eto);
        }
    }
}
