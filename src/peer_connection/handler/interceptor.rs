use crate::peer_connection::event::{
    RTCEvent, RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use log::{debug, trace, warn};
use rtcp::header::{FORMAT_CCFB, PacketType};
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use shared::error::{Error, Result};
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct InterceptorHandlerContext {
    is_dtls_handshake_complete: bool,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a> {
    ctx: &'a mut InterceptorHandlerContext,
    interceptor: &'a mut dyn Interceptor,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> InterceptorHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut InterceptorHandlerContext,
        interceptor: &'a mut dyn Interceptor,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        InterceptorHandler {
            ctx,
            interceptor,
            stats,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "InterceptorHandler"
    }

    /// Process incoming RTCP packets and update stats
    fn process_read_rtcp_for_stats(
        &mut self,
        rtcp_packets: &[Box<dyn rtcp::Packet>],
        now: Instant,
    ) {
        for packet in rtcp_packets {
            // Check for CCFB (Congestion Control Feedback) packets: PT=205, FMT=11
            let header = packet.header();
            if header.packet_type == PacketType::TransportSpecificFeedback
                && header.count == FORMAT_CCFB
            {
                self.stats.transport.on_ccfb_received();
            }

            // Try to downcast to SenderReport
            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>() {
                // SR contains info about the remote sender
                // Update inbound stream stats with remote sender info (if accumulator exists)
                if let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&sr.ssrc) {
                    stream.on_rtcp_sr_received(sr.packet_count as u64, sr.octet_count as u64, now);
                }
            }

            // Try to downcast to ReceiverReport
            if let Some(rr) = packet.as_any().downcast_ref::<ReceiverReport>() {
                // RR contains info about how the remote receiver is receiving our stream
                for report in &rr.reports {
                    if let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&report.ssrc) {
                        let fraction_lost = report.fraction_lost as f64 / 256.0;

                        stream.on_rtcp_rr_received(
                            report.last_sequence_number as u64,
                            report.total_lost as u64,
                            report.jitter as f64,
                            fraction_lost,
                            0.0, // RTT calculation would require additional tracking
                        );
                    }
                }
            }

            // NACK received from remote - feedback about our outbound stream
            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                && let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&nack.media_ssrc)
            {
                stream.on_nack_received();
            }

            // PLI received from remote - feedback about our outbound stream
            if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>()
                && let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&pli.media_ssrc)
            {
                stream.on_pli_received();
            }

            // FIR received from remote - feedback about our outbound stream
            if let Some(fir) = packet.as_any().downcast_ref::<FullIntraRequest>() {
                for fir_entry in &fir.fir {
                    if let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&fir_entry.ssrc) {
                        stream.on_fir_received();
                    }
                }
            }
        }
    }

    /// Process outgoing RTCP packets and update stats
    fn process_write_rtcp_for_stats(&mut self, rtcp_packets: &[Box<dyn rtcp::Packet>]) {
        for packet in rtcp_packets {
            // Check for CCFB (Congestion Control Feedback) packets: PT=205, FMT=11
            let header = packet.header();
            if header.packet_type == PacketType::TransportSpecificFeedback
                && header.count == FORMAT_CCFB
            {
                self.stats.transport.on_ccfb_sent();
            }

            // Receiver Report sent - contains packets_lost and jitter for inbound streams
            if let Some(rr) = packet.as_any().downcast_ref::<ReceiverReport>() {
                for report in &rr.reports {
                    if let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&report.ssrc) {
                        stream.on_rtcp_rr_generated(report.total_lost as i64, report.jitter as f64);
                    }
                }
            }

            // NACK sent - feedback about inbound stream we want retransmission for
            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                && let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&nack.media_ssrc)
            {
                stream.on_nack_sent();
            }

            // PLI sent - requesting keyframe from remote sender
            if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>()
                && let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&pli.media_ssrc)
            {
                stream.on_pli_sent();
            }

            // FIR sent - requesting keyframe from remote sender
            if let Some(fir) = packet.as_any().downcast_ref::<FullIntraRequest>() {
                for fir_entry in &fir.fir {
                    if let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&fir_entry.ssrc) {
                        stream.on_fir_sent();
                    }
                }
            }
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for InterceptorHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = msg.message
        {
            if let Packet::Rtp(rtp_packet) = &packet {
                let ssrc = rtp_packet.header.ssrc;
                let payload_bytes = rtp_packet.payload.len();
                self.stats
                    .on_rtx_packet_received_if_rtx(ssrc, payload_bytes);
                self.stats
                    .on_fec_packet_received_if_fec(ssrc, payload_bytes);
            }

            self.interceptor.handle_read(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.into(),
            })?;
        } else {
            debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.ctx.is_dtls_handshake_complete {
            while let Some(packet) = self.interceptor.poll_read() {
                // Attributes are how information crosses interceptors; this is where the ones
                // that mean something beyond the chain are translated into events the application
                // already polls for. Connection-level facts only — a per-packet attribute like
                // `RecoveredByFec` means nothing to an application and stops here.
                for attribute in &packet.message.attributes {
                    if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                        // #840's stats half. The estimate is one number for the connection, while
                        // `target_bitrate` is reported per outbound stream — with a single stream
                        // they are the same thing. Splitting one estimate across simulcast layers
                        // is an allocation problem, and belongs wherever that allocation is made
                        // rather than here.
                        for stream in self.stats.outbound_rtp_streams.values_mut() {
                            stream.target_bitrate = *bits_per_second;
                        }
                        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                            now: packet.now,
                            event: RTCEventInternal::RTCPeerConnectionEvent(
                                RTCPeerConnectionEvent::OnTargetBitrateChangeEvent(
                                    *bits_per_second,
                                ),
                            ),
                        });
                    }
                }

                // An empty RTCP packet is an attribute carrier, not a message: the terminus strips
                // an annotated report down to this so its attributes can reach here. Its work is
                // done, and surfacing it would hand the application a packet with nothing in it.
                if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                    continue;
                }

                if let Packet::Rtcp(rtcp_packet) = &packet.message.packet {
                    trace!("Interceptor forwarded a RTCP packet {:?}", rtcp_packet);
                }

                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message.packet)),
                });
            }
        }

        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = msg.message
        {
            self.interceptor.handle_write(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.into(),
            })?;
        } else {
            debug!("interceptor bypass {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        if self.ctx.is_dtls_handshake_complete {
            while let Some(packet) = self.interceptor.poll_write() {
                // Process outgoing packets for stats
                match &packet.message.packet {
                    Packet::Rtcp(rtcp_packets) => {
                        self.process_write_rtcp_for_stats(rtcp_packets);
                    }
                    Packet::Rtp(rtp_packet) => {
                        // Track outbound RTP stats if the stream accumulator exists
                        let ssrc = rtp_packet.header.ssrc;
                        let payload_bytes = rtp_packet.payload.len();
                        self.stats.on_rtx_packet_sent_if_rtx(ssrc, payload_bytes);

                        if let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&ssrc) {
                            stream.on_rtp_sent(
                                rtp_packet.header.marshal_size(),
                                payload_bytes,
                                packet.now,
                            );
                        }
                    }
                    _ => {}
                }

                // The carrier's work is done: every interceptor has seen its attributes. An
                // empty RTCP packet on the wire would be a malformed datagram, so it stops here.
                if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                    continue;
                }

                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message.packet)),
                });
                trace!("interceptor write {:?}", packet.transport.peer_addr);
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        if let RTCEventInternal::DTLSHandshakeComplete(_, _) = &evt.event {
            debug!("interceptor recv dtls handshake complete");
            self.ctx.is_dtls_handshake_complete = true;
        }

        // An application's request becomes an attribute on a carrier packet. The write walk starts
        // at the application end, so an attribute injected here is seen by *every* interceptor —
        // which is what makes this the general application-to-chain command channel rather than a
        // special case for any one of them.
        if let RTCEventInternal::RTCEvent(event) = &evt.event {
            let attribute = match event {
                RTCEvent::ForcePli { ssrcs } => Attribute::ForcePli {
                    ssrcs: ssrcs.clone(),
                },
            };

            // An empty RTCP packet: inert to every interceptor that does not read attributes, and
            // dropped again by `poll_write` below so it never reaches the wire.
            let carrier = TaggedPacket {
                now: evt.now,
                transport: Default::default(),
                message: AttributedPacket::new(Packet::Rtcp(Vec::new())).with(attribute),
            };
            if let Err(err) = self.interceptor.handle_write(carrier) {
                warn!("interceptor rejected an application event: {err}");
            }
        }

        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        // self.interceptor.poll_event(());

        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete {
            self.interceptor.handle_timeout(now)
        } else {
            Ok(())
        }
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        if self.ctx.is_dtls_handshake_complete {
            self.interceptor.poll_timeout()
        } else {
            None
        }
    }

    fn close(&mut self) -> Result<()> {
        self.interceptor.close()
    }
}

#[cfg(test)]
mod boundary_tests {
    //! The last hop, in both directions (P7-08a, P7-08b).
    //!
    //! `Ein`/`Eout` on the interceptor trait are `()`, so an attribute riding on a packet is the
    //! only channel between interceptors. It carries information as far as the end of the chain and
    //! no further — everything here is about what happens at that end, where attributes become
    //! events and events become attributes.

    use super::*;
    use crate::statistics::accumulator::OutboundRtpStreamAccumulator;
    use interceptor::StreamInfo;
    use sansio::Protocol;
    use shared::TransportContext;

    /// A stand-in for a chain, so a test can put an arbitrary attribute on the read leg and see
    /// exactly what came back down the write leg. A real chain cannot be made to emit an arbitrary
    /// attribute from outside, which is precisely what needs checking here.
    #[derive(Default)]
    struct FakeChain {
        reads: VecDeque<TaggedPacket>,
        writes: VecDeque<TaggedPacket>,
        /// What the handler pushed down the write leg: its attributes, and whether the packet
        /// carrying them was an empty RTCP one. `TaggedPacket` is not `Clone`, and these two facts
        /// are the whole of what the injection contract promises.
        written: Vec<(Vec<Attribute>, bool)>,
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for FakeChain {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<()> {
            self.reads.push_back(msg);
            Ok(())
        }
        fn poll_read(&mut self) -> Option<TaggedPacket> {
            self.reads.pop_front()
        }
        fn handle_write(&mut self, msg: TaggedPacket) -> Result<()> {
            self.written.push((
                msg.message.attributes.clone(),
                matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty()),
            ));
            self.writes.push_back(msg);
            Ok(())
        }
        fn poll_write(&mut self) -> Option<TaggedPacket> {
            self.writes.pop_front()
        }
        fn handle_event(&mut self, _: ()) -> Result<()> {
            Ok(())
        }
        fn poll_event(&mut self) -> Option<()> {
            None
        }
        fn handle_timeout(&mut self, _: Instant) -> Result<()> {
            Ok(())
        }
        fn poll_timeout(&mut self) -> Option<Instant> {
            None
        }
        fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Interceptor for FakeChain {
        fn bind_local_stream(&mut self, _: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
    }

    fn carrier(attribute: Attribute) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(Vec::new())).with(attribute),
        }
    }

    /// A context past the handshake — before it, the handler bypasses the chain entirely.
    fn connected() -> InterceptorHandlerContext {
        InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        }
    }

    /// **P7-08a.** An estimate arriving as an attribute becomes an event the application already
    /// polls for, and lands in the stats it already reads. Without this the estimator can run
    /// perfectly and no one outside the chain ever learns what it decided.
    #[test]
    fn an_estimate_becomes_an_event_and_a_stat() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();
        stats.outbound_rtp_streams.insert(
            7,
            OutboundRtpStreamAccumulator {
                ssrc: 7,
                ..Default::default()
            },
        );

        chain
            .handle_read(carrier(Attribute::TargetBitrateChanged {
                bits_per_second: 750_000.0,
            }))
            .expect("seed");

        let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);
        let message = handler.poll_read();
        let event = handler.poll_event();

        assert!(
            message.is_none(),
            "the carrier is not a message — an empty RTCP packet means nothing to an application"
        );
        assert!(
            matches!(
                event,
                Some(TaggedRTCEventInternal {
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTargetBitrateChangeEvent(rate)
                    ),
                    ..
                }) if rate == 750_000.0
            ),
            "the estimate must surface as an event"
        );
        assert_eq!(
            750_000.0, stats.outbound_rtp_streams[&7].target_bitrate,
            "and must reach the stats #840 asks for"
        );
    }

    /// A per-packet attribute is chain business. `RecoveredByFec` tells the NACK generator not to
    /// ask for a packet again; an application has nothing to do with it, so it stops here.
    #[test]
    fn a_per_packet_attribute_produces_no_event() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        let mut packet = carrier(Attribute::RecoveredByFec);
        packet.message.packet = Packet::Rtcp(Vec::new());
        chain.handle_read(packet).expect("seed");

        let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);
        while handler.poll_read().is_some() {}

        assert!(
            handler.poll_event().is_none(),
            "only connection-level facts cross the boundary"
        );
    }

    /// A real RTCP packet still reaches the application when it asked for one — the carrier drop
    /// keys on emptiness, not on RTCP.
    #[test]
    fn a_real_report_still_reaches_the_application() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                    ReceiverReport::default(),
                )])),
            })
            .expect("seed");

        let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);

        assert!(
            handler.poll_read().is_some(),
            "dropping the carrier must not drop RTCP the application asked for"
        );
    }

    /// **P7-08b.** An application's request becomes an attribute on a carrier and enters the chain
    /// at the write leg's start, so *every* interceptor sees it. This is the general command
    /// channel: adding a second command means adding a match arm, not a second mechanism.
    #[test]
    fn a_request_becomes_an_attribute_on_the_write_leg() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        {
            let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now: Instant::now(),
                    event: RTCEventInternal::RTCEvent(RTCEvent::ForcePli {
                        ssrcs: Some(vec![42]),
                    }),
                })
                .expect("event");
        }

        assert_eq!(1, chain.written.len(), "the request must enter the chain");
        let (attributes, is_carrier) = &chain.written[0];
        assert!(
            *is_carrier,
            "on a carrier: inert to every interceptor that does not read attributes"
        );
        assert!(
            matches!(
                attributes.as_slice(),
                [Attribute::ForcePli { ssrcs: Some(ssrcs) }] if ssrcs == &vec![42]
            ),
            "carrying the request itself, got {attributes:?}"
        );
    }

    /// And the carrier stops at the boundary on the way back out. An empty RTCP packet on the wire
    /// is a malformed datagram; the far end is entitled to drop the whole compound.
    #[test]
    fn the_carrier_never_reaches_the_wire() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        chain
            .handle_write(carrier(Attribute::ForcePli { ssrcs: None }))
            .expect("seed");

        let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);

        assert!(
            handler.poll_write().is_none(),
            "an empty RTCP packet must not be sent"
        );
    }

    /// A genuine outbound packet is untouched by the drop, so the invariant costs nothing.
    #[test]
    fn a_real_outbound_packet_is_unaffected() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        chain
            .handle_write(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                    PictureLossIndication::default(),
                )])),
            })
            .expect("seed");

        let mut handler = InterceptorHandler::new(&mut ctx, &mut chain, &mut stats);

        assert!(
            handler.poll_write().is_some(),
            "real RTCP must still be sent"
        );
    }
}
