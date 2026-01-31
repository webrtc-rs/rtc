use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Interceptor, Packet, TaggedPacket};
use log::{debug, trace};
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
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    ctx: &'a mut InterceptorHandlerContext,
    interceptor: &'a mut I,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a, I> InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    pub(crate) fn new(
        ctx: &'a mut InterceptorHandlerContext,
        interceptor: &'a mut I,
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

impl<'a, I> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for InterceptorHandler<'a, I>
where
    I: Interceptor,
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
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
                message: packet,
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
                if let Packet::Rtcp(rtcp_packet) = &packet.message {
                    trace!("Interceptor forwarded a RTCP packet {:?}", rtcp_packet);
                }

                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message)),
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
                message: packet,
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
                match &packet.message {
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
                }

                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message)),
                });
                trace!("interceptor write {:?}", packet.transport.peer_addr);
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        if let RTCEventInternal::DTLSHandshakeComplete(_, _) = &evt {
            debug!("interceptor recv dtls handshake complete");
            self.ctx.is_dtls_handshake_complete = true;
            // self.interceptor.handle_event(());
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
