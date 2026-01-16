use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Interceptor, Packet, TaggedPacket};
use log::{debug, error, trace};
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use shared::error::{Error, Result};
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

    /// Process RTCP packets and update stats
    fn process_rtcp_for_stats(&mut self, rtcp_packets: &[Box<dyn rtcp::Packet>], now: Instant) {
        for packet in rtcp_packets {
            // Try to downcast to SenderReport
            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>() {
                // SR contains info about the remote sender
                // Update inbound stream stats with remote sender info
                let stream = self
                    .stats
                    .get_or_create_inbound_rtp_streams(sr.ssrc, RtpCodecKind::Video);
                stream.on_rtcp_sr_received(sr.packet_count as u64, sr.octet_count as u64, now);
            }

            // Try to downcast to ReceiverReport
            if let Some(rr) = packet.as_any().downcast_ref::<ReceiverReport>() {
                // RR contains info about how the remote receiver is receiving our stream
                for report in &rr.reports {
                    if let Some(stream) = self.stats.outbound_rtp_streams.get_mut(&report.ssrc) {
                        // Calculate jitter in seconds (jitter is in timestamp units, divide by typical clock rate)
                        let jitter_seconds = report.jitter as f64 / 90000.0; // Assume 90kHz for video
                        let fraction_lost = report.fraction_lost as f64 / 256.0;

                        stream.on_rtcp_rr_received(
                            report.last_sequence_number as u64,
                            report.total_lost as u64,
                            jitter_seconds,
                            fraction_lost,
                            0.0, // RTT calculation would require additional tracking
                        );
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
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = &msg.message
        {
            self.interceptor.handle_read(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.clone(),
                // RTP packet use Bytes which is zero-copy,
                // RTCP packet may have clone overhead.
                // TODO: Future optimization: If RTCP becomes a bottleneck, wrap it in Arc (minor change)
            })?;

            if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(rtcp_packets))) =
                &msg.message
            {
                // Process RTCP packets for stats (SR/RR parsing)
                self.process_rtcp_for_stats(rtcp_packets, msg.now);

                // RTCP message read must end here. If any rtcp packet needs to be forwarded to PeerConnection,
                // just add a new interceptor to forward it by using self.interceptor.poll_read()
                debug!("interceptor terminates Rtcp {:?}", msg.transport.peer_addr);
                return Ok(());
            }
            // For Packet::Rtp packet, self.interceptor.poll_read() must not have return it,
            // since it has already been bypassed as below, otherwise, it will cause duplicated rtp packets in SRTP
        }

        debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
        self.ctx.read_outs.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.ctx.is_dtls_handshake_complete {
            while let Some(packet) = self.interceptor.poll_read() {
                match &packet.message {
                    Packet::Rtp(_) => {
                        error!(
                            "Interceptor should never forward RTP packet!!! Please double check your interceptor handle/poll_read implementation."
                        );
                    }
                    Packet::Rtcp(rtcp_packet) => {
                        trace!("Interceptor forward a RTCP packet {:?}", rtcp_packet);
                        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                            now: packet.now,
                            transport: packet.transport,
                            message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message)),
                        });
                    }
                }
            }
        }

        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = &msg.message
        {
            self.interceptor.handle_write(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.clone(),
                // RTP packet use Bytes which is zero-copy,
                // RTCP packet may have clone overhead.
                // TODO: Future optimization: If RTCP becomes a bottleneck, wrap it in Arc (minor change)
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
