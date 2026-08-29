use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::handler::endpoint::resolve_rtx_primary;
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{find_fec_payload_type, find_rtx_payload_type};
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::{
    PayloadType, RTCRtpReceiverId, SSRC, internal::RTCRtpTransceiverInternal,
};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Attribute, Interceptor, Packet, TaggedPacket};
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
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a> {
    ctx: &'a mut InterceptorHandlerContext,
    rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal>,
    media_engine: &'a MediaEngine,
    interceptor: &'a mut dyn Interceptor,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> InterceptorHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut InterceptorHandlerContext,
        rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal>,
        media_engine: &'a MediaEngine,
        interceptor: &'a mut dyn Interceptor,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        InterceptorHandler {
            ctx,
            rtp_transceivers,
            media_engine,
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

    // Establishing an inbound stream, before the interceptor chain sees its first packet.
    //
    // # Why this is not in the endpoint handler
    //
    // A remote stream cannot be bound to the interceptors at negotiation time: a declared-SSRC track
    // is created with an empty codec (see `RTCPeerConnection::start_rtp`), and which codec the peer
    // actually sends is only known from the payload type of an arriving packet.
    //
    // That resolution used to live in the endpoint handler, which sits *application-ward* of the
    // interceptor chain on the read walk. So the packet that resolved the codec had already traversed
    // every interceptor by the time the bind happened, and each one missed it:
    //
    // - the FlexFEC decoder never saw packet one, then rebuilt it from the first repair packet —
    //   handing the application a duplicate of a packet that had arrived perfectly well;
    // - the NACK generator's receive log started at packet two, so its notion of "first seen" was off
    //   by one;
    // - the TWCC and RFC 8888 arrival recorders under-reported by one arrival;
    // - `on_rtx_packet_received_if_rtx` / `on_fec_packet_received_if_fec` in the interceptor handler
    //   silently dropped the first packet's bytes, because the accumulator they look up is created
    //   here.
    //
    // Running establishment from the interceptor handler, immediately before the chain is handed the
    // packet, removes the whole class: every interceptor sees every packet of a stream it is bound to,
    // starting with the first.
    //
    // # How upstream avoids the same problem
    //
    // pion's chain is pull-based — an interceptor *wraps* the SRTP read stream, so "bind, then read"
    // is the only expressible order. For a declared SSRC it binds at negotiation time with
    // `Codecs[0]`, a guess it never revisits: `checkAndUpdateTrack` corrects the application-facing
    // `TrackRemote` when the real payload type shows up, but not the `StreamInfo` the interceptors
    // were given, which keeps a possibly-wrong clock rate and feedback list for the life of the
    // stream. For an undeclared SSRC it peeks the payload type without consuming the packet, so the
    // packet is still queued when the bind happens.
    //
    // This module takes pion's ordering and not its guess: the codec is still resolved from the
    // payload type actually on the wire, and the packet still reaches the chain, because the bind
    // simply happens first.

    /// Bind this packet's stream to the interceptors, unless it is already bound.
    ///
    /// A no-op for every packet after the first of a stream, which is the overwhelming majority:
    /// the declared-SSRC path finds a codec already set and returns immediately.
    fn ensure_remote_stream_bound(&mut self, now: Instant, rtp_header: &rtp::Header) {
        // An RTX packet identifies the stream it repairs, not one of its own. Resolving it here
        // rather than de-encapsulating first keeps the packet untouched for the chain — the
        // endpoint handler still de-encapsulates on its way to the application — while letting a
        // stream whose first arrival happens to be a retransmission establish anyway.
        let (ssrc, payload_type) = self
            .rtx_primary_for(rtp_header.ssrc, rtp_header.payload_type)
            .unwrap_or((rtp_header.ssrc, rtp_header.payload_type));

        // Same order the endpoint's `find_track_id` used: a declared SSRC settles it, otherwise
        // the single-media-section shortcut, otherwise mid/rid.
        if self.bind_declared_ssrc(now, ssrc, payload_type) {
            return;
        }
        if self.bind_undeclared_ssrc(now, ssrc, payload_type) {
            return;
        }
        self.bind_by_rid(now, ssrc, payload_type, rtp_header);
    }

    /// RTX SSRC of one of this endpoint's receive codings (declared via
    /// `a=ssrc-group:FID <primary> <rtx>` in the remote SDP, RFC 5576). The original payload type
    /// is resolved from the negotiated RTX codec's `apt=` parameter, looked up by the packet's RTX
    /// `payload_type`. Returns `None` when the SSRC is not a known RTX SSRC or the `apt` mapping
    /// cannot be resolved.
    fn rtx_primary_for(
        &self,
        rtx_ssrc: SSRC,
        rtx_payload_type: PayloadType,
    ) -> Option<(SSRC, PayloadType)> {
        self.rtp_transceivers.iter().find_map(|transceiver| {
            let receiver = transceiver.receiver().as_ref()?;
            resolve_rtx_primary(
                receiver.get_coding_parameters(),
                receiver.get_codec_preferences(),
                rtx_ssrc,
                rtx_payload_type,
            )
        })
    }

    /// Returns whether a receiver owns `ssrc`, establishing it if this is its first packet.
    ///
    /// The return value is "this SSRC is accounted for", not "work was done": an already-bound
    /// stream must still stop the caller from trying the rid and undeclared paths, exactly as the
    /// endpoint's `find_track_id_by_ssrc` returning `Some` used to.
    fn bind_declared_ssrc(&mut self, now: Instant, ssrc: SSRC, payload_type: PayloadType) -> bool {
        let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    if let Some(receiver) = transceiver.receiver() {
                        receiver.get_coding_parameters().iter().any(|coding| {
                            coding.ssrc.is_some_and(|coding_ssrc| coding_ssrc == ssrc)
                        })
                    } else {
                        false
                    }
                })
        else {
            return false;
        };

        // Get kind and mid before borrowing receiver mutably
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        if !receiver
            .track()
            .ssrcs()
            .any(|track_ssrc| track_ssrc == ssrc)
        {
            return false;
        }

        let is_track_codec_empty = receiver
            .track()
            .get_codec_by_ssrc(ssrc)
            .is_some_and(|codec| codec.mime_type.is_empty());

        // `payload_type` is the *primary* codec's: an RTX packet was resolved back to the stream it
        // repairs before we got here. FEC de-encapsulation is still TODO (see #12).
        let track_codec = if is_track_codec_empty
            && let Some(codec) = receiver
                .get_codec_preferences()
                .iter()
                .find(|codec| codec.payload_type == payload_type)
        {
            Some((codec.rtp_codec.clone(), codec.payload_type))
        } else {
            None
        };

        let Some((codec, payload_type)) = track_codec else {
            // Already established — the common case, once per packet after the first.
            return true;
        };

        // Get RTX and FEC SSRCs from coding parameters
        let (rtx_ssrc, fec_ssrc) = receiver
            .get_coding_parameters()
            .iter()
            .find(|c| c.ssrc == Some(ssrc))
            .map(|c| {
                (
                    c.rtx.as_ref().map(|r| r.ssrc),
                    c.fec.as_ref().map(|f| f.ssrc),
                )
            })
            .unwrap_or((None, None));

        let parameters = receiver.get_parameters(self.media_engine);
        // Both halves or neither, per repair flow — see `interceptor_remote_streams_op`. RTX and
        // FEC are handled identically: both repair this stream from a separate SSRC.
        let rtx = rtx_ssrc.zip(find_rtx_payload_type(
            payload_type,
            &parameters.rtp_parameters.codecs,
        ));
        let fec = fec_ssrc.zip(find_fec_payload_type(&parameters.rtp_parameters.codecs));

        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
            fec.map(|(ssrc_fec, _)| ssrc_fec),
            payload_type,
            rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
            fec.map(|(_, payload_type_fec)| payload_type_fec),
            &codec,
            &parameters.rtp_parameters.header_extensions,
        );

        // Each repair flow is also bound in its own right, exactly as
        // `interceptor_remote_streams_op` does it: a real RTP stream with its own SSRC and
        // sequence-number space, which an interceptor tracking arrivals has to know about. Binding
        // only the primary here would also leave the pair unbalanced — `stop` unbinds all three, so
        // the repair flows would be unbound having never been bound.
        if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_rtx,
                None,
                None,
                payload_type_rtx,
                None,
                None,
                &codec,
                &parameters.rtp_parameters.header_extensions,
            );
        }

        if let Some((ssrc_fec, payload_type_fec)) = fec {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_fec,
                None,
                None,
                payload_type_fec,
                None,
                None,
                &codec,
                &parameters.rtp_parameters.header_extensions,
            );
        }

        // Set valid Codec for track when received the first RTP packet for such ssrc stream
        // assert not inserting new entry
        let track_id = receiver.track().track_id().clone();
        let stream_id = receiver.track().stream_id().to_owned();
        let new_entry = receiver.track_mut().set_codec_by_ssrc(codec, ssrc);
        assert!(!new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id);

        self.emit_on_open(now, id, track_id, stream_id, ssrc, None);
        true
    }

    /// The single-media-section shortcut: an SSRC absent from the SDP, resolved by there being
    /// only one place it could belong to.
    fn bind_undeclared_ssrc(
        &mut self,
        now: Instant,
        ssrc: SSRC,
        payload_type: PayloadType,
    ) -> bool {
        if self.rtp_transceivers.len() != 1 {
            // it is multi-media-section case, let's use the rid path
            return false;
        }

        if let Some(transceiver) = self.rtp_transceivers.first()
            && let Some(receiver) = transceiver.receiver()
            && !receiver.track().codings().is_empty()
        {
            // it is rid-based, let's use the rid path
            return false;
        }

        let Some(transceiver) = self.rtp_transceivers.first_mut() else {
            return false;
        };
        // Get kind and mid before borrowing receiver mutably
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        let Some(codec) = receiver
            .get_codec_preferences()
            .iter()
            .find(|codec| codec.payload_type == payload_type)
            .cloned()
        else {
            return false;
        };

        let receive_codings = vec![RTCRtpCodingParameters {
            rid: "".to_string(),
            ssrc: Some(ssrc),
            rtx: None,
            fec: None,
        }];
        receiver.set_coding_parameters(receive_codings);

        let parameters = receiver.get_parameters(self.media_engine);
        // An undeclared SSRC arrived without any `a=ssrc-group` to associate it with, so there is
        // no repair flow to report — the codings above are built with `fec: None`.
        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            None,
            None,
            codec.payload_type,
            None,
            None,
            &codec.rtp_codec,
            &parameters.rtp_parameters.header_extensions,
        );

        let track_id = receiver.track().track_id().to_owned();
        let stream_id = receiver.track().stream_id().to_owned();
        // assert it inserts a new entry
        let new_entry = receiver
            .track_mut()
            .set_codec_by_ssrc(codec.rtp_codec, ssrc);
        assert!(new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        // Note: undeclared SSRC case doesn't have RTX/FEC info
        self.stats.get_or_create_inbound_rtp_streams(
            ssrc, kind, &track_id, &mid, None, None,
            0, // Undeclared SSRC is always for the first transceiver
        );

        self.emit_on_open(now, 0, track_id, stream_id, ssrc, None);
        true
    }

    /// Simulcast: the layer is identified by the `mid`/`rid` header extensions rather than by an
    /// SSRC the SDP declared.
    fn bind_by_rid(
        &mut self,
        now: Instant,
        ssrc: SSRC,
        payload_type: PayloadType,
        rtp_header: &rtp::Header,
    ) -> bool {
        let Some((mid, rid, rrid)) = self.get_rtp_header_extension_ids(rtp_header) else {
            return false;
        };
        if mid.is_empty() || (rid.is_empty() && rrid.is_empty()) {
            return false;
        }
        if !rrid.is_empty() {
            //TODO: Add support of handling repair rtp stream id (rrid) #12
            return false;
        }

        // If rtp header extension has valid mid, find receiver based on mid, instead of rid,
        // since rid is not unique across m= lines
        let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    transceiver
                        .mid()
                        .as_deref()
                        .is_some_and(|t_mid| t_mid == mid)
                })
        else {
            return false;
        };

        // Get kind before borrowing receiver mutably
        let kind = transceiver.kind();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        let Some(codec) = receiver
            .get_codec_preferences()
            .iter()
            .find(|codec| codec.payload_type == payload_type) //TODO: what about RTX/FEC stream?
            .cloned()
        else {
            return false;
        };

        if let Some(coding) = receiver.get_coding_parameter_mut_by_rid(rid.as_str()) {
            if coding.ssrc == Some(ssrc) {
                // Already established for this layer.
                return true;
            }
            coding.ssrc = Some(ssrc);
        }

        // Get RTX and FEC SSRCs from coding parameters.
        //
        // Resolved before the bind rather than after it: each simulcast layer has its own repair
        // flow, so the association has to be the one belonging to *this* coding, and it is what the
        // bind below hands to the interceptors.
        let (rtx_ssrc, fec_ssrc) = receiver
            .get_coding_parameters()
            .iter()
            .find(|c| c.ssrc == Some(ssrc))
            .map(|c| {
                (
                    c.rtx.as_ref().map(|r| r.ssrc),
                    c.fec.as_ref().map(|f| f.ssrc),
                )
            })
            .unwrap_or((None, None));

        let parameters = receiver.get_parameters(self.media_engine);
        // Both halves or neither, per repair flow — see `interceptor_remote_streams_op`. RTX and
        // FEC are handled identically: both repair this stream from a separate SSRC.
        let rtx = rtx_ssrc.zip(find_rtx_payload_type(
            codec.payload_type,
            &parameters.rtp_parameters.codecs,
        ));
        let fec = fec_ssrc.zip(find_fec_payload_type(&parameters.rtp_parameters.codecs));

        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
            fec.map(|(ssrc_fec, _)| ssrc_fec),
            codec.payload_type,
            rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
            fec.map(|(_, payload_type_fec)| payload_type_fec),
            &codec.rtp_codec,
            &parameters.rtp_parameters.header_extensions,
        );

        // And each repair flow in its own right, as `interceptor_remote_streams_op` does: naming it
        // as an association on the primary tells an interceptor which flow repairs which, not that
        // a stream with its own SSRC and sequence-number space is arriving. Simulcast is where this
        // matters most — every layer has its own retransmission flow, and NACK-driven repair is
        // what keeps the upper layers usable.
        if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_rtx,
                None,
                None,
                payload_type_rtx,
                None,
                None,
                &codec.rtp_codec,
                &parameters.rtp_parameters.header_extensions,
            );
        }

        if let Some((ssrc_fec, payload_type_fec)) = fec {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_fec,
                None,
                None,
                payload_type_fec,
                None,
                None,
                &codec.rtp_codec,
                &parameters.rtp_parameters.header_extensions,
            );
        }

        let track_id = receiver.track().track_id().to_owned();
        let stream_id = receiver.track().stream_id().to_owned();
        let new_entry = receiver
            .track_mut()
            .set_codec_ssrc_by_rid(codec.rtp_codec, ssrc, &rid);
        assert!(!new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id);

        self.emit_on_open(now, id, track_id, stream_id, ssrc, Some(rid));
        true
    }

    /// Fire `RTCTrackEvent::OnOpen` for the first RTP packet of a stream.
    ///
    /// Queued to the interceptor handler's events rather than the endpoint's, which is where
    /// establishment now happens. Events and media travel in separate queues to the application, so
    /// their relative order was never guaranteed; what is guaranteed either way is that the
    /// accumulator above exists before this fires.
    fn emit_on_open(
        &mut self,
        now: Instant,
        receiver_id: usize,
        track_id: MediaStreamTrackId,
        stream_id: String,
        ssrc: SSRC,
        rid: Option<String>,
    ) {
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnTrack(
                RTCTrackEvent::OnOpen(RTCTrackEventInit {
                    receiver_id: RTCRtpReceiverId(receiver_id),
                    track_id,
                    stream_ids: vec![stream_id],
                    ssrc,
                    rid,
                }),
            )),
        });
    }

    fn get_rtp_header_extension_ids(
        &self,
        rtp_header: &rtp::Header,
    ) -> Option<(String, String, String)> {
        if !rtp_header.extension {
            return None;
        }

        // Get MID extension ID
        let (mid_extension_id, audio_supported, video_supported) = self
            .media_engine
            .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
            });
        if !audio_supported && !video_supported {
            return None;
        }

        // Get RID extension ID
        let (rid_extension_id, audio_supported, video_supported) = self
            .media_engine
            .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
            });
        if !audio_supported && !video_supported {
            return None;
        }

        // Get RRID extension ID
        let (rrid_extension_id, _, _) =
            self.media_engine
                .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                    uri: ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI.to_owned(),
                });

        let mid = if let Some(payload) = rtp_header.get_extension(mid_extension_id as u8) {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        let rid = if let Some(payload) = rtp_header.get_extension(rid_extension_id as u8) {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        let rrid = if let Some(payload) = rtp_header.get_extension(rrid_extension_id as u8) {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        Some((mid, rid, rrid))
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
                // Establish the stream *before* the chain is handed the packet. The codec can only
                // be resolved from an arriving payload type, so this is the first moment it can be
                // done — and doing it here rather than in the endpoint handler, which sits
                // application-ward of the chain, is what stops the first packet of every stream
                // from traversing interceptors that have not yet been told the stream exists.
                // See "Stream establishment" below.
                self.ensure_remote_stream_bound(msg.now, &rtp_packet.header);

                let ssrc = rtp_packet.header.ssrc;
                let payload_bytes = rtp_packet.payload.len();
                // Reached only now that the accumulator exists: `ensure_remote_stream_bound` creates it, and until
                // this ran here these two silently dropped the first packet of every stream.
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
                // Attributes are how information crosses interceptors, and this is where the ones
                // that mean something beyond the chain are recorded. The estimate reaches the
                // application through `get_stats` rather than through an event of its own: it is
                // one more number about the send side, and it belongs with the rest of them.
                for attribute in &packet.message.attributes {
                    if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                        // The estimate is one number for the connection, while `target_bitrate` is
                        // reported per outbound stream — with a single stream they are the same
                        // thing. Splitting one estimate across simulcast layers is an allocation
                        // problem, and belongs wherever that allocation is made rather than here.
                        for stream in self.stats.outbound_rtp_streams.values_mut() {
                            stream.target_bitrate = *bits_per_second;
                        }
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
    //! The last hop inbound: an attribute becomes a statistic.
    //!
    //! `Ein`/`Eout` on the interceptor trait are `()`, so an attribute riding on a packet is the
    //! only channel between interceptors. It carries information as far as the end of the chain and
    //! no further — these tests are about what happens at that end, where the congestion
    //! controller's estimate stops being chain business and becomes something `get_stats` reports.

    use super::*;
    use crate::statistics::accumulator::OutboundRtpStreamAccumulator;
    use interceptor::{AttributedPacket, StreamInfo};
    use sansio::Protocol;
    use shared::TransportContext;

    /// A stand-in for a chain, so a test can put an arbitrary attribute on the read leg. A real
    /// chain cannot be made to emit one from outside, which is what needs checking here.
    #[derive(Default)]
    struct FakeChain {
        reads: VecDeque<TaggedPacket>,
        writes: VecDeque<TaggedPacket>,
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

    /// The estimate lands in the stats, which is the whole of how it reaches an application.
    #[test]
    fn an_estimate_becomes_a_stat() {
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

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        let message = handler.poll_read();

        assert!(
            message.is_none(),
            "the carrier is not a message — an empty RTCP packet means nothing to an application"
        );
        assert_eq!(
            750_000.0, stats.outbound_rtp_streams[&7].target_bitrate,
            "the estimate must reach the stats, or nothing outside the chain ever learns it"
        );
    }

    /// A per-packet attribute is chain business. `RecoveredByFec` tells the NACK generator not to
    /// ask for a packet again; an application has nothing to do with it, so it stops here.
    #[test]
    fn a_per_packet_attribute_changes_no_stats() {
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
            .handle_read(carrier(Attribute::RecoveredByFec))
            .expect("seed");

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        while handler.poll_read().is_some() {}

        assert_eq!(
            0.0, stats.outbound_rtp_streams[&7].target_bitrate,
            "only the estimate writes this field"
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

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );

        assert!(
            handler.poll_read().is_some(),
            "dropping the carrier must not drop RTCP the application asked for"
        );
    }
}

#[cfg(test)]
mod stream_binding_tests {
    //! Binding an inbound stream to the interceptors, on the first packet that identifies it.
    //!
    //! These drive `InterceptorHandler::handle_read` rather than the chain directly, because the
    //! property under test is an *ordering*: the stream must be bound before the chain is handed
    //! the packet that resolved it. A test that called the chain itself could not tell the
    //! difference.

    use super::*;
    use crate::media_stream::track::MediaStreamTrack;
    use crate::peer_connection::configuration::media_engine::MIME_TYPE_RTX;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters,
        RTCRtpHeaderExtensionCapability, RTCRtpRtxParameters, RtpCodecKind,
    };
    use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    use bytes::Bytes;
    use interceptor::StreamInfo;
    use sansio::Protocol as _;
    use shared::TransportContext;
    use std::sync::{Arc, Mutex};

    fn coding(primary_ssrc: u32, rtx_ssrc: Option<u32>) -> RTCRtpCodingParameters {
        RTCRtpCodingParameters {
            rid: String::new(),
            ssrc: Some(primary_ssrc),
            rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
            fec: None,
        }
    }

    fn codec(payload_type: u8, mime_type: &str, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    #[derive(Clone, Default)]
    struct Recorder {
        bound: Arc<Mutex<Vec<StreamInfo>>>,
    }

    impl Recorder {
        fn bound_ssrcs(&self) -> Vec<u32> {
            self.bound
                .lock()
                .unwrap()
                .iter()
                .map(|info| info.ssrc)
                .collect()
        }
    }

    impl sansio::Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, _msg: TaggedPacket) -> Result<()> {
            Ok(())
        }
        fn poll_read(&mut self) -> Option<Self::Rout> {
            None
        }
        fn handle_write(&mut self, _msg: TaggedPacket) -> Result<()> {
            Ok(())
        }
        fn poll_write(&mut self) -> Option<Self::Wout> {
            None
        }
        fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
            Ok(())
        }
        fn poll_timeout(&mut self) -> Option<Instant> {
            None
        }
    }

    impl Interceptor for Recorder {
        fn bind_local_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
        fn bind_remote_stream(&mut self, info: &StreamInfo) {
            self.bound.lock().unwrap().push(info.clone());
        }
        fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
    }

    /// A receiver for a remote track whose SSRC was declared in the SDP but whose codec is not yet
    /// known — the state `RTCPeerConnection::start_rtp` leaves a declared-SSRC track in, with the
    /// codec deferred until the first RTP packet names a payload type.
    fn declared_ssrc_transceiver(
        ssrc: u32,
        payload_type: u8,
        rtx: Option<(u32, u8)>,
    ) -> RTCRtpTransceiverInternal {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );

        let mut preferences = vec![codec(payload_type, "video/VP8", "")];
        if let Some((_, rtx_payload_type)) = rtx {
            preferences.push(codec(
                rtx_payload_type,
                "video/rtx",
                &format!("apt={payload_type}"),
            ));
        }

        let receiver = transceiver.receiver_mut().as_mut().unwrap();
        receiver.set_coding_parameters(vec![coding(ssrc, rtx.map(|(rtx_ssrc, _)| rtx_ssrc))]);
        receiver.set_codec_preferences(preferences);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_string(),
            "track".to_string(),
            "label".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: coding(ssrc, rtx.map(|(rtx_ssrc, _)| rtx_ssrc)),
                active: true,
                // Empty: not known until a packet arrives. This is the whole point.
                codec: RTCRtpCodec::default(),
                max_bitrate: 0,
                max_framerate: None,
                scale_resolution_down_by: None,
            }],
        ));
        transceiver
    }

    /// A media engine that has negotiated VP8 and its RTX pairing.
    ///
    /// `MediaEngine::default()` registers nothing, and the repair payload type is resolved against
    /// the *negotiated* codecs — so with an empty engine `find_rtx_payload_type` returns `None`,
    /// no repair flow is ever recognised, and a test asserting one would fail for a reason that has
    /// nothing to do with binding.
    fn media_engine_with_rtx() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, "video/VP8", ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
            .register_codec(codec(97, MIME_TYPE_RTX, "apt=96"), RtpCodecKind::Video)
            .expect("rtx");
        media_engine
    }

    /// Drive `packets` RTP packets through `InterceptorHandler::handle_read`.
    ///
    /// The handler, not the chain directly: the property under test is that the stream is bound
    /// *before* the chain is handed the packet, and only the handler can get that wrong.
    fn feed(
        transceivers: &mut Vec<RTCRtpTransceiverInternal>,
        interceptor: &mut Recorder,
        ssrc: u32,
        payload_type: u8,
        packets: u16,
    ) {
        let media_engine = media_engine_with_rtx();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = InterceptorHandlerContext {
            // Media is bypassed entirely until the handshake finishes, so without this the handler
            // would forward every packet untouched and each test would pass vacuously.
            is_dtls_handshake_complete: true,
            ..Default::default()
        };
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            transceivers,
            &media_engine,
            interceptor,
            &mut stats,
        );

        for sequence_number in 1..=packets {
            let packet = rtp::Packet {
                header: rtp::Header {
                    payload_type,
                    sequence_number,
                    timestamp: 12_345,
                    ssrc,
                    ..Default::default()
                },
                payload: Bytes::from_static(&[0xDE, 0xAD]),
            };
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))),
                })
                .expect("handle_read");
        }
    }

    /// A declared-SSRC remote stream reaches the interceptors once its codec resolves.
    ///
    /// The track is built from the remote SDP before any packet arrives, so its codec is empty then
    /// and the bind attempted at that point resolves nothing — see `RTCPeerConnection::start_rtp`.
    /// The first RTP packet is the first moment the stream can be described, and if it is not bound
    /// there it never is.
    ///
    /// The failure this guards against is silent: media flows perfectly and only the *feedback* is
    /// missing, because the interceptors that generate receiver reports, TWCC, NACK and PLI sit in
    /// the chain having never been told the stream exists. A publisher then sees its
    /// `remote-inbound-rtp` stats stay empty and quietly lowers its bitrate.
    #[test]
    fn a_declared_ssrc_stream_is_bound_when_its_codec_resolves() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let mut transceivers = vec![declared_ssrc_transceiver(ssrc, payload_type, None)];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 1);

        assert_eq!(
            vec![ssrc],
            recorder.bound_ssrcs(),
            "the stream must be bound once its codec is known"
        );
    }

    /// Bound exactly once, however many packets arrive.
    ///
    /// The bind rides the same branch that resolves the codec, and that branch is guarded on the
    /// codec still being empty. Binding per packet would re-register the stream on every one,
    /// resetting whatever the interceptors keep per stream — sequence tracking, loss counters,
    /// jitter — so the feedback would be wrong rather than absent.
    #[test]
    fn a_declared_ssrc_stream_is_bound_only_once() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let mut transceivers = vec![declared_ssrc_transceiver(ssrc, payload_type, None)];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 5);

        assert_eq!(
            vec![ssrc],
            recorder.bound_ssrcs(),
            "five packets, one bind: the codec is only unresolved once"
        );
    }

    /// The repair flow is bound in its own right, not merely named as an association on the primary.
    ///
    /// `interceptor_remote_streams_op` binds all three — primary, RTX, FEC — and `stop` unbinds all
    /// three. Binding only the primary here would leave the RTX stream unbound while still being
    /// unbound at teardown, and an interceptor tracking arrivals would never learn that the
    /// retransmission SSRC exists.
    #[test]
    fn a_declared_ssrc_stream_binds_its_repair_flow_too() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);
        let mut transceivers = vec![declared_ssrc_transceiver(
            ssrc,
            payload_type,
            Some((rtx_ssrc, rtx_payload_type)),
        )];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 1);

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the primary and its retransmission stream are both real streams"
        );
    }

    /// A simulcast layer binds its repair flow in its own right, as the declared-SSRC path does.
    ///
    /// The RID path already bound the primary, naming the RTX SSRC as an *association* on it —
    /// which tells an interceptor which flow repairs which, not that a stream with its own SSRC and
    /// sequence-number space is arriving. Simulcast is where that matters most: every layer has its
    /// own retransmission flow, and NACK-driven repair is what keeps the upper layers usable.
    ///
    /// It also kept the pair unbalanced — `stop` unbinds all three per coding, so the repair flow
    /// was unbound having never been bound.
    #[test]
    fn a_simulcast_layer_binds_its_repair_flow_too() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let mut media_engine = media_engine_with_rtx();
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .expect("mid extension");
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .expect("rid extension");

        // Registering makes an extension *offerable*; the handler resolves mid/rid through the
        // *negotiated* set, which SDP fills in. Negotiate them here, as an answer would.
        media_engine
            .update_header_extension(1, ::sdp::extmap::SDES_MID_URI, RtpCodecKind::Video)
            .expect("negotiate mid");
        media_engine
            .update_header_extension(
                2,
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                RtpCodecKind::Video,
            )
            .expect("negotiate rid");

        // Ask the engine which ids it assigned rather than assuming: the handler resolves mid/rid
        // through the same lookup, so a guess that disagreed would make this test fail for a
        // reason unrelated to binding.
        let (mid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
            });
        let (rid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
            });

        // A layer whose SSRC is not yet known: the RID path is what learns it from the first packet.
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid("0".to_owned()).expect("mid");
        {
            let receiver = transceiver.receiver_mut().as_mut().unwrap();
            receiver.set_coding_parameters(vec![RTCRtpCodingParameters {
                rid: "h".to_owned(),
                ssrc: None,
                rtx: Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                fec: None,
            }]);
            receiver.set_codec_preferences(vec![
                codec(payload_type, "video/VP8", ""),
                codec(
                    rtx_payload_type,
                    MIME_TYPE_RTX,
                    &format!("apt={payload_type}"),
                ),
            ]);
            receiver.set_track(MediaStreamTrack::new(
                "stream".to_string(),
                "track".to_string(),
                "label".to_string(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        rid: "h".to_owned(),
                        ssrc: None,
                        rtx: Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                        fec: None,
                    },
                    active: true,
                    codec: RTCRtpCodec::default(),
                    max_bitrate: 0,
                    max_framerate: None,
                    scale_resolution_down_by: None,
                }],
            ));
        }
        let mut transceivers = vec![transceiver];

        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        };

        let mut header = rtp::Header {
            extension: true,
            // One-byte extension form (RFC 8285). Without it the header is read as RFC 3550 and
            // rejects these ids outright.
            extension_profile: 0xBEDE,
            payload_type,
            sequence_number: 1,
            timestamp: 12_345,
            ssrc,
            ..Default::default()
        };
        header
            .set_extension(mid_extension_id as u8, Bytes::from_static(b"0"))
            .expect("mid extension");
        header
            .set_extension(rid_extension_id as u8, Bytes::from_static(b"h"))
            .expect("rid extension");

        {
            let mut handler = InterceptorHandler::new(
                &mut ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                &mut stats,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(
                        rtp::Packet {
                            header,
                            payload: Bytes::from_static(&[0xDE, 0xAD]),
                        },
                    ))),
                })
                .expect("handle_read");
        }

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the layer and its retransmission stream are both real streams"
        );
    }
}
