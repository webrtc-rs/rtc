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
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpRtxParameters,
};
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
        // A repair stream naming its primary by rrid declares the pairing on the wire rather than
        // in the SDP. Record it first, so the RTX resolution below sees it on this packet and not
        // only on the next one.
        let paired_now = self.pair_rrid_repair_stream(rtp_header);

        // An RTX packet identifies the stream it repairs, not one of its own. Resolving it here
        // rather than de-encapsulating first keeps the packet untouched for the chain — the
        // endpoint handler still de-encapsulates on its way to the application — while letting a
        // stream whose first arrival happens to be a retransmission establish anyway.
        let (ssrc, payload_type) = self
            .rtx_primary_for(rtp_header.ssrc, rtp_header.payload_type)
            .unwrap_or((rtp_header.ssrc, rtp_header.payload_type));

        // The pairing resolved, which means the layer it names had already bound — and a bound
        // layer takes the early return in `bind_by_rid`, so the repair flow it has just acquired
        // would never be handed to the chain. Bind it here instead. When the pairing did not
        // resolve the layer has yet to see a packet of its own, and `bind_by_rid` will bind both
        // together from the coding this call just wrote.
        if paired_now && ssrc != rtp_header.ssrc {
            self.bind_rrid_repair_stream(ssrc, payload_type, rtp_header.ssrc);
        }

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

    /// RFC 8852 section 4: a repair stream identifies the layer it repairs with a
    /// `repaired-rtp-stream-id`, because a rid simulcast offer names rids rather than SSRCs and so
    /// carries no `a=ssrc-group:FID` to read.
    ///
    /// Records the pairing on the primary layer's coding. From there the existing RTX path
    /// resolves it: `rtx_primary_for` reads `coding.rtx`, and the endpoint handler
    /// de-encapsulates and dispatches against the primary's track id. Without it the packet dies
    /// at `find_track_id` — no track owns a repair SSRC the SDP never mentioned — and the layer's
    /// NACKs go unrepaired for the life of the stream.
    ///
    /// An rrid-carrying packet is not a stream of its own to bind, it is a statement about a
    /// stream that already exists, so this runs ahead of the bind ladder rather than inside it.
    ///
    /// Returns whether a new pairing was recorded.
    fn pair_rrid_repair_stream(&mut self, rtp_header: &rtp::Header) -> bool {
        let Some((mid, _rid, rrid)) = self.get_rtp_header_extension_ids(rtp_header) else {
            return false;
        };
        if mid.is_empty() || rrid.is_empty() {
            return false;
        }

        let rtx_ssrc = rtp_header.ssrc;
        let Some(transceiver) = self.rtp_transceivers.iter_mut().find(|transceiver| {
            transceiver
                .mid()
                .as_deref()
                .is_some_and(|t_mid| t_mid == mid)
        }) else {
            return false;
        };
        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };

        // A publisher chooses the rrid string it puts on the wire. One naming a layer this
        // m= section never negotiated names nothing, so there is nowhere to record the pairing:
        // drop it rather than inventing a coding for it.
        let Some(coding) = receiver.get_coding_parameter_mut_by_rid(rrid) else {
            return false;
        };

        match &coding.rtx {
            // Already paired, and to this same repair stream. Every subsequent retransmission
            // takes this path, so it must be cheap and silent.
            Some(existing) if existing.ssrc == rtx_ssrc => return false,
            // The layer already has a different repair SSRC. Keep the first: a second one is
            // either an SSRC collision or a publisher changing its mind mid-stream, and
            // overwriting would strand the packets already in flight from the first.
            Some(_) => return false,
            None => coding.rtx = Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
        }

        // The receiver's codings and the track's are two copies of the same state, seeded
        // together in `RTCPeerConnection::start_rtp`. `stop` unbinds from the track's, so a
        // pairing recorded on only the receiver's would leave the repair flow bound below having
        // never been unbound.
        receiver.track_mut().set_rtx_ssrc_by_rid(rrid, rtx_ssrc);
        true
    }

    /// Bind a repair flow whose pairing arrived after the layer it repairs had already bound.
    ///
    /// `bind_by_rid` binds a layer's repair flow from `coding.rtx` at the moment the layer binds,
    /// which covers the ordering where the first rrid packet precedes the layer's first media
    /// packet. The other ordering is the common one — media flows, a packet is lost, and only then
    /// does a retransmission appear — and by then the layer is established, so `bind_by_rid`
    /// returns early and never looks at the coding again.
    ///
    /// Only the repair flow is bound. The primary is deliberately left alone: `bind_remote_stream`
    /// is how the NACK generator acquires its receive log, so re-binding the layer to name the
    /// association on it would discard every sequence number that layer has seen — a worse trade
    /// than an association no interceptor currently reads. The one consumer that does read it is
    /// the stats accumulator, which is updated directly.
    fn bind_rrid_repair_stream(
        &mut self,
        primary_ssrc: SSRC,
        primary_payload_type: PayloadType,
        rtx_ssrc: SSRC,
    ) {
        let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    transceiver.receiver().as_ref().is_some_and(|receiver| {
                        receiver
                            .get_coding_parameters()
                            .iter()
                            .any(|coding| coding.ssrc == Some(primary_ssrc))
                    })
                })
        else {
            return;
        };

        // Get kind and mid before borrowing receiver mutably
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();

        let Some(receiver) = transceiver.receiver_mut() else {
            return;
        };
        // The codec the layer bound with, not one resolved afresh: the repair flow is described to
        // the chain exactly as `bind_by_rid` would have described it.
        let Some(codec) = receiver.track().get_codec_by_ssrc(primary_ssrc).cloned() else {
            return;
        };
        let track_id = receiver.track().track_id().to_owned();

        let parameters = receiver.get_parameters(self.media_engine);
        // Both halves or neither, per repair flow — see `interceptor_remote_streams_op`. `stop`
        // resolves the payload type the same way, so a bind here that teardown would not undo
        // must not happen.
        let Some(payload_type_rtx) =
            find_rtx_payload_type(primary_payload_type, &parameters.rtp_parameters.codecs)
        else {
            return;
        };

        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            rtx_ssrc,
            None,
            None,
            payload_type_rtx,
            None,
            None,
            &codec,
            &parameters.rtp_parameters.header_extensions,
        );

        // The accumulator already exists — the layer created it when it bound — so this is an
        // update, and the reverse map it fills is what attributes this packet's bytes to the
        // right layer in `on_rtx_packet_received_if_rtx`. FEC is left as it was: nothing here
        // learned anything about it.
        self.stats
            .get_or_create_inbound_rtp_streams(
                primary_ssrc,
                kind,
                &track_id,
                &mid,
                Some(rtx_ssrc),
                None,
                id,
            )
            .rtx_ssrc = Some(rtx_ssrc);
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

        let Some(receiver) = transceiver.receiver() else {
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

        // Setup-only metadata, read once the stream is known to need establishing: the mid is an
        // owned copy, and taking it above the early return cost an allocation on every packet.
        // Read before borrowing the receiver mutably.
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
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
        // A packet carrying an rrid is a repair stream, and a repair stream is not a layer: its
        // SSRC belongs on the primary's coding, not on a coding of its own, which
        // `pair_rrid_repair_stream` has already seen to. Binding here would claim the layer for
        // the retransmission SSRC and strand the media that follows.
        if !rrid.is_empty() {
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

        // Validate rid against SDP. If invalid then drop it.
        match receiver.get_coding_parameter_mut_by_rid(rid) {
            None => return false,
            Some(coding) if coding.ssrc == Some(ssrc) => return true,
            Some(coding) => coding.ssrc = Some(ssrc),
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
            .set_codec_ssrc_by_rid(codec.rtp_codec, ssrc, rid);
        assert!(!new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, mid, rtx_ssrc, fec_ssrc, id);

        self.emit_on_open(now, id, track_id, stream_id, ssrc, Some(rid.to_owned()));
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

    /// The `mid`, `rid` and `repaired-rtp-stream-id` a packet carries, each empty when absent or
    /// not valid UTF-8.
    ///
    /// Borrowed from the header rather than copied out of it. This runs for every packet that
    /// carries any header extension — which, from a browser, is every packet — and until now it
    /// allocated six strings a packet to answer it: three URIs to look the ids up with, and
    /// three values that are only ever compared.
    fn get_rtp_header_extension_ids<'h>(
        &self,
        rtp_header: &'h rtp::Header,
    ) -> Option<(&'h str, &'h str, &'h str)> {
        if !rtp_header.extension {
            return None;
        }

        // Get MID extension ID
        let (mid_extension_id, audio_supported, video_supported) = self
            .media_engine
            .negotiated_header_extension_id(::sdp::extmap::SDES_MID_URI);
        if !audio_supported && !video_supported {
            return None;
        }

        // Get RID extension ID
        let (rid_extension_id, audio_supported, video_supported) = self
            .media_engine
            .negotiated_header_extension_id(::sdp::extmap::SDES_RTP_STREAM_ID_URI);
        if !audio_supported && !video_supported {
            return None;
        }

        // Get RRID extension ID
        let (rrid_extension_id, _, _) = self
            .media_engine
            .negotiated_header_extension_id(::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI);

        // `Header::get_extension`'s lookup, without the `Bytes` clone it returns.
        let text = |id: u16| {
            rtp_header
                .extensions
                .iter()
                .find(|extension| extension.id == id as u8)
                .map(|extension| std::str::from_utf8(&extension.payload).unwrap_or_default())
                .unwrap_or_default()
        };

        Some((
            text(mid_extension_id),
            text(rid_extension_id),
            text(rrid_extension_id),
        ))
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

    /// A media engine that has negotiated VP8, its RTX pairing, and the simulcast extensions.
    ///
    /// Registering makes an extension *offerable*; the handler resolves mid/rid/rrid through the
    /// *negotiated* set, which SDP fills in. Both halves are done here, as an answer would.
    fn simulcast_media_engine() -> MediaEngine {
        let mut media_engine = media_engine_with_rtx();
        for (id, uri) in [
            (1, ::sdp::extmap::SDES_MID_URI),
            (2, ::sdp::extmap::SDES_RTP_STREAM_ID_URI),
            (3, ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI),
        ] {
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    },
                    RtpCodecKind::Video,
                    None,
                )
                .expect("register extension");
            media_engine
                .update_header_extension(id, uri, RtpCodecKind::Video)
                .expect("negotiate extension");
        }
        media_engine
    }

    /// The id the handler will resolve `uri` through. Asked of the engine rather than assumed: the
    /// handler uses the same lookup, so a guess that disagreed would make a test fail for a reason
    /// unrelated to what it is about.
    fn extension_id(media_engine: &MediaEngine, uri: &str) -> u8 {
        let (id, _, _) = media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
            uri: uri.to_owned(),
        });
        id as u8
    }

    /// A rid-simulcast receiver: one coding per rid, none of them carrying an SSRC yet.
    ///
    /// This is the state `RTCPeerConnection::start_rtp` leaves a rid m= section in. The offer
    /// named rids rather than SSRCs, so it declared no media SSRC to bind against and no
    /// `a=ssrc-group:FID` to pair a repair flow with. `rtx` is the slot that pairing belongs in,
    /// and a test passing `None` for it is asking where it comes from when the SDP cannot say.
    fn rid_transceiver(mid: &str, rids: &[(&str, Option<u32>)]) -> RTCRtpTransceiverInternal {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid(mid.to_owned()).expect("mid");

        let codings: Vec<RTCRtpCodingParameters> = rids
            .iter()
            .map(|(rid, rtx_ssrc)| RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ssrc: None,
                rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                fec: None,
            })
            .collect();

        let receiver = transceiver.receiver_mut().as_mut().unwrap();
        receiver.set_coding_parameters(codings.clone());
        receiver.set_codec_preferences(vec![
            codec(96, "video/VP8", ""),
            codec(97, MIME_TYPE_RTX, "apt=96"),
        ]);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_string(),
            "track".to_string(),
            "label".to_string(),
            RtpCodecKind::Video,
            codings
                .into_iter()
                .map(|rtp_coding_parameters| RTCRtpEncodingParameters {
                    rtp_coding_parameters,
                    active: true,
                    // Empty: not known until a packet arrives. This is the whole point.
                    codec: RTCRtpCodec::default(),
                    max_bitrate: 0,
                    max_framerate: None,
                    scale_resolution_down_by: None,
                })
                .collect(),
        ));
        transceiver
    }

    /// A header carrying the extensions a simulcast stream identifies itself with: `rid` names the
    /// layer a media packet belongs to, `rrid` the layer a repair packet repairs (RFC 8852).
    fn simulcast_header(
        media_engine: &MediaEngine,
        ssrc: u32,
        payload_type: u8,
        sequence_number: u16,
        mid: &str,
        rid: Option<&str>,
        rrid: Option<&str>,
    ) -> rtp::Header {
        let mut header = rtp::Header {
            extension: true,
            // One-byte extension form (RFC 8285). Without it the header is read as RFC 3550 and
            // rejects these ids outright.
            extension_profile: 0xBEDE,
            payload_type,
            sequence_number,
            timestamp: 12_345,
            ssrc,
            ..Default::default()
        };
        for (uri, value) in [
            (::sdp::extmap::SDES_MID_URI, Some(mid)),
            (::sdp::extmap::SDES_RTP_STREAM_ID_URI, rid),
            (::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI, rrid),
        ] {
            if let Some(value) = value {
                header
                    .set_extension(
                        extension_id(media_engine, uri),
                        Bytes::copy_from_slice(value.as_bytes()),
                    )
                    .expect("extension");
            }
        }
        header
    }

    /// Drive crafted packets through `InterceptorHandler::handle_read`, all of them through one
    /// handler so that what each leaves behind is what the next one meets. Arrival order is the
    /// whole subject of the rrid tests, so it has to be the order these are written in.
    fn feed_simulcast(
        transceivers: &mut Vec<RTCRtpTransceiverInternal>,
        media_engine: &MediaEngine,
        interceptor: &mut Recorder,
        stats: &mut RTCStatsAccumulator,
        headers: Vec<rtp::Header>,
    ) {
        let mut ctx = InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        };
        let mut handler =
            InterceptorHandler::new(&mut ctx, transceivers, media_engine, interceptor, stats);

        for header in headers {
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
    }

    /// The repair SSRC a coding was paired with, as the RTX path reads it.
    fn paired_rtx_ssrc(transceiver: &RTCRtpTransceiverInternal, rid: &str) -> Option<u32> {
        transceiver
            .receiver()
            .as_ref()
            .expect("receiver")
            .get_coding_parameters()
            .iter()
            .find(|coding| coding.rid == rid)
            .and_then(|coding| coding.rtx.as_ref())
            .map(|rtx| rtx.ssrc)
    }

    /// The same, read off the track — the copy `stop` unbinds from.
    fn track_rtx_ssrc(transceiver: &RTCRtpTransceiverInternal, rid: &str) -> Option<u32> {
        transceiver
            .receiver()
            .as_ref()
            .expect("receiver")
            .track()
            .codings()
            .iter()
            .find(|coding| coding.rtp_coding_parameters.rid == rid)
            .and_then(|coding| coding.rtp_coding_parameters.rtx.as_ref())
            .map(|rtx| rtx.ssrc)
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
        let rtx_ssrc = 2000u32;

        let media_engine = simulcast_media_engine();
        // A layer whose SSRC is not yet known: the RID path is what learns it from the first
        // packet. Its repair flow is already known, as it would be from an `a=ssrc-group:FID`.
        let mut transceivers = vec![rid_transceiver("0", &[("h", Some(rtx_ssrc))])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![simulcast_header(
                &media_engine,
                ssrc,
                payload_type,
                1,
                "0",
                Some("h"),
                None,
            )],
        );

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the layer and its retransmission stream are both real streams"
        );
    }

    /// RFC 8852 section 4: a repair stream pairs with the layer its rrid names.
    ///
    /// This is the ordering that happens in practice — media flows, a packet is lost, and only
    /// then does a retransmission appear — so the layer has already bound by the time the pairing
    /// can be learned. Nothing in the SDP could have said it: a rid simulcast offer names rids,
    /// not SSRCs, so there is no `a=ssrc-group:FID` for the receiver to read.
    ///
    /// Until it was recorded the retransmission was discarded inside the core, at
    /// `find_track_id` — no track owns a repair SSRC the SDP never mentioned — so the application
    /// saw a gap its own NACK had already been answered for.
    #[test]
    fn a_repair_stream_pairs_with_the_layer_its_rrid_names() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![
                simulcast_header(&media_engine, ssrc, payload_type, 1, "0", Some("h"), None),
                simulcast_header(
                    &media_engine,
                    rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("h"),
                ),
            ],
        );

        assert_eq!(
            Some(rtx_ssrc),
            paired_rtx_ssrc(&transceivers[0], "h"),
            "the pairing belongs on the layer's coding, which is where the RTX path reads it"
        );
        assert_eq!(
            Some(rtx_ssrc),
            track_rtx_ssrc(&transceivers[0], "h"),
            "and on the track, or `stop` unbinds a repair flow it was never told about"
        );
        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the repair flow reaches the chain on the packet that declared it, not the next one"
        );
    }

    /// A repair stream that arrives before the layer it repairs is paired all the same.
    ///
    /// A publisher is free to start its repair flow first — nothing orders the two — and the
    /// pairing is a statement about the layer, not about this packet. So it is recorded against a
    /// coding with no SSRC yet, and the layer picks it up when its own first packet binds it,
    /// binding both flows together exactly as a declared `a=ssrc-group:FID` would have.
    #[test]
    fn a_repair_stream_arriving_first_is_paired_anyway() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![
                simulcast_header(
                    &media_engine,
                    rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("h"),
                ),
                simulcast_header(&media_engine, ssrc, payload_type, 1, "0", Some("h"), None),
            ],
        );

        assert_eq!(
            Some(rtx_ssrc),
            paired_rtx_ssrc(&transceivers[0], "h"),
            "a coding with no SSRC yet is still the right place to record the pairing"
        );
        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the layer binds both flows once it knows its own SSRC, and binds neither before"
        );
    }

    /// Bound once, however many retransmissions arrive.
    ///
    /// Every packet of a repair flow carries the rrid, so the pairing is re-stated continuously
    /// and only the first statement may act. Binding per retransmission would re-register the
    /// repair stream on each one, resetting whatever the interceptors keep per stream — and on a
    /// lossy path, which is the only time a repair flow runs at all.
    #[test]
    fn a_paired_repair_stream_is_bound_only_once() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        let mut headers = vec![simulcast_header(
            &media_engine,
            ssrc,
            payload_type,
            1,
            "0",
            Some("h"),
            None,
        )];
        headers.extend((1..=5).map(|sequence_number| {
            simulcast_header(
                &media_engine,
                rtx_ssrc,
                rtx_payload_type,
                sequence_number,
                "0",
                None,
                Some("h"),
            )
        }));

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            headers,
        );

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "five retransmissions, one bind: the pairing is only new once"
        );
    }

    /// A publisher chooses the rrid string it puts on the wire, and one naming a layer this
    /// m= section never negotiated names nothing.
    ///
    /// There is nowhere to record such a pairing — inventing a coding for it would hand the
    /// repair SSRC a layer of its own, and every retransmission would then be delivered to the
    /// application as though it were media.
    #[test]
    fn an_rrid_naming_an_unnegotiated_layer_is_dropped() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![
                simulcast_header(&media_engine, ssrc, payload_type, 1, "0", Some("h"), None),
                simulcast_header(
                    &media_engine,
                    rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("q"),
                ),
            ],
        );

        assert_eq!(
            None,
            paired_rtx_ssrc(&transceivers[0], "h"),
            "an rrid naming no negotiated layer must not be attached to some other one"
        );
        assert_eq!(
            vec![ssrc],
            recorder.bound_ssrcs(),
            "and nothing is bound for it: the repair flow has no layer to repair"
        );
    }

    /// The first repair SSRC a layer is paired with is the one it keeps.
    ///
    /// A second is either an SSRC collision or a publisher changing its mind mid-stream. Either
    /// way the packets already in flight from the first are addressed to a pairing that
    /// overwriting would remove, and they would be discarded on arrival — so the layer keeps what
    /// it has and the newcomer is ignored.
    #[test]
    fn a_second_repair_ssrc_does_not_displace_the_first() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);
        let other_rtx_ssrc = 3000u32;

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![
                simulcast_header(&media_engine, ssrc, payload_type, 1, "0", Some("h"), None),
                simulcast_header(
                    &media_engine,
                    rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("h"),
                ),
                simulcast_header(
                    &media_engine,
                    other_rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("h"),
                ),
            ],
        );

        assert_eq!(
            Some(rtx_ssrc),
            paired_rtx_ssrc(&transceivers[0], "h"),
            "the layer keeps the repair stream it is already receiving"
        );
        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "and the second repair SSRC is bound to nothing"
        );
    }

    /// A paired repair flow's bytes are attributed to the layer it repairs.
    ///
    /// `on_rtx_packet_received_if_rtx` resolves an arriving SSRC through the accumulator's reverse
    /// map, which is filled when a stream's repair flow is declared. For rid simulcast that is
    /// never at negotiation time, so without the pairing `retransmittedPacketsReceived` stays zero
    /// for the life of the connection and the repair bytes are counted as nothing at all.
    #[test]
    fn a_paired_repair_stream_is_counted_against_its_layer() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let media_engine = simulcast_media_engine();
        let mut transceivers = vec![rid_transceiver("0", &[("h", None)])];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();

        feed_simulcast(
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
            vec![
                simulcast_header(&media_engine, ssrc, payload_type, 1, "0", Some("h"), None),
                simulcast_header(
                    &media_engine,
                    rtx_ssrc,
                    rtx_payload_type,
                    1,
                    "0",
                    None,
                    Some("h"),
                ),
            ],
        );

        let stream = stats
            .inbound_rtp_streams
            .get(&ssrc)
            .expect("the layer's accumulator");
        assert_eq!(
            Some(rtx_ssrc),
            stream.rtx_ssrc,
            "the layer reports the repair flow it acquired, not the none it was negotiated with"
        );
        assert_eq!(
            1, stream.retransmitted_packets_received,
            "the retransmission is counted against the layer it repairs"
        );
    }
}
