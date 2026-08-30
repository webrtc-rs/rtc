use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
    TaggedRTCMessageInternal, TrackPacket,
};

use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::configuration::media_engine::{MIME_TYPE_RTX, MediaEngine};
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    find_fec_payload_type, find_rtx_payload_type, parse_rtx_apt,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpHeaderExtensionCapability,
};
use crate::rtp_transceiver::{
    PayloadType, RTCRtpReceiverId, SSRC, internal::RTCRtpTransceiverInternal,
};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Interceptor, Packet};
use log::{debug, trace, warn};
use shared::TransportContext;
use shared::error::{Error, Result};
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct EndpointHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

/// EndpointHandler implements DataChannel/Media Endpoint handling
/// The transmits queue is now stored in RTCPeerConnection and passed by reference
pub(crate) struct EndpointHandler<'a, I>
where
    I: Interceptor,
{
    ctx: &'a mut EndpointHandlerContext,
    rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal<I>>,
    media_engine: &'a MediaEngine,
    interceptor: &'a mut I,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a, I> EndpointHandler<'a, I>
where
    I: Interceptor,
{
    pub(crate) fn new(
        ctx: &'a mut EndpointHandlerContext,
        rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal<I>>,
        media_engine: &'a MediaEngine,
        interceptor: &'a mut I,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        EndpointHandler {
            ctx,
            rtp_transceivers,
            media_engine,
            interceptor,
            stats,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "EndpointHandler"
    }
}

// Implement Protocol trait for message processing
impl<'a, I> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for EndpointHandler<'a, I>
where
    I: Interceptor,
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        match msg.message {
            RTCMessageInternal::Dtls(DTLSMessage::DataChannel(message)) => {
                self.handle_dtls_message(msg.now, msg.transport, message)
            }
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(message))) => {
                self.handle_rtp_message(msg.now, msg.transport, message)
            }
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(message))) => {
                self.handle_rtcp_message(msg.now, msg.transport, message)
            }
            _ => {
                warn!("drop unsupported message from {}", msg.transport.peer_addr);
                Ok(())
            }
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        self.ctx.write_outs.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a, I> EndpointHandler<'a, I>
where
    I: Interceptor,
{
    fn handle_dtls_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        message: ApplicationMessage,
    ) -> Result<()> {
        match message.data_channel_event {
            DataChannelEvent::Open => {
                self.handle_datachannel_open(now, transport_context, message.data_channel_id)
            }
            DataChannelEvent::Message(data_channel_message) => self.handle_datachannel_message(
                now,
                transport_context,
                message.data_channel_id,
                data_channel_message,
            ),
            DataChannelEvent::Close => {
                self.handle_datachannel_close(now, transport_context, message.data_channel_id)
            }
        }
    }

    fn handle_rtp_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        mut rtp_packet: rtp::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

        // RFC 4588: if this packet belongs to a retransmission (RTX) stream,
        // de-encapsulate it back into its primary stream before dispatching.
        // The RTX payload is `[OSN (2 bytes)][original RTP payload]`; the
        // recovered packet carries the primary SSRC, the original payload type
        // (resolved via the RTX codec's `apt=`) and the original sequence number
        // (OSN), while keeping the timestamp/marker/extensions "as is". RTX
        // receive statistics are tracked upstream in the interceptor handler
        // (using the RTX SSRC), so they are not touched here.
        if let Some((primary_ssrc, primary_payload_type)) =
            self.rtx_primary_for(rtp_packet.header.ssrc, rtp_packet.header.payload_type)
        {
            let recovered = deencapsulate_rtx(&mut rtp_packet, primary_ssrc, primary_payload_type);
            if !recovered {
                // RTX packet with no OSN header (e.g. a padding-only bandwidth-probe
                // packet, RFC 4588 §4): nothing to recover.
                trace!(
                    "drop rtx packet ssrc = {} without OSN payload",
                    rtp_packet.header.ssrc
                );
                return Ok(());
            }
        }

        let ssrc = rtp_packet.header.ssrc;

        if let Some(track_id) = self.find_track_id(ssrc, Some(&rtp_packet.header)) {
            // Track RTP stats if accumulator exists (created when OnOpen event is fired)
            if let Some(stream) = self.stats.inbound_rtp_streams.get_mut(&ssrc) {
                stream.on_rtp_received(
                    rtp_packet.header.marshal_size(),
                    rtp_packet.payload.len(),
                    now,
                );
            }

            self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                now,
                transport: transport_context,
                message: RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                    track_id,
                    packet: Packet::Rtp(rtp_packet),
                })),
            });
        } else {
            debug!("drop rtp packet ssrc = {}", ssrc);
        }
        Ok(())
    }

    fn handle_rtcp_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        rtcp_packets: Vec<Box<dyn rtcp::Packet>>,
    ) -> Result<()> {
        debug!("handle_rtcp_message {}", transport_context.peer_addr);

        let rtcp_ssrc = if let Some(rtcp_packet) = rtcp_packets.first() {
            rtcp_packet.destination_ssrc().first().cloned()
        } else {
            None
        };

        if let Some(rtcp_ssrc) = rtcp_ssrc {
            if let Some(track_id) = self.find_track_id(rtcp_ssrc, None) {
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: transport_context,
                    message: RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                        track_id,
                        packet: Packet::Rtcp(rtcp_packets),
                    })),
                });
            } else {
                debug!("drop rtcp packet ssrc = {}", rtcp_ssrc);
            }
        } else {
            debug!("drop rtcp packet due to empty ssrc");
        }

        Ok(())
    }

    fn handle_datachannel_open(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        data_channel_id: RTCDataChannelId,
    ) -> Result<()> {
        debug!("data channel is open for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(data_channel_id)),
            ));

        Ok(())
    }

    fn handle_datachannel_close(
        &mut self,
        _now: Instant,
        transport_context: TransportContext,
        data_channel_id: RTCDataChannelId,
    ) -> Result<()> {
        debug!("data channel is close for {:?}", transport_context);
        self.ctx
            .event_outs
            .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(
                    data_channel_id,
                )),
            ));

        Ok(())
    }

    fn handle_datachannel_message(
        &mut self,
        now: Instant,
        transport_context: TransportContext,
        data_channel_id: RTCDataChannelId,
        data_channel_message: RTCDataChannelMessage,
    ) -> Result<()> {
        debug!("data channel recv message for {:?}", transport_context);
        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport: transport_context,
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id,
                data_channel_event: DataChannelEvent::Message(data_channel_message),
            })),
        });

        Ok(())
    }

    /// RFC 4588: resolves a retransmission (RTX) SSRC to the primary stream it repairs.
    ///
    /// Returns `(primary_ssrc, primary_payload_type)` when `rtx_ssrc` matches the
    /// RTX SSRC of one of this endpoint's receive codings (declared via
    /// `a=ssrc-group:FID <primary> <rtx>` in the remote SDP, RFC 5576). The
    /// original payload type is resolved from the negotiated RTX codec's `apt=`
    /// parameter, looked up by the packet's RTX `payload_type`. Returns `None`
    /// (leaving the packet to be handled as a regular RTP packet) when the SSRC
    /// is not a known RTX SSRC or the `apt` mapping cannot be resolved.
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

    // crosscheck with RTCPeerConnection::start_rtp, since remote tracks(RTCRtpCodingParameters) are added in it
    fn find_track_id(
        &mut self,
        ssrc: SSRC,
        rtp_header: Option<&rtp::Header>,
    ) -> Option<MediaStreamTrackId> {
        if let Some(track_id) = self.find_track_id_by_ssrc(ssrc, rtp_header) {
            Some(track_id)
        } else if let Some(rtp_header) = rtp_header // rid search only for RTP packet
            && let Some(track_id) = self.find_track_id_by_rid(ssrc, rtp_header)
        {
            Some(track_id)
        } else {
            None
        }
    }

    fn find_track_id_by_ssrc(
        &mut self,
        ssrc: SSRC,
        rtp_header: Option<&rtp::Header>,
    ) -> Option<MediaStreamTrackId> {
        if let Some((id, transceiver)) =
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
        {
            // Get kind and mid before borrowing receiver mutably
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();

            if let Some(receiver) = transceiver.receiver_mut()
                && receiver
                    .track()
                    .ssrcs()
                    .any(|track_ssrc| track_ssrc == ssrc)
            {
                let (is_track_codec_empty, track_id) = (
                    receiver
                        .track()
                        .get_codec_by_ssrc(ssrc)
                        .is_some_and(|codec| codec.mime_type.is_empty()),
                    receiver.track().track_id().clone(),
                );

                let track_codec = if is_track_codec_empty
                    && let Some(rtp_header) = rtp_header
                    && let Some(codec) = receiver
                        .get_codec_preferences()
                        .iter()
                        .find(|codec| codec.payload_type == rtp_header.payload_type)
                // RTX packets are de-encapsulated into their primary stream in
                // handle_rtp_message before reaching here, so payload_type is the
                // primary codec's. FEC de-encapsulation is still TODO (see #12).
                {
                    Some((codec.rtp_codec.clone(), rtp_header.payload_type))
                } else {
                    None
                };

                if let Some((codec, payload_type)) = track_codec {
                    // Resolved before the bind rather than after it: the repair flows are bound
                    // alongside the primary below, and the stats accumulator wants the same pair.
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
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        self.interceptor,
                        true,
                        ssrc,
                        payload_type,
                        &codec,
                        &parameters.rtp_parameters.header_extensions,
                    );

                    // Each repair flow in its own right, exactly as `interceptor_remote_streams_op`
                    // binds them: a real RTP stream with its own SSRC and sequence-number space,
                    // which an interceptor tracking arrivals has to know about. It also keeps the
                    // pair balanced — `stop` unbinds all three, so binding only the primary would
                    // leave the repair flows unbound having never been bound.
                    if let Some(ssrc_rtx) = rtx_ssrc {
                        RTCRtpReceiverInternal::interceptor_remote_stream_op(
                            self.interceptor,
                            true,
                            ssrc_rtx,
                            find_rtx_payload_type(payload_type, &parameters.rtp_parameters.codecs)
                                .unwrap_or_default(),
                            &codec,
                            &parameters.rtp_parameters.header_extensions,
                        );
                    }

                    if let Some(ssrc_fec) = fec_ssrc {
                        RTCRtpReceiverInternal::interceptor_remote_stream_op(
                            self.interceptor,
                            true,
                            ssrc_fec,
                            find_fec_payload_type(&parameters.rtp_parameters.codecs)
                                .unwrap_or_default(),
                            &codec,
                            &parameters.rtp_parameters.header_extensions,
                        );
                    }

                    // Set valid Codec for track when received the first RTP packet for such ssrc stream
                    // assert not inserting new entry
                    let new_entry = receiver.track_mut().set_codec_by_ssrc(codec, ssrc);
                    assert!(!new_entry);

                    // Create inbound stream accumulator before firing OnOpen event
                    self.stats.get_or_create_inbound_rtp_streams(
                        ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id,
                    );

                    // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(
                                RTCTrackEventInit {
                                    receiver_id: RTCRtpReceiverId(id),
                                    track_id: receiver.track().track_id().to_owned(),
                                    stream_ids: vec![receiver.track().stream_id().to_owned()],
                                    ssrc,
                                    rid: None,
                                },
                            )),
                        ));
                }

                return Some(track_id);
            }
        }

        // No receiver owns this ssrc. For inbound RTCP (no rtp_header) it may be feedback
        // (PLI/FIR/RR) about one of our *senders* — e.g. a subscriber's keyframe request for
        // a forwarded stream. Surface it tagged with the sender's track id so the
        // application (an SFU) can relay the feedback upstream to the publisher. RTP media
        // is never inbound on a sender, so this branch is RTCP-only.
        if rtp_header.is_none()
            && let Some(track_id) = self.rtp_transceivers.iter().find_map(|transceiver| {
                transceiver.sender().as_ref().and_then(|sender| {
                    let track = sender.track();
                    track
                        .ssrcs()
                        .any(|track_ssrc| track_ssrc == ssrc)
                        .then(|| track.track_id().clone())
                })
            })
        {
            return Some(track_id);
        }

        trace!(
            "no track id for {:?} for {}",
            ssrc,
            if rtp_header.is_some() {
                "RTP packet, let's try search rid"
            } else {
                "RTCP packet"
            }
        );
        None
    }

    fn find_track_id_by_rid(
        &mut self,
        ssrc: SSRC,
        rtp_header: &rtp::Header,
    ) -> Option<MediaStreamTrackId> {
        // If the remote SDP was only one media section the ssrc doesn't have to be explicitly declared
        let track_id = self.handle_undeclared_ssrc(rtp_header);
        if track_id.is_some() {
            return track_id;
        }

        let (mid, rid, rrid) =
            if let Some((mid, rid, rrid)) = self.get_rtp_header_extension_ids(rtp_header) {
                if mid.is_empty() || (rid.is_empty() && rrid.is_empty()) {
                    return None;
                }
                (mid, rid, rrid)
            } else {
                return None;
            };

        // If rtp header extension has valid mid, find receiver based on mid, instead of rid,
        // since rid is not unique across m= lines
        if let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    transceiver
                        .mid()
                        .as_deref()
                        .is_some_and(|t_mid| t_mid == mid)
                })
        {
            // Get kind before borrowing receiver mutably
            let kind = transceiver.kind();

            if let Some(receiver) = transceiver.receiver_mut()
                && let Some(codec) = receiver
                    .get_codec_preferences()
                    .iter()
                    .find(|codec| codec.payload_type == rtp_header.payload_type) //TODO: what about RTX/FEC stream?
                    .cloned()
            {
                if !rrid.is_empty() {
                    //TODO: Add support of handling repair rtp stream id (rrid) #12
                } else {
                    if let Some(coding) = receiver.get_coding_parameter_mut_by_rid(rid.as_str()) {
                        coding.ssrc = Some(ssrc);
                    }

                    // Resolved before the bind: each simulcast layer has its own repair flow, so
                    // the pair has to be the one belonging to *this* coding — the `ssrc` assigned
                    // just above.
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
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        self.interceptor,
                        true,
                        rtp_header.ssrc,
                        codec.payload_type,
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );

                    // And each repair flow in its own right. Simulcast is where this matters most:
                    // every layer has its own retransmission flow, and NACK-driven repair is what
                    // keeps the upper layers usable.
                    if let Some(ssrc_rtx) = rtx_ssrc {
                        RTCRtpReceiverInternal::interceptor_remote_stream_op(
                            self.interceptor,
                            true,
                            ssrc_rtx,
                            find_rtx_payload_type(
                                codec.payload_type,
                                &parameters.rtp_parameters.codecs,
                            )
                            .unwrap_or_default(),
                            &codec.rtp_codec,
                            &parameters.rtp_parameters.header_extensions,
                        );
                    }

                    if let Some(ssrc_fec) = fec_ssrc {
                        RTCRtpReceiverInternal::interceptor_remote_stream_op(
                            self.interceptor,
                            true,
                            ssrc_fec,
                            find_fec_payload_type(&parameters.rtp_parameters.codecs)
                                .unwrap_or_default(),
                            &codec.rtp_codec,
                            &parameters.rtp_parameters.header_extensions,
                        );
                    }

                    let new_entry =
                        receiver
                            .track_mut()
                            .set_codec_ssrc_by_rid(codec.rtp_codec, ssrc, &rid);
                    assert!(!new_entry);

                    let track_id = receiver.track().track_id().to_owned();

                    // Create inbound stream accumulator before firing OnOpen event
                    self.stats.get_or_create_inbound_rtp_streams(
                        ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id,
                    );

                    // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                    self.ctx
                        .event_outs
                        .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(
                                RTCTrackEventInit {
                                    receiver_id: RTCRtpReceiverId(id),
                                    track_id: track_id.clone(),
                                    stream_ids: vec![receiver.track().stream_id().to_owned()],
                                    ssrc,
                                    rid: Some(rid),
                                },
                            )),
                        ));
                    return Some(track_id);
                }
            }
        }
        None
    }

    fn handle_undeclared_ssrc(&mut self, rtp_header: &rtp::Header) -> Option<MediaStreamTrackId> {
        if self.rtp_transceivers.len() != 1 {
            // it is multi-media-section case, let's use find_track_id_by_rid
            return None;
        }

        if let Some(transceiver) = self.rtp_transceivers.first()
            && let Some(receiver) = transceiver.receiver()
            && !receiver.track().codings().is_empty()
        {
            // it is rid-based, let's use find_track_id_by_rid
            return None;
        }

        if let Some(transceiver) = self.rtp_transceivers.first_mut() {
            // Get kind and mid before borrowing receiver mutably
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();

            if let Some(receiver) = transceiver.receiver_mut()
                && let Some(codec) = receiver
                    .get_codec_preferences()
                    .iter()
                    .find(|codec| codec.payload_type == rtp_header.payload_type) //TODO: what about RTX/FEC stream?
                    .cloned()
            {
                let receive_codings = vec![RTCRtpCodingParameters {
                    rid: "".to_string(),
                    ssrc: Some(rtp_header.ssrc),
                    rtx: None,
                    fec: None,
                }];
                receiver.set_coding_parameters(receive_codings);

                let parameters = receiver.get_parameters(self.media_engine);
                RTCRtpReceiverInternal::interceptor_remote_stream_op(
                    self.interceptor,
                    true,
                    rtp_header.ssrc,
                    codec.payload_type,
                    &codec.rtp_codec,
                    &parameters.rtp_parameters.header_extensions,
                );

                // assert it inserts a new entry
                let new_entry = receiver
                    .track_mut()
                    .set_codec_by_ssrc(codec.rtp_codec, rtp_header.ssrc);
                assert!(new_entry);

                let track_id = receiver.track().track_id().to_owned();

                // Create inbound stream accumulator before firing OnOpen event
                // Note: undeclared SSRC case doesn't have RTX/FEC info
                self.stats.get_or_create_inbound_rtp_streams(
                    rtp_header.ssrc,
                    kind,
                    &track_id,
                    &mid,
                    None,
                    None,
                    0, // Undeclared SSRC is always for the first transceiver
                );

                // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(RTCTrackEventInit {
                            receiver_id: RTCRtpReceiverId(0),
                            track_id: track_id.clone(),
                            stream_ids: vec![receiver.track().stream_id().to_owned()],
                            ssrc: rtp_header.ssrc,
                            rid: None,
                        })),
                    ));
                return Some(track_id);
            }
        }
        None
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

/// RFC 4588: resolve a single receiver's coding/codec state to the primary
/// stream that an RTX packet (`rtx_ssrc`, `rtx_payload_type`) repairs.
///
/// Returns `(primary_ssrc, primary_payload_type)` when `rtx_ssrc` is the RTX
/// SSRC of one of `coding_parameters` (declared via `a=ssrc-group:FID <primary>
/// <rtx>`, RFC 5576) and the original payload type can be resolved from the
/// matching RTX codec's `apt=` parameter (looked up by `rtx_payload_type`).
/// Returns `None` when the SSRC is not a known RTX SSRC or the `apt` mapping
/// cannot be resolved.
fn resolve_rtx_primary(
    coding_parameters: &[RTCRtpCodingParameters],
    codec_preferences: &[RTCRtpCodecParameters],
    rtx_ssrc: SSRC,
    rtx_payload_type: PayloadType,
) -> Option<(SSRC, PayloadType)> {
    // Associate the RTX SSRC with its primary stream via the FID group recorded
    // in the coding parameters.
    let primary_ssrc =
        coding_parameters
            .iter()
            .find_map(|coding| match (&coding.rtx, coding.ssrc) {
                (Some(rtx), Some(primary_ssrc)) if rtx.ssrc == rtx_ssrc => Some(primary_ssrc),
                _ => None,
            })?;

    // Resolve the original payload type from the negotiated RTX codec's `apt=`
    // parameter.
    let primary_payload_type = codec_preferences.iter().find_map(|codec| {
        if codec.payload_type == rtx_payload_type
            && codec
                .rtp_codec
                .mime_type
                .eq_ignore_ascii_case(MIME_TYPE_RTX)
        {
            parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
        } else {
            None
        }
    })?;

    Some((primary_ssrc, primary_payload_type))
}

/// RFC 4588 §4: recover the original RTP packet carried inside an RTX packet.
///
/// The retransmission payload is `[OSN: u16 big-endian][original RTP payload]`,
/// where OSN "MUST be set to the sequence number of the associated original RTP
/// packet" (RFC 4588 §4). On success the packet is rewritten in place to look
/// like the original: the SSRC becomes `primary_ssrc`, the payload type becomes
/// `primary_payload_type` (the `apt`), the sequence number becomes the OSN, and
/// the 2-byte OSN header is stripped from the payload. The timestamp, marker and
/// CSRC list are already carried "as is" by the RTX packet per RFC 4588 §4 and
/// are left untouched; any original RTP padding was removed by the sender before
/// retransmission, so the padding flag is cleared.
///
/// Returns `false` without modifying the packet when the payload is shorter than
/// the 2-byte OSN header (e.g. a padding-only bandwidth-probe packet).
fn deencapsulate_rtx(
    packet: &mut rtp::Packet,
    primary_ssrc: SSRC,
    primary_payload_type: PayloadType,
) -> bool {
    if packet.payload.len() < 2 {
        return false;
    }

    let original_sequence_number = u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
    packet.header.ssrc = primary_ssrc;
    packet.header.payload_type = primary_payload_type;
    packet.header.sequence_number = original_sequence_number;
    packet.header.padding = false;
    packet.payload = packet.payload.slice(2..);

    true
}

#[cfg(test)]
mod rtx_tests {
    use super::{
        EndpointHandler, EndpointHandlerContext, Instant, Packet, RTCMessageInternal,
        RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpTransceiverInternal, RTPMessage,
        TrackPacket, TransportContext, deencapsulate_rtx, resolve_rtx_primary,
    };
    use crate::media_stream::track::MediaStreamTrack;
    use crate::peer_connection::configuration::media_engine::{MIME_TYPE_RTX, MediaEngine};
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpEncodingParameters, RTCRtpHeaderExtensionCapability,
        RTCRtpRtxParameters, RtpCodecKind,
    };
    use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::Bytes;
    use interceptor::{Interceptor, NoopInterceptor, StreamInfo, TaggedPacket};
    use shared::TransportProtocol;
    use shared::error::{Error, Result};
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
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    #[test]
    fn resolves_rtx_ssrc_to_primary_and_apt() {
        let codings = [coding(1000, Some(2000))];
        let prefs = [codec(96, "video/VP8", ""), codec(97, "video/rtx", "apt=96")];
        assert_eq!(
            resolve_rtx_primary(&codings, &prefs, 2000, 97),
            Some((1000, 96))
        );
    }

    #[test]
    fn selects_the_correct_primary_among_several_codings() {
        let codings = [coding(1000, Some(2000)), coding(1001, Some(2001))];
        let prefs = [
            codec(97, "video/rtx", "apt=96"),
            codec(99, "video/rtx", "apt=98"),
        ];
        assert_eq!(
            resolve_rtx_primary(&codings, &prefs, 2001, 99),
            Some((1001, 98))
        );
    }

    #[test]
    fn unknown_rtx_ssrc_is_not_resolved() {
        let codings = [coding(1000, Some(2000))];
        let prefs = [codec(97, "video/rtx", "apt=96")];
        // 2000 is the only RTX SSRC: an unknown SSRC (9999) and the primary's own
        // SSRC (1000) must not be mistaken for RTX.
        assert_eq!(resolve_rtx_primary(&codings, &prefs, 9999, 97), None);
        assert_eq!(resolve_rtx_primary(&codings, &prefs, 1000, 97), None);
    }

    #[test]
    fn coding_without_rtx_pairing_is_not_resolved() {
        // rid-based / undeclared codings carry no rtx SSRC (rtx: None).
        let codings = [coding(1000, None)];
        let prefs = [codec(97, "video/rtx", "apt=96")];
        assert_eq!(resolve_rtx_primary(&codings, &prefs, 2000, 97), None);
    }

    #[test]
    fn missing_or_mismatched_rtx_codec_pref_is_not_resolved() {
        let codings = [coding(1000, Some(2000))];
        // No codec preference at the RTX payload type.
        assert_eq!(resolve_rtx_primary(&codings, &[], 2000, 97), None);
        // Payload type present but it is not an RTX codec.
        let non_rtx = [codec(97, "video/VP8", "")];
        assert_eq!(resolve_rtx_primary(&codings, &non_rtx, 2000, 97), None);
        // RTX codec present but without a parseable apt.
        let no_apt = [codec(97, "video/rtx", "")];
        assert_eq!(resolve_rtx_primary(&codings, &no_apt, 2000, 97), None);
    }

    // RFC 4588 §4: the RTX payload is [OSN (2 bytes, big-endian)][original payload].
    #[test]
    fn deencapsulates_rtx_packet_into_primary() {
        let mut packet = rtp::Packet {
            header: rtp::Header {
                marker: true,
                payload_type: 97,    // negotiated RTX payload type
                sequence_number: 42, // RTX stream sequence number (independent)
                timestamp: 9000,     // already the original timestamp (RFC 4588 §4)
                ssrc: 0xDEAD_BEEF,   // RTX SSRC
                padding: true,
                ..Default::default()
            },
            // OSN = 0x1234, followed by the original media payload.
            payload: Bytes::from(vec![0x12, 0x34, 0xAA, 0xBB, 0xCC]),
        };

        assert!(deencapsulate_rtx(&mut packet, 0x1111_2222, 96));

        // Rewritten to look like the original primary packet.
        assert_eq!(packet.header.ssrc, 0x1111_2222);
        assert_eq!(packet.header.payload_type, 96);
        assert_eq!(packet.header.sequence_number, 0x1234); // OSN
        // Kept "as is".
        assert_eq!(packet.header.timestamp, 9000);
        assert!(packet.header.marker);
        // Original padding was removed by the sender before retransmission.
        assert!(!packet.header.padding);
        // OSN header stripped, original payload preserved.
        assert_eq!(&packet.payload[..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn padding_only_probe_packet_is_left_unchanged() {
        // A bandwidth-probe RTX packet may carry fewer than 2 payload bytes and
        // therefore has no OSN to recover.
        let mut packet = rtp::Packet {
            header: rtp::Header {
                payload_type: 97,
                ssrc: 0xDEAD_BEEF,
                ..Default::default()
            },
            payload: Bytes::from(vec![0x00]),
        };
        let before = packet.clone();

        assert!(!deencapsulate_rtx(&mut packet, 0x1111_2222, 96));
        assert_eq!(packet, before);
    }

    #[test]
    fn empty_payload_is_left_unchanged() {
        let mut packet = rtp::Packet {
            header: rtp::Header {
                payload_type: 97,
                ssrc: 7,
                ..Default::default()
            },
            payload: Bytes::new(),
        };

        assert!(!deencapsulate_rtx(&mut packet, 1, 96));
    }

    // Builds a video receive transceiver whose primary stream is paired with an
    // RTX stream via the FID group, matching what start_rtp sets up for an
    // `a=ssrc-group:FID` offer. The primary SSRC already has a (non-empty) codec
    // so find_track_id resolves it directly.
    fn rtx_receiver_transceiver(
        primary_ssrc: u32,
        rtx_ssrc: u32,
        primary_pt: u8,
        rtx_pt: u8,
    ) -> RTCRtpTransceiverInternal<NoopInterceptor> {
        let mut transceiver = RTCRtpTransceiverInternal::<NoopInterceptor>::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );

        let receiver = transceiver.receiver_mut().as_mut().unwrap();
        receiver.set_coding_parameters(vec![coding(primary_ssrc, Some(rtx_ssrc))]);
        receiver.set_codec_preferences(vec![
            codec(primary_pt, "video/VP8", ""),
            codec(rtx_pt, "video/rtx", &format!("apt={primary_pt}")),
        ]);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_string(),
            "track".to_string(),
            "label".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: coding(primary_ssrc, Some(rtx_ssrc)),
                active: true,
                codec: RTCRtpCodec {
                    mime_type: "video/VP8".to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                max_bitrate: 0,
                max_framerate: None,
                scale_resolution_down_by: None,
            }],
        ));
        transceiver
    }

    fn test_transport() -> TransportContext {
        TransportContext {
            local_addr: "127.0.0.1:5000".parse().unwrap(),
            peer_addr: "127.0.0.1:5001".parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        }
    }

    #[test]
    fn handle_rtp_message_deencapsulates_and_dispatches_rtx() {
        let (primary_ssrc, rtx_ssrc, primary_pt, rtx_pt) = (1000u32, 2000u32, 96u8, 97u8);
        let mut transceivers = vec![rtx_receiver_transceiver(
            primary_ssrc,
            rtx_ssrc,
            primary_pt,
            rtx_pt,
        )];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = EndpointHandlerContext::default();

        // RTX packet on the RTX SSRC: payload = [OSN=42][media 0xDE 0xAD].
        let rtx_packet = rtp::Packet {
            header: rtp::Header {
                marker: true,
                payload_type: rtx_pt,
                sequence_number: 9, // RTX stream sequence number (independent)
                timestamp: 12_345,
                ssrc: rtx_ssrc,
                ..Default::default()
            },
            payload: Bytes::from(vec![0x00, 0x2A, 0xDE, 0xAD]),
        };

        {
            let mut handler = EndpointHandler::new(
                &mut ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                &mut stats,
            );
            handler
                .handle_rtp_message(Instant::now(), test_transport(), rtx_packet)
                .expect("handle_rtp_message");
        }

        // The recovered packet is dispatched on the primary stream, de-encapsulated.
        let dispatched = ctx
            .read_outs
            .pop_front()
            .expect("a track packet should be dispatched");
        match dispatched.message {
            RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                packet: Packet::Rtp(packet),
                ..
            })) => {
                assert_eq!(packet.header.ssrc, primary_ssrc);
                assert_eq!(packet.header.payload_type, primary_pt);
                assert_eq!(packet.header.sequence_number, 42); // OSN
                assert_eq!(packet.header.timestamp, 12_345); // preserved
                assert!(packet.header.marker); // preserved
                assert_eq!(&packet.payload[..], &[0xDE, 0xAD]); // OSN stripped
            }
            _ => panic!("expected a de-encapsulated RTP TrackPacket on the primary stream"),
        }
    }

    #[test]
    fn handle_rtp_message_drops_rtx_probe_packet() {
        let (primary_ssrc, rtx_ssrc, primary_pt, rtx_pt) = (1000u32, 2000u32, 96u8, 97u8);
        let mut transceivers = vec![rtx_receiver_transceiver(
            primary_ssrc,
            rtx_ssrc,
            primary_pt,
            rtx_pt,
        )];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = EndpointHandlerContext::default();

        // A padding-only probe on the RTX SSRC: payload shorter than the OSN.
        let probe = rtp::Packet {
            header: rtp::Header {
                payload_type: rtx_pt,
                ssrc: rtx_ssrc,
                ..Default::default()
            },
            payload: Bytes::from(vec![0x00]),
        };

        {
            let mut handler = EndpointHandler::new(
                &mut ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                &mut stats,
            );
            handler
                .handle_rtp_message(Instant::now(), test_transport(), probe)
                .expect("handle_rtp_message");
        }

        assert!(
            ctx.read_outs.is_empty(),
            "an RTX probe packet with no OSN should be dropped, not dispatched"
        );
    }

    /// An interceptor that records which remote streams it was told about.
    ///
    /// `NoopInterceptor` suffices where only the packets matter; this exists because the property
    /// under test is a *call that never happened*, which no amount of inspecting packets can show.
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
    ) -> RTCRtpTransceiverInternal<Recorder> {
        let mut transceiver = RTCRtpTransceiverInternal::<Recorder>::new(
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

    fn feed(
        transceivers: &mut Vec<RTCRtpTransceiverInternal<Recorder>>,
        interceptor: &mut Recorder,
        ssrc: u32,
        payload_type: u8,
        packets: u16,
    ) {
        let media_engine = media_engine_with_rtx();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = EndpointHandlerContext::default();
        let mut handler = EndpointHandler::new(
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
                .handle_rtp_message(Instant::now(), test_transport(), packet)
                .expect("handle_rtp_message");
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
        let mut transceiver = RTCRtpTransceiverInternal::<Recorder>::new(
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
        let mut ctx = EndpointHandlerContext::default();

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
            let mut handler = EndpointHandler::new(
                &mut ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                &mut stats,
            );
            handler
                .handle_rtp_message(
                    Instant::now(),
                    test_transport(),
                    rtp::Packet {
                        header,
                        payload: Bytes::from_static(&[0xDE, 0xAD]),
                    },
                )
                .expect("handle_rtp_message");
        }

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the layer and its retransmission stream are both real streams"
        );
    }
}
