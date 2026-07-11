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
use crate::rtp_transceiver::rtp_sender::rtp_codec::parse_rtx_apt;
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
        data_channel_id: u16,
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
        data_channel_id: u16,
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
        data_channel_id: u16,
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
                    Some(codec.rtp_codec.clone())
                } else {
                    None
                };

                if let Some(codec) = track_codec {
                    // Set valid Codec for track when received the first RTP packet for such ssrc stream
                    // assert not inserting new entry
                    let new_entry = receiver.track_mut().set_codec_by_ssrc(codec, ssrc);
                    assert!(!new_entry);

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
                    // RTX is de-encapsulated in handle_rtp_message, so payload_type is the primary codec's; FEC is still TODO (#12).
                    .find(|codec| codec.payload_type == rtp_header.payload_type)
                    .cloned()
            {
                if !rrid.is_empty() {
                    //TODO: Add support of handling repair rtp stream id (rrid) #12
                } else {
                    if let Some(coding) = receiver.get_coding_parameter_mut_by_rid(rid.as_str()) {
                        coding.ssrc = Some(ssrc);
                    }

                    let parameters = receiver.get_parameters(self.media_engine);
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        self.interceptor,
                        true,
                        rtp_header.ssrc,
                        codec.payload_type,
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );

                    let new_entry =
                        receiver
                            .track_mut()
                            .set_codec_ssrc_by_rid(codec.rtp_codec, ssrc, &rid);
                    assert!(!new_entry);

                    let track_id = receiver.track().track_id().to_owned();

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
                    // RTX is de-encapsulated in handle_rtp_message, so payload_type is the primary codec's; FEC is still TODO (#12).
                    .find(|codec| codec.payload_type == rtp_header.payload_type)
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
        RTCRtpCodecParameters, RTCRtpCodingParameters, deencapsulate_rtx, resolve_rtx_primary,
    };
    use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpRtxParameters};
    use bytes::Bytes;

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
}
