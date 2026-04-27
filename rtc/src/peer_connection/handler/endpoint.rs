use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
    TaggedRTCMessageInternal, TrackPacket,
};

use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpHeaderExtensionCapability, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::{RTCRtpReceiverId, SSRC, internal::RTCRtpTransceiverInternal};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{Interceptor, Packet};
use log::{debug, trace, warn};
use shared::TransportContext;
use shared::error::{Error, Result};
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::Instant;

/// Returns `true` if the given MIME type identifies a repair codec (RTX or FEC)
/// rather than a primary media codec. The check is case-insensitive and covers
/// all RTX variants (e.g. `video/rtx`, `audio/rtx`) as well as FEC types
/// (`video/ulpfec`, `video/flexfec`, `video/flexfec-03`).
fn is_repair_mime_type(mime_type: &str) -> bool {
    let mt = mime_type.to_ascii_lowercase();
    mt.ends_with("/rtx")
        || mt.ends_with("/ulpfec")
        || mt.ends_with("/flexfec")
        || mt.ends_with("/flexfec-03")
}

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
        rtp_packet: rtp::Packet,
    ) -> Result<()> {
        debug!("handle_rtp_message {}", transport_context.peer_addr);

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
        // Determine whether the SSRC matches a primary or repair (RTX/FEC) sub-stream
        // in a single pass, avoiding redundant receiver/coding-parameter lookups.
        //
        // First, classify the SSRC across all transceivers. We record whether the match
        // was against a primary SSRC or a repair (RTX/FEC) SSRC so the subsequent code
        // can take the right path without re-scanning coding parameters.
        let ssrc_match = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .find_map(|(id, transceiver)| {
                let receiver = transceiver.receiver().as_ref()?;
                let mut is_repair = false;
                let matched = receiver.get_coding_parameters().iter().any(|coding| {
                    if coding.ssrc.is_some_and(|coding_ssrc| coding_ssrc == ssrc) {
                        return true;
                    }
                    // Also match RTX/FEC repair SSRCs so repair packets are routed to
                    // the primary stream's receiver rather than silently dropped.
                    if coding.rtx.as_ref().is_some_and(|r| r.ssrc == ssrc)
                        || coding.fec.as_ref().is_some_and(|f| f.ssrc == ssrc)
                    {
                        is_repair = true;
                        return true;
                    }
                    false
                });
                if matched {
                    // Grab the track_id while we have the receiver borrowed immutably,
                    // so repair packets can be returned without a second lookup.
                    let track_id = receiver.track().track_id().clone();
                    Some((id, is_repair, track_id))
                } else {
                    None
                }
            });

        if let Some((id, is_repair, repair_track_id)) = ssrc_match {
            // If the SSRC belongs to a repair (RTX/FEC) sub-stream, route it to the primary
            // stream's receiver without firing track-open events or updating codec state.
            if is_repair {
                return Some(repair_track_id);
            }

            let transceiver = &mut self.rtp_transceivers[id];

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

                // For primary streams, look up the primary codec only (not RTX/FEC codecs).
                // RTX/FEC packets are routed via the early-return above.
                let track_codec = if is_track_codec_empty
                    && let Some(rtp_header) = rtp_header
                    && let Some(codec) = receiver.get_codec_preferences().iter().find(|codec| {
                        codec.payload_type == rtp_header.payload_type
                            && !is_repair_mime_type(&codec.rtp_codec.mime_type)
                    }) {
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
                    // Accept both primary and RTX codecs here; the rrid branch handles repair
                    // packets (it only needs the codec lookup to succeed to enter the block).
                    .find(|codec| codec.payload_type == rtp_header.payload_type)
                    .cloned()
            {
                if !rrid.is_empty() {
                    // rrid identifies the base stream (rid) that this repair/RTX packet belongs to.
                    // Associate the repair SSRC with the base stream's RTX parameters.
                    let has_base_coding =
                        match receiver.get_coding_parameter_mut_by_rid(rrid.as_str()) {
                            Some(coding) => {
                                match coding.rtx.as_mut() {
                                    Some(rtx) => rtx.ssrc = ssrc,
                                    None => coding.rtx = Some(RTCRtpRtxParameters { ssrc }),
                                }
                                true
                            }
                            None => {
                                warn!(
                                    "dropping repair/RTX SSRC association: no base coding \
                                     parameters found for rrid='{}' (repair_ssrc={}, mid='{}', \
                                     rid='{}')",
                                    rrid, ssrc, mid, rid,
                                );
                                false
                            }
                        };

                    if has_base_coding {
                        // Register the repair stream with the interceptor so RTX
                        // packets are actually demuxed and forwarded. Use the
                        // actual packet payload type here: in this branch `codec`
                        // corresponds to the repair/RTX packet, so looking up an
                        // RTX PT from `codec.payload_type` would fail (it is
                        // already the RTX PT).
                        let parameters = receiver.get_parameters(self.media_engine);
                        RTCRtpReceiverInternal::interceptor_remote_stream_op(
                            self.interceptor,
                            true,
                            ssrc,
                            codec.payload_type,
                            &codec.rtp_codec,
                            &parameters.rtp_parameters.header_extensions,
                        );

                        // Update the stats accumulator so RTX packets are
                        // attributed to the primary stream's stats (the inbound
                        // stream accumulator may already exist from the base
                        // stream's OnOpen event).
                        if let Some(primary_ssrc) = receiver
                            .get_coding_parameters()
                            .iter()
                            .find(|c| c.rid == rrid)
                            .and_then(|c| c.ssrc)
                        {
                            self.stats.update_inbound_rtx_ssrc(primary_ssrc, ssrc);
                        }
                    }

                    return Some(receiver.track().track_id().clone());
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
                    // Only match primary codecs here; RTX/FEC repair packets are handled
                    // via find_track_id_by_ssrc once their SSRC is registered.
                    .find(|codec| {
                        codec.payload_type == rtp_header.payload_type
                            && !is_repair_mime_type(&codec.rtp_codec.mime_type)
                    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: RTX must be excluded regardless of media type (video/rtx, audio/rtx)
    /// and case variations so it is never selected as a primary codec.
    #[test]
    fn is_repair_mime_type_detects_rtx_variants() {
        // Standard RTX
        assert!(is_repair_mime_type("video/rtx"));
        // Hypothetical audio RTX
        assert!(is_repair_mime_type("audio/rtx"));
        // Case-insensitive
        assert!(is_repair_mime_type("Video/RTX"));
        assert!(is_repair_mime_type("VIDEO/RTX"));
    }

    /// Regression: all FEC mime types must be treated as repair codecs.
    #[test]
    fn is_repair_mime_type_detects_fec_variants() {
        assert!(is_repair_mime_type("video/ulpfec"));
        assert!(is_repair_mime_type("video/flexfec"));
        assert!(is_repair_mime_type("video/flexfec-03"));
        // Case-insensitive
        assert!(is_repair_mime_type("Video/ULPFEC"));
        assert!(is_repair_mime_type("VIDEO/FLEXFEC"));
        assert!(is_repair_mime_type("VIDEO/FLEXFEC-03"));
    }

    /// Primary media codecs must NOT be classified as repair.
    #[test]
    fn is_repair_mime_type_rejects_primary_codecs() {
        assert!(!is_repair_mime_type("video/VP8"));
        assert!(!is_repair_mime_type("video/VP9"));
        assert!(!is_repair_mime_type("video/H264"));
        assert!(!is_repair_mime_type("audio/opus"));
        assert!(!is_repair_mime_type("audio/PCMU"));
        assert!(!is_repair_mime_type(""));
    }

    // ================================================================
    // Integration-style regression tests for RTX/FEC packet routing
    // ================================================================

    use crate::media_stream::track::MediaStreamTrack;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RTCRtpFecParameters,
        RtpCodecKind,
    };
    use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    use interceptor::NoopInterceptor;

    const PRIMARY_SSRC: SSRC = 1000;
    const RTX_SSRC: SSRC = 2000;
    const FEC_SSRC: SSRC = 3000;

    fn vp8_codec() -> RTCRtpCodec {
        RTCRtpCodec {
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            ..Default::default()
        }
    }

    fn rtx_codec() -> RTCRtpCodec {
        RTCRtpCodec {
            mime_type: "video/rtx".to_string(),
            clock_rate: 90000,
            ..Default::default()
        }
    }

    /// Build a transceiver with a receiver whose track has a primary SSRC
    /// and whose coding parameters include RTX and FEC sub-streams.
    fn make_transceiver_with_repair() -> RTCRtpTransceiverInternal<NoopInterceptor> {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            },
        );
        transceiver.set_mid("0".to_string()).unwrap();

        let receiver = transceiver.receiver_mut().as_mut().unwrap();

        // Set up coding parameters with primary + RTX + FEC SSRCs
        receiver.set_coding_parameters(vec![RTCRtpCodingParameters {
            rid: "".to_string(),
            ssrc: Some(PRIMARY_SSRC),
            rtx: Some(RTCRtpRtxParameters { ssrc: RTX_SSRC }),
            fec: Some(RTCRtpFecParameters { ssrc: FEC_SSRC }),
        }]);

        // Set up the track with the primary SSRC and a non-empty codec
        // so the SSRC lookup succeeds and finds the codec already set.
        let track = MediaStreamTrack::new(
            "stream-1".to_string(),
            "track-1".to_string(),
            "video".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: "".to_string(),
                    ssrc: Some(PRIMARY_SSRC),
                    rtx: Some(RTCRtpRtxParameters { ssrc: RTX_SSRC }),
                    fec: Some(RTCRtpFecParameters { ssrc: FEC_SSRC }),
                },
                codec: vp8_codec(),
                ..Default::default()
            }],
        );
        receiver.set_track(track);

        // Set codec preferences so codec lookups work
        receiver.set_codec_preferences(vec![
            RTCRtpCodecParameters {
                rtp_codec: vp8_codec(),
                payload_type: 96,
            },
            RTCRtpCodecParameters {
                rtp_codec: rtx_codec(),
                payload_type: 97,
            },
        ]);

        transceiver
    }

    /// Regression: RTX SSRC must be routed to the primary track (not dropped).
    #[test]
    fn find_track_id_by_ssrc_routes_rtx_to_primary_track() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_repair()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        let result = handler.find_track_id_by_ssrc(RTX_SSRC, None);
        assert_eq!(result, Some("track-1".to_string()));
    }

    /// Regression: FEC SSRC must be routed to the primary track (not dropped).
    #[test]
    fn find_track_id_by_ssrc_routes_fec_to_primary_track() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_repair()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        let result = handler.find_track_id_by_ssrc(FEC_SSRC, None);
        assert_eq!(result, Some("track-1".to_string()));
    }

    /// Repair SSRC routing must NOT emit OnOpen events.
    #[test]
    fn find_track_id_by_ssrc_no_on_open_for_repair_ssrc() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_repair()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        // Route RTX and FEC packets
        handler.find_track_id_by_ssrc(RTX_SSRC, None);
        handler.find_track_id_by_ssrc(FEC_SSRC, None);

        // No OnOpen events should have been emitted
        assert!(
            ctx.event_outs.is_empty(),
            "No events should be emitted for repair SSRC routing"
        );
    }

    /// Primary SSRC must still be routed correctly alongside repair SSRCs.
    #[test]
    fn find_track_id_by_ssrc_routes_primary_ssrc() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_repair()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        let result = handler.find_track_id_by_ssrc(PRIMARY_SSRC, None);
        assert_eq!(result, Some("track-1".to_string()));
    }

    /// An unknown SSRC must not match any track.
    #[test]
    fn find_track_id_by_ssrc_returns_none_for_unknown() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_repair()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        let result = handler.find_track_id_by_ssrc(9999, None);
        assert_eq!(result, None);
    }

    /// Build a transceiver for simulcast with rid-based coding parameters
    /// (no SSRC initially set, as is the case before the first RTP packet).
    fn make_transceiver_with_rid() -> RTCRtpTransceiverInternal<NoopInterceptor> {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            },
        );
        transceiver.set_mid("0".to_string()).unwrap();

        let receiver = transceiver.receiver_mut().as_mut().unwrap();

        // Coding parameters with rid but no SSRC yet (filled in on first packet)
        receiver.set_coding_parameters(vec![RTCRtpCodingParameters {
            rid: "q".to_string(),
            ssrc: Some(PRIMARY_SSRC),
            rtx: None,
            fec: None,
        }]);

        let track = MediaStreamTrack::new(
            "stream-1".to_string(),
            "track-1".to_string(),
            "video".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: "q".to_string(),
                    ssrc: Some(PRIMARY_SSRC),
                    rtx: None,
                    fec: None,
                },
                codec: vp8_codec(),
                ..Default::default()
            }],
        );
        receiver.set_track(track);

        receiver.set_codec_preferences(vec![
            RTCRtpCodecParameters {
                rtp_codec: vp8_codec(),
                payload_type: 96,
            },
            RTCRtpCodecParameters {
                rtp_codec: rtx_codec(),
                payload_type: 97,
            },
        ]);

        transceiver
    }

    /// Regression: rrid packets must route to the primary track and register
    /// the RTX SSRC in the stats accumulator's reverse lookup map.
    #[test]
    fn rrid_branch_registers_rtx_ssrc_in_stats() {
        let mut ctx = EndpointHandlerContext::default();
        let mut transceivers = vec![make_transceiver_with_rid()];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        // Pre-create the primary stream's stats entry (simulates the first
        // primary RTP packet having already been received).
        stats.get_or_create_inbound_rtp_streams(
            PRIMARY_SSRC,
            RtpCodecKind::Video,
            "track-1",
            "0",
            None,
            None,
            0,
        );

        // Simulate the rrid branch: directly call update_inbound_rtx_ssrc as the
        // endpoint handler would after processing an rrid header extension.
        stats.update_inbound_rtx_ssrc(PRIMARY_SSRC, RTX_SSRC);

        // Now on_rtx_packet_received_if_rtx should find the RTX SSRC
        let tracked = stats.on_rtx_packet_received_if_rtx(RTX_SSRC, 100);
        assert!(
            tracked,
            "RTX packets must be tracked after update_inbound_rtx_ssrc"
        );
    }

    /// Regression: handle_undeclared_ssrc must not select RTX codec as primary.
    #[test]
    fn undeclared_ssrc_rejects_rtx_codec() {
        let mut ctx = EndpointHandlerContext::default();

        // Build a single transceiver with no codings (undeclared SSRC scenario)
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            },
        );

        let receiver = transceiver.receiver_mut().as_mut().unwrap();
        // Empty coding parameters = no declared SSRCs
        receiver.set_coding_parameters(vec![]);
        // Track with no codings
        let track = MediaStreamTrack::new(
            "stream-1".to_string(),
            "track-1".to_string(),
            "video".to_string(),
            RtpCodecKind::Video,
            vec![],
        );
        receiver.set_track(track);

        // Codec preferences include both VP8 and RTX
        receiver.set_codec_preferences(vec![
            RTCRtpCodecParameters {
                rtp_codec: vp8_codec(),
                payload_type: 96,
            },
            RTCRtpCodecParameters {
                rtp_codec: rtx_codec(),
                payload_type: 97,
            },
        ]);

        let mut transceivers = vec![transceiver];
        let media_engine = MediaEngine::default();
        let mut interceptor = NoopInterceptor::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = EndpointHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut interceptor,
            &mut stats,
        );

        // Simulate an RTP packet with RTX payload type arriving as undeclared SSRC
        let rtp_header = rtp::Header {
            ssrc: 5555,
            payload_type: 97, // RTX payload type
            ..Default::default()
        };

        let result = handler.handle_undeclared_ssrc(&rtp_header);
        assert_eq!(
            result, None,
            "RTX codec must not be selected as the primary codec for undeclared SSRC"
        );

        // But a VP8 packet should be accepted
        let rtp_header_vp8 = rtp::Header {
            ssrc: 5555,
            payload_type: 96, // VP8 payload type
            ..Default::default()
        };

        let result = handler.handle_undeclared_ssrc(&rtp_header_vp8);
        assert_eq!(
            result,
            Some("track-1".to_string()),
            "Primary codec should be accepted for undeclared SSRC"
        );
    }
}
