use crate::data_channel::message::RTCDataChannelMessage;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
    TaggedRTCMessageInternal, TrackPacket,
};

use crate::media_stream::track::MediaStreamTrackId;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpHeaderExtensionCapability};
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiver, SSRC};
use interceptor::{Interceptor, Packet};
use log::{debug, trace, warn};
use shared::TransportContext;
use shared::error::{Error, Result};
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
    rtp_transceivers: &'a mut Vec<RTCRtpTransceiver>,
    media_engine: &'a MediaEngine,
    interceptor: &'a mut I,
}

impl<'a, I> EndpointHandler<'a, I>
where
    I: Interceptor,
{
    pub(crate) fn new(
        ctx: &'a mut EndpointHandlerContext,
        rtp_transceivers: &'a mut Vec<RTCRtpTransceiver>,
        media_engine: &'a MediaEngine,
        interceptor: &'a mut I,
    ) -> Self {
        EndpointHandler {
            ctx,
            rtp_transceivers,
            media_engine,
            interceptor,
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

        if let Some(track_id) = self.find_track_id(rtp_packet.header.ssrc, Some(&rtp_packet.header))
        {
            self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                now,
                transport: transport_context,
                message: RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                    track_id,
                    packet: Packet::Rtp(rtp_packet),
                })),
            });
        } else {
            debug!("drop rtp packet ssrc = {}", rtp_packet.header.ssrc);
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
            && let Some(receiver) = transceiver.receiver_mut()
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
            //TODO: what about RTX/FEC stream?
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

                // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(RTCTrackEventInit {
                            receiver_id: RTCRtpReceiverId(id),
                            track_id: receiver.track().track_id().to_owned(),
                            stream_ids: vec![receiver.track().stream_id().to_owned()],
                            rid: None,
                        })),
                    ));
            }

            Some(track_id)
        } else {
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
            && let Some(receiver) = transceiver.receiver_mut()
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

                let parameters = receiver.get_parameters(self.media_engine);
                RTCPeerConnection::rtp_receiver_remote_stream_op(
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

                // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(RTCTrackEventInit {
                            receiver_id: RTCRtpReceiverId(id),
                            track_id: receiver.track().track_id().to_owned(),
                            stream_ids: vec![receiver.track().stream_id().to_owned()],
                            rid: Some(rid),
                        })),
                    ));
                return Some(receiver.track().track_id().to_owned());
            }
        }
        None
    }

    fn handle_undeclared_ssrc(&mut self, rtp_header: &rtp::Header) -> Option<MediaStreamTrackId> {
        if self.rtp_transceivers.len() != 1 {
            return None;
        }

        if let Some(transceiver) = self.rtp_transceivers.first_mut()
            && let Some(receiver) = transceiver.receiver_mut()
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
            RTCPeerConnection::rtp_receiver_remote_stream_op(
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

            // Fire RTCTrackEvent::OnOpen event when received the first RTP packet for such ssrc stream
            self.ctx
                .event_outs
                .push_back(RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(RTCTrackEventInit {
                        receiver_id: RTCRtpReceiverId(0),
                        track_id: receiver.track().track_id().to_owned(),
                        stream_ids: vec![receiver.track().stream_id().to_owned()],
                        rid: None,
                    })),
                ));
            Some(receiver.track().track_id().to_owned())
        } else {
            None
        }
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
