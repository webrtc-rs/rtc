//! A receiver's keyframe request for any layer of a simulcast stream reaches the sender.
//!
//! An SFU relays a subscriber's picture loss indication to the publisher of the stream it asks
//! about. The publisher sends a simulcast stream (one SSRC per layer), and the request names the
//! SSRC of the layer the subscriber is fed from, which can be any of them.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::sim::Sim;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_keyframe_request_forwarding, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use std::time::Instant;

const SSRCS: [(&str, u32); 2] = [("l", 2020), ("h", 2021)];

fn peer() -> rtc::peer_connection::RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let registry = configure_keyframe_request_forwarding(
        register_default_interceptors(Registry::new(), &mut me).unwrap(),
    );
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap()
}

#[test]
fn a_keyframe_request_for_either_simulcast_layer_surfaces_at_the_sender() {
    let mut sender = peer();
    let codings = SSRCS
        .iter()
        .map(|&(rid, ssrc)| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: "video/VP8".into(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        })
        .collect();
    let track = MediaStreamTrack::new(
        "stream".into(),
        "track".into(),
        "track".into(),
        RtpCodecKind::Video,
        codings,
    );
    let id = sender
        .add_transceiver_from_track(
            track,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![],
            }),
        )
        .unwrap();
    let sender_id = RTCRtpSenderId::from(id);

    let mut sim = Sim::new(sender, peer());
    sim.negotiate(true);
    sim.run_for(Duration::from_secs(1));

    // The sender's packets open the receiver's tracks; browsers put mid and rid on every packet.
    let (mid_id, rid_id, pt) = {
        let mut s = sim.a.pc.rtp_sender(sender_id).unwrap();
        let p = s.get_parameters();
        let ext = |uri: &str| {
            p.rtp_parameters
                .header_extensions
                .iter()
                .find(|e| e.uri == uri)
                .map(|e| e.id as u8)
                .unwrap()
        };
        (
            ext("urn:ietf:params:rtp-hdrext:sdes:mid"),
            ext("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"),
            p.rtp_parameters.codecs[0].payload_type,
        )
    };
    let mid = sim.a.pc.rtp_transceiver(id).unwrap().mid().clone().unwrap();
    for n in 0..10u16 {
        for &(rid, ssrc) in &SSRCS {
            let mut header = rtc::rtp::header::Header {
                version: 2,
                payload_type: pt,
                sequence_number: n,
                timestamp: u32::from(n) * 3000,
                ssrc,
                ..Default::default()
            };
            header
                .set_extension(mid_id, Bytes::from(mid.clone().into_bytes()))
                .unwrap();
            header
                .set_extension(rid_id, Bytes::from(rid.to_owned()))
                .unwrap();
            let now = sim.now;
            sim.a
                .pc
                .rtp_sender(sender_id)
                .unwrap()
                .write_rtp(
                    now,
                    rtc::rtp::packet::Packet {
                        header,
                        payload: Bytes::from_static(&[0x10, 0, 0]),
                    },
                )
                .unwrap();
        }
        sim.run_for(Duration::from_millis(20));
    }
    let receiver = sim
        .b
        .events
        .iter()
        .find_map(|e| match e {
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => Some(init.receiver_id),
            _ => None,
        })
        .expect("the receiver's track opened");

    for &(rid, ssrc) in &SSRCS {
        let now = sim.now;
        sim.b
            .pc
            .rtp_receiver(receiver)
            .unwrap()
            .write_rtcp(
                now,
                vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: ssrc,
                })],
            )
            .unwrap();
        sim.run_for(Duration::from_millis(100));
        let seen = sim
            .a
            .messages
            .iter()
            .filter_map(|m| match m {
                RTCMessage::RtcpPacket(_, packets) => Some(packets),
                _ => None,
            })
            .flatten()
            .filter_map(|p| p.as_any().downcast_ref::<PictureLossIndication>())
            .any(|pli| pli.media_ssrc == ssrc);
        assert!(
            seen,
            "the request for layer {rid} (ssrc {ssrc}) never reached the sender"
        );
    }
}
