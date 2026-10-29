//! A renegotiation does not reopen the tracks of a simulcast stream that is already being received.
//!
//! An SFU renegotiates with every participant whenever someone joins or leaves, and the
//! publisher's simulcast layers keep flowing across it. Pion fires `OnTrack` once per track; the
//! layers must not be announced a second time (and bound to the interceptors a second time) when
//! the next remote description lists the same section again.

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

/// Sends `count` packets per layer, as a browser does: mid and rid on every packet.
fn send_layers(sim: &mut Sim, sender_id: RTCRtpSenderId, mid: &str, from: u16, count: u16) {
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
    for n in from..from + count {
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
                .set_extension(mid_id, Bytes::from(mid.to_owned().into_bytes()))
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
}

fn opened(sim: &Sim) -> Vec<(u32, Option<String>)> {
    sim.b
        .events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                Some((init.ssrc, init.rid.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn simulcast_layers_are_announced_once_across_renegotiations() {
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
    let mid = sim.a.pc.rtp_transceiver(id).unwrap().mid().clone().unwrap();

    send_layers(&mut sim, sender_id, &mid, 0, 10);
    let first = opened(&sim);
    assert_eq!(first.len(), 2, "one announcement per layer: {first:?}");
    let received = sim.b.rtp_received();

    // The receiving side renegotiates (as an SFU does when the call changes) and the sender
    // answers; the receiver applies that answer, which lists the same simulcast section again.
    for round in 0..3 {
        sim.negotiate(false);
        sim.run_for(Duration::from_millis(200));
        send_layers(&mut sim, sender_id, &mid, 100 + round * 20, 10);
    }

    assert_eq!(
        opened(&sim),
        first,
        "the layers were announced again after a renegotiation"
    );
    assert_eq!(sim.b.tracks_closed(), 0, "no track ended");
    assert!(
        sim.b.rtp_received() > received + 30,
        "the layers kept arriving across the renegotiations"
    );
}
