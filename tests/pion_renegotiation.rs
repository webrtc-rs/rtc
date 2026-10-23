//! Ported from pion/webrtc v4.2.24 `peerconnection_renegotiation_test.go`, on the deterministic
//! in-memory network (`common::sim`): media added after the first negotiation, track events, and
//! how directions and mids survive renegotiation.

mod common;

use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

fn pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap()
}

fn vp8_track(id: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        format!("stream-{id}"),
        format!("track-{id}"),
        format!("label-{id}"),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

fn recvonly() -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Recvonly,
        streams: vec![],
        send_encodings: vec![],
    })
}

/// `TestPeerConnection_Renegotiation_AddRecvonlyTransceiver`, "add recvonly, then receive from
/// answerer" and "add recvonly, then send to answerer".
#[test]
fn test_add_recvonly_transceiver_then_send_either_way() {
    for answerer_sends in [false, true] {
        let mut sim = Sim::new(pc(), pc());
        sim.a
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
            .unwrap();
        sim.negotiate(true);
        assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
            && s.b.connected()));

        // The answerer's side of that section is sendonly (or inactive).
        let (sender_side, ssrc) = if answerer_sends {
            (false, 0xb0b0_0001)
        } else {
            (true, 0xa0a0_0001)
        };
        let sender_id = sim
            .side(sender_side)
            .pc
            .add_track(vp8_track("one", ssrc))
            .unwrap();
        // Signal from the side that sent the original offer or the other, as pion does.
        sim.negotiate(!answerer_sends);

        let receiver_has_track = |s: &mut Sim| s.side(!sender_side).tracks_opened() > 0;
        sim.send_video(sender_side, sender_id, ssrc, 10);
        assert!(
            sim.run_until(Duration::from_secs(2), receiver_has_track),
            "answerer_sends={answerer_sends}: OnTrack never fired"
        );
        assert!(sim.side(!sender_side).rtp_received() > 0);
    }
}

/// `TestPeerConnection_Renegotiation_AddTrack`: a track added after signaling does not surface on
/// the other side until the renegotiation that announces it.
#[test]
fn test_add_track_after_signaling_fires_on_track_only_after_renegotiation() {
    let mut sim = Sim::new(pc(), pc());
    // pion's `signalPair` opens with an initial data channel; without it there is nothing to offer.
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    sim.negotiate(true);

    sim.b
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    let ssrc = 0xa0a0_0001;
    let sender = sim.a.pc.add_track(vp8_track("foo", ssrc)).unwrap();

    // Ten packets before any renegotiation: OnTrack must not fire.
    sim.send_video(true, sender, ssrc, 10);
    assert_eq!(sim.b.tracks_opened(), 0, "OnTrack before renegotiation");

    sim.negotiate(true);
    sim.send_video(true, sender, ssrc, 10);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1),
        "OnTrack after renegotiation"
    );
}

/// `TestPeerConnection_Renegotiation_AddTrack_Multiple`: three tracks added across three
/// renegotiations each fire `OnTrack` exactly once.
#[test]
fn test_add_track_multiple_each_fires_once() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    sim.negotiate(true);

    let mut senders = vec![];
    for i in 0..3u32 {
        sim.b
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
            .unwrap();
        let ssrc = 0xa0a0_0100 + i;
        let sender = sim
            .a
            .pc
            .add_track(vp8_track(&format!("t{i}"), ssrc))
            .unwrap();
        senders.push((sender, ssrc));
        sim.negotiate(true);
        for (sender, ssrc) in senders.clone() {
            sim.send_video(true, sender, ssrc, 5);
        }
        assert!(
            sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened()
                == i as usize + 1),
            "track {i}: OnTrack count {}",
            sim.b.tracks_opened()
        );
    }
    assert_eq!(sim.b.tracks_opened(), 3);
}
