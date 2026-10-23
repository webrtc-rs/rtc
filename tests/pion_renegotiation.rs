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

/// Whether the media section with `mid` in `sdp` declares `ssrc` (pion `sdpMidHasSsrc`).
fn sdp_mid_has_ssrc(sdp: &str, mid: &str, ssrc: u32) -> bool {
    sdp.split("\r\nm=").skip(1).any(|section| {
        section.lines().any(|l| l == format!("a=mid:{mid}"))
            && section
                .lines()
                .any(|l| l.starts_with(&format!("a=ssrc:{ssrc} ")))
    })
}

fn media_sections(sdp: &str) -> usize {
    sdp.matches("\r\nm=").count()
}

/// `TestPeerConnection_Transceiver_Mid`: a section keeps its mid and its sender's SSRC across
/// offers, and a track added after another was removed reuses the freed transceiver.
#[test]
fn test_transceiver_mid_is_stable_and_reused() {
    let mut offerer = pc();
    let mut answerer = pc();
    let ssrc1 = 0xa0a0_0001;
    let ssrc2 = 0xa0a0_0002;
    let ssrc3 = 0xa0a0_0003;
    let sender1 = offerer.add_track(vp8_track("pion1", ssrc1)).unwrap();
    let _sender2 = offerer.add_track(vp8_track("pion2", ssrc2)).unwrap();

    let offer = offerer.create_offer(None).unwrap();
    offerer
        .set_local_description(Instant::now(), offer.clone())
        .unwrap();
    answerer
        .set_remote_description(Instant::now(), offer.clone())
        .unwrap();
    let answer = answerer.create_answer(None).unwrap();
    answerer
        .set_local_description(Instant::now(), answer.clone())
        .unwrap();
    offerer
        .set_remote_description(Instant::now(), answer)
        .unwrap();

    assert_eq!(media_sections(&offer.sdp), 2, "two video sections");
    assert!(sdp_mid_has_ssrc(&offer.sdp, "0", ssrc1), "{}", offer.sdp);

    // Removing the first track keeps both sections and the second track's mid and SSRC.
    offerer.remove_track(sender1).unwrap();
    let offer = offerer.create_offer(None).unwrap();
    offerer
        .set_local_description(Instant::now(), offer.clone())
        .unwrap();
    assert_eq!(media_sections(&offer.sdp), 2);
    assert!(sdp_mid_has_ssrc(&offer.sdp, "1", ssrc2), "{}", offer.sdp);

    // The answerer is still in a stable state and cannot answer an offer it has not seen.
    assert!(answerer.create_answer(None).is_err());

    answerer
        .set_remote_description(Instant::now(), offer)
        .unwrap();
    let answer = answerer.create_answer(None).unwrap();
    offerer
        .set_remote_description(Instant::now(), answer)
        .unwrap();

    // A new track reuses the transceiver that no longer sends.
    offerer.add_track(vp8_track("pion3", ssrc3)).unwrap();
    let offer = offerer.create_offer(None).unwrap();
    assert_eq!(
        media_sections(&offer.sdp),
        2,
        "the idle transceiver is reused"
    );
    assert!(sdp_mid_has_ssrc(&offer.sdp, "0", ssrc3), "{}", offer.sdp);
    assert!(sdp_mid_has_ssrc(&offer.sdp, "1", ssrc2), "{}", offer.sdp);
}

/// `TestPeerConnection_Renegotiation_RemoveTrack`: removing the track closes it on the remote.
#[test]
fn test_remove_track_closes_the_remote_track() {
    let mut sim = Sim::new(pc(), pc());
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
    sim.negotiate(true);
    sim.send_video(true, sender, ssrc, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1));

    sim.a.pc.remove_track(sender).unwrap();
    sim.negotiate(true);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_closed() == 1),
        "the remote track is closed once the sender is gone"
    );
}

/// `TestPeerConnection_RoleSwitch`: after the first side offered, the other side can offer, with
/// its new track going to the transceiver the first offer created.
#[test]
fn test_role_switch_second_offerer_adds_a_track() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    sim.negotiate(true);

    sim.a
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    let ssrc = 0xb0b0_0001;
    let sender = sim.b.pc.add_track(vp8_track("foo", ssrc)).unwrap();

    sim.negotiate(false);
    sim.send_video(false, sender, ssrc, 10);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.a.tracks_opened() == 1),
        "the first offerer receives the second offerer's track"
    );
}
