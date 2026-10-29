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

fn sendrecv() -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Sendrecv,
        streams: vec![],
        send_encodings: vec![],
    })
}

/// `TestPeerConnection_Renegotiation_NoApplication`: media-only peers connect, twice negotiated,
/// and no SCTP transport is involved.
#[test]
fn test_renegotiation_without_application_section() {
    let mut sim = Sim::new(pc(), pc());
    let send = |pc: &mut RTCPeerConnection, id: &str, ssrc| {
        pc.add_transceiver_from_track(
            vp8_track(id, ssrc),
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings: vec![],
            }),
        )
        .unwrap();
    };
    send(&mut sim.a.pc, "a", 0xa0a0_0001);
    send(&mut sim.b.pc, "b", 0xb0b0_0001);
    sim.negotiate(true);
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    assert!(
        !sim.a
            .pc
            .local_description()
            .unwrap()
            .sdp
            .contains("m=application")
    );
}

/// `TestAddDataChannelDuringRenegotiation`: a data channel created after a media-only negotiation
/// puts exactly one application section in the next offer, and the other side sees the channel.
#[test]
fn test_add_data_channel_during_renegotiation() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.add_track(vp8_track("video", 0xa0a0_0001)).unwrap();
    sim.negotiate(true);
    sim.a.pc.create_data_channel("data-channel", None).unwrap();

    let offer = sim.a.pc.create_offer(None).unwrap();
    assert_eq!(offer.sdp.matches("m=application").count(), 1);

    sim.negotiate(true);
    assert!(
        sim.run_until(Duration::from_secs(10), |s| {
            s.b.events.iter().any(|e| {
                matches!(
                    e,
                    rtc::peer_connection::event::RTCPeerConnectionEvent::OnDataChannel(_)
                )
            })
        }),
        "OnDataChannel fired on the answerer"
    );
}

/// `TestNegotiationNeededRemoveTrack`: adding a track asks for negotiation, and so does removing
/// it once that was settled.
#[test]
fn test_negotiation_needed_after_add_and_after_remove() {
    let mut sim = Sim::new(pc(), pc());
    let sender = sim.a.pc.add_track(vp8_track("video", 0xa0a0_0001)).unwrap();
    assert_eq!(sim.a.negotiation_needed() + drain_needed(&mut sim), 1);
    sim.negotiate(true);
    drain_needed(&mut sim);
    let before = sim.a.negotiation_needed();

    sim.a.pc.remove_track(sender).unwrap();
    drain_needed(&mut sim);
    assert!(
        sim.a.negotiation_needed() > before,
        "removing the track asks for a new negotiation"
    );
}

/// Moves the `OnNegotiationNeeded` events of `sim.a` the simulator has not yet collected into its
/// event list, and returns how many arrived.
fn drain_needed(sim: &mut Sim) -> usize {
    let before = sim.a.negotiation_needed();
    sim.run_for(Duration::from_millis(1));
    sim.a.negotiation_needed() - before
}

/// `TestPeerConnection_Renegotiation_DisableTrack`: stopping a transceiver turns its section
/// `inactive`, and the answer mirrors that.
#[test]
fn test_stopping_a_transceiver_makes_its_section_inactive() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    for _ in 0..2 {
        sim.a
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Video, None)
            .ok();
    }
    // A sendrecv transceiver needs a track in this API; use tracks for the two video sections.
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    sim.a.pc.add_track(vp8_track("one", 0xa0a0_0001)).unwrap();
    let second = sim
        .a
        .pc
        .add_transceiver_from_track(vp8_track("two", 0xa0a0_0002), sendrecv())
        .unwrap();
    sim.negotiate(true);

    let offer = sim.a.pc.create_offer(None).unwrap();
    assert_eq!(offer.sdp.matches("a=sendrecv").count(), 3, "{}", offer.sdp);

    sim.a.pc.rtp_transceiver(second).unwrap().stop().unwrap();
    let offer = sim.a.pc.create_offer(None).unwrap();
    assert_eq!(offer.sdp.matches("a=sendrecv").count(), 2, "{}", offer.sdp);
    assert_eq!(offer.sdp.matches("a=inactive").count(), 1, "{}", offer.sdp);

    // The answerer sees one section disabled.
    sim.b.pc.set_remote_description(sim.now, offer).unwrap();
    let answer = sim.b.pc.create_answer(None).unwrap();
    assert_eq!(
        answer.sdp.matches("a=sendrecv").count(),
        1,
        "the data channel"
    );
    assert_eq!(
        answer.sdp.matches("a=recvonly").count(),
        1,
        "the live video"
    );
    assert_eq!(
        answer.sdp.matches("a=inactive").count(),
        1,
        "the stopped video"
    );
}

/// `TestNegotiationNeededWithRecvonlyTrack`: an answerer that created a transceiver in answering a
/// `recvonly` offer is not asked to negotiate again (nothing differs from what it answered).
#[test]
fn test_answerer_of_a_recvonly_offer_does_not_need_negotiation() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    sim.a
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    sim.negotiate(true);
    sim.run_for(Duration::from_secs(1));
    assert_eq!(
        sim.b.negotiation_needed(),
        0,
        "the answerer needs nothing the exchange did not settle"
    );
}

/// `TestPeerConnection_Regegotiation_AnswerAddsTrack`: the answering side adds a track on a
/// transceiver the offerer created recvonly, and the offerer receives it.
#[test]
fn test_answerer_adds_a_track_later() {
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
    sim.negotiate(true);

    let ssrc = 0xb0b0_0001;
    let sender = sim.b.pc.add_track(vp8_track("foo", ssrc)).unwrap();
    sim.negotiate(true);
    sim.send_video(false, sender, ssrc, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.a.tracks_opened() == 1));
}

/// `TestPeerConnection_Regegotiation_ReuseTransceiver`
#[test]
fn test_reuse_of_a_freed_transceiver() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    let ssrc1 = 0xa0a0_0001;
    let sender = sim.a.pc.add_track(vp8_track("foo", ssrc1)).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));

    assert_eq!(sim.a.pc.get_transceivers().count(), 1);
    sim.a.pc.remove_track(sender).unwrap();

    // The transceiver is not free until the removal is negotiated: a new track gets a new one.
    let ssrc2 = 0xa0a0_0002;
    let sender2 = sim.a.pc.add_track(vp8_track("foo2", ssrc2)).unwrap();
    assert_eq!(
        sim.a.pc.get_transceivers().count(),
        2,
        "not reused before negotiation"
    );
    sim.negotiate(true);

    // After the removal was negotiated, the first transceiver is reused.
    let sender1b = sim.a.pc.add_track(vp8_track("foo", ssrc1)).unwrap();
    assert_eq!(
        sim.a.pc.get_transceivers().count(),
        2,
        "the freed transceiver is reused"
    );
    assert_eq!(
        sim.a.pc.get_transceivers().next().and_then(|id| sim
            .a
            .pc
            .rtp_transceiver(id)
            .unwrap()
            .sender()),
        Some(sender1b),
        "it is the first one"
    );
    sim.negotiate(true);
    sim.send_video(true, sender1b, ssrc1, 10);
    sim.send_video(true, sender2, ssrc2, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() >= 2));
}

fn setup_of(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=setup:"))
        .unwrap_or_default()
        .to_owned()
}

/// `TestPeerConnection_Renegotiation_CodecChange`: one transceiver carries a track, then none,
/// then another, each opening and closing on the remote with its own ids, with the mid unchanged.
#[test]
fn test_one_transceiver_carries_successive_tracks() {
    use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
    let mut sim = Sim::new(pc(), pc());
    let ssrc1 = 0xa0a0_0001;
    let ssrc2 = 0xa0a0_0002;
    let sender1 = sim.a.pc.add_track(vp8_track("1", ssrc1)).unwrap();
    sim.b
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    sim.negotiate(true);
    for pc in [&mut sim.a.pc, &mut sim.b.pc] {
        let ids: Vec<_> = pc.get_transceivers().collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(
            pc.rtp_transceiver(ids[0]).unwrap().mid().as_deref(),
            Some("0")
        );
    }

    sim.send_video(true, sender1, ssrc1, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1));
    let opened = |sim: &Sim| -> Vec<(String, Vec<String>)> {
        sim.b
            .events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(i)) => {
                    Some((i.track_id.clone(), i.stream_ids.clone()))
                }
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        opened(&sim)[0],
        ("track-1".to_owned(), vec!["stream-1".to_owned()])
    );

    sim.a.pc.remove_track(sender1).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_closed() == 1));

    let sender2 = sim.a.pc.add_track(vp8_track("2", ssrc2)).unwrap();
    sim.negotiate(true);
    for pc in [&sim.a.pc, &sim.b.pc] {
        assert_eq!(
            pc.get_transceivers().count(),
            1,
            "the transceiver is reused"
        );
    }
    sim.send_video(true, sender2, ssrc2, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 2));
    assert_eq!(
        opened(&sim)[1],
        ("track-2".to_owned(), vec!["stream-2".to_owned()])
    );

    sim.a.pc.remove_track(sender2).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_closed() == 2));
}

/// `TestPeerConnection_Renegotiation_MidConflict`: a transceiver given the mid of an existing
/// section, plus another new one, does not stop the next offer from being created.
#[test]
fn test_mid_conflict_does_not_break_the_next_offer() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("test", None).unwrap();
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        sim.a
            .pc
            .add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
    }
    sim.negotiate(true);
    assert_eq!(
        sim.a.pc.signaling_state(),
        rtc::peer_connection::state::RTCSignalingState::Stable
    );

    let id = sim
        .a
        .pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![],
            }),
        )
        .unwrap();
    // pion lets the application name the mid; that interface does not exist here (mids are
    // generated), so the conflict cannot be constructed directly. What remains checkable is that
    // a further new transceiver and offer work after a completed negotiation.
    let _ = id;
    sim.a
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, sendrecv())
        .unwrap();
    sim.a
        .pc
        .create_offer(None)
        .expect("the next offer is created");
}

/// `TestPeerConnection_Renegotiation_DTLSRole`: whichever role the answerer is configured with,
/// every later offer, from either side and with or without an ICE restart, is answered with the
/// same role per side and the connection stays up.
#[test]
fn test_dtls_role_is_kept_across_renegotiations() {
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtc::peer_connection::transport::RTCDtlsRole;
    for role in [None, Some(RTCDtlsRole::Client), Some(RTCDtlsRole::Server)] {
        let build = || {
            let mut me = MediaEngine::default();
            me.register_default_codecs().unwrap();
            let mut builder = SettingEngineBuilder::new();
            if let Some(role) = role {
                builder = builder.with_answering_dtls_role(role);
            }
            RTCPeerConnectionBuilder::new()
                .with_media_engine(me)
                .with_setting_engine(builder.build())
                .build(Instant::now())
                .unwrap()
        };
        let mut sim = Sim::new(build(), build());
        sim.a.pc.create_data_channel("d", None).unwrap();
        sim.negotiate(true);
        assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
            && s.b.connected()));

        // The first answerer (`b`) took `answer_role`; `a`, the first offerer, took the other.
        let answer_setup = setup_of(&sim.b.pc.local_description().unwrap().sdp);
        let offerer_setup = if answer_setup == "active" {
            "passive"
        } else {
            "active"
        };

        for restart in [false, true] {
            for a_offers in [false, true] {
                sim.negotiate_with(a_offers, restart);
                assert!(
                    sim.run_until(Duration::from_secs(10), |s| s.a.connected()
                        && s.b.connected()),
                    "role {role:?} restart {restart} a_offers {a_offers}"
                );
                let (answerer, want) = if a_offers {
                    (&sim.b.pc, answer_setup.as_str())
                } else {
                    (&sim.a.pc, offerer_setup)
                };
                let got = setup_of(&answerer.local_description().unwrap().sdp);
                assert_eq!(
                    got, want,
                    "role {role:?} restart {restart} a_offers {a_offers}"
                );
            }
        }
    }
}

/// `TestPeerConnection_Renegotiation_AddTrack_Rename`: a sender's track is replaced by one with
/// other ids between two negotiations; the remote track that opens carries the new ids.
#[test]
fn test_renamed_track_surfaces_with_the_new_ids() {
    use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    let ssrc = 0xb0b0_0001;
    let sender = sim.b.pc.add_track(vp8_track("foo1", ssrc)).unwrap();
    sim.negotiate(true);
    assert_eq!(sim.a.tracks_opened(), 0, "no media yet, no track");

    // Same SSRC, renamed.
    let renamed = MediaStreamTrack::new(
        "bar2".to_owned(),
        "foo2".to_owned(),
        "label".to_owned(),
        RtpCodecKind::Video,
        vp8_track("foo1", ssrc).codings().to_vec(),
    );
    sim.b
        .pc
        .rtp_sender(sender)
        .unwrap()
        .replace_track(renamed)
        .unwrap();
    sim.negotiate(true);

    sim.send_video(false, sender, ssrc, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.a.tracks_opened() == 1));
    let ids = sim.a.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(i)) => {
            Some((i.track_id.clone(), i.stream_ids.clone()))
        }
        _ => None,
    });
    assert_eq!(ids, Some(("foo2".to_owned(), vec!["bar2".to_owned()])));
}

/// `TestPeerConnection_Renegotiation_SetLocalDescription`: the answerer's new sender sends only
/// once its answer is applied, and then the offerer receives it.
#[test]
fn test_new_sender_sends_once_the_answer_is_applied() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("d", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));

    sim.a
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, recvonly())
        .unwrap();
    let ssrc = 0xb0b0_0001;
    let sender = sim.b.pc.add_track(vp8_track("foo", ssrc)).unwrap();

    let now = sim.now;
    let offer = sim.a.pc.create_offer(None).unwrap();
    sim.a.pc.set_local_description(now, offer.clone()).unwrap();
    sim.b.pc.set_remote_description(now, offer).unwrap();
    let answer = sim.b.pc.create_answer(None).unwrap();
    sim.b.pc.set_local_description(now, answer.clone()).unwrap();
    sim.a.pc.set_remote_description(now, answer).unwrap();

    sim.send_video(false, sender, ssrc, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.a.tracks_opened() == 1));
}

/// `TestNegotiationCreateDataChannel`: creating a channel on a fresh connection fires
/// `OnNegotiationNeeded`.
#[test]
fn test_creating_a_data_channel_asks_for_negotiation() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("testChannel", None).unwrap();
    sim.run_for(Duration::from_millis(50));
    assert!(sim.a.negotiation_needed() >= 1);
}
