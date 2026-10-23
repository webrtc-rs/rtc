//! Ported from pion/webrtc v4.2.24 `peerconnection_media_test.go`, on the deterministic in-memory
//! network (`common::sim`).

mod common;

use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

fn pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap()
}

fn track(kind: RtpCodecKind, stream: &str, id: &str, ssrc: u32) -> MediaStreamTrack {
    let (mime_type, clock_rate, channels) = match kind {
        RtpCodecKind::Audio => (MIME_TYPE_OPUS, 48000, 2),
        _ => (MIME_TYPE_VP8, 90000, 0),
    };
    MediaStreamTrack::new(
        stream.to_owned(),
        id.to_owned(),
        format!("label-{id}"),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate,
                channels,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

fn without_lines(prefix: &'static str) -> impl FnOnce(String) -> String {
    move |sdp| {
        let mut out = sdp
            .split("\r\n")
            .filter(|l| !l.starts_with(prefix))
            .collect::<Vec<_>>()
            .join("\r\n");
        if !out.ends_with("\r\n") {
            out.push_str("\r\n");
        }
        out
    }
}

/// The `(track id, stream ids)` of every `OnTrack(OnOpen)` a side has seen.
fn opened(sim: &mut Sim, a: bool) -> Vec<(String, Vec<String>)> {
    sim.side(a)
        .events
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                Some((init.track_id.clone(), init.stream_ids.clone()))
            }
            _ => None,
        })
        .collect()
}

/// `TestUndeclaredSSRC`, "No SSRC": a single media section with no `a=ssrc` is taken to carry
/// every RTP packet, and the track keeps the ids from its `a=msid`.
#[test]
fn test_undeclared_ssrc_no_ssrc() {
    let mut sim = Sim::new(pc(), pc());
    let sender = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "pion2", "video", 0x1111_0001))
        .unwrap();
    sim.negotiate_edited(true, false, without_lines("a=ssrc"));

    sim.send_video(true, sender, 0x1111_0001, 10);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1),
        "OnTrack must fire without a declared SSRC"
    );
    let tracks = opened(&mut sim, false);
    assert_eq!(tracks[0].0, "video");
    assert_eq!(tracks[0].1, vec!["pion2".to_owned()]);
    assert!(sim.b.rtp_received() > 0);
}

/// `TestUndeclaredSSRC`, "multiple media sections, no sdp extensions": with several sections, no
/// `a=ssrc` and no `a=extmap` (so no mid header extension), packets are matched to their section
/// by payload type.
#[test]
fn test_undeclared_ssrc_multiple_sections_no_extensions() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("data", None).unwrap();
    let video = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "pion", "video", 0x1111_0001))
        .unwrap();
    let audio = sim
        .a
        .pc
        .add_track(track(
            RtpCodecKind::Audio,
            "pion-audio",
            "audio",
            0x2222_0002,
        ))
        .unwrap();
    sim.negotiate_edited(true, false, |sdp| {
        without_lines("a=extmap")(without_lines("a=ssrc")(sdp))
    });

    sim.send_video(true, video, 0x1111_0001, 10);
    sim.send_video(true, audio, 0x2222_0002, 10);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 2),
        "each section opens exactly one track, got {}",
        sim.b.tracks_opened()
    );
    let mut tracks = opened(&mut sim, false);
    tracks.sort();
    assert_eq!(tracks[0].0, "audio");
    assert_eq!(tracks[0].1, vec!["pion-audio".to_owned()]);
    assert_eq!(tracks[1].0, "video");
    assert_eq!(tracks[1].1, vec!["pion".to_owned()]);
}

use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use sansio::Protocol;

fn init(direction: RTCRtpTransceiverDirection) -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction,
        streams: vec![],
        send_encodings: vec![],
    })
}

/// The `a=<direction>` of the first section of `kind`.
fn offer_media_has_direction(sdp: &str, kind: &str, direction: RTCRtpTransceiverDirection) -> bool {
    let mut in_kind = false;
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("m=") {
            in_kind = rest.starts_with(kind);
        } else if in_kind && line == format!("a={direction}") {
            return true;
        }
    }
    false
}

/// `TestAddTransceiverFromTrackSendOnly`
#[test]
fn test_add_transceiver_from_track_send_only() {
    let mut pc = pc();
    let id = pc
        .add_transceiver_from_track(
            track(RtpCodecKind::Audio, "stream-id", "track-id", 1),
            init(RTCRtpTransceiverDirection::Sendonly),
        )
        .unwrap();
    assert!(pc.rtp_transceiver(id).unwrap().sender().is_some());
    assert_eq!(pc.get_transceivers().count(), 1);
    assert_eq!(pc.get_senders().count(), 1);
    let offer = pc.create_offer(None).unwrap();
    assert!(offer_media_has_direction(
        &offer.sdp,
        "audio",
        RTCRtpTransceiverDirection::Sendonly
    ));
    pc.close().unwrap();
}

/// `TestAddTransceiverFromTrackSendRecv`
#[test]
fn test_add_transceiver_from_track_send_recv() {
    let mut pc = pc();
    let id = pc
        .add_transceiver_from_track(
            track(RtpCodecKind::Audio, "stream-id", "track-id", 1),
            init(RTCRtpTransceiverDirection::Sendrecv),
        )
        .unwrap();
    let transceiver = pc.rtp_transceiver(id).unwrap();
    assert!(transceiver.sender().is_some() && transceiver.receiver().is_some());
    assert_eq!(pc.get_transceivers().count(), 1);
    let offer = pc.create_offer(None).unwrap();
    assert!(offer_media_has_direction(
        &offer.sdp,
        "audio",
        RTCRtpTransceiverDirection::Sendrecv
    ));
    pc.close().unwrap();
}

/// `TestAddTransceiverFromTrackFailsRecvOnly`: a transceiver that only receives cannot start from
/// a track.
#[test]
fn test_add_transceiver_from_track_fails_recv_only() {
    let mut pc = pc();
    for direction in [
        RTCRtpTransceiverDirection::Recvonly,
        RTCRtpTransceiverDirection::Inactive,
    ] {
        assert!(
            pc.add_transceiver_from_track(
                track(RtpCodecKind::Audio, "stream-id", "track-id", 1),
                init(direction),
            )
            .is_err(),
            "{direction}"
        );
    }
    pc.close().unwrap();
}

fn offer_answer(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) {
    let now = Instant::now();
    let offer = offerer.create_offer(None).unwrap();
    offerer.set_local_description(now, offer.clone()).unwrap();
    answerer.set_remote_description(now, offer).unwrap();
    let answer = answerer.create_answer(None).unwrap();
    answerer.set_local_description(now, answer.clone()).unwrap();
    offerer.set_remote_description(now, answer).unwrap();
}

/// `TestAddTransceiverAddTrack_Reuse`, "reuse test": `add_track` reuses a transceiver whose
/// sender was removed, and adds a new one once none is free.
#[test]
fn test_add_track_reuses_a_free_transceiver() {
    let mut pc = pc();
    let tr = pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(RTCRtpTransceiverDirection::Recvonly),
        )
        .unwrap();
    assert_eq!(pc.get_transceivers().collect::<Vec<_>>(), vec![tr]);

    let sender1 = pc
        .add_track(track(RtpCodecKind::Video, "bar", "foo", 1))
        .unwrap();
    assert_eq!(pc.get_transceivers().count(), 1);
    assert_eq!(pc.rtp_transceiver(tr).unwrap().sender(), Some(sender1));
    pc.remove_track(sender1).unwrap();

    let sender2 = pc
        .add_track(track(RtpCodecKind::Video, "bar", "foo", 2))
        .unwrap();
    assert_eq!(
        pc.get_transceivers().count(),
        1,
        "the free transceiver is reused"
    );
    assert_eq!(pc.rtp_transceiver(tr).unwrap().sender(), Some(sender2));

    pc.add_track(track(RtpCodecKind::Video, "bar", "foo", 3))
        .unwrap();
    assert_eq!(pc.get_transceivers().count(), 2);
    pc.close().unwrap();
}

/// `TestAddTransceiverAddTrack_Reuse`, "reuse remote direction test".
#[test]
fn test_add_track_reuse_follows_the_remote_direction() {
    use RTCRtpTransceiverDirection::{Inactive, Recvonly, Sendonly, Sendrecv};
    // (what the offerer sent, the answerer's direction once its sender is gone, send allowed)
    for (remote, _without_sender, send_allowed) in
        [(Sendrecv, Recvonly, true), (Sendonly, Inactive, false)]
    {
        let mut offerer = pc();
        let mut answerer = pc();
        let remote_sender = offerer
            .add_transceiver_from_track(
                track(RtpCodecKind::Video, "track-label", "track-id", 0x1000),
                init(remote),
            )
            .unwrap();
        let remote_sender = offerer
            .rtp_transceiver(remote_sender)
            .unwrap()
            .sender()
            .unwrap();

        let now = Instant::now();
        let offer = offerer.create_offer(None).unwrap();
        offerer.set_local_description(now, offer.clone()).unwrap();
        answerer.set_remote_description(now, offer).unwrap();
        // The remote description created a local transceiver.
        assert_eq!(answerer.get_transceivers().count(), 1, "{remote}");

        let local_sender = answerer
            .add_track(track(RtpCodecKind::Video, "bar", "foo", 0x2000))
            .unwrap();
        let transceivers: Vec<_> = answerer.get_transceivers().collect();
        if send_allowed {
            assert_eq!(
                transceivers.len(),
                1,
                "{remote}: the remote section is reused"
            );
            assert_eq!(
                answerer.rtp_transceiver(transceivers[0]).unwrap().sender(),
                Some(local_sender)
            );
        } else {
            assert_eq!(
                transceivers.len(),
                2,
                "{remote}: a new transceiver is needed"
            );
            assert_eq!(
                answerer.rtp_transceiver(transceivers[1]).unwrap().sender(),
                Some(local_sender)
            );
        }

        let answer = answerer.create_answer(None).unwrap();
        answerer.set_local_description(now, answer.clone()).unwrap();
        offerer.set_remote_description(now, answer).unwrap();
        // The new transceiver had no section to join, so the offerer still sees one.
        assert_eq!(offerer.get_transceivers().count(), 1, "{remote}");

        // Remove the answerer's track and renegotiate to clear its sender from the answer.
        answerer.remove_track(local_sender).unwrap();
        offer_answer(&mut offerer, &mut answerer);

        // Remove the offerer's track to change the remote direction, then renegotiate.
        offerer.remove_track(remote_sender).unwrap();
        offer_answer(&mut offerer, &mut answerer);

        // Adding again follows the same rule.
        let again = answerer
            .add_track(track(RtpCodecKind::Video, "bar", "foo", 0x3000))
            .unwrap();
        let transceivers: Vec<_> = answerer.get_transceivers().collect();
        if send_allowed {
            assert_eq!(transceivers.len(), 1, "{remote}: reused again");
            assert_eq!(
                answerer.rtp_transceiver(transceivers[0]).unwrap().sender(),
                Some(again)
            );
        } else {
            assert_eq!(
                transceivers.len(),
                2,
                "{remote}: the unmatched transceiver is reusable"
            );
            assert_eq!(
                answerer.rtp_transceiver(transceivers[1]).unwrap().sender(),
                Some(again)
            );
        }
        offerer.close().unwrap();
        answerer.close().unwrap();
    }
}

/// `TestAddTransceiverFromKind`: a recvonly transceiver has a receiver and no sender, and the
/// offer says `recvonly`.
#[test]
fn test_add_transceiver_from_kind() {
    let mut pc = pc();
    let id = pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(RTCRtpTransceiverDirection::Recvonly),
        )
        .unwrap();
    let transceiver = pc.rtp_transceiver(id).unwrap();
    assert!(transceiver.receiver().is_some());
    assert!(transceiver.sender().is_none());
    let offer = pc.create_offer(None).unwrap();
    assert!(offer_media_has_direction(
        &offer.sdp,
        "video",
        RTCRtpTransceiverDirection::Recvonly
    ));
    pc.close().unwrap();
}

/// `TestPeerConnection_Start_Only_Negotiated_Senders`: a track added between creating the offer
/// and applying the answer is not part of this negotiation, so nothing it writes reaches the
/// other side, while the negotiated sender works.
#[test]
fn test_only_negotiated_senders_are_started() {
    let mut sim = Sim::new(pc(), pc());
    let sender1 = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "pion1", "video", 0x1111_0001))
        .unwrap();

    let now = sim.now;
    let offer = sim.a.pc.create_offer(None).unwrap();
    sim.a.pc.set_local_description(now, offer.clone()).unwrap();
    sim.b.pc.set_remote_description(now, offer).unwrap();
    let answer = sim.b.pc.create_answer(None).unwrap();
    sim.b.pc.set_local_description(now, answer.clone()).unwrap();

    // Added after the offer was made, before its answer is applied.
    let sender2 = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "pion2", "video2", 0x2222_0002))
        .unwrap();
    sim.a.pc.set_remote_description(now, answer).unwrap();
    sim.exchange_candidates();

    sim.send_video(true, sender1, 0x1111_0001, 10);
    let second = sim.a.pc.rtp_sender(sender2).map(|mut s| {
        s.write_rtp(
            sim.now,
            rtc::rtp::Packet {
                header: rtc::rtp::Header {
                    version: 2,
                    payload_type: 96,
                    ssrc: 0x2222_0002,
                    ..Default::default()
                },
                payload: bytes::Bytes::from_static(&[0x10, 0, 0]),
            },
        )
    });
    sim.run_for(Duration::from_millis(200));
    assert_eq!(
        sim.b.tracks_opened(),
        1,
        "only the negotiated sender's track opens; second write result: {second:?}"
    );
}

fn pc_with_interceptors() -> RTCPeerConnection {
    use rtc::interceptor::Registry;
    use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let registry = register_default_interceptors(Registry::new(), &mut me).unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap()
}

/// Whether `datagram` is an RTP packet (not STUN, DTLS or RTCP) and its payload type.
fn rtp_payload_type(datagram: &[u8]) -> Option<u8> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Some(datagram[1] & 0x7f)
}

/// `Test_PeerConnection_RTX_E2E`: media sent over a path that loses every fifth packet arrives
/// complete, the lost ones recovered through NACK and RTX with no configuration beyond the
/// default interceptors.
#[test]
fn test_nack_and_rtx_recover_lost_packets() {
    let mut sim = Sim::new(pc_with_interceptors(), pc_with_interceptors());
    let ssrc = 0x1111_0001;
    let sender = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "stream-id", "track-id", ssrc))
        .unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));

    let media_pt = sim
        .a
        .pc
        .rtp_sender(sender)
        .unwrap()
        .get_parameters()
        .rtp_parameters
        .codecs[0]
        .payload_type;
    let mut seen = 0u32;
    sim.drop_if = Some(Box::new(move |from_a, datagram| {
        if from_a && rtp_payload_type(datagram) == Some(media_pt) {
            seen += 1;
            return seen % 5 == 0;
        }
        false
    }));

    const COUNT: u16 = 120;
    sim.send_video(true, sender, ssrc, COUNT);
    sim.run_for(Duration::from_secs(3));

    let mut received: Vec<u16> = sim
        .b
        .messages
        .iter()
        .filter_map(|m| match m {
            rtc::peer_connection::message::RTCMessage::RtpPacket(_, packet) => {
                Some(packet.header.sequence_number)
            }
            _ => None,
        })
        .collect();
    received.sort_unstable();
    received.dedup();
    // The tail cannot be NACKed until something later arrives.
    let missing: Vec<u16> = (0..COUNT - 10).filter(|s| !received.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "lost packets that were never recovered: {missing:?} (received {})",
        received.len()
    );
}

/// `TestPeerConnection_CreateOffer_NoCodecs`: with no codec registered, a track can be added but
/// an offer cannot be made for it.
#[test]
fn test_create_offer_with_no_codecs() {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(MediaEngine::default())
        .build(Instant::now())
        .unwrap();
    let added = pc.add_track(track(RtpCodecKind::Video, "pion", "video", 1));
    let offered = added.as_ref().ok().map(|_| pc.create_offer(None));
    assert!(
        added.is_err() || matches!(offered, Some(Err(_))),
        "added: {added:?}, offered: {offered:?}"
    );
    if let Some(Err(err)) = offered {
        assert!(
            matches!(err, shared::error::Error::ErrSenderWithNoCodecs),
            "{err:?}"
        );
    }
    pc.close().unwrap();
}

/// `TestPeerConnection_Zero_PayloadType`: PCMU is payload type 0, which must not be mistaken for
/// "unset" when the track opens.
#[test]
fn test_zero_payload_type_opens_a_track() {
    let mut sim = Sim::new(pc(), pc());
    let ssrc = 0x3333_0003;
    let mut pcmu = track(RtpCodecKind::Audio, "audio", "audio", ssrc);
    pcmu = MediaStreamTrack::new(
        pcmu.stream_id().to_owned(),
        pcmu.track_id().to_owned(),
        "audio".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: "audio/PCMU".to_owned(),
                clock_rate: 8000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    );
    let sender = sim.a.pc.add_track(pcmu).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    let pt = sim
        .a
        .pc
        .rtp_sender(sender)
        .unwrap()
        .get_parameters()
        .rtp_parameters
        .codecs[0]
        .payload_type;
    assert_eq!(pt, 0, "PCMU is static payload type 0");

    sim.send_video(true, sender, ssrc, 10);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1),
        "OnTrack must fire for payload type 0"
    );
    assert!(sim.b.rtp_received() > 0);
}

/// `TestPeerConnection_Start_Right_Receiver`: a track surfaces on the receiver of the section it
/// was negotiated in, ends with that section's track, and a new transceiver gets its own.
#[test]
fn test_start_right_receiver() {
    let mut sim = Sim::new(pc(), pc());
    let first_recv = sim
        .b
        .pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(RTCRtpTransceiverDirection::Recvonly),
        )
        .unwrap();
    let receiver_of = |sim: &mut Sim, id| sim.b.pc.rtp_transceiver(id).unwrap().receiver().unwrap();
    let first_receiver = receiver_of(&mut sim, first_recv);

    let ssrc1 = 0x1111_0001;
    let sender1 = sim
        .a
        .pc
        .add_track(track(RtpCodecKind::Video, "pion1", "video", ssrc1))
        .unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    sim.send_video(true, sender1, ssrc1, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 1));
    let opened_receivers = |sim: &mut Sim| -> Vec<_> {
        sim.b
            .events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    Some(init.receiver_id)
                }
                _ => None,
            })
            .collect()
    };
    assert_eq!(opened_receivers(&mut sim), vec![first_receiver]);

    // Remove the track: that section's track ends.
    sim.a.pc.remove_track(sender1).unwrap();
    sim.negotiate(true);
    assert!(
        sim.run_until(Duration::from_secs(2), |s| s.b.tracks_closed() == 1),
        "the track of the removed sender closes"
    );

    // A new transceiver (not `add_track`, which would reuse the first) with a new receiver on
    // the other side gets its own track and leaves the first alone.
    let ssrc2 = 0x2222_0002;
    sim.a
        .pc
        .add_transceiver_from_track(track(RtpCodecKind::Video, "pion1", "video", ssrc2), None)
        .unwrap();
    let second_recv = sim
        .b
        .pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(RTCRtpTransceiverDirection::Recvonly),
        )
        .unwrap();
    let second_receiver = receiver_of(&mut sim, second_recv);
    sim.negotiate(true);
    let second_sender = sim
        .a
        .pc
        .get_senders()
        .find(|s| s != &sender1)
        .expect("the new sender");
    sim.send_video(true, second_sender, ssrc2, 10);
    assert!(sim.run_until(Duration::from_secs(2), |s| s.b.tracks_opened() == 2));
    assert_eq!(
        opened_receivers(&mut sim),
        vec![first_receiver, second_receiver],
        "the second track opens on the second receiver"
    );
}
