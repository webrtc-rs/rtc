//! Ported from pion/webrtc v4.2.24 `peerconnection_go_test.go`: state errors, SDP shape and
//! direction handling that need no network.

use sansio::Protocol;
use std::time::Instant;

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::{
    IceRenomination, SettingEngine, SettingEngineBuilder,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::statistics::StatsSelector;
use rtc::statistics::stats::RTCStatsType;
use shared::error::Error;

fn pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap()
}

/// `TestPeerConnection_AnswerWithoutOffer`
#[test]
fn test_answer_without_offer() {
    let mut pc = pc();
    assert!(matches!(
        pc.create_answer(None),
        Err(Error::ErrNoRemoteDescription)
    ));
    pc.close().unwrap();
}

/// `TestPeerConnection_AnswerWithClosedConnection` (the closed-state half).
#[test]
fn test_answer_with_closed_connection() {
    let mut offerer = pc();
    let mut answerer = pc();
    offerer.create_data_channel("test-channel", None).unwrap();
    let offer = offerer.create_offer(None).unwrap();
    offerer
        .set_local_description(Instant::now(), offer.clone())
        .unwrap();
    offerer.close().unwrap();
    answerer
        .set_remote_description(Instant::now(), offer)
        .unwrap();
    answerer.close().unwrap();
    assert!(matches!(
        answerer.create_answer(None),
        Err(Error::ErrConnectionClosed)
    ));
}

/// `TestOneAttrKeyConnectionSetupPerMediaDescriptionInSDP`: four transceivers, four `a=setup`.
#[test]
fn test_one_setup_attribute_per_media_description() {
    let mut pc = pc();
    for kind in [
        RtpCodecKind::Video,
        RtpCodecKind::Audio,
        RtpCodecKind::Audio,
        RtpCodecKind::Video,
    ] {
        pc.add_transceiver_from_kind(kind, None).unwrap();
    }
    let offer = pc.create_offer(None).unwrap();
    let count = offer.sdp.matches("a=setup:").count();
    assert_eq!(count, 4, "{}", offer.sdp);
    pc.close().unwrap();
}

/// `TestOfferWithInactiveDirection`: an inactive remote section yields an inactive transceiver.
#[test]
fn test_offer_with_inactive_direction() {
    let remote = "v=0\r
o=- 4596489990601351948 2 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=fingerprint:sha-256 F7:BF:B4:42:5B:44:C0:B9:49:70:6D:26:D7:3E:E6:08:B1:5B:25:2E:32:88:50:B6:3C:BE:4E:18:A7:2C:85:7C\r
a=group:BUNDLE 0\r
a=msid-semantic:WMS *\r
m=video 9 UDP/TLS/RTP/SAVPF 97\r
c=IN IP4 0.0.0.0\r
a=inactive\r
a=ice-pwd:05d682b2902af03db90d9a9a5f2f8d7f\r
a=ice-ufrag:93cc7e4d\r
a=mid:0\r
a=rtpmap:97 H264/90000\r
a=setup:actpass\r
a=ssrc:1455629982 cname:{61fd3093-0326-4b12-8258-86bdc1fe677a}\r
";
    let mut pc = pc();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(remote.to_owned()).unwrap(),
    )
    .unwrap();
    let id = pc.get_transceivers().next().expect("a transceiver");
    assert_eq!(
        pc.rtp_transceiver(id).unwrap().direction(),
        RTCRtpTransceiverDirection::Inactive
    );
    pc.close().unwrap();
}

/// `TestNoDuplicatedAttributesInMediaDescriptions`
#[test]
fn test_no_duplicated_attributes_in_media_descriptions() {
    let mut pc = pc();
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)
        .unwrap();
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)
        .unwrap();
    pc.create_data_channel("initial_data_channel", None)
        .unwrap();
    let offer = pc.create_offer(None).unwrap();
    let parsed = offer.unmarshal().unwrap();
    for md in &parsed.media_descriptions {
        let mut seen = std::collections::HashSet::new();
        for attr in &md.attributes {
            let line = format!("{} {:?}", attr.key, attr.value);
            assert!(seen.insert(line.clone()), "duplicate attribute: {line}");
        }
    }
    pc.close().unwrap();
}

fn track(kind: RtpCodecKind, id: &str, ssrc: u32) -> rtc::media_stream::MediaStreamTrack {
    use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MIME_TYPE_VP8};
    use rtc::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    };
    let (mime_type, clock_rate, channels) = match kind {
        RtpCodecKind::Audio => (MIME_TYPE_OPUS.to_owned(), 48000, 2),
        _ => (MIME_TYPE_VP8.to_owned(), 90000, 0),
    };
    rtc::media_stream::MediaStreamTrack::new(
        format!("stream-{id}"),
        format!("track-{id}"),
        format!("label-{id}"),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type,
                clock_rate,
                channels,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

fn first_media_has(sdp: &str, direction: &str) -> bool {
    let first = sdp.split("\r\nm=").nth(1).expect("a media section");
    let section = first.split("\r\nm=").next().unwrap();
    section
        .lines()
        .any(|l| l.trim() == format!("a={direction}"))
}

fn media_sections(sdp: &str) -> usize {
    sdp.matches("\r\nm=").count()
}

/// `TestPeerConnection_MediaDirectionInSDP`, "add track before remote description": the
/// answerer's own track may or may not match the transceiver created from the offer, depending
/// on the offered direction; removing the offerer's track changes the directions on both sides.
#[test]
fn test_media_direction_in_sdp() {
    use rtc::rtp_transceiver::RTCRtpTransceiverInit;

    // (remote direction, transceivers on the answerer, answer direction, offer direction after
    // removing the track, answer direction after that)
    let cases = [
        (
            RTCRtpTransceiverDirection::Sendonly,
            2usize,
            "recvonly",
            "inactive",
            "inactive",
        ),
        (
            RTCRtpTransceiverDirection::Sendrecv,
            1usize,
            "sendrecv",
            "recvonly",
            "sendonly",
        ),
    ];
    for (remote, transceivers, answer_dir, offer_dir_after, answer_dir_after) in cases {
        let mut offerer = pc();
        let mut answerer = pc();

        // A track added to the answerer before any remote description makes a sendrecv
        // transceiver.
        answerer
            .add_track(track(RtpCodecKind::Video, "answerer", 0xaaaa_0001))
            .unwrap();

        let sender = if remote == RTCRtpTransceiverDirection::Sendonly {
            let id = offerer
                .add_transceiver_from_track(
                    track(RtpCodecKind::Video, "offerer", 0xbbbb_0001),
                    Some(RTCRtpTransceiverInit {
                        direction: remote,
                        streams: vec![],
                        send_encodings: vec![],
                    }),
                )
                .unwrap();
            offerer
                .rtp_transceiver(id)
                .unwrap()
                .sender()
                .expect("a sender")
        } else {
            offerer
                .add_track(track(RtpCodecKind::Video, "offerer", 0xbbbb_0001))
                .unwrap()
        };

        let offer = offerer.create_offer(None).unwrap();
        offerer
            .set_local_description(Instant::now(), offer.clone())
            .unwrap();
        answerer
            .set_remote_description(Instant::now(), offer)
            .unwrap();
        assert_eq!(
            answerer.get_transceivers().count(),
            transceivers,
            "{remote:?}: transceivers on the answerer"
        );

        let answer = answerer.create_answer(None).unwrap();
        assert!(
            first_media_has(&answer.sdp, answer_dir),
            "{remote:?}: answer should be {answer_dir}\n{}",
            answer.sdp
        );
        answerer
            .set_local_description(Instant::now(), answer.clone())
            .unwrap();
        offerer
            .set_remote_description(Instant::now(), answer)
            .unwrap();

        offerer.remove_track(sender).unwrap();
        let offer = offerer.create_offer(None).unwrap();
        assert!(
            first_media_has(&offer.sdp, offer_dir_after),
            "{remote:?}: re-offer should be {offer_dir_after}\n{}",
            offer.sdp
        );
        offerer
            .set_local_description(Instant::now(), offer.clone())
            .unwrap();
        answerer
            .set_remote_description(Instant::now(), offer)
            .unwrap();
        let answer = answerer.create_answer(None).unwrap();
        assert!(
            first_media_has(&answer.sdp, answer_dir_after),
            "{remote:?}: second answer should be {answer_dir_after}\n{}",
            answer.sdp
        );
        assert_eq!(media_sections(&answer.sdp), 1);
        offerer.close().unwrap();
        answerer.close().unwrap();
    }
}

/// `TestPeerConnection_TransceiverDirection`: the answerer starts with a transceiver of its own
/// and receives an offer; what directions its transceivers end up with.
#[test]
fn test_transceiver_direction_matrix() {
    use RTCRtpTransceiverDirection::{Recvonly, Sendonly, Sendrecv};
    use rtc::rtp_transceiver::RTCRtpTransceiverInit;

    fn create(pc: &mut RTCPeerConnection, dir: RTCRtpTransceiverDirection, ssrc: u32) {
        if dir.has_send() {
            // A sending transceiver needs a track to send.
            let t = track(RtpCodecKind::Video, "local", ssrc);
            pc.add_transceiver_from_track(
                t,
                Some(RTCRtpTransceiverInit {
                    direction: dir,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        } else {
            pc.add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: dir,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        }
    }

    // (name, offer direction, answerer's starting direction, answerer's final directions)
    let cases: [(&str, _, _, Vec<RTCRtpTransceiverDirection>); 9] = [
        (
            "offer sendrecv answer sendrecv",
            Sendrecv,
            Sendrecv,
            vec![Sendrecv],
        ),
        (
            "offer sendonly answer sendrecv",
            Sendonly,
            Sendrecv,
            vec![Sendrecv, Recvonly],
        ),
        (
            "offer recvonly answer sendrecv",
            Recvonly,
            Sendrecv,
            vec![Sendonly],
        ),
        (
            "offer sendrecv answer sendonly",
            Sendrecv,
            Sendonly,
            vec![Sendrecv],
        ),
        (
            "offer sendonly answer sendonly",
            Sendonly,
            Sendonly,
            vec![Sendonly, Recvonly],
        ),
        (
            "offer recvonly answer sendonly",
            Recvonly,
            Sendonly,
            vec![Sendonly],
        ),
        (
            "offer sendrecv answer recvonly",
            Sendrecv,
            Recvonly,
            vec![Recvonly],
        ),
        (
            "offer sendonly answer recvonly",
            Sendonly,
            Recvonly,
            vec![Recvonly],
        ),
        (
            "offer recvonly answer recvonly",
            Recvonly,
            Recvonly,
            vec![Recvonly, Sendonly],
        ),
    ];
    for (name, offer_dir, answer_start, finals) in cases {
        let mut offerer = pc();
        let mut answerer = pc();
        create(&mut offerer, offer_dir, 0x1000_0001);
        let offer = offerer.create_offer(None).unwrap();
        create(&mut answerer, answer_start, 0x2000_0001);
        answerer
            .set_remote_description(Instant::now(), offer)
            .unwrap();
        let got: Vec<_> = answerer
            .get_transceivers()
            .map(|id| answerer.rtp_transceiver(id).unwrap().direction())
            .collect();
        assert_eq!(got, finals, "{name}");
        offerer.close().unwrap();
        answerer.close().unwrap();
    }
}

/// `TestInvalidCandidateTransport`: a candidate with a transport this stack does not know
/// (`ssltcp`) is dropped without failing the call.
#[test]
fn test_invalid_candidate_transport_is_ignored() {
    use rtc::peer_connection::transport::RTCIceCandidateInit;
    let candidate = "candidate:1 1 ssltcp 1 127.0.0.1 443 typ host generation 0";
    let offer = format!(
        "v=0\r\no=- 0 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=msid-semantic: WMS\r\n\
m=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:1/MvHwjAyVf27aLu\r\n\
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E\r\n\
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24\r\n\
a=mid:0\r\na={candidate}\r\n"
    );
    let mut pc = pc();
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer).unwrap())
        .unwrap();
    pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: candidate.to_owned(),
        ..Default::default()
    })
    .unwrap();
    pc.close().unwrap();
}

const ICE_OPTIONS_OFFER: &str = "v=0\r
o=- 0 0 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=group:BUNDLE 0\r
a=ice-ufrag:someufrag\r
a=ice-pwd:somepwd\r
a=fingerprint:sha-256 F7:BF:B4:42:5B:44:C0:B9:49:70:6D:26:D7:3E:E6:08:B1:5B:25:2E:32:88:50:B6:3C:BE:4E:18:A7:2C:85:7C\r
a=msid-semantic: WMS *\r
m=audio 9 UDP/TLS/RTP/SAVPF 111\r
c=IN IP4 0.0.0.0\r
a=rtcp:9 IN IP4 0.0.0.0\r
a=mid:0\r
a=rtcp-mux\r
a=setup:actpass\r
a=rtpmap:111 opus/48000/2\r
";

fn pc_with(setting_engine: SettingEngine) -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_setting_engine(setting_engine)
        .build(Instant::now())
        .unwrap()
}

fn ice_options(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix("a=ice-options:"))
        .collect()
}

/// `TestICETricklingSupported`: no `ice-options` unless asked for, then `trickle` in both the
/// offer and the answer.
#[test]
fn test_ice_trickling_supported() {
    let mut plain = pc();
    plain.create_data_channel("d", None).unwrap();
    assert!(ice_options(&plain.create_offer(None).unwrap().sdp).is_empty());

    let setting = SettingEngineBuilder::new()
        .with_ice_trickle_advertised(true)
        .build();
    let mut offerer = pc_with(setting.clone());
    offerer.create_data_channel("d", None).unwrap();
    let offer = offerer.create_offer(None).unwrap();
    assert_eq!(vec!["trickle"], ice_options(&offer.sdp));

    let mut answerer = pc_with(setting);
    answerer
        .set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(ICE_OPTIONS_OFFER.to_owned()).unwrap(),
        )
        .unwrap();
    let answer = answerer.create_answer(None).unwrap();
    assert_eq!(vec!["trickle"], ice_options(&answer.sdp));
}

/// `TestICERenominationAdvertised`: `renomination` joins the same attribute; both together are
/// one space-separated list, not two attributes.
#[test]
fn test_ice_renomination_advertised() {
    let renomination = SettingEngineBuilder::new()
        .with_ice_renomination(IceRenomination::default())
        .build();
    let mut offerer = pc_with(renomination.clone());
    offerer.create_data_channel("d", None).unwrap();
    assert_eq!(
        vec!["renomination"],
        ice_options(&offerer.create_offer(None).unwrap().sdp)
    );

    let mut answerer = pc_with(renomination);
    answerer
        .set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(ICE_OPTIONS_OFFER.to_owned()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        vec!["renomination"],
        ice_options(&answerer.create_answer(None).unwrap().sdp)
    );

    let both = SettingEngineBuilder::new()
        .with_ice_trickle_advertised(true)
        .with_ice_renomination(IceRenomination::default())
        .build();
    let mut pc = pc_with(both);
    pc.create_data_channel("d", None).unwrap();
    assert_eq!(
        vec!["trickle renomination"],
        ice_options(&pc.create_offer(None).unwrap().sdp)
    );
}

/// `TestEmptyCandidate`: an empty candidate string is the end-of-candidates marker and is fine,
/// a real candidate is fine, and garbage is an error.
#[test]
fn test_empty_candidate() {
    for (candidate, expect_error) in [
        ("", false),
        (
            "211962667 1 udp 2122194687 10.0.3.1 40864 typ host generation 0",
            false,
        ),
        ("1234567", true),
    ] {
        let mut pc = pc();
        pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(ICE_OPTIONS_OFFER.to_owned()).unwrap(),
        )
        .unwrap();
        let result = pc.add_remote_candidate(RTCIceCandidateInit {
            candidate: candidate.to_owned(),
            ..Default::default()
        });
        assert_eq!(expect_error, result.is_err(), "candidate {candidate:?}");
        pc.close().unwrap();
    }
}

/// `TestAddICECandidate__DroppingOldGenerationCandidates`: a candidate naming a ufrag the remote
/// description does not carry is dropped (not an error); one with no ufrag or the right one is
/// kept.
#[test]
fn test_old_generation_candidates_are_dropped() {
    let remote_candidates = |pc: &mut RTCPeerConnection| {
        pc.get_stats(Instant::now(), StatsSelector::None)
            .iter_by_type(RTCStatsType::RemoteCandidate)
            .count()
    };

    let mut pc = pc();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(ICE_OPTIONS_OFFER.to_owned()).unwrap(),
    )
    .unwrap();
    let add = |pc: &mut RTCPeerConnection, candidate: &str| {
        pc.add_remote_candidate(RTCIceCandidateInit {
            candidate: candidate.to_owned(),
            ..Default::default()
        })
    };

    add(
        &mut pc,
        "candidate:1 1 UDP 2122252543 192.168.1.1 12345 typ host",
    )
    .unwrap();
    assert_eq!(1, remote_candidates(&mut pc), "no ufrag: kept");

    add(
        &mut pc,
        "candidate:2 1 UDP 2122252543 192.168.1.2 12345 typ host ufrag someufrag",
    )
    .unwrap();
    assert_eq!(2, remote_candidates(&mut pc), "the current ufrag: kept");

    add(
        &mut pc,
        "candidate:3 1 UDP 2122252543 192.168.1.3 12345 typ host ufrag invalid",
    )
    .unwrap();
    assert_eq!(
        2,
        remote_candidates(&mut pc),
        "another generation's ufrag: dropped"
    );
    pc.close().unwrap();
}

const DATA_OFFER: &str = "v=0\r
o=- 4596489990601351948 2 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=group:BUNDLE data\r
a=msid-semantic: WMS\r
m=application 47299 DTLS/SCTP 5000\r
c=IN IP4 192.168.20.129\r
a=ice-ufrag:1/MvHwjAyVf27aLu\r
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E\r
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24\r
a=setup:actpass\r
a=mid:data\r
a=sctpmap:5000 webrtc-datachannel 1024\r
";

fn answer_setup_for(offer_setup: &str) -> String {
    let mut pc = pc();
    let offer = DATA_OFFER.replace("actpass", offer_setup);
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer).unwrap())
        .unwrap();
    let answer = pc.create_answer(None).unwrap();
    pc.close().unwrap();
    answer
        .sdp
        .lines()
        .find_map(|l| l.strip_prefix("a=setup:"))
        .unwrap()
        .to_owned()
}

/// `TestCreateAnswerActiveOfferPassiveAnswer`: an `active` offer is answered `passive`.
#[test]
fn test_create_answer_active_offer_passive_answer() {
    assert_eq!(answer_setup_for("active"), "passive");
}

/// `TestCreateAnswerPassiveOfferActiveAnswer`: a `passive` offer is answered `active`.
#[test]
fn test_create_answer_passive_offer_active_answer() {
    assert_eq!(answer_setup_for("passive"), "active");
}

/// `Test_WriteRTCP_Disconnected`: RTCP cannot be written before the connection exists.
#[test]
fn test_write_rtcp_disconnected() {
    let mut pc = pc();
    let sender = pc
        .add_transceiver_from_track(track(RtpCodecKind::Video, "local", 1234), None)
        .unwrap();
    let packets: Vec<Box<dyn rtcp::Packet>> = vec![Box::new(
        rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest {
            sender_ssrc: 5,
            media_ssrc: 10,
        },
    )];
    let sender_id = pc.rtp_transceiver(sender).unwrap().sender().unwrap();
    let result = pc
        .rtp_sender(sender_id)
        .unwrap()
        .write_rtcp(Instant::now(), packets);
    assert!(result.is_err());
    pc.close().unwrap();
}
