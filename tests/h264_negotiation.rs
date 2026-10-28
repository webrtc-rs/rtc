use rtc::{
    peer_connection::{
        RTCPeerConnection, RTCPeerConnectionBuilder, configuration::media_engine::MediaEngine,
        sdp::RTCSessionDescription,
    },
    rtp::{Header, Packet},
    rtp_transceiver::{
        RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
        rtp_sender::{
            RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
            RtpCodecKind,
        },
    },
};
use std::time::Instant;

fn codec(profile: &str, asymmetry: Option<bool>) -> RTCRtpCodecParameters {
    let mut fmtp = format!("packetization-mode=1;profile-level-id={profile}");
    if let Some(asymmetry) = asymmetry {
        fmtp.push_str(&format!(";level-asymmetry-allowed={}", u8::from(asymmetry)));
    }
    RTCRtpCodecParameters {
        payload_type: 102,
        rtp_codec: RTCRtpCodec {
            mime_type: "video/H264".into(),
            clock_rate: 90000,
            sdp_fmtp_line: fmtp,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn peer(profile: &str, asymmetry: Option<bool>) -> RTCPeerConnection {
    let mut media = MediaEngine::default();
    media
        .register_codec(codec(profile, asymmetry), RtpCodecKind::Video)
        .unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(media)
        .build(Instant::now())
        .unwrap()
}

fn transceiver(pc: &mut RTCPeerConnection, source: &str, ssrc: u32) -> RTCRtpTransceiverId {
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            send_encodings: vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: codec(source, Some(true)).rtp_codec,
                ..Default::default()
            }],
            ..Default::default()
        }),
    )
    .unwrap()
}

fn exchange(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> RTCSessionDescription {
    let offer = offerer.create_offer(None).unwrap();
    offerer
        .set_local_description(Instant::now(), offer.clone())
        .unwrap();
    answerer
        .set_remote_description(Instant::now(), offer)
        .unwrap();
    let answer = answerer.create_answer(None).unwrap();
    answerer
        .set_local_description(Instant::now(), answer.clone())
        .unwrap();
    offerer
        .set_remote_description(Instant::now(), answer.clone())
        .unwrap();
    answer
}

fn profile(codecs: &[RTCRtpCodecParameters]) -> String {
    codecs
        .iter()
        .find(|codec| codec.rtp_codec.mime_type.eq_ignore_ascii_case("video/H264"))
        .unwrap()
        .rtp_codec
        .sdp_fmtp_line
        .split(';')
        .find_map(|part| part.trim().strip_prefix("profile-level-id="))
        .unwrap()
        .into()
}

fn directions(pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId) -> (String, String) {
    let transceiver = pc.rtp_transceiver(id).unwrap();
    let (sender, receiver) = (
        transceiver.sender().unwrap(),
        transceiver.receiver().unwrap(),
    );
    (
        profile(
            &pc.rtp_sender(sender)
                .unwrap()
                .get_parameters()
                .rtp_parameters
                .codecs,
        ),
        profile(
            &pc.rtp_receiver(receiver)
                .unwrap()
                .get_parameters()
                .rtp_parameters
                .codecs,
        ),
    )
}

#[test]
fn answer_and_directional_parameters_use_their_own_description() {
    for (local, remote, local_asym, remote_asym, answer_level) in [
        ("42e01f", "42c02a", Some(true), Some(true), "42e01f"),
        ("42e01f", "42c02a", Some(true), Some(false), "42e01f"),
        ("42e02a", "4d801f", Some(true), Some(true), "42e02a"),
        ("42e02a", "58c01f", Some(true), None, "42e01f"),
        ("42e02a", "42c01f", Some(false), Some(true), "42e01f"),
        ("42e00a", "42f00b", Some(false), Some(false), "42e00a"),
        ("42e00b", "4d900b", Some(false), Some(false), "42f00b"),
    ] {
        let mut a = peer(local, local_asym);
        let a_id = transceiver(&mut a, local, 100);
        let mut b = peer(remote, remote_asym);
        let b_id = transceiver(&mut b, remote, 200);
        exchange(&mut b, &mut a);
        assert_eq!(
            directions(&mut a, a_id),
            (remote.into(), answer_level.into()),
            "answerer {local} / offerer {remote}; asymmetry {local_asym:?}/{remote_asym:?}"
        );
        assert_eq!(
            directions(&mut b, b_id),
            (answer_level.into(), remote.into())
        );
    }
}

#[test]
fn retained_pc_and_two_mids_do_not_share_or_retain_remote_receive_limits() {
    let mut a = peer("42e01f", Some(true));
    let a_ids = [
        transceiver(&mut a, "42e01f", 100),
        transceiver(&mut a, "42e01f", 101),
    ];
    let mut b = peer("42c02a", Some(true));
    let b_ids = [
        transceiver(&mut b, "42c02a", 200),
        transceiver(&mut b, "42c01e", 201),
    ];
    b.rtp_transceiver(b_ids[1])
        .unwrap()
        .set_codec_preferences(vec![codec("42c01e", Some(true))])
        .unwrap();
    exchange(&mut b, &mut a);
    assert_eq!(
        directions(&mut a, a_ids[0]),
        ("42c02a".into(), "42e01f".into())
    );
    assert_eq!(
        directions(&mut a, a_ids[1]),
        ("42c01e".into(), "42e01f".into())
    );

    b.rtp_transceiver(b_ids[0])
        .unwrap()
        .set_codec_preferences(vec![codec("42c00b", Some(false))])
        .unwrap();
    exchange(&mut b, &mut a);
    assert_eq!(
        directions(&mut a, a_ids[0]),
        ("42c00b".into(), "42e00b".into())
    );
    assert_eq!(
        directions(&mut a, a_ids[1]),
        ("42c01e".into(), "42e01f".into())
    );

    b.rtp_transceiver(b_ids[0])
        .unwrap()
        .set_codec_preferences(vec![codec("42c02a", Some(true))])
        .unwrap();
    exchange(&mut b, &mut a);
    assert_eq!(
        directions(&mut a, a_ids[0]),
        ("42c02a".into(), "42e01f".into())
    );
    exchange(&mut a, &mut b);
    assert_eq!(
        directions(&mut a, a_ids[0]),
        ("42c02a".into(), "42e01f".into())
    );
    assert_eq!(a.get_transceivers().collect::<Vec<_>>(), a_ids);
    assert_eq!(b.get_transceivers().collect::<Vec<_>>(), b_ids);

    let added = transceiver(&mut a, "42c01f", 102);
    exchange(&mut a, &mut b);
    assert_eq!(
        directions(&mut a, added).1,
        "42e01f",
        "a new sender must select local capabilities, not the previous remote receive level"
    );
}

#[test]
fn raw_rtp_does_not_require_source_format_metadata() {
    let mut a = peer("42e01f", Some(true));
    let id = a
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                send_encodings: vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(100),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            }),
        )
        .unwrap();
    let mut b = peer("42c02a", Some(false));
    transceiver(&mut b, "42c02a", 200);
    exchange(&mut b, &mut a);
    let sender = a.rtp_transceiver(id).unwrap().sender().unwrap();
    // This API writes opaque RTP; SDP capabilities are not an SPS declaration.
    a.rtp_sender(sender)
        .unwrap()
        .write_rtp(
            Instant::now(),
            Packet {
                header: Header {
                    version: 2,
                    payload_type: 102,
                    ssrc: 100,
                    ..Default::default()
                },
                payload: vec![0x65, 1].into(),
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn public_capabilities_remain_local_before_and_after_negotiation() {
    use rtc::rtp_transceiver::rtp_sender::{RTCRtpCapabilities, RTCRtpHeaderExtensionCapability};
    let extension = "urn:ietf:params:rtp-hdrext:sdes:mid";
    let mut media = MediaEngine::default();
    media
        .register_codec(codec("42e01f", Some(true)), RtpCodecKind::Video)
        .unwrap();
    media
        .register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: extension.into(),
            },
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverDirection::Sendrecv),
        )
        .unwrap();
    let mut a = RTCPeerConnectionBuilder::new()
        .with_media_engine(media)
        .build(Instant::now())
        .unwrap();
    let id = transceiver(&mut a, "42e01f", 100);
    let ids = a.rtp_transceiver(id).unwrap();
    let (sender, receiver) = (ids.sender().unwrap(), ids.receiver().unwrap());
    let before_send = a
        .rtp_sender(sender)
        .unwrap()
        .get_capabilities(RtpCodecKind::Video)
        .unwrap();
    let before_recv = a
        .rtp_receiver(receiver)
        .unwrap()
        .get_capabilities(RtpCodecKind::Video)
        .unwrap();
    let mut b = peer("42c02a", Some(true));
    transceiver(&mut b, "42c02a", 200);
    exchange(&mut b, &mut a);
    let after_send = a
        .rtp_sender(sender)
        .unwrap()
        .get_capabilities(RtpCodecKind::Video)
        .unwrap();
    let after_recv = a
        .rtp_receiver(receiver)
        .unwrap()
        .get_capabilities(RtpCodecKind::Video)
        .unwrap();
    let capabilities = |capabilities: RTCRtpCapabilities| {
        (
            capabilities
                .codecs
                .into_iter()
                .map(|codec| codec.sdp_fmtp_line)
                .collect::<Vec<_>>(),
            capabilities
                .header_extensions
                .into_iter()
                .map(|extension| extension.uri)
                .collect::<Vec<_>>(),
        )
    };
    let actual = [
        capabilities(before_send),
        capabilities(before_recv),
        capabilities(after_send),
        capabilities(after_recv),
    ];
    eprintln!("public capabilities before/after: {actual:?}");
    let expected = (
        vec![codec("42e01f", Some(true)).rtp_codec.sdp_fmtp_line],
        vec![extension.to_owned()],
    );
    assert_eq!(
        actual,
        [
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected
        ]
    );
}

#[test]
fn retained_mid_can_reoffer_a_previously_unselected_local_codec() {
    let vp8 = |payload_type| RTCRtpCodecParameters {
        payload_type,
        rtp_codec: RTCRtpCodec {
            mime_type: "video/VP8".into(),
            clock_rate: 90000,
            ..Default::default()
        },
        ..Default::default()
    };
    let rtx = |payload_type, apt| RTCRtpCodecParameters {
        payload_type,
        rtp_codec: RTCRtpCodec {
            mime_type: "video/rtx".into(),
            clock_rate: 90000,
            sdp_fmtp_line: format!("apt={apt}"),
            ..Default::default()
        },
        ..Default::default()
    };
    let both = |vp8_pt, rtx_pt| {
        let mut media = MediaEngine::default();
        for codec in [
            vp8(vp8_pt),
            rtx(rtx_pt, vp8_pt),
            codec("42e01f", Some(true)),
            rtx(103, 102),
        ] {
            media.register_codec(codec, RtpCodecKind::Video).unwrap();
        }
        RTCPeerConnectionBuilder::new()
            .with_media_engine(media)
            .build(Instant::now())
            .unwrap()
    };
    let mut a = both(96, 97);
    let a_id = transceiver(&mut a, "42e01f", 100);
    let mut b = both(120, 121);
    let b_id = transceiver(&mut b, "42e01f", 200);
    a.rtp_transceiver(a_id)
        .unwrap()
        .set_codec_preferences(vec![vp8(96)])
        .unwrap();
    b.rtp_transceiver(b_id)
        .unwrap()
        .set_codec_preferences(vec![vp8(120)])
        .unwrap();
    exchange(&mut b, &mut a);
    let a_mid = a.rtp_transceiver(a_id).unwrap().mid().clone();
    let b_mid = b.rtp_transceiver(b_id).unwrap().mid().clone();
    a.rtp_transceiver(a_id)
        .unwrap()
        .set_codec_preferences(vec![vp8(96), codec("42e01f", Some(true))])
        .unwrap();
    let offer = a.create_offer(None).unwrap();
    eprintln!(
        "new local H264 preference on retained VP8 MID:\n{}",
        offer.sdp
    );
    assert!(
        offer.sdp.contains("a=rtpmap:102 H264/90000"),
        "local capability must not remain intersected with the previous remote formats"
    );
    for mapping in [
        "a=rtpmap:120 VP8/90000",
        "a=rtpmap:121 rtx/90000",
        "a=fmtp:121 apt=120",
        "a=rtpmap:103 rtx/90000",
        "a=fmtp:103 apt=102",
    ] {
        assert!(
            offer.sdp.contains(mapping),
            "old payload/RTX mappings remain valid when adding local H264: {mapping}"
        );
    }
    a.set_local_description(Instant::now(), offer.clone())
        .unwrap();
    b.rtp_transceiver(b_id)
        .unwrap()
        .set_codec_preferences(vec![vp8(120), codec("42e01f", Some(true))])
        .unwrap();
    b.set_remote_description(Instant::now(), offer).unwrap();
    let answer = b.create_answer(None).unwrap();
    assert!(answer.sdp.contains("a=rtpmap:102 H264/90000"));
    b.set_local_description(Instant::now(), answer.clone())
        .unwrap();
    a.set_remote_description(Instant::now(), answer).unwrap();
    assert_eq!(a.rtp_transceiver(a_id).unwrap().mid().clone(), a_mid);
    assert_eq!(b.rtp_transceiver(b_id).unwrap().mid().clone(), b_mid);
    assert_eq!(a.get_transceivers().collect::<Vec<_>>(), vec![a_id]);
    assert_eq!(b.get_transceivers().collect::<Vec<_>>(), vec![b_id]);
}
