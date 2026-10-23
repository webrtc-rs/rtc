//! Ported from pion/webrtc v4.2.24 `peerconnection_go_test.go`: state errors, SDP shape and
//! direction handling that need no network.

use sansio::Protocol;
use std::time::Instant;

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
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
