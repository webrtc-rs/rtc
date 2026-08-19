//! Regression test for `RtpCodecKind::Application` (SMPTE ST 336 / KLV metadata).
//!
//! The SDP media name `"application"` is shared by two unrelated things: the WebRTC
//! SCTP data channel m-line and any other RTP-carried "application" media, such as an
//! SMPTE336M metadata track. This test builds a peer that negotiates a video track, a
//! real data channel, *and* an SMPTE336M metadata transceiver in the same offer/answer,
//! and checks that all three come out as distinct m-lines rather than the SMPTE336M
//! section being misread as (or clobbering) the data channel.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_SMPTE336M, MIME_TYPE_VP8, MediaEngine,
};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use std::time::Instant;

fn application_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_SMPTE336M.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type: 96,
        ..Default::default()
    }
}

fn video_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type: 98,
        ..Default::default()
    }
}

fn media_engine_with_video_and_smpte336m() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(video_codec(), RtpCodecKind::Video)
        .expect("register video codec");
    media_engine
        .register_codec(application_codec(), RtpCodecKind::Application)
        .expect("register application codec");
    media_engine
}

/// Splits an SDP into its m= sections (including the leading session-level block).
fn media_sections(sdp: &str) -> Vec<&str> {
    let mut sections = vec![];
    let mut rest = sdp;
    while let Some(idx) = rest[1..].find("\r\nm=") {
        sections.push(&rest[..idx + 1]);
        rest = &rest[idx + 3..];
    }
    sections.push(rest);
    sections
}

fn find_section<'a>(sections: &[&'a str], predicate: impl Fn(&str) -> bool) -> &'a str {
    sections
        .iter()
        .copied()
        .find(|s| predicate(s))
        .unwrap_or_else(|| panic!("no matching m= section in {sections:?}"))
}

#[test]
fn test_smpte336m_transceiver_negotiates_alongside_video_and_data_channel() {
    let config = RTCConfigurationBuilder::new().build();

    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_configuration(config.clone())
        .with_media_engine(media_engine_with_video_and_smpte336m())
        .build(Instant::now())
        .expect("build offerer");

    offerer
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    codec: video_codec().rtp_codec,
                    ..Default::default()
                }],
            }),
        )
        .expect("add video transceiver");

    let smpte336m_transceiver_id = offerer
        .add_transceiver_from_kind(
            RtpCodecKind::Application,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    codec: application_codec().rtp_codec,
                    ..Default::default()
                }],
            }),
        )
        .expect("add smpte336m transceiver");

    offerer
        .create_data_channel("chat", None)
        .expect("create data channel");

    let offer = offerer.create_offer(None).expect("create offer");
    offerer
        .set_local_description(Instant::now(), offer.clone())
        .expect("set local offer");

    let sections = media_sections(&offer.sdp);
    assert_eq!(
        sections.len(),
        4,
        "expected session block + video + smpte336m + data channel, got: {}",
        offer.sdp
    );

    let video_section = find_section(&sections, |s| s.starts_with("m=video"));
    assert!(video_section.contains("VP8/90000"), "{video_section}");

    let datachannel_section = find_section(&sections, |s| {
        s.starts_with("m=application") && s.contains("webrtc-datachannel")
    });
    assert!(
        datachannel_section.contains("UDP/DTLS/SCTP"),
        "{datachannel_section}"
    );
    assert!(
        !datachannel_section.contains("smpte336m"),
        "the data channel section must not absorb the SMPTE336M codec: {datachannel_section}"
    );

    let smpte336m_section = find_section(&sections, |s| {
        s.starts_with("m=application") && s.contains("smpte336m")
    });
    assert!(
        !smpte336m_section.contains("webrtc-datachannel"),
        "the SMPTE336M section must not be mistaken for the data channel: {smpte336m_section}"
    );
    assert!(
        smpte336m_section.contains("UDP/TLS/RTP"),
        "{smpte336m_section}"
    );

    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(media_engine_with_video_and_smpte336m())
        .build(Instant::now())
        .expect("build answerer");

    answerer
        .set_remote_description(Instant::now(), offer)
        .expect("set remote offer");
    let answer = answerer.create_answer(None).expect("create answer");

    let answer_sections = media_sections(&answer.sdp);
    assert_eq!(answer_sections.len(), 4, "{}", answer.sdp);
    let answer_smpte336m_section = find_section(&answer_sections, |s| {
        s.starts_with("m=application") && s.contains("smpte336m")
    });
    assert!(
        !answer_smpte336m_section.contains("webrtc-datachannel"),
        "{answer_smpte336m_section}"
    );

    answerer
        .set_local_description(Instant::now(), answer.clone())
        .expect("set local answer");
    offerer
        .set_remote_description(Instant::now(), answer)
        .expect("set remote answer");

    let smpte336m_sender_id = RTCRtpSenderId::from(smpte336m_transceiver_id);
    let parameters = offerer
        .rtp_sender(smpte336m_sender_id)
        .expect("offerer smpte336m sender")
        .get_parameters()
        .clone();
    assert_eq!(parameters.rtp_parameters.codecs.len(), 1);
    assert_eq!(
        parameters.rtp_parameters.codecs[0].rtp_codec.mime_type,
        MIME_TYPE_SMPTE336M
    );
}
