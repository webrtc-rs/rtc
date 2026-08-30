//! Regression test for webrtc-rs/rtc#213.
//!
//! An answer must keep the codec ordering of the offer it answers: the offerer reads the
//! answer's `m=` format list back as the negotiated preference. `set_codec_preferences_from
//! _remote_description` scans the remote codec list backwards so that matched entries can be
//! removed by index, so each match has to be prepended to undo that; appending instead leaves
//! the preferences reversed and the answer leads with the offer's *last* codec.
//!
//! The visible consequence with Chrome is a VP8-then-VP9 offer coming back VP9-first, at which
//! point Chrome switches to single-stream SVC and every simulcast encoding collapses.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use std::time::Instant;

fn codec(mime: &str, payload_type: u8, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

fn video_engine(codecs: &[RTCRtpCodecParameters]) -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    for c in codecs {
        media_engine
            .register_codec(c.clone(), RtpCodecKind::Video)
            .expect("register codec");
    }
    media_engine
}

/// The payload-type list from the `m=video` line, in order.
fn video_format_list(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .find(|l| l.starts_with("m=video "))
        .expect("offer/answer should carry a video media section")
        .split_whitespace()
        .skip(3) // "m=video", port, proto
        .collect()
}

#[test]
fn test_answer_preserves_offer_codec_order() -> Result<(), Box<dyn std::error::Error>> {
    // The offerer prefers VP8 over VP9, using Chrome-like non-default numbering.
    let offer_codecs = [
        codec("video/VP8", 100, ""),
        codec("video/VP9", 98, "profile-id=0"),
    ];
    // The answerer registers the same two codecs in the opposite order, under its own
    // numbering, so that echoing local preference would be visible in the answer.
    let answer_codecs = [
        codec("video/VP9", 96, "profile-id=0"),
        codec("video/VP8", 97, ""),
    ];

    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&offer_codecs))
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&answer_codecs))
        .build(Instant::now())?;

    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let offer = offerer.create_offer(None)?;
    let offered = video_format_list(&offer.sdp)
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        offered,
        vec!["100", "98"],
        "offer should list VP8 (100) ahead of VP9 (98)",
    );

    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;

    let answer = answerer.create_answer(None)?;
    assert_eq!(
        video_format_list(&answer.sdp),
        offered,
        "the answer must keep the offer's codec order, not reverse it or echo local preference",
    );

    Ok(())
}
