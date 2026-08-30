//! Regression test for the RTX ordering in an answer's codec table.
//!
//! `set_codec_preferences_from_remote_description` matches the offer's primary codecs first and
//! appends an RTX format per match afterwards. That second pass used to walk a `HashMap`, so the
//! rtx formats landed in a different order on every run: the same offer produced different
//! answers from one process to the next, and RFC 3264 §6.1 asks an answer to keep the offer's
//! ordering rather than an arbitrary one.
//!
//! Each rtx format accompanies one primary (RFC 4588 `apt`), so the order that means anything is
//! the primaries' own: rtx-for-VP8 belongs ahead of rtx-for-VP9 exactly when VP8 leads VP9.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use std::time::Instant;

const VP9_FMTP: &str = "profile-id=0";
const FEC_FMTP: &str = "repair-window=10000000";

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

/// VP8 and VP9, each with an RTX flow, plus FlexFEC.
///
/// FEC is included because it reaches the answer by neither of the routes the others take: it
/// is not skipped by the primary scan the way RTX is, and it is re-added a second time by the
/// repair-survival pass in `RTCRtpReceiverInternal::get_codecs`. Both of those walk vectors, so
/// its placement should already be stable - this pins that down rather than assuming it.
fn codec_set(vp8: u8, vp8_rtx: u8, vp9: u8, vp9_rtx: u8, fec: u8) -> Vec<RTCRtpCodecParameters> {
    vec![
        codec(MIME_TYPE_VP8, vp8, ""),
        codec(MIME_TYPE_RTX, vp8_rtx, &format!("apt={vp8}")),
        codec(MIME_TYPE_VP9, vp9, VP9_FMTP),
        codec(MIME_TYPE_RTX, vp9_rtx, &format!("apt={vp9}")),
        codec(MIME_TYPE_FLEX_FEC03, fec, FEC_FMTP),
    ]
}

/// The `m=video` payload type list of an answer to an offer carrying `codec_set(..)`.
fn answer_formats() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // The answerer registers the same codecs under its own numbering, so nothing about the
    // result can be inherited from the local registration order by accident.
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&codec_set(100, 101, 98, 99, 35)))
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&codec_set(96, 97, 94, 95, 45)))
        .build(Instant::now())?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;

    Ok(video_formats(&answer.sdp))
}

fn video_formats(sdp: &str) -> Vec<u8> {
    sdp.lines()
        .find(|l| l.starts_with("m=video "))
        .expect("answer should carry a video media section")
        .split_whitespace()
        .skip(3) // "m=video", port, proto
        .map(|f| f.parse().expect("payload type should be numeric"))
        .collect()
}

/// Position of `payload_type` in the format list.
fn index_of(formats: &[u8], payload_type: u8) -> usize {
    formats
        .iter()
        .position(|pt| *pt == payload_type)
        .unwrap_or_else(|| panic!("payload type {payload_type} missing from {formats:?}"))
}

#[test]
fn test_answer_rtx_order_follows_primaries() -> Result<(), Box<dyn std::error::Error>> {
    let formats = answer_formats()?;

    // The offer leads with VP8 (100, rtx 101) ahead of VP9 (98, rtx 99).
    assert!(
        index_of(&formats, 100) < index_of(&formats, 98),
        "answer should keep the offer's primary order, got {formats:?}",
    );
    assert!(
        index_of(&formats, 101) < index_of(&formats, 99),
        "rtx-for-VP8 (101) should precede rtx-for-VP9 (99), matching their primaries; \
         got {formats:?}",
    );

    // FlexFEC accompanies the media rather than competing with it, so its place in the list
    // carries no preference; it just has to be there, exactly once, under the offered number.
    assert_eq!(
        formats.iter().filter(|pt| **pt == 35).count(),
        1,
        "FlexFEC (35) should appear exactly once, got {formats:?}",
    );

    Ok(())
}

#[test]
fn test_answer_codec_order_is_stable_across_answers() -> Result<(), Box<dyn std::error::Error>> {
    // Every hash map gets its own random state, so repeating the exchange within one process is
    // enough to catch an ordering that depends on one.
    let first = answer_formats()?;
    for round in 2..=16 {
        assert_eq!(
            answer_formats()?,
            first,
            "answer codec order changed on round {round}; the same offer must always produce \
             the same answer",
        );
    }

    Ok(())
}
