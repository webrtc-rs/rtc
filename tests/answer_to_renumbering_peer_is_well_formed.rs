//! Robustness test for webrtc-rs/rtc#213: a peer that renumbers an already-negotiated codec.
//!
//! RFC 3264 §8.3.2 forbids this on the peer's side:
//!
//! > the mapping from a particular dynamic payload type number to a particular codec within
//! > that media stream MUST NOT change for the duration of a session.
//!
//! So a conformant peer never renumbers, and this stack is under no obligation to follow one
//! that does. What it *is* obliged to do is answer with well-formed SDP either way. Today the
//! answer keeps the numbering agreed in the first exchange, which is stale but valid; the
//! failure mode worth guarding against is an answer that names one payload type twice, or the
//! same format twice under two numbers. Either makes the media section ambiguous to parse.
//!
//! The guard matters because `MediaEngine::update_from_remote_description` latches
//! `negotiated_video` on the first remote description. Any change that lets it accumulate a
//! second numbering — the natural way to make answers track a renumbering peer — puts two
//! entries for one codec in reach of the answer, and repair formats get there by routes the
//! primaries do not:
//!
//! - **primaries** are renumbered in `set_codec_preferences_from_remote_description`;
//! - **RTX** is skipped by that scan and re-added afterwards from the local codec list;
//! - **FEC** is not skipped, and is *additionally* re-added by the repair-survival pass in
//!   `RTCRtpReceiverInternal::get_codecs`, which excludes duplicates by payload type only —
//!   it has no `apt` to bind it to a primary, so a stale copy is not filtered out.
//!
//! Prototypes of the "make the answer track the new numbering" fix failed here in both ways:
//! taking the RTX association from the remote's rtx entry emitted one payload type twice, and
//! letting the engine accumulate numberings emitted FlexFEC twice under two numbers. This test
//! fails on both while passing on the current, stale-but-valid behaviour.

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use std::collections::HashMap;
use std::time::Instant;

const FEC_FMTP: &str = "repair-window=10000000";
const VP9_FMTP: &str = "profile-id=0";

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

/// The codec table of an SDP's video media section, as the peer on the wire would read it.
struct VideoSection {
    /// Payload types in `m=video` order.
    formats: Vec<u8>,
    /// payload type -> encoding name from `a=rtpmap` (lowercased).
    names: HashMap<u8, String>,
    /// payload type -> `a=fmtp` parameters.
    fmtps: HashMap<u8, String>,
}

impl VideoSection {
    fn parse(sdp: &str) -> Self {
        let mut in_video = false;
        let (mut formats, mut names, mut fmtps) = (vec![], HashMap::new(), HashMap::new());

        for line in sdp.lines() {
            if line.starts_with("m=") {
                in_video = line.starts_with("m=video ");
                if in_video {
                    formats = line
                        .split_whitespace()
                        .skip(3) // "m=video", port, proto
                        .map(|f| f.parse().expect("payload type should be numeric"))
                        .collect();
                }
                continue;
            }
            if !in_video {
                continue;
            }
            if let Some(rest) = line.strip_prefix("a=rtpmap:")
                && let Some((pt, encoding)) = rest.split_once(' ')
            {
                let name = encoding
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_lowercase();
                names.insert(pt.parse().expect("rtpmap payload type"), name);
            }
            if let Some(rest) = line.strip_prefix("a=fmtp:")
                && let Some((pt, params)) = rest.split_once(' ')
            {
                fmtps.insert(pt.parse().expect("fmtp payload type"), params.to_owned());
            }
        }

        Self {
            formats,
            names,
            fmtps,
        }
    }

    /// The payload type carrying `name`, for codecs with no distinguishing fmtp.
    fn find_plain(&self, name: &str) -> Option<u8> {
        self.formats
            .iter()
            .copied()
            .find(|pt| self.names.get(pt).map(String::as_str) == Some(name))
    }
}

/// A full codec set: two primaries, an RTX flow for each, and FlexFEC.
fn codec_set(vp8: u8, vp8_rtx: u8, vp9: u8, vp9_rtx: u8, fec: u8) -> Vec<RTCRtpCodecParameters> {
    vec![
        codec(MIME_TYPE_VP8, vp8, ""),
        codec(MIME_TYPE_RTX, vp8_rtx, &format!("apt={vp8}")),
        codec(MIME_TYPE_VP9, vp9, VP9_FMTP),
        codec(MIME_TYPE_RTX, vp9_rtx, &format!("apt={vp9}")),
        codec(MIME_TYPE_FLEX_FEC03, fec, FEC_FMTP),
    ]
}

/// Offer from `offerer`, answer from `answerer`, returning the answer SDP.
fn exchange(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> Result<String, Box<dyn std::error::Error>> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;

    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

#[test]
fn test_answer_to_renumbering_peer_is_well_formed() -> Result<(), Box<dyn std::error::Error>> {
    // First exchange establishes one numbering...
    let first = codec_set(100, 101, 98, 99, 35);
    // ...the answerer's own registration differs, so echoing local preference is visible.
    let local = codec_set(96, 97, 94, 95, 45);
    // ...and a later peer numbers the very same codecs differently.
    let second = codec_set(102, 104, 103, 105, 115);

    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&first))
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&local))
        .build(Instant::now())?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let first_answer = VideoSection::parse(&exchange(&mut offerer, &mut answerer)?);
    assert_eq!(
        first_answer.find_plain("vp8"),
        Some(100),
        "sanity: the first answer adopts the first offer's numbering",
    );

    // Renegotiate from a peer that numbers the same codecs differently.
    let mut offerer2 = RTCPeerConnectionBuilder::new()
        .with_media_engine(video_engine(&second))
        .build(Instant::now())?;
    offerer2.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let offer2 = offerer2.create_offer(None)?;
    let offered = VideoSection::parse(&offer2.sdp);
    assert_eq!(
        offered.formats,
        vec![102, 104, 103, 105, 115],
        "sanity: the second offer uses the renumbered set",
    );

    answerer.set_remote_description(Instant::now(), offer2)?;
    let answer2 = answerer.create_answer(None)?;
    let answered = VideoSection::parse(&answer2.sdp);

    assert!(
        !answered.formats.is_empty(),
        "the answer should still describe a usable codec set",
    );

    // A payload type names exactly one format within a media section.
    let mut by_number = answered.formats.clone();
    by_number.sort_unstable();
    let distinct = by_number.len();
    by_number.dedup();
    assert_eq!(
        distinct,
        by_number.len(),
        "answer names a payload type more than once: {:?}",
        answered.formats,
    );

    // ...and one format is not offered twice under two numbers. `apt` is part of the identity,
    // so the several RTX entries a media section legitimately carries stay distinct.
    let mut identities: Vec<(&str, &str)> = answered
        .formats
        .iter()
        .map(|pt| {
            (
                answered.names.get(pt).map(String::as_str).unwrap_or(""),
                answered.fmtps.get(pt).map(String::as_str).unwrap_or(""),
            )
        })
        .collect();
    identities.sort_unstable();
    let distinct = identities.len();
    identities.dedup();
    assert_eq!(
        distinct,
        identities.len(),
        "answer describes the same format under two payload types: {:?}\n  rtpmap: {:?}\n  fmtp:   {:?}",
        answered.formats,
        answered.names,
        answered.fmtps,
    );

    Ok(())
}
