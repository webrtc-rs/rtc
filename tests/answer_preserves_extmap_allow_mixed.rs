//! Regression test for webrtc-rs/rtc#257.
//!
//! RFC 8285 Section-6: mixing one- and two-byte header extensions requires both parties to
//! signal `a=extmap-allow-mixed`. `generate_matched_sdp` computed the flag from the bare
//! `remote_description` field, which the constructor sets to `None` and nothing ever
//! assigns — the maintained state lives in `current_`/`pending_remote_description`, reached
//! through the `remote_description()` accessor the very next statement uses. The answer
//! therefore never carried the attribute, whatever the offer said.
//!
//! The visible consequence with Chrome is that the sender is pinned to one-byte headers,
//! whose 4-bit length field caps an extension at 16 bytes. An AV1 SVC (L2T3_KEY)
//! Dependency Descriptor exceeds that on the packets carrying the template structure, so
//! Chrome never writes the extension.

use rtc::{
    peer_connection::{
        RTCPeerConnectionBuilder, configuration::media_engine::MediaEngine,
        sdp::RTCSessionDescription,
    },
    rtp_transceiver::rtp_sender::RtpCodecKind,
};
use std::time::Instant;

fn has_extmap_allow_mixed(sdp: &str) -> bool {
    sdp.lines().any(|l| l == "a=extmap-allow-mixed")
}

fn without_extmap_allow_mixed(sdp: &str) -> String {
    sdp.lines()
        .filter(|l| *l != "a=extmap-allow-mixed")
        .map(|l| format!("{l}\r\n"))
        .collect()
}

#[test]
fn test_answer_preserves_extmap_allow_mixed() -> Result<(), Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine.clone())
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;

    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let offer = offerer.create_offer(None)?;
    answerer.set_remote_description(Instant::now(), offer)?;

    let answer = answerer.create_answer(None)?;
    assert!(
        has_extmap_allow_mixed(&answer.sdp),
        "answer should have extmap-allow-mixed when the offer has"
    );

    Ok(())
}

#[test]
fn test_answer_omits_extmap_allow_mixed() -> Result<(), Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine.clone())
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;

    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    let offer = offerer.create_offer(None)?;
    let offer = RTCSessionDescription::offer(without_extmap_allow_mixed(&offer.sdp))?;

    answerer.set_remote_description(Instant::now(), offer)?;

    let answer = answerer.create_answer(None)?;
    assert!(
        !has_extmap_allow_mixed(&answer.sdp),
        "answer should not have extmap-allow-mixed when the offer doesn't have"
    );

    Ok(())
}
