//! RFC 9335 (Cryptex) negotiation between two peers, through their session descriptions: what is
//! offered, what is answered, which transceivers end up with encrypted header extensions, and what
//! the header-encryption policy accepts. Mirrors pion's `TestCryptex*` tests.

use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtpHeaderEncryptionPolicy};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn peer(
    policy: RTCRtpHeaderEncryptionPolicy,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_rtp_header_encryption_policy(policy)
                .build(),
        )
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn lines(sdp: &str) -> Vec<&str> {
    sdp.lines().collect()
}

/// Whether the SDP has `a=cryptex` before its first media section (session level).
fn session_level_cryptex(sdp: &str) -> bool {
    lines(sdp)
        .into_iter()
        .take_while(|l| !l.starts_with("m="))
        .any(|l| l == "a=cryptex")
}

/// How many media sections carry their own `a=cryptex`.
fn media_level_cryptex(sdp: &str) -> usize {
    let mut in_media = false;
    let mut n = 0;
    for l in lines(sdp) {
        if l.starts_with("m=") {
            in_media = true;
        }
        if in_media && l == "a=cryptex" {
            n += 1;
        }
    }
    n
}

fn av_offerer(
    policy: RTCRtpHeaderEncryptionPolicy,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = peer(policy)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    Ok(pc)
}

fn negotiated(pc: &mut RTCPeerConnection) -> Vec<bool> {
    let ids: Vec<_> = pc.get_transceivers().collect();
    ids.into_iter()
        .map(|id| {
            pc.rtp_transceiver(id)
                .unwrap()
                .rtp_header_encryption_negotiated()
        })
        .collect()
}

/// Both sides at the default policy: offered at the session level, answered, and negotiated for
/// every transceiver on both sides (pion `TestCryptexNegotiatedInSDP`, `TestCryptexAttributeInOffer`).
#[test]
fn default_policy_negotiates_cryptex() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Unspecified)?;
    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Unspecified)?;

    let offer = offerer.create_offer(None)?;
    assert!(session_level_cryptex(&offer.sdp), "{}", offer.sdp);
    assert_eq!(media_level_cryptex(&offer.sdp), 0);
    offerer.set_local_description(Instant::now(), offer.clone())?;

    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert!(session_level_cryptex(&answer.sdp), "{}", answer.sdp);
    answerer.set_local_description(Instant::now(), answer.clone())?;
    assert_eq!(negotiated(&mut answerer), [true, true]);

    offerer.set_remote_description(Instant::now(), answer)?;
    assert_eq!(negotiated(&mut offerer), [true, true]);
    Ok(())
}

/// A peer that disabled it neither offers nor answers with it, and nothing is negotiated.
#[test]
fn disabled_policy_does_not_offer_or_answer_cryptex() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Disable)?;
    let offer = offerer.create_offer(None)?;
    assert!(!session_level_cryptex(&offer.sdp));
    assert_eq!(media_level_cryptex(&offer.sdp), 0);

    // A default answerer, offered no Cryptex, answers without it.
    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert!(!session_level_cryptex(&answer.sdp));
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    assert_eq!(negotiated(&mut offerer), [false, false]);
    assert_eq!(negotiated(&mut answerer), [false, false]);
    Ok(())
}

/// An answerer that disabled it does not echo an offer's `a=cryptex`.
#[test]
fn disabled_answerer_declines_an_offer_with_cryptex() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let offer = offerer.create_offer(None)?;
    assert!(session_level_cryptex(&offer.sdp));
    offerer.set_local_description(Instant::now(), offer.clone())?;

    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Disable)?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert!(!session_level_cryptex(&answer.sdp) && media_level_cryptex(&answer.sdp) == 0);
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    assert_eq!(negotiated(&mut offerer), [false, false]);
    assert_eq!(negotiated(&mut answerer), [false, false]);
    Ok(())
}

/// An offer with the attribute on its media sections gets an answer with it on its media sections
/// (pion `TestCryptexAttributeInAnswerForMediaLevelCryptex`).
#[test]
fn answer_mirrors_the_attribute_level_of_the_offer() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let offer = offerer.create_offer(None)?;

    // Move `a=cryptex` from the session to every media section.
    let mut sdp = String::new();
    for l in lines(&offer.sdp) {
        if l == "a=cryptex" && !sdp.contains("\r\nm=") {
            continue;
        }
        sdp.push_str(l);
        sdp.push_str("\r\n");
        if l.starts_with("a=mid:") {
            sdp.push_str("a=cryptex\r\n");
        }
    }
    let moved = RTCSessionDescription::offer(sdp)?;
    assert!(!session_level_cryptex(&moved.sdp));
    assert_eq!(media_level_cryptex(&moved.sdp), 2);

    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    answerer.set_remote_description(Instant::now(), moved)?;
    let answer = answerer.create_answer(None)?;
    assert!(!session_level_cryptex(&answer.sdp), "{}", answer.sdp);
    assert_eq!(media_level_cryptex(&answer.sdp), 2, "{}", answer.sdp);
    Ok(())
}

/// Cryptex on only some of the RTP sections is refused (pion
/// `TestCryptexAnswerWithPartialMediaCryptexIsRejected`), and the refusal leaves the signaling
/// state alone (`TestCryptexRejectedAnswerPreservesSignalingState`).
#[test]
fn partial_media_level_cryptex_is_rejected_without_changing_state() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let offer = offerer.create_offer(None)?;

    // Keep `a=cryptex` on the first media section only. Without a BUNDLE group, so that the
    // first section's attribute does not stand for the others (RFC 9143 §7.1.3).
    let mut sdp = String::new();
    let mut seen_media_mid = 0;
    for l in lines(&offer.sdp) {
        if l == "a=cryptex" || l.starts_with("a=group:BUNDLE") {
            continue;
        }
        sdp.push_str(l);
        sdp.push_str("\r\n");
        if l.starts_with("a=mid:") {
            seen_media_mid += 1;
            if seen_media_mid == 1 {
                sdp.push_str("a=cryptex\r\n");
            }
        }
    }
    let partial = RTCSessionDescription::offer(sdp)?;

    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let err = answerer
        .set_remote_description(Instant::now(), partial)
        .unwrap_err();
    assert_eq!(
        err,
        shared::error::Error::ErrRtpHeaderEncryptionMixedModeNotSupported
    );
    assert_eq!(answerer.signaling_state(), RTCSignalingState::Stable);
    assert!(answerer.remote_description().is_none());
    Ok(())
}

/// `Require` rejects an offer that does not negotiate it for every RTP section, and accepts one
/// that does (pion `TestCryptexRequired*`).
#[test]
fn require_policy_rejects_a_peer_without_cryptex() -> TestResult {
    let mut plain = av_offerer(RTCRtpHeaderEncryptionPolicy::Disable)?;
    let offer = plain.create_offer(None)?;

    let mut strict = peer(RTCRtpHeaderEncryptionPolicy::Require)?;
    let err = strict
        .set_remote_description(Instant::now(), offer)
        .unwrap_err();
    assert_eq!(err, shared::error::Error::ErrRtpHeaderEncryptionRequired);
    assert_eq!(strict.signaling_state(), RTCSignalingState::Stable);

    let mut capable = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let offer = capable.create_offer(None)?;
    strict.set_remote_description(Instant::now(), offer)?;
    let answer = strict.create_answer(None)?;
    assert!(session_level_cryptex(&answer.sdp));
    Ok(())
}

/// A session with only a data channel has no RTP to protect, so `Require` does not reject it
/// (pion `TestCryptexRequiredDoesNotFailForDataOnlyOffer`) and no `a=cryptex` is written.
#[test]
fn data_only_sessions_are_not_subject_to_the_requirement() -> TestResult {
    let mut offerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    offerer.create_data_channel("data", None)?;
    let offer = offerer.create_offer(None)?;
    assert!(!session_level_cryptex(&offer.sdp), "{}", offer.sdp);

    let mut strict = peer(RTCRtpHeaderEncryptionPolicy::Require)?;
    strict.set_remote_description(Instant::now(), offer)?;
    let answer = strict.create_answer(None)?;
    assert!(!session_level_cryptex(&answer.sdp));
    Ok(())
}

/// After a first exchange that negotiated Cryptex, a renegotiated offer still carries it.
#[test]
fn renegotiation_keeps_offering_cryptex() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;

    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let second = offerer.create_offer(None)?;
    assert!(session_level_cryptex(&second.sdp), "{}", second.sdp);
    Ok(())
}

/// With BUNDLE, `a=cryptex` on the tag section stands for every section in the group
/// (RFC 9143 §7.1.3), so it is not "mixed".
#[test]
fn bundle_tag_cryptex_applies_to_the_whole_group() -> TestResult {
    let mut offerer = av_offerer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    let offer = offerer.create_offer(None)?;
    assert!(offer.sdp.contains("a=group:BUNDLE"));

    let mut sdp = String::new();
    let mut first = true;
    for l in lines(&offer.sdp) {
        if l == "a=cryptex" {
            continue;
        }
        sdp.push_str(l);
        sdp.push_str("\r\n");
        if l.starts_with("a=mid:") && first {
            first = false;
            sdp.push_str("a=cryptex\r\n");
        }
    }
    let tagged = RTCSessionDescription::offer(sdp)?;

    let mut answerer = peer(RTCRtpHeaderEncryptionPolicy::Negotiate)?;
    answerer.set_remote_description(Instant::now(), tagged)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer)?;
    assert_eq!(negotiated(&mut answerer), [true, true]);
    Ok(())
}
