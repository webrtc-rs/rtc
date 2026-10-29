//! pion/webrtc v4.2.24 `peerconnection_go_test.go`, the `TestCryptex*` tests that look at the
//! modes the DTLS transport ends up with. The black-box half of the family is in
//! `tests/cryptex_negotiation.rs`; these need the transport's send and receive modes, which are
//! crate-private.

use super::*;
use crate::peer_connection::configuration::RTCConfigurationBuilder;
use crate::peer_connection::configuration::RTCRtpHeaderEncryptionPolicy as Policy;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use ::srtp::context::cryptex::CryptexMode;

fn peer(policy: Policy) -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_rtp_header_encryption_policy(policy)
                .build(),
        )
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap()
}

fn add(pc: &mut RTCPeerConnection, kind: RtpCodecKind) {
    pc.add_transceiver_from_kind(kind, None).unwrap();
}

/// One full exchange, optionally rewriting the answer before the offerer sees it.
fn exchange(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
    rewrite_answer: impl FnOnce(String) -> String,
) -> Result<()> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    let sdp = rewrite_answer(answer.sdp.clone());
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(sdp)?)
}

fn modes(pc: &RTCPeerConnection) -> (CryptexMode, CryptexMode) {
    let dtls = pc.dtls_transport();
    (dtls.cryptex_send_mode, dtls.cryptex_receive_mode)
}

fn strip_session_cryptex(sdp: String) -> String {
    let mut in_media = false;
    sdp.split("\r\n")
        .filter(|line| {
            if line.starts_with("m=") {
                in_media = true;
            }
            in_media || *line != "a=cryptex"
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn has_session_cryptex(sdp: &str) -> bool {
    sdp.lines()
        .take_while(|l| !l.starts_with("m="))
        .any(|l| l == "a=cryptex")
}

fn has_media_cryptex(sdp: &str, media: &str) -> bool {
    let mut current = "";
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("m=") {
            current = rest.split(' ').next().unwrap_or("");
        } else if line == "a=cryptex" && current == media {
            return true;
        }
    }
    false
}

/// `TestCryptexRequiredDataOnlyOfferAcceptsNonCryptexAnswer`: Require only binds negotiated RTP
/// sections, and a data-only exchange has none, so a non-cryptex answer is fine and cryptex stays
/// off in both directions.
#[test]
fn require_with_data_only_accepts_a_non_cryptex_answer() {
    let mut offerer = peer(Policy::Require);
    let mut answerer = peer(Policy::Disable);
    offerer.create_data_channel("data", None).unwrap();
    let offer = offerer.create_offer(None).unwrap();
    assert!(!offer.sdp.contains("m=audio") && !offer.sdp.contains("m=video"));
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
    assert!(!has_session_cryptex(&answer.sdp));
    assert!(!has_media_cryptex(&answer.sdp, "application"));
    offerer
        .set_remote_description(Instant::now(), answer)
        .unwrap();
    assert_eq!(
        modes(&offerer),
        (CryptexMode::Disabled, CryptexMode::Disabled)
    );
}

/// `TestCryptexIsStillOfferedDuringRenegotiationIfNotNegotiatedInitially`
#[test]
fn cryptex_is_still_offered_when_the_first_exchange_did_not_negotiate_it() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Disable);
    add(&mut offerer, RtpCodecKind::Video);
    add(&mut offerer, RtpCodecKind::Audio);
    offerer
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();

    let offer2 = offerer.create_offer(None).unwrap();
    assert!(has_session_cryptex(&offer2.sdp), "session-level a=cryptex");
    for media in ["video", "audio", "application"] {
        assert!(!has_media_cryptex(&offer2.sdp, media), "{media}");
    }
}

/// `TestCryptexModeChangeDuringRenegotiation`: a peer that did not negotiate cryptex at first
/// then offers it at the media level; the mode is applied to the running session.
#[test]
fn a_later_offer_with_media_level_cryptex_enables_it() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Disable);
    add(&mut offerer, RtpCodecKind::Video);
    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    assert_eq!(
        modes(&offerer).0,
        CryptexMode::Disabled,
        "nothing is sent encrypted yet"
    );

    // The former answerer offers back, with a=cryptex injected into each live RTP section.
    let offer2 = answerer.create_offer(None).unwrap();
    answerer
        .set_local_description(Instant::now(), offer2.clone())
        .unwrap();
    let mut out = vec![];
    let mut current_port_zero = false;
    let mut current_app = false;
    for line in offer2.sdp.split("\r\n") {
        if let Some(rest) = line.strip_prefix("m=") {
            let mut f = rest.split(' ');
            current_app = f.next() == Some("application");
            current_port_zero = f.next() == Some("0");
        }
        out.push(line.to_owned());
        if line.starts_with("a=mid:") && !current_app && !current_port_zero {
            out.push("a=cryptex".to_owned());
        }
    }
    let rewritten = RTCSessionDescription::offer(out.join("\r\n")).unwrap();
    offerer
        .set_remote_description(Instant::now(), rewritten)
        .unwrap();
    assert_eq!(modes(&offerer).1, CryptexMode::Enabled);
}

/// `TestCryptexDataOnlyThenAddRTPRenegotiation`: a data-only first exchange does not block the
/// renegotiation that adds the first RTP media.
#[test]
fn data_only_then_adding_rtp_renegotiates() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Disable);
    offerer.create_data_channel("data", None).unwrap();
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();

    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| sdp)
        .expect("adding the first RTP media must not break renegotiation");
    assert_eq!(modes(&offerer).0, CryptexMode::Disabled);
}

/// `TestCryptexAsymmetricOfferAnswerPreservesOwnReceiveCapability`: our offer declared cryptex
/// receive support; an answer without it stops us sending it but not receiving it (RFC 9335 §4).
#[test]
fn an_answer_without_cryptex_only_stops_our_sending() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Disable);
    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| {
        assert!(
            !has_session_cryptex(&sdp),
            "the Disable answerer omits cryptex"
        );
        sdp
    })
    .unwrap();
    assert_eq!(
        modes(&offerer),
        (CryptexMode::Disabled, CryptexMode::Enabled),
        "send follows the answer, receive follows our own offer"
    );
}

/// `TestCryptexIndependentLocalRemoteModeUpdateDuringRenegotiation`: a renegotiation whose answer
/// drops cryptex changes only the send direction.
#[test]
fn a_renegotiation_changes_only_the_direction_that_changed() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    assert_eq!(
        modes(&offerer),
        (CryptexMode::Enabled, CryptexMode::Enabled)
    );

    exchange(&mut offerer, &mut answerer, strip_session_cryptex).unwrap();
    assert_eq!(
        modes(&offerer),
        (CryptexMode::Disabled, CryptexMode::Enabled),
        "outbound follows the answer; inbound is kept because our offer still declares support"
    );
}

/// `TestCryptexNegotiatedIsPerTransceiverNotTransport`
#[test]
fn negotiated_is_per_transceiver() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    let audio = offerer.get_transceivers().next().unwrap();
    assert!(
        offerer
            .rtp_transceiver(audio)
            .unwrap()
            .rtp_header_encryption_negotiated()
    );

    add(&mut offerer, RtpCodecKind::Video);
    let video = offerer.get_transceivers().nth(1).unwrap();
    assert!(
        !offerer
            .rtp_transceiver(video)
            .unwrap()
            .rtp_header_encryption_negotiated(),
        "a transceiver that has not been through an exchange reports false"
    );
    assert!(
        offerer
            .rtp_transceiver(audio)
            .unwrap()
            .rtp_header_encryption_negotiated()
    );
}

/// `TestCryptexBundleOnlyZeroPortRTPOfferRequiresPeerCapability`
#[test]
fn a_bundle_only_audio_section_counts_as_active_rtp() {
    fn offer_text() -> String {
        let mut pc = peer(Policy::Disable);
        pc.create_data_channel("data", None).unwrap();
        add(&mut pc, RtpCodecKind::Audio);
        let offer = pc.create_offer(None).unwrap();
        // Make the audio section zero-port and bundle-only instead of dropping it.
        let mut out = vec![];
        let mut audio = false;
        for line in offer.sdp.split("\r\n") {
            if let Some(rest) = line.strip_prefix("m=") {
                audio = rest.starts_with("audio");
                if audio {
                    let mut f: Vec<&str> = line.split(' ').collect();
                    f[1] = "0";
                    out.push(f.join(" "));
                    out.push("a=bundle-only".to_owned());
                    continue;
                }
            }
            out.push(line.to_owned());
        }
        let _ = audio;
        out.join("\r\n")
    }

    // Require rejects: the bundle-only section is RTP media and nothing declared cryptex.
    let mut require = peer(Policy::Require);
    let err = require
        .set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(offer_text()).unwrap(),
        )
        .unwrap_err();
    assert!(
        matches!(err, Error::ErrRtpHeaderEncryptionRequired),
        "{err}"
    );

    // Negotiate accepts, and does not treat the section as cryptex-capable.
    let mut negotiate = peer(Policy::Negotiate);
    negotiate
        .set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(offer_text()).unwrap(),
        )
        .unwrap();
    let answer = negotiate.create_answer(None).unwrap();
    assert!(!has_media_cryptex(&answer.sdp, "audio"), "{}", answer.sdp);
}

/// Gives the offer to `answerer` (after `edit`), applies the offerer's local description and
/// returns the answerer's answer, leaving the answer unapplied on the offerer.
fn offer_and_answer(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
    edit_offer: impl FnOnce(String) -> String,
) -> Result<RTCSessionDescription> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    let delivered = RTCSessionDescription::offer(edit_offer(offer.sdp.clone()))?;
    answerer.set_remote_description(Instant::now(), delivered)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer)
}

fn first_bundle_mid(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=group:BUNDLE "))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("a BUNDLE group")
        .to_owned()
}

/// Moves cryptex from the session level to the media section whose mid is `mid` only.
fn cryptex_on_media_section_only(sdp: &str, mid: &str) -> String {
    let mut sections: Vec<Vec<String>> = vec![vec![]];
    for line in sdp.split("\r\n").filter(|l| !l.is_empty()) {
        if line.starts_with("m=") {
            sections.push(vec![]);
        }
        sections.last_mut().unwrap().push(line.to_owned());
    }
    sections[0].retain(|l| l != "a=cryptex");
    for section in sections.iter_mut().skip(1) {
        if section.iter().any(|l| l == &format!("a=mid:{mid}")) {
            section.push("a=cryptex".to_owned());
        }
    }
    let mut out = sections
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\r\n");
    out.push_str("\r\n");
    out
}

/// `TestCryptexAnswerWithTagOnlyCryptexIsAccepted`: cryptex declared only on the BUNDLE tag
/// section is inherited by the other bundled sections (RFC 9143 section 7.1.3), not rejected as
/// mixed mode.
#[test]
fn an_answer_with_cryptex_only_on_the_bundle_tag_is_accepted() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    add(&mut offerer, RtpCodecKind::Video);
    exchange(&mut offerer, &mut answerer, |sdp| {
        let tag = first_bundle_mid(&sdp);
        cryptex_on_media_section_only(&sdp, &tag)
    })
    .unwrap();
    assert_eq!(modes(&offerer).0, CryptexMode::Enabled);
}

/// `TestRTPHeaderEncryptionNegotiatedInheritsFromBundleTag`: a section that only inherits cryptex
/// from the BUNDLE tag section still counts as negotiated on its transceiver.
#[test]
fn a_section_inheriting_cryptex_from_the_bundle_tag_is_negotiated() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    add(&mut offerer, RtpCodecKind::Video);
    exchange(&mut offerer, &mut answerer, |sdp| {
        let tag = first_bundle_mid(&sdp);
        cryptex_on_media_section_only(&sdp, &tag)
    })
    .unwrap();
    let ids: Vec<_> = offerer.get_transceivers().collect();
    assert_eq!(ids.len(), 2);
    for id in ids {
        assert!(
            offerer
                .rtp_transceiver(id)
                .unwrap()
                .rtp_header_encryption_negotiated(),
            "both transceivers, the tag section's and the inheriting one"
        );
    }
}

/// `TestCryptexReceiveModeUpdatedOnNewLocalAnswer`: when a renegotiation offer newly carries
/// cryptex and our regenerated answer mirrors it, applying that answer updates the receive mode.
#[test]
fn applying_a_new_local_answer_updates_the_receive_mode() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);

    // The first offer reaches the answerer with cryptex stripped (JSEP section 5.4 lets
    // signaling filter capabilities), so the first answer omits it too.
    let answer = offer_and_answer(&mut offerer, &mut answerer, strip_session_cryptex).unwrap();
    assert!(!has_session_cryptex(&answer.sdp));
    offerer
        .set_remote_description(Instant::now(), answer)
        .unwrap();
    assert_eq!(modes(&answerer).1, CryptexMode::Disabled);

    // The renegotiation offer arrives intact and the answer mirrors it.
    let answer2 = offer_and_answer(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    assert!(has_session_cryptex(&answer2.sdp), "{}", answer2.sdp);
    assert_eq!(
        modes(&answerer).1,
        CryptexMode::Enabled,
        "applying the new local answer must update the receive mode"
    );
    offerer
        .set_remote_description(Instant::now(), answer2)
        .unwrap();
}

/// `TestCryptexPreservedWhenDescriptionRejected`: a description refused for an invalid signaling
/// transition leaves the active modes alone.
#[test]
fn a_rejected_description_leaves_the_modes_alone() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    let answer = offer_and_answer(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    offerer
        .set_remote_description(Instant::now(), answer.clone())
        .unwrap();
    let before = modes(&offerer);
    assert_eq!(before, (CryptexMode::Enabled, CryptexMode::Enabled));
    assert_eq!(offerer.signaling_state(), RTCSignalingState::Stable);

    // Stable already: another answer, even one with cryptex removed, is an invalid transition.
    let stripped = RTCSessionDescription::answer(strip_session_cryptex(answer.sdp)).unwrap();
    assert!(
        offerer
            .set_remote_description(Instant::now(), stripped)
            .is_err()
    );
    assert_eq!(modes(&offerer), before);
}

/// `TestCryptexPreservedWhenLateStageRejectsRenegotiationOffer`: an offer that fails deep inside
/// `set_remote_description` (a media section without a mid) does not apply the cryptex change
/// it also carries.
#[test]
fn a_late_failure_does_not_apply_the_cryptex_change() {
    let mut offerer = peer(Policy::Negotiate);
    let mut answerer = peer(Policy::Negotiate);
    add(&mut offerer, RtpCodecKind::Audio);
    exchange(&mut offerer, &mut answerer, |sdp| sdp).unwrap();
    let before = modes(&answerer);
    assert_eq!(before, (CryptexMode::Enabled, CryptexMode::Enabled));

    let offer = offerer.create_offer(None).unwrap();
    let mut in_audio = false;
    let stripped = strip_session_cryptex(offer.sdp.clone());
    let broken: Vec<&str> = stripped
        .split("\r\n")
        .filter(|line| {
            if line.starts_with("m=") {
                in_audio = line.starts_with("m=audio");
            }
            !(in_audio && line.starts_with("a=mid:"))
        })
        .collect();
    let result = answerer.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(broken.join("\r\n")).unwrap(),
    );
    assert!(result.is_err(), "the broken offer is refused");
    assert_eq!(modes(&answerer), before);
}
