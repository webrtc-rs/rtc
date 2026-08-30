//! Regression test for webrtc-rs/rtc#212.
//!
//! `check_negotiation_needed` implements the W3C "check if negotiation is needed" steps. Its
//! step 5.3.1 compares the msid of each send-direction transceiver against the one in the
//! current local description. A transceiver can hold a send direction without holding a
//! sender — answering a `recvonly` offer creates one implicitly with direction `sendonly`,
//! and `remove_track` leaves one behind — and such a transceiver has no track, hence no msid
//! for that step to compare and nothing a renegotiation could settle.
//!
//! Reporting "negotiation needed" for it fires `OnNegotiationNeededEvent` every time the
//! connection returns to a stable signaling state. Since the follow-up negotiation cannot
//! change the condition, an application that honours the event by re-offering never stops.
//!
//! See <https://www.w3.org/TR/webrtc/#dfn-update-the-negotiation-needed-flag>.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use sansio::Protocol;
use std::time::Instant;

/// Drain every queued peer-connection event, returning how many were negotiation-needed.
fn count_negotiation_needed(pc: &mut rtc::peer_connection::RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// Run one full offer/answer exchange from `offerer` to `answerer`.
fn negotiate(
    offerer: &mut rtc::peer_connection::RTCPeerConnection,
    answerer: &mut rtc::peer_connection::RTCPeerConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;

    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(())
}

#[test]
fn test_recvonly_answer_without_track_settles() -> Result<(), Box<dyn std::error::Error>> {
    let mut me = MediaEngine::default();
    me.register_default_codecs()?;
    let me2 = me.clone();

    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me2)
        .build(Instant::now())?;

    // The offerer wants to receive only; the answerer never adds a track of its own.
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    negotiate(&mut offerer, &mut answerer)?;

    // The answerer's transceiver is the shape under test: send-capable, no sender.
    let transceiver_id = answerer
        .get_transceivers()
        .next()
        .expect("answering a recvonly offer creates a transceiver");
    let transceiver = answerer
        .rtp_transceiver(transceiver_id)
        .expect("transceiver should exist");
    assert_eq!(
        transceiver.direction(),
        RTCRtpTransceiverDirection::Sendonly,
        "answering a recvonly offer yields a sendonly transceiver",
    );
    assert!(
        transceiver.sender().is_none(),
        "no local track was added, so the transceiver has no sender",
    );

    // Drain whatever the initial exchange produced so the count starts clean.
    let _ = count_negotiation_needed(&mut offerer);
    let _ = count_negotiation_needed(&mut answerer);

    // Play out what an application does when it honours `negotiationneeded`: renegotiate.
    // Each round returns the connection to a stable signaling state, which re-runs the
    // negotiation-needed check. A settled connection must stop asking.
    for round in 1..=5 {
        negotiate(&mut answerer, &mut offerer)?;

        assert_eq!(
            count_negotiation_needed(&mut answerer),
            0,
            "answerer asked to renegotiate again in round {round}; \
             nothing about a senderless sendonly transceiver can be settled by re-offering",
        );
        assert_eq!(
            count_negotiation_needed(&mut offerer),
            0,
            "offerer asked to renegotiate again in round {round}",
        );
    }

    Ok(())
}
