//! Regression test for webrtc-rs/rtc#51.
//!
//! Calling `RTCRtpTransceiver::set_direction` must update the negotiation-needed
//! flag for the connection, which (when negotiation is otherwise idle) fires an
//! `OnNegotiationNeededEvent`. Per the WebRTC specification the direction setter
//! only takes effect when the new direction differs from the current one:
//!
//! > 3. If newDirection is equal to transceiver.[[Direction]], abort these steps.
//! > ...
//! > 6. Update the negotiation-needed flag for connection.
//!
//! See <https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction>.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use sansio::Protocol;

/// Drain every currently queued peer-connection event and return how many of
/// them were `OnNegotiationNeededEvent`.
fn count_negotiation_needed<I: rtc::interceptor::Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

#[test]
fn test_set_direction_updates_negotiation_needed_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut me = MediaEngine::default();
    me.register_default_codecs()?;
    let me2 = me.clone();

    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build()?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me2)
        .build()?;

    // Add one video transceiver on each side (defaults to "recvonly").
    let transceiver_id = offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    answerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    // Complete a full offer/answer exchange so the offerer settles back into a
    // stable, idle negotiation state.
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer)?;

    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer)?;

    // Drain everything produced by the initial negotiation so the counter starts clean.
    let _ = count_negotiation_needed(&mut offerer);

    // Sanity: with negotiation idle, poll produces no further negotiation-needed events.
    assert_eq!(
        count_negotiation_needed(&mut offerer),
        0,
        "connection should be idle after a clean negotiation",
    );

    // Pick a direction that actually differs from the current one.
    let current_direction = offerer
        .rtp_transceiver(transceiver_id)
        .expect("transceiver should exist")
        .direction();
    let new_direction = if current_direction == RTCRtpTransceiverDirection::Inactive {
        RTCRtpTransceiverDirection::Sendrecv
    } else {
        RTCRtpTransceiverDirection::Inactive
    };

    // Changing the direction must update the negotiation-needed flag (spec step 6),
    // firing exactly one negotiation-needed event.
    offerer
        .rtp_transceiver(transceiver_id)
        .expect("transceiver should exist")
        .set_direction(new_direction);

    assert_eq!(
        count_negotiation_needed(&mut offerer),
        1,
        "changing the transceiver direction must trigger negotiation-needed",
    );

    // Setting the same direction again is a no-op (spec step 3) and must not
    // trigger negotiation.
    offerer
        .rtp_transceiver(transceiver_id)
        .expect("transceiver should exist")
        .set_direction(new_direction);

    assert_eq!(
        count_negotiation_needed(&mut offerer),
        0,
        "setting the same direction must not trigger negotiation-needed",
    );

    offerer.close()?;
    answerer.close()?;
    Ok(())
}
