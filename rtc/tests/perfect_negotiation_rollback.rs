//! Integration tests for the Perfect Negotiation rollback flows (RFC 8829, Section 5.7 /
//! W3C WebRTC "perfect negotiation"), driving two real `RTCPeerConnection`s exchanging real SDP.
//!
//! Both tests verify the RFC's addTrack/rollback/createOffer guarantee:
//!
//!   "an application may call addTrack, then call setRemoteDescription with an offer, then roll
//!    back that offer, then call createOffer and have an "m=" section for the added track appear
//!    in the generated offer."
//!
//! There are two variants, one per rollback entry point. Note these are NOT interchangeable at
//! the same signaling state: the state machine only permits `SetLocal(rollback)` from
//! `have-local-offer` and `SetRemote(rollback)` from `have-remote-offer`. So the polite peer in
//! the classic glare position (it sent an offer and a remote offer collides) rolls back its own
//! offer via `set_local_description`, whereas rolling back an already-applied remote offer uses
//! `set_remote_description`.

use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;

fn media_pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    rtc::peer_connection::RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build()
        .unwrap()
}

fn track(kind: RtpCodecKind, id: &str, ssrc: u32) -> MediaStreamTrack {
    let (mime_type, clock_rate, channels) = match kind {
        RtpCodecKind::Audio => (MIME_TYPE_OPUS.to_owned(), 48000, 2),
        _ => (MIME_TYPE_VP8.to_owned(), 90000, 0),
    };
    MediaStreamTrack::new(
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

fn rollback() -> RTCSessionDescription {
    RTCSessionDescription::rollback(None).unwrap()
}

/// Drain queued events so their side effects settle.
fn drain_events(pc: &mut RTCPeerConnection) {
    while pc.poll_event().is_some() {}
}

fn count_media(sdp: &RTCSessionDescription, media: &str) -> usize {
    sdp.sdp.matches(&format!("m={media}")).count()
}

/// Polite-peer glare recovery via local-offer rollback — the classic perfect-negotiation flow.
///
/// The polite peer adds a video track and sends its own offer. The impolite peer concurrently
/// sends an audio offer (glare). The polite peer rolls back its own offer via
/// `set_local_description(rollback)`, applies the impolite offer, and answers it. Its own video
/// track was never negotiated, so it must resurface in a subsequent offer.
///
/// A different media kind is used for each peer so the polite peer's rolled-back transceiver
/// cannot merely be reused to satisfy the impolite offer's m= section — the added track must
/// appear as its own section in the follow-up offer.
#[test]
fn polite_peer_glare_recovery_with_local_offer_rollback() {
    // Polite peer: add video track, offer, enter have-local-offer.
    let mut polite = media_pc();
    polite
        .add_track(track(RtpCodecKind::Video, "polite", 11111))
        .unwrap();
    let polite_offer = polite.create_offer(None).unwrap();
    polite.set_local_description(polite_offer).unwrap();
    drain_events(&mut polite);

    // Impolite peer: add audio track, offer (glare).
    let mut impolite = media_pc();
    impolite
        .add_track(track(RtpCodecKind::Audio, "impolite", 22222))
        .unwrap();
    let impolite_offer = impolite.create_offer(None).unwrap();
    impolite
        .set_local_description(impolite_offer.clone())
        .unwrap();

    // Polite peer yields: roll back its own offer, then accept the impolite peer's offer.
    polite.set_local_description(rollback()).unwrap();
    drain_events(&mut polite);

    // RFC 8829 Section 5.7: rollback sets the pending local description to null.
    assert!(
        polite.pending_local_description().is_none(),
        "rollback must clear the pending local description"
    );

    polite.set_remote_description(impolite_offer).unwrap();
    let answer = polite.create_answer(None).unwrap();

    // The answer covers only the impolite peer's single audio m= section. The rolled-back video
    // track must not appear in it.
    assert_eq!(
        count_media(&answer, "audio"),
        1,
        "answer must contain exactly the remote offer's single audio section"
    );
    assert_eq!(
        count_media(&answer, "video"),
        0,
        "the rolled-back video track must not appear in the answer"
    );

    polite.set_local_description(answer).unwrap();
    drain_events(&mut polite);

    // The polite peer's added track survived the rollback (a track was attached via add_track)
    // and was disassociated, so a follow-up offer must re-include an m= section for it.
    let followup = polite.create_offer(None).unwrap();
    assert_eq!(
        count_media(&followup, "audio"),
        1,
        "follow-up offer must retain the negotiated audio section: {}",
        followup.sdp
    );
    assert_eq!(
        count_media(&followup, "video"),
        1,
        "follow-up offer must renegotiate the rolled-back local video track: {}",
        followup.sdp
    );
}

/// Rollback of an already-applied remote offer via `set_remote_description(rollback)`.
///
/// The peer has its own pending video track (added via add_track). It applies a remote audio
/// offer (entering have-remote-offer, which implicitly creates a remote-originated audio
/// transceiver), then rolls that offer back via `set_remote_description(rollback)`. Per RFC 8829
/// Section 5.7 the remote-created transceiver must be removed while the app's own add_track
/// transceiver survives — and a subsequent createOffer must still include the added track.
#[test]
fn glare_recovery_with_remote_offer_rollback() {
    // The peer under test has its own pending video track.
    let mut pc = media_pc();
    pc.add_track(track(RtpCodecKind::Video, "local", 33333))
        .unwrap();

    // A remote peer offers audio.
    let mut remote = media_pc();
    remote
        .add_track(track(RtpCodecKind::Audio, "remote", 44444))
        .unwrap();
    let remote_offer = remote.create_offer(None).unwrap();

    // Apply the remote offer (creates a remote-originated audio transceiver), then roll it back.
    pc.set_remote_description(remote_offer).unwrap();
    drain_events(&mut pc);

    pc.set_remote_description(rollback()).unwrap();
    drain_events(&mut pc);

    // RFC 8829 Section 5.7: rollback sets the pending remote description to null.
    assert!(
        pc.pending_remote_description().is_none(),
        "rollback must clear the pending remote description"
    );

    // The remote-created audio transceiver must be gone; the app's own video track must survive
    // and appear in a fresh offer. The remote audio section must NOT appear (it was removed).
    let followup = pc.create_offer(None).unwrap();
    assert_eq!(
        count_media(&followup, "video"),
        1,
        "offer after remote-offer rollback must include the app's own added video track: {}",
        followup.sdp
    );
    assert_eq!(
        count_media(&followup, "audio"),
        0,
        "the transceiver created by the rolled-back remote offer must be removed: {}",
        followup.sdp
    );
}
