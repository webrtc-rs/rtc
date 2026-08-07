//! Issue #837 end-to-end: the generated SDP must carry no ULPFEC rtpmap.
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use std::time::Instant;

#[test]
fn default_offer_sdp_contains_no_ulpfec() {
    let mut me = MediaEngine::default();
    me.register_default_codecs()
        .expect("register default codecs");

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(me)
        .build(Instant::now())
        .expect("build peer connection");
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )
    .expect("add video transceiver");

    let offer = pc.create_offer(None).expect("create offer");
    let lower = offer.sdp.to_lowercase();
    assert!(
        !lower.contains("ulpfec"),
        "issue #837: the default offer still advertises ULPFEC:\n{}",
        offer.sdp
    );
    // sanity: the offer really does carry video codecs, so the assertion above is meaningful
    assert!(
        lower.contains("vp8"),
        "expected a video offer, got:\n{}",
        offer.sdp
    );
}
