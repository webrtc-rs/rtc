/// Integration test: verify that changing a transceiver's direction triggers
/// an `OnNegotiationNeededEvent`, and that setting the same direction does not.
///
/// Per W3C WebRTC §5.5, mutating the direction property MUST update the
/// negotiation-needed flag, causing the peer connection to fire the event.
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceServer,
};
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodec;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::sansio::Protocol;

fn drain_events(pc: &mut rtc::peer_connection::RTCPeerConnection) -> Vec<RTCPeerConnectionEvent> {
    let mut events = vec![];
    while let Some(e) = pc.poll_event() {
        events.push(e);
    }
    events
}

fn has_negotiation_needed(events: &[RTCPeerConnectionEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent))
}

fn make_media_engine() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
            ..Default::default()
        },
        RtpCodecKind::Audio,
    )
    .unwrap();
    me
}

/// Bind a UDP socket to `127.0.0.1:0` and return the OS-assigned port.
fn ephemeral_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn build_pc(dtls_role: RTCDtlsRole, port: u16) -> rtc::peer_connection::RTCPeerConnection {
    let mut se = SettingEngine::default();
    se.set_answering_dtls_role(dtls_role).unwrap();

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(make_media_engine())
        .with_setting_engine(se)
        .build()
        .unwrap();

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap();
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json().unwrap())
        .unwrap();

    pc
}

#[test]
fn test_set_direction_change_triggers_renegotiation() {
    let mut offer_pc = build_pc(RTCDtlsRole::Server, ephemeral_port());
    let mut answer_pc = build_pc(RTCDtlsRole::Client, ephemeral_port());

    // Add a recvonly audio transceiver on the offer side.
    let tid = offer_pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)
        .unwrap();

    // Complete an initial offer/answer cycle to clear is_negotiation_ongoing.
    let offer = offer_pc.create_offer(None).unwrap();
    offer_pc.set_local_description(offer.clone()).unwrap();
    answer_pc.set_remote_description(offer).unwrap();
    let answer = answer_pc.create_answer(None).unwrap();
    answer_pc.set_local_description(answer.clone()).unwrap();
    offer_pc.set_remote_description(answer).unwrap();

    // Drain all events from the initial negotiation.
    drain_events(&mut offer_pc);

    // --- Test 1: changing direction triggers OnNegotiationNeededEvent ---
    {
        let mut t = offer_pc.rtp_transceiver(tid).unwrap();
        assert_eq!(
            t.direction(),
            RTCRtpTransceiverDirection::Recvonly,
            "precondition: direction should be Recvonly"
        );
        t.set_direction(RTCRtpTransceiverDirection::Inactive);
    }

    let events = drain_events(&mut offer_pc);
    assert!(
        has_negotiation_needed(&events),
        "changing direction from Recvonly to Inactive should trigger OnNegotiationNeededEvent, \
         but got: {:?}",
        events
    );

    // --- Test 2: setting the same direction is a no-op ---
    drain_events(&mut offer_pc);
    {
        let mut t = offer_pc.rtp_transceiver(tid).unwrap();
        t.set_direction(RTCRtpTransceiverDirection::Inactive);
    }
    let events = drain_events(&mut offer_pc);
    assert!(
        !has_negotiation_needed(&events),
        "setting the same direction (Inactive -> Inactive) should NOT trigger \
         OnNegotiationNeededEvent, but got: {:?}",
        events
    );
}
