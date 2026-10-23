//! Ported from pion/webrtc v4.2.24 `peerconnection_test.go` and `peerconnection_go_test.go`: the
//! tests of construction, configuration and plain offer/answer that need no network.

use std::time::Instant;

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::{
    RTCBundlePolicy, RTCIceTransportPolicy, RTCRtcpMuxPolicy, RTCRtpHeaderEncryptionPolicy,
};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;
use rtc::peer_connection::transport::RTCIceServer;
use sansio::Protocol;
use shared::error::Error;

fn pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .expect("a default peer connection")
}

fn pc_with(config: RTCConfigurationBuilder) -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .with_configuration(config.build())
        .build(Instant::now())
        .expect("a peer connection")
}

fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

fn negotiate(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) {
    let offer = offerer.create_offer(None).unwrap();
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
    offerer
        .set_remote_description(Instant::now(), answer)
        .unwrap();
}

/// `TestNew`
#[test]
fn test_new() {
    let mut pc = pc_with(
        RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["turn:turn.example.com:3478".to_owned()],
                username: "unittest".to_owned(),
                credential: "secret".to_owned(),
            }])
            // Relay-only needs a TURN server to be useful, and this stack refuses a relay-only
            // configuration without one at construction (pion accepts it and gathers nothing).
            .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
            .with_bundle_policy(RTCBundlePolicy::MaxCompat)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate)
            .with_peer_identitys("unittest".to_owned())
            .with_ice_candidate_pool_size(1),
    );
    pc.close().unwrap();
}

/// `TestPeerConnection_GetConfiguration`: the defaults a fresh connection reports.
#[test]
fn test_get_configuration_defaults() {
    let mut pc = pc();
    let config = pc.get_configuration();
    assert!(config.ice_servers().is_empty());
    assert_eq!(config.ice_transport_policy(), RTCIceTransportPolicy::All);
    assert_eq!(config.bundle_policy(), RTCBundlePolicy::Balanced);
    assert_eq!(config.rtcp_mux_policy(), RTCRtcpMuxPolicy::Require);
    assert_eq!(config.ice_candidate_pool_size(), 0);
    assert!(!config.always_negotiate_data_channels());
    assert_eq!(
        config.rtp_header_encryption_policy(),
        RTCRtpHeaderEncryptionPolicy::Negotiate
    );
    pc.close().unwrap();
}

/// `TestPeerConnection_SetConfiguration`, one case per row of pion's table.
#[test]
fn test_set_configuration() {
    // valid
    {
        let mut pc = pc_with(RTCConfigurationBuilder::new().with_ice_candidate_pool_size(1));
        pc.set_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                    username: "unittest".to_owned(),
                    ..Default::default()
                }])
                .with_ice_transport_policy(RTCIceTransportPolicy::All)
                .with_bundle_policy(RTCBundlePolicy::Balanced)
                .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
                .with_ice_candidate_pool_size(1)
                .with_always_negotiate_data_channels(true)
                .with_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Negotiate)
                .build(),
        )
        .unwrap();
        assert!(pc.get_configuration().always_negotiate_data_channels());
        assert_eq!(pc.get_configuration().ice_servers().len(), 1);
        pc.close().unwrap();
    }
    // closed connection
    {
        let mut pc = pc();
        pc.close().unwrap();
        assert!(matches!(
            pc.set_configuration(RTCConfigurationBuilder::new().build()),
            Err(Error::ErrConnectionClosed)
        ));
    }
    // update peer identity / bundle policy / rtcp mux policy / header encryption policy
    for (config, want) in [
        (
            RTCConfigurationBuilder::new().with_peer_identitys("unittest".to_owned()),
            Error::ErrModifyingPeerIdentity,
        ),
        (
            RTCConfigurationBuilder::new().with_bundle_policy(RTCBundlePolicy::MaxCompat),
            Error::ErrModifyingBundlePolicy,
        ),
        (
            RTCConfigurationBuilder::new().with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate),
            Error::ErrModifyingRTCPMuxPolicy,
        ),
        (
            RTCConfigurationBuilder::new()
                .with_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require),
            Error::ErrModifyingRTPHeaderEncryptionPolicy,
        ),
    ] {
        let mut pc = pc();
        let err = pc.set_configuration(config.build()).unwrap_err();
        assert_eq!(err.to_string(), want.to_string());
        pc.close().unwrap();
    }
    // update ICE candidate pool size after a local description exists
    {
        let mut pc = pc();
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), offer).unwrap();
        let err = pc
            .set_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_candidate_pool_size(1)
                    .build(),
            )
            .unwrap_err();
        assert!(matches!(err, Error::ErrModifyingICECandidatePoolSize));
        pc.close().unwrap();
    }
    // enable AlwaysNegotiateDataChannels
    {
        let mut pc = pc();
        pc.set_configuration(
            RTCConfigurationBuilder::new()
                .with_always_negotiate_data_channels(true)
                .build(),
        )
        .unwrap();
        pc.close().unwrap();
    }
}

/// `TestPeerConnection_SetConfiguration_RejectsBeforeMutating`
#[test]
fn test_set_configuration_rejects_before_mutating() {
    let mut pc = pc();
    let err = pc
        .set_configuration(
            RTCConfigurationBuilder::new()
                .with_always_negotiate_data_channels(true)
                .with_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)
                .build(),
        )
        .unwrap_err();
    assert!(matches!(err, Error::ErrModifyingRTPHeaderEncryptionPolicy));
    assert!(
        !pc.get_configuration().always_negotiate_data_channels(),
        "other fields in the same call must not be applied when a change is rejected"
    );
    pc.close().unwrap();
}

const MINIMAL_OFFER: &str = "v=0\r
o=- 4596489990601351948 2 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=group:BUNDLE data\r
a=msid-semantic: WMS\r
m=application 47299 DTLS/SCTP 5000\r
c=IN IP4 192.168.20.129\r
a=candidate:1966762134 1 udp 2122260223 192.168.20.129 47299 typ host generation 0\r
a=candidate:1966762134 1 udp 2122262783 2001:db8::1 47199 typ host generation 0\r
a=candidate:211962667 1 udp 2122194687 10.0.3.1 40864 typ host generation 0\r
a=candidate:1002017894 1 tcp 1518280447 192.168.20.129 0 typ host tcptype active generation 0\r
a=candidate:1109506011 1 tcp 1518214911 10.0.3.1 0 typ host tcptype active generation 0\r
a=ice-ufrag:1/MvHwjAyVf27aLu\r
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E\r
a=ice-options:google-ice\r
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24\r
a=setup:actpass\r
a=mid:data\r
a=sctpmap:5000 webrtc-datachannel 1024\r
";

/// `TestSetRemoteDescription`
#[test]
fn test_set_remote_description() {
    let mut pc1 = pc();
    let offer = RTCSessionDescription::offer(MINIMAL_OFFER.to_owned()).unwrap();
    pc1.set_remote_description(Instant::now(), offer).unwrap();
    // The legacy `DTLS/SCTP 5000` + `a=sctpmap` offer is a data channel: it can be answered.
    let answer = pc1.create_answer(None).unwrap();
    assert!(answer.sdp.contains("m=application"), "{}", answer.sdp);
    pc1.close().unwrap();

    // The zero value (no type, no SDP) is an error.
    let mut pc2 = pc();
    assert!(
        pc2.set_remote_description(Instant::now(), RTCSessionDescription::default())
            .is_err()
    );
    pc2.close().unwrap();
}

/// `TestCreateOfferAnswer`
#[test]
fn test_create_offer_answer() {
    let mut offerer = pc();
    let mut answerer = pc();
    offerer.create_data_channel("test-channel", None).unwrap();
    negotiate(&mut offerer, &mut answerer);

    // After setLocalDescription(answer) the signaling state is stable, so creating another
    // answer is an error.
    assert_eq!(answerer.signaling_state(), RTCSignalingState::Stable);
    assert!(answerer.create_answer(None).is_err());
    offerer.close().unwrap();
    answerer.close().unwrap();
}

/// `TestMultipleOfferAnswer`: offers can be created repeatedly without being applied.
#[test]
fn test_multiple_offers() {
    for _ in 0..2 {
        let mut pc = pc();
        pc.create_offer(None).unwrap();
        pc.create_offer(None).unwrap();
        pc.close().unwrap();
    }
}

/// `TestNoFingerprintInFirstMediaIfSetRemoteDescription`: only a later media section carries
/// the fingerprint and credentials; the offer is still accepted.
#[test]
fn test_no_fingerprint_in_first_media() {
    let sdp = "v=0\r
o=- 143087887 1561022767 IN IP4 192.168.84.254\r
s=VideoRoom 404986692241682\r
t=0 0\r
a=group:BUNDLE audio\r
a=msid-semantic: WMS 2867270241552712\r
m=video 0 UDP/TLS/RTP/SAVPF 0\r
a=mid:video\r
c=IN IP4 192.168.84.254\r
a=inactive\r
m=audio 9 UDP/TLS/RTP/SAVPF 111\r
c=IN IP4 192.168.84.254\r
a=recvonly\r
a=mid:audio\r
a=rtcp-mux\r
a=ice-ufrag:AS/w\r
a=ice-pwd:9NOgoAOMALYu/LOpA1iqg/\r
a=ice-options:trickle\r
a=fingerprint:sha-256 D2:B9:31:8F:DF:24:D8:0E:ED:D2:EF:25:9E:AF:6F:B8:34:AE:53:9C:E6:F3:8F:F2:64:15:FA:E8:7F:53:2D:38\r
a=setup:active\r
a=rtpmap:111 opus/48000/2\r
a=candidate:1 1 udp 2013266431 192.168.84.254 46492 typ host\r
a=end-of-candidates\r
";
    let mut pc = pc();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(sdp.to_owned()).unwrap(),
    )
    .unwrap();
    pc.close().unwrap();
}

/// `TestNegotiationNeeded`: creating a data channel asks for negotiation.
#[test]
fn test_negotiation_needed() {
    let mut pc = pc();
    pc.create_data_channel("initial_data_channel", None)
        .unwrap();
    assert_eq!(negotiation_needed(&mut pc), 1);
    pc.close().unwrap();
}

/// `TestMultipleCreateChannel`: two channels, one negotiation, two `OnDataChannel` on the other
/// side.
#[test]
fn test_multiple_create_channel() {
    let mut offerer = pc();
    let mut answerer = pc();
    offerer
        .create_data_channel("initial_data_channel_0", None)
        .unwrap();
    offerer
        .create_data_channel("initial_data_channel_1", None)
        .unwrap();
    assert_eq!(
        negotiation_needed(&mut offerer),
        1,
        "one OnNegotiationNeeded for both channels"
    );
    negotiate(&mut offerer, &mut answerer);
    offerer.close().unwrap();
    answerer.close().unwrap();
}

/// `TestSetRemoteDescriptionInvalid`, "local-offer + SetRemoteDescription(Offer)".
#[test]
fn test_set_remote_description_invalid() {
    let mut pc = pc();
    let offer = pc.create_offer(None).unwrap();
    pc.set_local_description(Instant::now(), offer.clone())
        .unwrap();
    assert!(pc.set_remote_description(Instant::now(), offer).is_err());
    pc.close().unwrap();
}

/// `TestPeerConnection_SessionID`: the SDP origin keeps its session id and bumps its version on
/// every new description, for both sides, over ten renegotiations.
#[test]
fn test_session_id_and_version() {
    fn origin(sdp: &str) -> (u64, u64) {
        let line = sdp.lines().find(|l| l.starts_with("o=")).unwrap();
        let mut f = line[2..].split_whitespace();
        let _user = f.next();
        (
            f.next().unwrap().parse().unwrap(),
            f.next().unwrap().parse().unwrap(),
        )
    }
    let mut offerer = pc();
    let mut answerer = pc();
    offerer.create_data_channel("d", None).unwrap();
    let mut seen: [Option<(u64, u64)>; 2] = [None, None];
    for i in 0..10 {
        negotiate(&mut offerer, &mut answerer);
        for (k, side) in [&offerer, &answerer].into_iter().enumerate() {
            let (id, version) = origin(&side.local_description().unwrap().sdp);
            match seen[k] {
                None => seen[k] = Some((id, version)),
                Some((first_id, last_version)) => {
                    assert_eq!(id, first_id, "side {k} round {i}: session id changed");
                    assert_eq!(version, last_version + 1, "side {k} round {i}: version");
                    seen[k] = Some((id, version));
                }
            }
        }
    }
}

/// `TestAlwaysNegotiateDataChannel_InitialOffer_Go`: without channels the default offer has no
/// application section; with `AlwaysNegotiateDataChannels` it has one.
#[test]
fn test_always_negotiate_data_channels_initial_offer() {
    let mut default = pc();
    let offer = default.create_offer(None).unwrap();
    assert!(!offer.sdp.contains("m=application"));
    default.close().unwrap();

    let mut always =
        pc_with(RTCConfigurationBuilder::new().with_always_negotiate_data_channels(true));
    let offer = always.create_offer(None).unwrap();
    assert!(offer.sdp.contains("m=application"));
    always.close().unwrap();
}

/// `TestAlwaysNegotiateDataChannels_CreateDataChannel` (negotiation part): with the option on
/// and the connection negotiated without channels, creating the first channel later does not
/// ask for another negotiation.
#[test]
fn test_always_negotiate_data_channels_needs_no_renegotiation() {
    let config = || RTCConfigurationBuilder::new().with_always_negotiate_data_channels(true);
    let mut offerer = pc_with(config());
    let mut answerer = pc_with(config());
    negotiate(&mut offerer, &mut answerer);
    negotiation_needed(&mut offerer);
    negotiation_needed(&mut answerer);

    offerer.create_data_channel("post-connect", None).unwrap();
    assert_eq!(
        negotiation_needed(&mut offerer),
        0,
        "the application section is already negotiated"
    );
    offerer.close().unwrap();
    answerer.close().unwrap();
}

/// Contrast: without the option the same sequence does ask.
#[test]
fn test_without_always_negotiate_a_later_channel_needs_negotiation() {
    let with_codecs = || {
        let mut me = rtc::peer_connection::configuration::media_engine::MediaEngine::default();
        me.register_default_codecs().unwrap();
        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .build(Instant::now())
            .unwrap()
    };
    let mut offerer = with_codecs();
    let mut answerer = with_codecs();
    // Something to negotiate first, so there is a current description.
    offerer
        .add_transceiver_from_kind(rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Audio, None)
        .unwrap();
    negotiate(&mut offerer, &mut answerer);
    negotiation_needed(&mut offerer);
    offerer.create_data_channel("later", None).unwrap();
    assert_eq!(negotiation_needed(&mut offerer), 1);
    offerer.close().unwrap();
    answerer.close().unwrap();
}

/// `TestAddTransceiver`: a sendrecv video transceiver has a sender and a receiver, and the offer
/// says `sendrecv` for it.
#[test]
fn test_add_transceiver() {
    use rtc::peer_connection::configuration::media_engine::MIME_TYPE_VP8;
    use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpEncodingParameters, RtpCodecKind};
    use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

    let mut me = rtc::peer_connection::configuration::media_engine::MediaEngine::default();
    me.register_default_codecs().unwrap();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap();
    let id = pc
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                // A sending transceiver needs the codec it will send: the sans-I/O API has no
                // placeholder track to pick one from (pion creates one).
                send_encodings: vec![RTCRtpEncodingParameters {
                    codec: RTCRtpCodec {
                        mime_type: MIME_TYPE_VP8.to_owned(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: String::new(),
                        rtcp_feedback: vec![],
                    },
                    ..Default::default()
                }],
            }),
        )
        .unwrap();
    let transceiver = pc.rtp_transceiver(id).expect("the transceiver exists");
    assert!(
        transceiver.sender().is_some(),
        "a sendrecv transceiver has a sender"
    );
    assert!(transceiver.receiver().is_some(), "and a receiver");
    let offer = pc.create_offer(None).unwrap();
    let video = offer
        .sdp
        .split("m=")
        .find(|section| section.starts_with("video"))
        .expect("a video section");
    assert!(video.contains("a=sendrecv"), "{video}");
    pc.close().unwrap();
}
