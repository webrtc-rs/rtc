use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_VP8, MediaEngine,
};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

fn video_codec(mime_type: &str, payload_type: u8) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type,
        ..Default::default()
    }
}

#[test]
fn test_add_transceiver_from_kind_negotiates_non_first_codec() {
    let vp8 = video_codec(MIME_TYPE_VP8, 96);
    let h264 = video_codec(MIME_TYPE_H264, 102);

    let mut offerer_media_engine = MediaEngine::default();
    offerer_media_engine
        .register_codec(vp8.clone(), RtpCodecKind::Video)
        .expect("register VP8");
    offerer_media_engine
        .register_codec(h264.clone(), RtpCodecKind::Video)
        .expect("register H264");

    let config = RTCConfigurationBuilder::new().build();
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_configuration(config.clone())
        .with_media_engine(offerer_media_engine)
        .build()
        .expect("build offerer");

    let transceiver_id = offerer
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![
                    RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(0x1111_1111),
                            ..Default::default()
                        },
                        codec: vp8.rtp_codec.clone(),
                        ..Default::default()
                    },
                    RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(0x2222_2222),
                            ..Default::default()
                        },
                        codec: h264.rtp_codec.clone(),
                        ..Default::default()
                    },
                ],
            }),
        )
        .expect("add transceiver from kind");

    let provisional_track = offerer
        .rtp_sender(RTCRtpSenderId::from(transceiver_id))
        .expect("offerer sender")
        .track()
        .clone();
    assert_eq!(provisional_track.kind(), RtpCodecKind::Video);
    assert_eq!(provisional_track.codings().len(), 2);

    let offer = offerer.create_offer(None).expect("create offer");
    offerer
        .set_local_description(offer.clone())
        .expect("set local offer");

    let mut answerer_media_engine = MediaEngine::default();
    answerer_media_engine
        .register_codec(h264.clone(), RtpCodecKind::Video)
        .expect("register answer H264");

    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(answerer_media_engine)
        .build()
        .expect("build answerer");

    answerer
        .set_remote_description(offer)
        .expect("set remote offer");

    let answer = answerer.create_answer(None).expect("create answer");
    assert!(answer.sdp.contains("H264/90000"), "{}", answer.sdp);
    assert!(!answer.sdp.contains("VP8/90000"), "{}", answer.sdp);

    answerer
        .set_local_description(answer.clone())
        .expect("set local answer");

    offerer
        .set_remote_description(answer)
        .expect("set remote answer");

    let parameters = offerer
        .rtp_sender(RTCRtpSenderId::from(transceiver_id))
        .expect("offerer sender")
        .get_parameters()
        .clone();

    assert_eq!(parameters.rtp_parameters.codecs.len(), 1);
    assert_eq!(
        parameters.rtp_parameters.codecs[0].rtp_codec.mime_type,
        MIME_TYPE_H264
    );
}
