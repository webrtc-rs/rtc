//! pion/webrtc v4.2.24 `mediaengine_test.go`.

use std::io::Cursor;

use super::media_engine::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::RTCConfigurationBuilder;
use crate::peer_connection::sdp::RTCSessionDescription;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection as Dir;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind::{Audio, Video};
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCPFeedback;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use sansio::Protocol;
use sdp::description::session::SessionDescription;
use shared::error::Error;
use std::time::Instant;

fn parse(raw: &str) -> SessionDescription {
    SessionDescription::unmarshal(&mut Cursor::new(raw.replace('\n', "\r\n").as_bytes()))
        .expect("the SDP parses")
}

fn codec(mime: &str, clock_rate: u32, channels: u16, fmtp: &str, pt: u8) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime.to_owned(),
            clock_rate,
            channels,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: pt,
    }
}

fn video(mime: &str, fmtp: &str, pt: u8) -> RTCRtpCodecParameters {
    codec(mime, 90000, 0, fmtp, pt)
}

fn ext(uri: &str) -> RTCRtpHeaderExtensionCapability {
    RTCRtpHeaderExtensionCapability {
        uri: uri.to_owned(),
    }
}

fn with_defaults() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    me
}

fn sdp_with(media: &str) -> String {
    format!("v=0\no=- 4596489990601351948 2 IN IP4 127.0.0.1\ns=-\nt=0 0\n{media}")
}

/// `TestOpusCase` and `TestVideoCase`.
#[test]
fn default_offers_carry_the_expected_rtpmaps() {
    let offer_for = |kind| {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(with_defaults())
            .build(Instant::now())
            .unwrap();
        pc.add_transceiver_from_kind(kind, None).unwrap();
        let sdp = pc.create_offer(None).unwrap().sdp;
        pc.close().unwrap();
        sdp
    };
    let has_rtpmap = |sdp: &str, name: &str| {
        sdp.lines().any(|l| {
            l.strip_prefix("a=rtpmap:")
                .and_then(|r| r.split_once(' '))
                .is_some_and(|(pt, rest)| {
                    pt.chars().all(|c| c.is_ascii_digit()) && rest.starts_with(name)
                })
        })
    };
    assert!(has_rtpmap(&offer_for(Audio), "opus/48000/2"));
    let video_offer = offer_for(Video);
    for name in ["H264/90000", "VP8/90000", "VP9/90000"] {
        assert!(has_rtpmap(&video_offer, name), "{name}");
    }
}

/// `TestMediaEngineRemoteDescription`.
mod remote_description {
    use super::*;

    fn negotiate(me: &mut MediaEngine, media: &str) -> shared::error::Result<()> {
        me.update_from_remote_description(&parse(&sdp_with(media)))
    }

    #[test]
    fn no_media() {
        let mut me = with_defaults();
        me.update_from_remote_description(&parse(
            "v=0\no=- 4596489990601351948 2 IN IP4 127.0.0.1\ns=-\nt=0 0\n",
        ))
        .unwrap();
        assert!(!me.negotiated_video && !me.negotiated_audio);
    }

    #[test]
    fn enable_opus() {
        let mut me = with_defaults();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=10; useinbandfec=1\n",
        )
        .unwrap();
        assert!(!me.negotiated_video && me.negotiated_audio);
        assert_eq!(
            me.get_codec_by_payload(111).unwrap().0.rtp_codec.mime_type,
            MIME_TYPE_OPUS
        );
    }

    #[test]
    fn change_payload_type() {
        let mut me = with_defaults();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 112\na=rtpmap:112 opus/48000/2\na=fmtp:112 minptime=10; useinbandfec=1\n",
        )
        .unwrap();
        assert!(me.negotiated_audio);
        assert!(me.get_codec_by_payload(111).is_err());
        assert_eq!(
            me.get_codec_by_payload(112).unwrap().0.rtp_codec.mime_type,
            MIME_TYPE_OPUS
        );
    }

    #[test]
    fn ambiguous_payload_type() {
        let mut me = with_defaults();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 96\na=rtpmap:96 opus/48000/2\na=fmtp:96 minptime=10; useinbandfec=1\n",
        )
        .unwrap();
        assert!(me.negotiated_audio);
        assert_eq!(
            me.get_codec_by_payload(96).unwrap().0.rtp_codec.mime_type,
            MIME_TYPE_OPUS
        );
    }

    #[test]
    fn case_insensitive() {
        let mut me = with_defaults();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 OPUS/48000/2\na=fmtp:111 minptime=10; useinbandfec=1\n",
        )
        .unwrap();
        assert!(me.negotiated_audio);
        assert_eq!(
            me.get_codec_by_payload(111).unwrap().0.rtp_codec.mime_type,
            "audio/OPUS"
        );
    }

    #[test]
    fn handle_different_fmtp() {
        let mut me = with_defaults();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 opus/48000/2\n",
        )
        .unwrap();
        assert!(me.negotiated_audio);
        assert_eq!(
            me.get_codec_by_payload(111).unwrap().0.rtp_codec.mime_type,
            MIME_TYPE_OPUS
        );
    }

    fn mid_and_abs(me: &MediaEngine) {
        let (abs, abs_audio, abs_video) =
            me.get_header_extension_id(ext(sdp::extmap::ABS_SEND_TIME_URI));
        assert_eq!((abs, abs_audio, abs_video), (0, false, false));
        let (mid, mid_audio, mid_video) =
            me.get_header_extension_id(ext(sdp::extmap::SDES_MID_URI));
        assert_eq!((mid, mid_audio, mid_video), (7, true, false));
    }

    #[test]
    fn header_extensions() {
        let mut me = with_defaults();
        me.register_header_extension(ext(sdp::extmap::SDES_MID_URI), Audio, None)
            .unwrap();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=extmap:7 urn:ietf:params:rtp-hdrext:sdes:mid\na=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\na=rtpmap:111 opus/48000/2\n",
        )
        .unwrap();
        assert!(!me.negotiated_video && me.negotiated_audio);
        mid_and_abs(&me);
    }

    #[test]
    fn different_header_extensions_on_same_codec() {
        let mut me = with_defaults();
        me.register_header_extension(ext(sdp::extmap::SDES_MID_URI), Audio, None)
            .unwrap();
        me.register_header_extension(ext(sdp::extmap::SDES_RTP_STREAM_ID_URI), Audio, None)
            .unwrap();
        negotiate(
            &mut me,
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 opus/48000/2\nm=audio 9 UDP/TLS/RTP/SAVPF 111\na=extmap:7 urn:ietf:params:rtp-hdrext:sdes:mid\na=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\na=rtpmap:111 opus/48000/2\n",
        )
        .unwrap();
        assert!(!me.negotiated_video && me.negotiated_audio);
        mid_and_abs(&me);
    }

    const H264_42E01F: &str =
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

    #[test]
    fn prefers_exact_codec_matches() {
        let mut me = MediaEngine::default();
        me.register_codec(video(MIME_TYPE_H264, H264_42E01F, 127), Video)
            .unwrap();
        negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 96 98\na=rtpmap:96 H264/90000\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\na=rtpmap:98 H264/90000\na=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\n",
        )
        .unwrap();
        assert!(me.negotiated_video && !me.negotiated_audio);
        assert_eq!(
            me.get_codec_by_payload(98).unwrap().0.rtp_codec.mime_type,
            MIME_TYPE_H264
        );
        assert!(me.get_codec_by_payload(96).is_err());
    }

    #[test]
    fn does_not_match_when_fmtpline_is_set_and_does_not_match() {
        let mut me = MediaEngine::default();
        me.register_codec(video(MIME_TYPE_H264, H264_42E01F, 127), Video)
            .unwrap();
        // pion errors here; so do we, with the error the negotiation of nothing yields.
        let result = negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 96 98\na=rtpmap:96 H264/90000\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\n",
        );
        assert!(result.is_err(), "{result:?}");
        assert!(me.get_codec_by_payload(96).is_err());
    }

    #[test]
    fn matches_when_fmtpline_is_not_set_in_offer_but_exists_in_mediaengine() {
        let mut me = MediaEngine::default();
        me.register_codec(video(MIME_TYPE_VP9, "profile-id=0", 98), Video)
            .unwrap();
        negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 96\na=rtpmap:96 VP9/90000\n",
        )
        .unwrap();
        assert!(me.negotiated_video);
        me.get_codec_by_payload(96).unwrap();
    }

    #[test]
    fn matches_when_fmtpline_exists_in_neither() {
        let mut me = MediaEngine::default();
        me.register_codec(video(MIME_TYPE_VP8, "", 96), Video)
            .unwrap();
        negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 96\na=rtpmap:96 VP8/90000\n",
        )
        .unwrap();
        assert!(me.negotiated_video);
        me.get_codec_by_payload(96).unwrap();
    }

    #[test]
    fn matches_when_rtx_apt_for_exact_match_codec() {
        let mut me = MediaEngine::default();
        for c in [
            video(MIME_TYPE_VP8, "", 96),
            video(MIME_TYPE_RTX, "apt=96", 97),
            video(
                MIME_TYPE_H264,
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
                102,
            ),
            video(MIME_TYPE_RTX, "apt=102", 103),
            video(
                MIME_TYPE_H264,
                "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f",
                104,
            ),
            video(MIME_TYPE_RTX, "apt=104", 105),
            video(MIME_TYPE_VP9, "profile-id=2", 98),
            video(MIME_TYPE_RTX, "apt=98", 99),
        ] {
            me.register_codec(c, Video).unwrap();
        }
        negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 94 95 106 107 108 109 96 97\na=rtpmap:94 VP8/90000\na=rtpmap:95 rtx/90000\na=fmtp:95 apt=94\na=rtpmap:106 H264/90000\na=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\na=rtpmap:107 rtx/90000\na=fmtp:107 apt=106\na=rtpmap:108 H264/90000\na=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\na=rtpmap:109 rtx/90000\na=fmtp:109 apt=108\na=rtpmap:96 VP9/90000\na=fmtp:96 profile-id=2\na=rtpmap:97 rtx/90000\na=fmtp:97 apt=96\n",
        )
        .unwrap();
        assert!(me.negotiated_video);

        let get = |pt| me.get_codec_by_payload(pt).unwrap().0.rtp_codec;
        assert_eq!(get(96).mime_type, MIME_TYPE_VP9);
        assert_eq!(get(97).mime_type, MIME_TYPE_RTX);
        assert_eq!(get(106).mime_type, MIME_TYPE_H264);
        assert_eq!(
            get(106).sdp_fmtp_line,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"
        );
        assert_eq!(get(107).mime_type, MIME_TYPE_RTX);
        assert_eq!(get(107).sdp_fmtp_line, "apt=106");
        assert_eq!(get(108).mime_type, MIME_TYPE_H264);
        assert_eq!(
            get(108).sdp_fmtp_line,
            "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f"
        );
        assert_eq!(get(109).mime_type, MIME_TYPE_RTX);
        assert_eq!(get(109).sdp_fmtp_line, "apt=108");
    }

    #[test]
    fn matches_when_rtx_apt_for_partial_match_codec() {
        let mut me = MediaEngine::default();
        for c in [
            video(MIME_TYPE_VP8, "", 94),
            video(MIME_TYPE_VP9, "profile-id=1", 96),
            video(MIME_TYPE_RTX, "apt=96", 97),
        ] {
            me.register_codec(c, Video).unwrap();
        }
        negotiate(
            &mut me,
            "m=video 60323 UDP/TLS/RTP/SAVPF 94 96 97\na=rtpmap:94 VP8/90000\na=rtpmap:96 VP9/90000\na=fmtp:96 profile-id=2\na=rtpmap:97 rtx/90000\na=fmtp:97 apt=96\n",
        )
        .unwrap();
        assert!(me.negotiated_video);
        assert!(matches!(
            me.get_codec_by_payload(97),
            Err(Error::ErrCodecNotFound)
        ));
    }
}

/// `TestMediaEngineHeaderExtensionDirection`.
mod header_extension_direction {
    use super::*;

    fn engine() -> MediaEngine {
        let mut me = MediaEngine::default();
        me.register_codec(codec(MIME_TYPE_OPUS, 48000, 0, "", 111), Audio)
            .unwrap();
        me
    }

    #[test]
    fn no_direction() {
        let mut me = engine();
        me.register_header_extension(ext("pion-header-test"), Audio, None)
            .unwrap();
        assert_eq!(
            me.get_rtp_parameters_by_kind(Audio, Dir::Recvonly)
                .header_extensions
                .len(),
            1
        );
    }

    #[test]
    fn same_direction() {
        let mut me = engine();
        me.register_header_extension(ext("pion-header-test"), Audio, Some(Dir::Recvonly))
            .unwrap();
        assert_eq!(
            me.get_rtp_parameters_by_kind(Audio, Dir::Recvonly)
                .header_extensions
                .len(),
            1
        );
    }

    #[test]
    fn different_direction() {
        let mut me = engine();
        me.register_header_extension(ext("pion-header-test"), Audio, Some(Dir::Sendonly))
            .unwrap();
        assert_eq!(
            me.get_rtp_parameters_by_kind(Audio, Dir::Recvonly)
                .header_extensions
                .len(),
            0
        );
    }

    #[test]
    fn invalid_direction() {
        let mut me = engine();
        for direction in [Dir::Inactive, Dir::Unspecified] {
            assert!(matches!(
                me.register_header_extension(ext("pion-header-test"), Audio, Some(direction)),
                Err(Error::ErrRegisterHeaderExtensionInvalidDirection)
            ));
        }
    }

    #[test]
    fn unique_extmapid_with_different_codec() {
        let mut me = engine();
        me.register_header_extension(ext("pion-header-test"), Audio, None)
            .unwrap();
        me.register_header_extension(ext("pion-header-test2"), Video, None)
            .unwrap();
        let audio = me.get_rtp_parameters_by_kind(Audio, Dir::Recvonly);
        let video = me.get_rtp_parameters_by_kind(Video, Dir::Recvonly);
        assert_eq!(audio.header_extensions.len(), 1);
        assert_eq!(video.header_extensions.len(), 1);
        assert_ne!(audio.header_extensions[0].id, video.header_extensions[0].id);
    }
}

/// `TestMediaEngineDoubleRegister`.
#[test]
fn registering_a_codec_twice_keeps_one() {
    let mut me = MediaEngine::default();
    for _ in 0..2 {
        me.register_codec(codec(MIME_TYPE_OPUS, 48000, 0, "", 111), Audio)
            .unwrap();
    }
    assert_eq!(me.audio_codecs.len(), 1);

    let mut me = MediaEngine::default();
    me.register_codec(codec("audio/OPUS", 48000, 0, "", 111), Audio)
        .unwrap();
    me.register_codec(codec("audio/opus", 48000, 0, "", 111), Audio)
        .unwrap();
    assert_eq!(me.audio_codecs.len(), 1, "mime types compare without case");

    let mut me = MediaEngine::default();
    for c in [
        video(&MIME_TYPE_RTX.to_uppercase(), "", 98),
        video(MIME_TYPE_RTX, "", 98),
        video(&MIME_TYPE_FLEX_FEC.to_uppercase(), "", 100),
        video(MIME_TYPE_FLEX_FEC, "", 100),
    ] {
        me.register_codec(c, Video).unwrap();
    }
    assert_eq!(me.video_codecs.len(), 2);
    assert!(me.is_rtx_enabled(Video, Dir::Recvonly));
    assert!(me.is_fec_enabled(Video, Dir::Recvonly));
}

/// `TestMediaEngineDoubleRegisterDifferentCodec`: a payload type already taken by another codec
/// is refused and the first registration stays.
#[test]
fn a_taken_payload_type_is_refused() {
    let mut me = MediaEngine::default();
    me.register_codec(codec(MIME_TYPE_G722, 8000, 0, "", 111), Audio)
        .unwrap();
    let result = me.register_codec(codec(MIME_TYPE_OPUS, 48000, 0, "", 111), Audio);
    assert!(
        matches!(result, Err(Error::ErrCodecAlreadyRegistered)),
        "{result:?}"
    );
    assert_eq!(me.audio_codecs.len(), 1);
}

/// `TestUpdateHeaderExtenstionToClonedMediaEngine`.
#[test]
fn a_cloned_engine_updates_negotiated_extensions() {
    let mut src = MediaEngine::default();
    src.register_codec(codec(MIME_TYPE_OPUS, 48000, 0, "", 111), Audio)
        .unwrap();
    src.register_header_extension(ext("test-extension"), Audio, None)
        .unwrap();

    let validate = |me: &mut MediaEngine| {
        me.update_header_extension(2, "test-extension", Audio)
            .unwrap();
        assert_eq!(
            me.get_header_extension_id(ext("test-extension")),
            (2, true, false)
        );
    };
    validate(&mut src);
    validate(&mut src.clone_to());
}

/// `TestExtensionIdCollision`.
#[test]
fn registered_extensions_avoid_the_negotiated_ids() {
    let mut me = with_defaults();
    me.register_header_extension(ext(sdp::extmap::SDES_MID_URI), Video, None)
        .unwrap();
    me.register_header_extension(ext("urn:3gpp:video-orientation"), Video, None)
        .unwrap();
    me.register_header_extension(ext(sdp::extmap::SDES_MID_URI), Audio, None)
        .unwrap();
    me.register_header_extension(ext(sdp::extmap::AUDIO_LEVEL_URI), Audio, None)
        .unwrap();

    me.update_from_remote_description(&parse(&sdp_with(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\na=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\na=rtpmap:111 opus/48000/2\n",
    )))
    .unwrap();
    assert!(me.negotiated_audio && !me.negotiated_video);

    assert_eq!(
        me.get_header_extension_id(ext(sdp::extmap::ABS_SEND_TIME_URI)),
        (0, false, false)
    );
    assert_eq!(
        me.get_header_extension_id(ext(sdp::extmap::SDES_MID_URI)),
        (2, true, false)
    );
    assert_eq!(
        me.get_header_extension_id(ext(sdp::extmap::AUDIO_LEVEL_URI)),
        (1, true, false)
    );

    let params = me.get_rtp_parameters_by_kind(Video, Dir::Sendonly);
    let extensions = params.header_extensions;
    assert_eq!(extensions.len(), 2);
    let mid = extensions
        .iter()
        .find(|e| e.uri == sdp::extmap::SDES_MID_URI)
        .expect("mid");
    let orientation = extensions
        .iter()
        .find(|e| e.uri == "urn:3gpp:video-orientation")
        .expect("video orientation");
    assert_eq!(mid.id, 2);
    assert!(
        ![1, 2, 5].contains(&orientation.id),
        "id {}",
        orientation.id
    );
}

const MIXED_CASE_OFFER: &str = "v=0
o=- 8448668841136641781 4 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 1
a=extmap-allow-mixed
a=msid-semantic: WMS 4beea6b0-cf95-449c-a1ec-78e16b247426
m=video 9 UDP/TLS/RTP/SAVPF 96 127
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:1/MvHwjAyVf27aLu
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E
a=ice-options:google-ice
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
a=setup:actpass
a=mid:1
a=sendonly
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtpmap:127 H264/90000
a=rtcp-fb:127 goog-remb
a=rtcp-fb:127 transport-cc
a=rtcp-fb:127 ccm fir
a=rtcp-fb:127 nack
a=rtcp-fb:127 nack pli
a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
";

fn fb(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    }
}

/// `TestCaseInsensitiveMimeType`.
#[test]
fn a_mime_type_registered_in_any_case_still_negotiates() {
    for vp8 in ["video/vp8", "video/VP8"] {
        let feedback = vec![
            fb("transport-cc", ""),
            fb("ccm", "fir"),
            fb("nack", ""),
            fb("nack", "pli"),
        ];
        let mut me = MediaEngine::default();
        for mut c in [
            video(vp8, "", 96),
            video(
                "video/h264",
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
                127,
            ),
        ] {
            c.rtp_codec.rtcp_feedback = feedback.clone();
            me.register_codec(c, Video).unwrap();
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(Instant::now())
            .unwrap();
        pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(MIXED_CASE_OFFER.replace('\n', "\r\n")).unwrap(),
        )
        .unwrap();
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer.clone())
            .unwrap();
        assert!(
            answer.sdp.to_lowercase().contains("vp8"),
            "{vp8}: {}",
            answer.sdp
        );
        pc.close().unwrap();
    }
}

/// `TestRTCPFeedbackHandling`: the answer's rtcp-fb is the intersection of both sides.
#[test]
fn rtcp_feedback_is_the_intersection() {
    const OFFER: &str = "v=0
o=- 8448668841136641781 4 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS 4beea6b0-cf95-449c-a1ec-78e16b247426
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:1/MvHwjAyVf27aLu
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E
a=ice-options:google-ice
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
a=setup:actpass
a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 nack
";
    for create_transceiver in [false, true] {
        let mut me = MediaEngine::default();
        let mut vp8 = video(MIME_TYPE_VP8, "", 96);
        vp8.rtp_codec.rtcp_feedback = vec![fb("transport-cc", ""), fb("nack", "")];
        me.register_codec(vp8, Video).unwrap();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .build(Instant::now())
            .unwrap();
        if create_transceiver {
            pc.add_transceiver_from_kind(Video, None).unwrap();
        }
        pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(OFFER.replace('\n', "\r\n")).unwrap(),
        )
        .unwrap();
        let answer = pc.create_answer(None).unwrap();
        assert!(
            answer.sdp.contains("a=rtcp-fb:96 nack"),
            "both support nack"
        );
        assert!(
            !answer.sdp.contains("a=rtcp-fb:96 goog-remb"),
            "only the offer has remb"
        );
        assert!(
            !answer.sdp.contains("a=rtcp-fb:96 transport-cc"),
            "only we have transport-cc"
        );
        pc.close().unwrap();
    }
}

/// `TestMultiCodecNegotiation`.
#[test]
fn multi_codec_negotiation_keeps_every_video_codec_only_when_enabled() {
    const OFFER: &str = "m=application 53555 UDP/DTLS/SCTP webrtc-datachannel
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
m=video 9 UDP/TLS/RTP/SAVPF 98
a=mid:1
a=sendonly
a=msid:be0216be-f3d8-40ca-a624-379edf70f1c9 3d032b3b-ffe5-48ec-b783-21375668d1c3
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:98 VP9/90000
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 transport-cc
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=fmtp:98 profile-id=0
a=rid:q send
a=rid:h send
a=simulcast:send q;h
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:2
a=sendonly
a=msid:6ff05509-be96-4ef1-a74f-425e14720983 16d5d7fe-d076-4718-9ca9-ec62b4543727
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=ssrc:4281768245 cname:JDM9GNMEg+9To6K7
a=ssrc:4281768245 msid:6ff05509-be96-4ef1-a74f-425e14720983 16d5d7fe-d076-4718-9ca9-ec62b4543727
";
    let offer = parse(&format!(
        "v=0\no=- 781500112831855234 6 IN IP4 127.0.0.1\ns=-\nt=0 0\na=group:BUNDLE 0 1 2 3\na=extmap-allow-mixed\na=msid-semantic: WMS be0216be-f3d8-40ca-a624-379edf70f1c9\n{OFFER}"
    ));

    let mut off = with_defaults();
    off.update_from_remote_description(&offer).unwrap();
    assert_eq!(off.negotiated_video_codecs.len(), 1);

    let mut on = MediaEngine::default();
    on.set_multi_codec_negotiation(true);
    assert!(on.multi_codec_negotiation());
    on.register_default_codecs().unwrap();
    on.update_from_remote_description(&offer).unwrap();
    assert_eq!(on.negotiated_video_codecs.len(), 2);
}
