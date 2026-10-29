//! Ported from pion/webrtc v4.2.24 `TestTransceiverCreatedByRemoteSdpHasSameCodecOrderAsRemote`:
//! transceivers created by a remote offer answer with the offer's codec order, with fuzzy
//! (profile-level mismatch) matches remapped onto the payload type the engine registered.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use sansio::Protocol;
use std::time::Instant;

const H264_P1: &str = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

fn codec(mime: &str, payload_type: u8, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

fn media_formats(sdp: &str) -> Vec<Vec<u8>> {
    sdp.lines()
        .filter(|l| l.starts_with("m=video "))
        .map(|l| {
            l.split_whitespace()
                .skip(3)
                .map(|pt| pt.parse().unwrap())
                .collect()
        })
        .collect()
}

fn answer_to(remote_sdp: &str, codecs: &[RTCRtpCodecParameters]) -> String {
    let mut media_engine = MediaEngine::default();
    for c in codecs {
        media_engine
            .register_codec(c.clone(), RtpCodecKind::Video)
            .unwrap();
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())
        .unwrap();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(remote_sdp.replace('\n', "\r\n")).unwrap(),
    )
    .unwrap();
    let answer = pc.create_answer(None).unwrap();
    pc.set_local_description(Instant::now(), answer.clone())
        .unwrap();
    pc.close().unwrap();
    answer.sdp
}

const HEADER: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
";

const TRANSPORT: &str = "a=ice-ufrag:1/MvHwjAyVf27aLu
a=ice-pwd:3dBU7cFOBl120v33cynDvN1E
a=ice-options:google-ice
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
";

/// "Codec MatchExact and MatchPartial".
#[test]
fn test_remote_codec_order_exact_and_partial() {
    let offer = format!(
        "{HEADER}m=video 60323 UDP/TLS/RTP/SAVPF 98 94 106 49
{TRANSPORT}a=mid:0
a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=rtpmap:94 VP8/90000
a=rtpmap:106 H264/90000
a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f
a=rtpmap:49 H265/90000
a=fmtp:49 level-id=186;profile-id=1;tier-flag=0;tx-mode=SRST
a=sendonly
m=video 60323 UDP/TLS/RTP/SAVPF 49 108 98 125
{TRANSPORT}a=mid:1
a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=rtpmap:108 VP8/90000
a=sendonly
a=rtpmap:125 H264/90000
a=fmtp:125 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f
a=rtpmap:49 H265/90000
a=fmtp:49 level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST
"
    );
    let answer = answer_to(
        &offer,
        &[
            codec("video/VP8", 94, ""),
            codec("video/H264", 98, H264_P1),
            codec(
                "video/H265",
                49,
                "level-id=186;profile-id=1;tier-flag=0;tx-mode=SRST",
            ),
        ],
    );
    assert_eq!(
        media_formats(&answer),
        vec![vec![98, 94, 49], vec![49, 94, 98]],
        "{answer}"
    );
}

/// "Codec PartialExact Only": a profile only the offer carries (640032) is remapped to the
/// payload type the first section gave it.
#[test]
fn test_remote_codec_order_partial_only() {
    let offer = format!(
        "{HEADER}m=video 60323 UDP/TLS/RTP/SAVPF 98 106
{TRANSPORT}a=mid:0
a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f
a=rtpmap:106 H264/90000
a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032
a=sendonly
m=video 60323 UDP/TLS/RTP/SAVPF 125 98
{TRANSPORT}a=mid:1
a=rtpmap:125 H264/90000
a=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032
a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f
a=sendonly
"
    );
    let answer = answer_to(
        &offer,
        &[codec("video/VP8", 94, ""), codec("video/H264", 98, H264_P1)],
    );
    assert_eq!(
        media_formats(&answer),
        vec![vec![98, 106], vec![106, 98]],
        "{answer}"
    );
}
