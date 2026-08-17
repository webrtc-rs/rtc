//! Answer-side SDP for a remote offer that requests simulcast RECEPTION.
//!
//! A browser-shaped offer carrying `a=simulcast:recv f;h;q` plus matching
//! `a=rid:<rid> recv` lines asks the answerer to SEND those simulcast layers.
//! When the local sender is configured with the same three encodings, the
//! answer must contain exactly one `a=rid:<rid> send` line per rid and a
//! single `send` description list in the `a=simulcast` attribute: the
//! RFC 8853 Section 5.1 ABNF (`sc-value = ( sc-send [SP sc-recv] ) /
//! ( sc-recv [SP sc-send] )`) permits at most one list per direction.
//!
//! Regression test: the answer used to duplicate every `a=rid:<rid> send`
//! line (once from the remote rid map, once from the sender's encodings) and
//! emit `a=simulcast:send f;h;q send f;h;q`, which WebKit/Safari rejects at
//! setRemoteDescription with "SyntaxError: Malformed simulcast line".

use anyhow::Result;
use std::time::Instant;

use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpHeaderExtensionCapability,
    RtpCodecKind,
};

/// Browser-shaped offer asking to receive three simulcast layers (f, h, q).
const RECV_SIMULCAST_OFFER: &str = "v=0
o=- 4215775240449105457 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz
a=ice-options:trickle
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=recvonly
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rid:f recv
a=rid:h recv
a=rid:q recv
a=simulcast:recv f;h;q
";

/// Build an answerer whose local video sender carries three simulcast
/// encodings (rids f, h, q), mirroring how
/// `tests/simulcast_rtc_to_webrtc_interop.rs` constructs its layers.
fn build_simulcast_sender_answerer()
-> Result<rtc::peer_connection::RTCPeerConnection<impl rtc::interceptor::Interceptor + use<>>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for uri in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }
    let registry = rtc::interceptor::Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(SettingEngine::default())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;

    let video_codec = RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "".to_owned(),
        rtcp_feedback: vec![],
    };
    let mut codings = vec![];
    for (i, rid) in ["f", "h", "q"].into_iter().enumerate() {
        codings.push(RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(3141590 + i as u32),
                ..Default::default()
            },
            codec: video_codec.clone(),
            ..Default::default()
        });
    }
    let track = MediaStreamTrack::new(
        "simulcast_stream".to_owned(),
        "simulcast_video".to_owned(),
        "simulcast_video".to_owned(),
        RtpCodecKind::Video,
        codings,
    );
    pc.add_track(track)?;
    Ok(pc)
}

/// Normalize to CRLF line endings per RFC 8866 §5.
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// The answer to an `a=simulcast:recv` offer must carry each `a=rid:<rid> send`
/// line exactly once and a simulcast attribute with a single `send` list.
#[test]
fn answer_to_simulcast_recv_offer_has_single_send_section() -> Result<()> {
    let mut pc = build_simulcast_sender_answerer()?;

    let offer = RTCSessionDescription::offer(crlf(RECV_SIMULCAST_OFFER))?;
    pc.set_remote_description(Instant::now(), offer)?;

    let answer = pc.create_answer(None)?;
    let ans = &answer.sdp;

    // Exactly one `a=rid:<rid> send` line per negotiated rid.
    for rid in ["f", "h", "q"] {
        let needle = format!("a=rid:{rid} send");
        let count = ans.matches(&needle).count();
        assert_eq!(
            count, 1,
            "expected exactly one `{needle}` line, got {count}:\n{ans}"
        );
    }

    // A single `a=simulcast` attribute with a single `send` description list.
    // RFC 8853 §5.1 permits at most one list per direction; WebKit rejects
    // `a=simulcast:send ... send ...` with "Malformed simulcast line".
    let ans_lf = ans.replace("\r\n", "\n");
    let sc_lines: Vec<&str> = ans_lf
        .lines()
        .filter(|line| line.starts_with("a=simulcast:"))
        .collect();
    assert_eq!(
        sc_lines.len(),
        1,
        "expected exactly one a=simulcast line:\n{ans}"
    );
    let sc_value = sc_lines[0].trim_start_matches("a=simulcast:");
    let send_sections = sc_value.split(' ').filter(|tok| *tok == "send").count();
    assert_eq!(
        send_sections, 1,
        "expected a single `send` section in `{}` (RFC 8853 §5.1):\n{ans}",
        sc_lines[0]
    );
    assert_eq!(sc_value, "send f;h;q", "unexpected simulcast value:\n{ans}");

    Ok(())
}
