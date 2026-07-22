//! Interop test against a REAL Firefox simulcast offer.
//!
//! The SDP fixture in `testdata/firefox_152_simulcast_offer.sdp` was captured
//! from Firefox 152 (Gecko) via its Marionette automation server, using
//! `addTransceiver('video', { sendEncodings: [ {rid:'h'}, {rid:'m'}, {rid:'l'} ] })`.
//!
//! It exercises the Firefox-specific quirks flagged in webrtc-rs/rtc#31
//! ("Simulcast configuration" ⚠ for Firefox): directional `a=extmap:<id>/sendonly`
//! qualifiers on the RID / repaired-RID header extensions, `a=msid:- <track>`, and
//! per-layer `a=ssrc-group:FID` lines alongside `a=rid` / `a=simulcast:send`.

use anyhow::Result;

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};

const FIREFOX_OFFER: &str = include_str!("testdata/firefox_152_simulcast_offer.sdp");

fn build_answerer()
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
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(SettingEngine::default())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?)
}

/// Normalize to CRLF line endings per RFC 8866 §5.
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// rtc must accept a genuine Firefox simulcast offer and produce an answer that
/// echoes back all three RID layers as `recv`. This is a general interop sanity
/// check over the whole `set_remote_description` -> `create_answer` pipeline;
/// note it does NOT guard the layer-ordering fix — Firefox emits `a=rid` and
/// `a=simulcast` in the same order, so this test passes with or without it. The
/// ordering fix is guarded by the reordered-rids test below.
#[test]
fn firefox_simulcast_offer_answer() -> Result<()> {
    let mut pc = build_answerer()?;

    let offer = RTCSessionDescription::offer(crlf(FIREFOX_OFFER))?;
    pc.set_remote_description(offer)?;

    let answer = pc.create_answer(None)?;
    let ans = &answer.sdp;

    // The answer must mirror Firefox's three simulcast layers as recv.
    for rid in ["h", "m", "l"] {
        assert!(
            ans.contains(&format!("a=rid:{rid} recv")),
            "answer missing `a=rid:{rid} recv`\n{ans}"
        );
    }
    assert!(
        ans.contains("a=simulcast:recv h;m;l"),
        "answer missing `a=simulcast:recv h;m;l`\n{ans}"
    );

    // The RID header extension must be negotiated, otherwise layers cannot be demuxed.
    // (Firefox announces it as `a=extmap:9/sendonly ...`; the `/direction` qualifier
    // is part of the extmap syntax per RFC 8285 §8 and must not prevent negotiation.)
    assert!(
        ans.contains("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"),
        "answer did not negotiate the RID header extension\n{ans}"
    );

    Ok(())
}

/// RFC 8853 §5.2: the `a=simulcast` send list "suggests a proposed order of
/// preference, in decreasing order"; the order of the `a=rid` lines is not
/// significant. §5.3.2 only mandates reversing send<->recv (SHALL) and forbids
/// adding streams — it does not itself require preserving order — but mirroring
/// the offered preference order back is the correct, interoperable behavior.
///
/// This offer lists the `a=rid` lines in the opposite order (`l`, `m`, `h`) to
/// the `a=simulcast:send h;m;l` preference list. rtc should still answer with
/// `a=simulcast:recv h;m;l`, following the attribute rather than the rid lines.
#[test]
fn simulcast_recv_order_follows_simulcast_attribute_not_rid_lines() -> Result<()> {
    // Work on LF-normalized text so the substitution is agnostic to however the
    // fixture's line endings are stored/checked out; `crlf()` restores CRLF below.
    let lf = FIREFOX_OFFER.replace("\r\n", "\n");
    // Reverse just the three consecutive `a=rid:* send` lines.
    let reordered = lf.replace(
        "a=rid:h send\na=rid:m send\na=rid:l send",
        "a=rid:l send\na=rid:m send\na=rid:h send",
    );
    // Guard: the substitution actually happened.
    assert!(
        reordered.contains("a=rid:l send\na=rid:m send\na=rid:h send"),
        "fixture rid lines not reordered as expected"
    );
    assert!(reordered.contains("a=simulcast:send h;m;l"));

    let mut pc = build_answerer()?;
    pc.set_remote_description(RTCSessionDescription::offer(crlf(&reordered))?)?;
    let answer = pc.create_answer(None)?;
    let ans = &answer.sdp;

    assert!(
        ans.contains("a=simulcast:recv h;m;l"),
        "answer should follow the offer's a=simulcast preference order (h;m;l), \
         not the a=rid line order (RFC 8853 §5.2). Got:\n{ans}"
    );
    // The a=rid recv lines follow the same order.
    let ans_lf = ans.replace("\r\n", "\n");
    assert!(
        ans_lf.contains("a=rid:h recv\na=rid:m recv\na=rid:l recv"),
        "a=rid recv lines should follow the a=simulcast order. Got:\n{ans}"
    );

    Ok(())
}
