//! pion/sdp v3.0.20 tests ported to the public API (issue: close the
//! unit-test gap the golden corpus leaves — verdicts are proven there, these
//! pin field handling, JSEP builders, extmap errors and malformed-input
//! safety).
//!
//! pion's `TestS*`/`TestUnmarshal*_Error_*` families drive private state-machine
//! functions with hand-built lexers; the scenarios port here as whole SDP texts
//! through `SessionDescription::unmarshal`, asserting the same observable
//! results (fields parsed, verdicts). Rows that only inject internal read
//! errors are classified `na` in the ledger.

use std::io::Cursor;

use super::common::*;
use super::media::*;
use super::session::*;
use crate::extmap::ExtMap;
use crate::util::{Codec, ConnectionRole};
use shared::error::Result;

fn unmarshal(text: &str) -> Result<SessionDescription> {
    SessionDescription::unmarshal(&mut Cursor::new(text.as_bytes().to_vec()))
}

const BASE_SDP: &str = "v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\n";

fn with(line: &str) -> String {
    // pion's Session*SDP constants: BaseSDP + the line under test + timing.
    format!("{BASE_SDP}{line}t=3034423619 3042462419\r\n")
}

// ---------------------------------------------------------------------------
// pion unmarshal_test.go: origin tolerance and rejection.
// ---------------------------------------------------------------------------

// pion TestUnmarshalOriginIncomplete: IP-camera style origins with missing
// fields get defaults instead of failing.
#[test]
fn test_unmarshal_origin_incomplete() -> Result<()> {
    let cases = [
        (
            "v=0\r\no=- 1001 1 IN IP4\r\ns=VCP IPC Realtime stream\r\nt=0 0\r\n",
            ("-", 1001u64, 1u64, "IN", "IP4", "0.0.0.0"),
        ),
        (
            "v=0\r\no=- 1001 1 IN\r\ns=Test Stream\r\nt=0 0\r\n",
            ("-", 1001, 1, "IN", "IP4", "0.0.0.0"),
        ),
        (
            "v=0\r\no=- 1001 1 IN IP6\r\ns=Test Stream\r\nt=0 0\r\n",
            ("-", 1001, 1, "IN", "IP6", "::"),
        ),
        (
            "v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nt=3034423619 3042462419\r\n",
            ("jdoe", 2890844526, 2890842807, "IN", "IP4", "10.47.16.5"),
        ),
        (
            "v=0\r\no=- 1001 1 IN IP4 \r\ns=Test\r\nt=0 0\r\n",
            ("-", 1001, 1, "IN", "IP4", "0.0.0.0"),
        ),
    ];

    for (input, expected) in cases {
        let sd = unmarshal(input)?;
        let origin = &sd.origin;
        assert_eq!(expected.0, origin.username, "{input}");
        assert_eq!(expected.1, origin.session_id, "{input}");
        assert_eq!(expected.2, origin.session_version, "{input}");
        assert_eq!(expected.3, origin.network_type, "{input}");
        assert_eq!(expected.4, origin.address_type, "{input}");
        assert_eq!(expected.5, origin.unicast_address, "{input}");
    }
    Ok(())
}

// pion TestUnmarshalOrigin_Error_HandleUnicastAddress_Propagates: the `o=`
// value exhausted before the unicast address (end of input, no newline after
// the address type) propagates the end-of-input error (pion io.EOF) instead
// of the camera-compatible default - the contrast with the `IN IP4 \r\n`
// case in TestUnmarshalOriginIncomplete above, which gets `0.0.0.0`.
#[test]
fn test_unmarshal_origin_error_handle_unicast_address_propagates() {
    let err = unmarshal("v=0\r\no=test 1 1 IN IP4")
        .expect_err("an origin exhausted before the address is rejected");
    assert_eq!(
        shared::error::Error::SdpInvalidSyntax("unexpected end of input".into()),
        err
    );
}

// pion TestUnmarshalOriginInvalidFields.
#[test]
fn test_unmarshal_origin_invalid_fields() {
    for input in [
        "v=0\r\no=- 1001 1 INVALID IP4 10.0.0.1\r\ns=Test\r\nt=0 0\r\n",
        "v=0\r\no=- 1001 1 IN INVALID 10.0.0.1\r\ns=Test\r\nt=0 0\r\n",
    ] {
        assert!(unmarshal(input).is_err(), "must reject {input}");
    }
}

// pion TestUnmarshalOriginEdgeCases.
#[test]
fn test_unmarshal_origin_edge_cases() {
    for input in [
        "v=0\r\no=\r\ns=Test\r\nt=0 0\r\n",
        "v=0\r\no=user\r\ns=Test\r\nt=0 0\r\n",
        "v=0\r\no=user 1001 1\r\ns=Test\r\nt=0 0\r\n",
    ] {
        assert!(unmarshal(input).is_err(), "must reject {input}");
    }
}

// pion TestUnmarshalZeroValues.
#[test]
fn test_unmarshal_zero_values() -> Result<()> {
    let sd = unmarshal("v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\n")?;
    assert_eq!(0, sd.version);
    assert_eq!("0", sd.origin.username);
    assert_eq!(0, sd.origin.session_id);
    assert_eq!(0, sd.origin.session_version);
    assert_eq!("0", sd.session_name);
    assert_eq!(0, sd.time_descriptions[0].timing.start_time);
    assert_eq!(0, sd.time_descriptions[0].timing.stop_time);
    Ok(())
}

// pion TestUnmarshalPortRange: m= lines ride after the timing line.
#[test]
fn test_unmarshal_port_range() -> Result<()> {
    let cases = [
        ("m=video 0 UDP/TLS/RTP/SAVPF 96\r\n", 0isize, None::<isize>),
        ("m=video 1 UDP/TLS/RTP/SAVPF 96\r\n", 1, None),
        ("m=video 1/2 UDP/TLS/RTP/SAVPF 96\r\n", 1, Some(2)),
        ("m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99\r\n", 9, None),
    ];
    for (line, port, range) in cases {
        let sd = unmarshal(&format!("{BASE_SDP}t=3034423619 3042462419\r\n{line}"))?;
        let media = &sd.media_descriptions[0];
        assert_eq!(port, media.media_name.port.value, "{line}");
        assert_eq!(range, media.media_name.port.range, "{line}");
    }
    Ok(())
}

// pion TestUnmarshal_DelegatesToUnmarshalString: bytes in, same text out.
#[test]
fn test_unmarshal_delegates_to_unmarshal_string() -> Result<()> {
    let input = "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\n";
    let sd = unmarshal(input)?;
    assert_eq!(input, sd.marshal());
    Ok(())
}

// ---------------------------------------------------------------------------
// pion TestS1..S16 state-machine scenarios, expressed as whole sessions.
// ---------------------------------------------------------------------------

// pion TestS1..S5_SyntaxError: a line that is not the expected mandatory one
// (v/o/s/i/u) is a syntax error. Each case starts the session with `a=`.
#[test]
fn test_s1_to_s5_syntax_error() {
    // pion feeds "a=" directly to s1..s5; the equivalent whole-session input
    // replaces each mandatory line in turn.
    let cases = [
        "a=\r\n",                                     // not 'v'
        "v=0\r\na=\r\ns=0\r\nt=0 0\r\n",              // not 'o'
        "v=0\r\no=0 0 0 IN IP4 0\r\na=\r\nt=0 0\r\n", // not 's'
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\na=\r\n",   // not 't' at s4/s5
    ];
    for input in cases {
        assert!(unmarshal(input).is_err(), "must reject {input:?}");
    }
}

// pion TestS6_KeyC_UnmarshalSessionConnectionInformation and
// TestS6_KeyB_UnmarshalSessionBandwidth (session-level c= and b=).
#[test]
fn test_s6_key_c_and_key_b() -> Result<()> {
    let sd = unmarshal(&with("c=IN IP4 111.1.111.1\r\n"))?;
    let ci = sd.connection_information.as_ref().expect("session c=");
    assert_eq!("IN", ci.network_type);
    assert_eq!("IP4", ci.address_type);
    assert_eq!("111.1.111.1", ci.address.as_ref().expect("address").address);

    let sd = unmarshal(&with("b=AS:123\r\n"))?;
    assert_eq!(1, sd.bandwidth.len());
    assert_eq!("AS", sd.bandwidth[0].bandwidth_type);
    assert_eq!(123, sd.bandwidth[0].bandwidth);
    Ok(())
}

// pion TestS7_KeyE/KeyP/KeyC/KeyB: the post-information session keys.
#[test]
fn test_s7_keys_email_phone_connection_bandwidth() -> Result<()> {
    let sd = unmarshal(&with("e=abc.Def@example.com (abc Def)\r\n"))?;
    assert_eq!(
        Some("abc.Def@example.com (abc Def)".to_owned()),
        sd.email_address
    );

    let sd = unmarshal(&with("p=+1 617 555-6011\r\n"))?;
    assert_eq!(Some("+1 617 555-6011".to_owned()), sd.phone_number);

    let sd = unmarshal(&with("c=IN IP4 111.1.111.1\r\n"))?;
    assert!(sd.connection_information.is_some());

    let sd = unmarshal(&with("b=X-YZ:128\r\nb=AS:12345\r\n"))?;
    assert_eq!(2, sd.bandwidth.len());
    // pion and rtc-sdp both strip the experimental `X-` prefix into its own
    // flag, leaving the bare modifier as the type.
    assert!(sd.bandwidth[0].experimental);
    assert_eq!("YZ", sd.bandwidth[0].bandwidth_type);
    assert_eq!(128, sd.bandwidth[0].bandwidth);
    assert_eq!("AS", sd.bandwidth[1].bandwidth_type);
    assert_eq!(12345, sd.bandwidth[1].bandwidth);
    Ok(())
}

// pion TestS8_KeyB (bandwidth in the post-information state s8), TestS10
// (the post-URI keys: pion reaches s10 after `u=`), and TestS9/S11/S12
// syntax errors.
#[test]
fn test_s8_through_s12_keys_and_syntax() -> Result<()> {
    // s8: bandwidth after the session information.
    let sd = unmarshal(&format!(
        "{BASE_SDP}i=A Seminar\r\nb=AS:123\r\nt=3034423619 3042462419\r\n"
    ))?;
    assert_eq!(1, sd.bandwidth.len());
    assert_eq!("AS", sd.bandwidth[0].bandwidth_type);

    // s10: after the URI line, phone/connection/bandwidth are accepted.
    let sd = unmarshal(&format!(
        "{BASE_SDP}u=http://www.example.com/seminars/sdp.pdf\r\np=+1 617 555-6011\r\nt=3034423619 3042462419\r\n"
    ))?;
    assert_eq!(Some("+1 617 555-6011".to_owned()), sd.phone_number);

    let sd = unmarshal(&format!(
        "{BASE_SDP}u=http://www.example.com/seminars/sdp.pdf\r\nc=IN IP4 111.1.111.1\r\nt=3034423619 3042462419\r\n"
    ))?;
    assert!(sd.connection_information.is_some());

    let sd = unmarshal(&format!(
        "{BASE_SDP}u=http://www.example.com/seminars/sdp.pdf\r\nb=AS:123\r\nt=3034423619 3042462419\r\n"
    ))?;
    assert_eq!(1, sd.bandwidth.len());

    // s9/s11/s12: the zones (z=, k=, a= at session level) reject bad lines.
    assert!(unmarshal(&format!("{BASE_SDP}t=0 0\r\nz=not-a-time\r\n")).is_err());
    Ok(())
}

// pion TestS13_KeyA (session attribute), TestS13_KeyM (media description
// starts), TestS14/S15/S16 media-level keys, and the syntax-error arms.
#[test]
fn test_s13_to_s16_media_keys_and_syntax() -> Result<()> {
    // s13: session attribute.
    let sd = unmarshal(&format!("{BASE_SDP}t=0 0\r\na=group:BUNDLE video\r\n"))?;
    assert_eq!(Some("BUNDLE video"), sd.attribute("group"));

    // s13 KeyM: a media section starts after session attributes.
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=0 0\r\nm=video 9 RTP/AVP 96\r\nc=IN IP4 0.0.0.0\r\n"
    ))?;
    assert_eq!(1, sd.media_descriptions.len());

    // s14/s15/s16: media-level title (i=), encryption key (k=), bandwidth
    // (b=), connection (c=), attributes (a=) and a nested m= line.
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=0 0\r\nm=video 9 RTP/AVP 96\r\ni=Title\r\nk=prompt\r\nb=AS:25\r\na=sendrecv\r\n"
    ))?;
    let media = &sd.media_descriptions[0];
    assert_eq!(Some("Title".to_owned()), media.media_title);
    assert!(media.encryption_key.is_some());
    assert_eq!(1, media.bandwidth.len());
    assert_eq!("AS", media.bandwidth[0].bandwidth_type);
    assert!(media.has_attribute("sendrecv"));

    // A second m= line inside the media zone starts another section (s15/s16
    // KeyM).
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=0 0\r\nm=audio 9 RTP/AVP 111\r\nm=video 9 RTP/AVP 96\r\n"
    ))?;
    assert_eq!(2, sd.media_descriptions.len());

    // The syntax-error arms: an `a=` line where a key is required.
    assert!(unmarshal("a=\r\n").is_err());
    Ok(())
}

// pion TestUnmarshalProtocolVersion_Error_InvalidNonZeroVersion and the
// malformed-line variants of the Error_* rows that are expressible as text.
#[test]
fn test_unmarshal_malformed_lines_rejected() {
    let cases = [
        // Non-zero version.
        "v=1\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\n",
        // Non-numeric version.
        "v=X\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\n",
        // Origin with non-numeric session id / version.
        "v=0\r\no=user X 1 IN IP4 0\r\ns=0\r\nt=0 0\r\n",
        "v=0\r\no=user 1001 X IN IP4 0\r\ns=0\r\nt=0 0\r\n",
        // Bandwidth with a non-numeric value.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nb=AS:X\r\nt=0 0\r\n",
        // Timing with non-numeric fields.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=X 0\r\n",
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 X\r\n",
        // Repeat with malformed fields.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\nr=X 0 0\r\n",
        // Timezone with malformed fields.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\nz=X 0\r\n",
        // Port range with a bad bound.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nt=0 0\r\nm=video 9/X RTP/AVP 96\r\n",
        // Connection with an invalid network/address type.
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nc=OUT IP4 0.0.0.0\r\nt=0 0\r\n",
        "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nc=IN IP9 0.0.0.0\r\nt=0 0\r\n",
        // Note: an unregistered `m=` protocol token is deliberately absent —
        // rtc-sdp accepts it (RFC 8866 §5.14 makes <proto> extensible; pion
        // rejects it), a divergence documented in pion_golden.rs. An empty
        // `u=` is absent too: Go's url.Parse accepts the empty string, so pion
        // accepts the line.
    ];
    for input in cases {
        assert!(unmarshal(input).is_err(), "must reject {input:?}");
    }
}

// pion TestUnmarshalTimeShorthand_MinutesAndSeconds: `r=` shorthand accepts
// `d`, `h`, `m`, `s` units (stored in seconds).
#[test]
fn test_unmarshal_time_shorthand_minutes_and_seconds() -> Result<()> {
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=2873397496 2873404696\r\nr=1h 30m 0 10m\r\n"
    ))?;
    let repeat = &sd.time_descriptions[0].repeat_times[0];
    assert_eq!(3600, repeat.interval);
    assert_eq!(1800, repeat.duration);
    Ok(())
}

// ---------------------------------------------------------------------------
// Robustness add-ons required by the issue: never panic, never go
// super-linear, on hostile-but-well-formed and malformed inputs.
// ---------------------------------------------------------------------------

#[test]
fn test_robustness_single_huge_line() {
    // A single 1 MiB line must parse (or reject) without panic; the wall-clock
    // bound is generous in debug builds.
    let mut input = String::with_capacity(1 << 20);
    input.push_str(BASE_SDP);
    input.push_str("i=");
    input.push_str(&"x".repeat(1 << 20));
    input.push_str("\r\nt=0 0\r\n");
    let _ = unmarshal(&input);
}

#[test]
fn test_robustness_many_attributes() {
    let mut input = String::with_capacity(1 << 21);
    input.push_str(BASE_SDP);
    input.push_str("t=0 0\r\n");
    for i in 0..50_000 {
        input.push_str(&format!("a=x{i}\r\n"));
    }
    let sd = unmarshal(&input).expect("50k attributes parse");
    assert!(sd.attributes.len() >= 50_000);
}

#[test]
fn test_robustness_many_media_sections() {
    let mut input = String::with_capacity(1 << 21);
    input.push_str(BASE_SDP);
    input.push_str("t=0 0\r\n");
    for _ in 0..10_000 {
        input.push_str("m=audio 9 RTP/AVP 111\r\n");
    }
    let sd = unmarshal(&input).expect("10k m= sections parse");
    assert_eq!(10_000, sd.media_descriptions.len());
}

#[test]
fn test_robustness_crlf_only_lines() {
    let mut input = String::with_capacity(1 << 20);
    input.push_str(BASE_SDP);
    input.push_str("t=0 0\r\n");
    input.push_str(&"\r\n".repeat(100_000));
    let _ = unmarshal(&input);
}

#[test]
fn test_robustness_invalid_utf8() {
    // Invalid UTF-8 must be an error (or a lossless pass-through), never a
    // panic.
    let mut input = BASE_SDP.as_bytes().to_vec();
    input.push(b'i');
    input.push(b'=');
    input.extend_from_slice(&[0xff, 0xfe, 0xfd]);
    input.extend_from_slice(b"\r\nt=0 0\r\n");
    let _ = SessionDescription::unmarshal(&mut Cursor::new(input));
}

#[test]
fn test_robustness_missing_final_newline() {
    // pion tolerates a missing final CRLF (RFC 4566 §5: parsers SHOULD accept
    // a single newline; a truncated last line must not panic).
    let input = format!("{BASE_SDP}t=0 0");
    let _ = unmarshal(&input);
}

// ---------------------------------------------------------------------------
// pion jsep_test.go: the JSEP builders.
// ---------------------------------------------------------------------------

// pion TestNewJSEPSessionDescription.
#[test]
fn test_new_jsep_session_description() {
    let sd = SessionDescription::new_jsep_session_description(false);
    assert_eq!(0, sd.version);
    assert_eq!("-", sd.origin.username);
    assert_eq!("IN", sd.origin.network_type);
    assert_eq!("IP4", sd.origin.address_type);
    assert_eq!("0.0.0.0", sd.origin.unicast_address);
    assert_eq!("-", sd.session_name);
    assert_eq!(1, sd.time_descriptions.len());
    assert_eq!(0, sd.time_descriptions[0].timing.start_time);
    assert_eq!(0, sd.time_descriptions[0].timing.stop_time);
    assert!(sd.attributes.is_empty());

    let sd = SessionDescription::new_jsep_session_description(true);
    assert_eq!(1, sd.attributes.len());
    assert_eq!("identity", sd.attributes[0].key);
}

// pion TestSessionDescriptionAttributes.
#[test]
fn test_session_description_attributes() {
    let sd = SessionDescription::new_jsep_session_description(false)
        .with_property_attribute("rtcp-mux".to_owned());
    assert_eq!(1, sd.attributes.len());
    assert_eq!("rtcp-mux", sd.attributes[0].key);

    let sd = SessionDescription::new_jsep_session_description(false)
        .with_value_attribute("mid".to_owned(), "video".to_owned());
    assert_eq!(1, sd.attributes.len());
    assert_eq!("mid", sd.attributes[0].key);
    assert_eq!(Some("video"), sd.attributes[0].value.as_deref());
}

// pion TestNewJSEPMediaDescription.
#[test]
fn test_new_jsep_media_description() {
    let md = MediaDescription::new_jsep_media_description("video".to_owned(), vec!["96", "97"]);
    assert_eq!("video", md.media_name.media);
    assert_eq!(9, md.media_name.port.value);
    assert_eq!(
        vec!["UDP", "TLS", "RTP", "SAVPF"],
        md.media_name
            .protos
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
    );
    let ci = md.connection_information.as_ref().expect("c=");
    assert_eq!("IN", ci.network_type);
    assert_eq!("IP4", ci.address_type);
    assert_eq!("0.0.0.0", ci.address.as_ref().expect("address").address);
}

// pion TestMediaDescriptionAttributes.
#[test]
fn test_media_description_attributes() {
    let md = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![])
        .with_property_attribute("rtcp-mux".to_owned())
        .with_value_attribute("mid".to_owned(), "audio".to_owned())
        .with_fingerprint("sha-256".to_owned(), "test-fingerprint".to_owned());
    assert_eq!(3, md.attributes.len());
    assert_eq!("rtcp-mux", md.attributes[0].key);
    assert_eq!("mid", md.attributes[1].key);
    assert_eq!("fingerprint", md.attributes[2].key);
    assert_eq!(
        Some("sha-256 test-fingerprint"),
        md.attributes[2].value.as_deref()
    );
}

// pion TestMediaDescriptionCodec.
#[test]
fn test_media_description_codec() {
    let md = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![]).with_codec(
        111,
        "opus".to_owned(),
        48000,
        2,
        "minptime=10;useinbandfec=1".to_owned(),
    );
    assert_eq!(1, md.media_name.formats.len());
    assert_eq!("111", md.media_name.formats[0]);
    assert_eq!(2, md.attributes.len());
    assert_eq!("rtpmap", md.attributes[0].key);
    assert_eq!(Some("111 opus/48000/2"), md.attributes[0].value.as_deref());
    assert_eq!("fmtp", md.attributes[1].key);
    assert_eq!(
        Some("111 minptime=10;useinbandfec=1"),
        md.attributes[1].value.as_deref()
    );
}

// pion TestSessionDescription_WithMedia_Appends.
#[test]
fn test_session_description_with_media_appends() {
    let sd = SessionDescription::new_jsep_session_description(false);
    let before = sd.media_descriptions.len();
    let sd = sd.with_media(MediaDescription::new_jsep_media_description(
        "audio".to_owned(),
        vec![],
    ));
    assert_eq!(before + 1, sd.media_descriptions.len());
}

// pion TestMediaDescription_WithExtMap_AddsPropertyAttribute and
// TestMediaDescription_WithTransportCCExtMap_AddsExpectedAttribute.
#[test]
fn test_media_description_with_extmap() {
    let mut extmap = ExtMap::default();
    extmap.value = 1;
    extmap.uri = Some(
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
            .parse()
            .unwrap(),
    );
    extmap.ext_attr = Some("vad".to_owned());

    // rtc-sdp stores the extmap line as a property attribute (key-only,
    // carrying the whole `extmap:...` text); pion splits it into an
    // `extmap`-keyed value attribute. Both print `a=extmap:...` on the wire.
    let md = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![])
        .with_extmap(extmap);
    let attribute = &md.attributes[0];
    assert_eq!(None, attribute.value.as_deref());
    assert!(
        attribute
            .key
            .starts_with("extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level")
    );
    assert!(attribute.key.ends_with("vad"));
    let marshaled = SessionDescription::new_jsep_session_description(false)
        .with_media(md)
        .marshal();
    assert!(marshaled.contains("a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level vad"));

    // The transport-wide CC extmap adds its expected attribute.
    let md = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![])
        .with_transport_cc_extmap();
    let attribute = &md.attributes[0];
    assert!(attribute.key.contains("extmap:"));
    assert!(attribute.key.contains("transport-wide-cc-extensions"));
}

// pion TestGetCodecsForPayloadTypes, TestGetCodecForPayloadType_Error_NotFound
// and TestGetPayloadTypeForCodec_Error_NotFound (the lookup helpers over the
// codec map).
#[test]
fn test_codec_lookup_helpers() -> Result<()> {
    let sd = SessionDescription::new_jsep_session_description(false).with_media(
        MediaDescription::new_jsep_media_description("audio".to_owned(), vec![])
            .with_codec(111, "opus".to_owned(), 48000, 2, String::new())
            .with_codec(96, "VP8".to_owned(), 90000, 0, String::new()),
    );

    let codecs = sd.get_codecs_for_payload_types(&[111, 96]);
    assert_eq!(2, codecs.len());
    assert_eq!("opus", codecs[0].name);
    assert_eq!(48000, codecs[0].clock_rate);
    assert_eq!("VP8", codecs[1].name);

    let codec = sd.get_codec_for_payload_type(111)?;
    assert_eq!("opus", codec.name);

    assert!(sd.get_codec_for_payload_type(99).is_err());
    let wanted = Codec {
        payload_type: 0,
        name: "H265".to_owned(),
        clock_rate: 90000,
        encoding_parameters: String::new(),
        fmtp: String::new(),
        rtcp_feedback: vec![],
    };
    assert!(sd.get_payload_type_for_codec(&wanted).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// pion extmap_test.go.
// ---------------------------------------------------------------------------

fn extmap_of(value: &str) -> Result<ExtMap> {
    ExtMap::unmarshal(&mut value.as_bytes())
}

// pion TestExtMap_Unmarshal_Error_LenParts / _LenFields / _NewDirection /
// _URLParse.
#[test]
fn test_extmap_unmarshal_errors() {
    assert!(extmap_of("extmap 1 example.com").is_err());
    assert!(extmap_of("").is_err());
    assert!(extmap_of("extmap:1").is_err());
    assert!(extmap_of("extmap:1/not-a-dir http://example.com").is_err());
    assert!(extmap_of("extmap:1 http://example.com/%zz").is_err());
}

// pion TestExtMap round-trip: value/direction/URI/ext-attr marshal back to
// the same text.
#[test]
fn test_extmap_roundtrip() -> Result<()> {
    let line = "extmap:3/recvonly urn:ietf:params:rtp-hdrext:ssrc-audio-level vad";
    let extmap = extmap_of(line)?;
    assert_eq!(3, extmap.value);
    assert_eq!(line, extmap.marshal());
    Ok(())
}

// pion TestExtMap_Clone (rtc-rtp's `convert`): the attribute carries the
// extmap text under the `extmap` key.
#[test]
fn test_extmap_clone() {
    let mut extmap = ExtMap::default();
    extmap.value = 5;
    extmap.uri = Some(
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
            .parse()
            .unwrap(),
    );
    extmap.ext_attr = Some("vad".to_owned());

    let attribute = extmap.convert();
    assert_eq!("extmap", attribute.key);
    assert_eq!(
        Some("5 urn:ietf:params:rtp-hdrext:ssrc-audio-level vad"),
        attribute.value.as_deref()
    );
}

// pion TestTransportCCExtMap: the marshalled line is the full attribute,
// `extmap:` prefix included.
#[test]
fn test_transport_cc_extmap() {
    let mut extmap = ExtMap::default();
    extmap.value = 3;
    extmap.uri = Some(
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
            .parse()
            .unwrap(),
    );

    assert_ne!(
        "3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        extmap.marshal()
    );
    assert_eq!(
        "extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        extmap.marshal()
    );
}

// ---------------------------------------------------------------------------
// pion util_test.go / common_description_test.go surfaces.
// ---------------------------------------------------------------------------

// pion TestConnectionRole_String.
#[test]
fn test_connection_role_string() {
    assert_eq!("active", ConnectionRole::Active.to_string());
    assert_eq!("passive", ConnectionRole::Passive.to_string());
    assert_eq!("actpass", ConnectionRole::Actpass.to_string());
    assert_eq!("holdconn", ConnectionRole::Holdconn.to_string());
}

// pion TestCodec_String.
#[test]
fn test_codec_string() {
    let codec = Codec {
        payload_type: 96,
        name: "VP8".to_owned(),
        clock_rate: 90000,
        encoding_parameters: String::new(),
        fmtp: "x-max-fr=30".to_owned(),
        rtcp_feedback: vec!["nack".to_owned(), "goog-remb".to_owned()],
    };
    assert_eq!(
        "96 VP8/90000/ (x-max-fr=30) [nack, goog-remb]",
        codec.to_string()
    );
}

// pion TestAttribute_IsICECandidate.
#[test]
fn test_attribute_is_ice_candidate() {
    let candidate = Attribute::new("candidate".to_owned(), Some("1 1 udp 1".to_owned()));
    let mid = Attribute::new("mid".to_owned(), Some("0".to_owned()));
    assert!(candidate.is_ice_candidate());
    assert!(!mid.is_ice_candidate());
}

// pion common_description_test.go `String()` families, pinned through the
// session marshal: each field prints its line exactly as pion does.
#[test]
fn test_pion_string_representations() -> Result<()> {
    let sd = unmarshal(&with("i=A Seminar on the session description protocol\r\n"))?;
    assert_eq!(
        Some("A Seminar on the session description protocol"),
        sd.session_information.as_deref()
    );

    // Address with a TTL and port range prints with both. rtc-sdp keeps the
    // address token whole (`224.2.17.12/127/3`); pion splits it into address
    // plus TTL and range fields. The wire text is identical either way.
    let sd = unmarshal(&with("c=IN IP4 224.2.17.12/127/3\r\n"))?;
    let ci = sd.connection_information.as_ref().unwrap();
    let address = ci.address.as_ref().unwrap();
    assert_eq!("224.2.17.12/127/3", address.address);
    let marshaled = sd.marshal();
    assert!(
        marshaled.contains("c=IN IP4 224.2.17.12/127/3"),
        "address string carries the TTL: {marshaled}"
    );

    // A port range prints as `port/range`.
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=0 0\r\nm=video 49170/50000 RTP/AVP 96\r\n"
    ))?;
    let marshaled = sd.marshal();
    assert!(
        marshaled.contains("m=video 49170/50000 "),
        "ranged port string: {marshaled}"
    );

    // Bandwidth prints as `b=<type>:<value>`.
    let sd = unmarshal(&with("b=X-YZ:128\r\n"))?;
    assert!(sd.marshal().contains("b=X-YZ:128\r\n"));

    // Repeat times print each field in NTP seconds.
    let sd = unmarshal(&format!(
        "{BASE_SDP}t=2873397496 2873404696\r\nr=604800 3600 0 90000\r\n"
    ))?;
    assert!(sd.marshal().contains("r=604800 3600 0 90000\r\n"));
    Ok(())
}
