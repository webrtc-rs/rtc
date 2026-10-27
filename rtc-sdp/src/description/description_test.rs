use super::common::*;
use super::media::*;
use super::session::*;
use shared::error::{Error, Result};

use std::io::Cursor;

const CANONICAL_MARSHAL_SDP: &str = "v=0\r\n\
     o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
     s=SDP Seminar\r\n\
     i=A Seminar on the session description protocol\r\n\
     u=http://www.example.com/seminars/sdp.pdf\r\n\
     e=j.doe@example.com (Jane Doe)\r\n\
     p=+1 617 555-6011\r\n\
     c=IN IP4 224.2.17.12/127\r\n\
     b=X-YZ:128\r\n\
     b=AS:12345\r\n\
     t=2873397496 2873404696\r\n\
     t=3034423619 3042462419\r\n\
     r=604800 3600 0 90000\r\n\
     z=2882844526 -3600 2898848070 0\r\n\
     k=prompt\r\n\
     a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host\r\n\
     a=recvonly\r\n\
     m=audio 49170 RTP/AVP 0\r\n\
     i=Vivamus a posuere nisl\r\n\
     c=IN IP4 203.0.113.1\r\n\
     b=X-YZ:128\r\n\
     k=prompt\r\n\
     a=sendrecv\r\n\
     m=video 51372 RTP/AVP 99\r\n\
     a=rtpmap:99 h263-1998/90000\r\n";

#[test]
fn test_unmarshal_marshal() -> Result<()> {
    let input = CANONICAL_MARSHAL_SDP;
    let mut reader = Cursor::new(input.as_bytes());
    let sdp = SessionDescription::unmarshal(&mut reader)?;
    let output = sdp.marshal();
    assert_eq!(output, input);

    Ok(())
}

#[test]
fn test_marshal() -> Result<()> {
    let sd = SessionDescription {
        version: 0,
        origin: Origin {
            username: "jdoe".to_string(),
            session_id: 2890844526,
            session_version: 2890842807,
            network_type: "IN".into(),
            address_type: "IP4".into(),
            unicast_address: "10.47.16.5".to_string(),
        },
        session_name: "SDP Seminar".to_string(),
        session_information: Some("A Seminar on the session description protocol".to_string()),
        uri: Some("http://www.example.com/seminars/sdp.pdf".to_owned()),
        email_address: Some("j.doe@example.com (Jane Doe)".to_string()),
        phone_number: Some("+1 617 555-6011".to_string()),
        connection_information: Some(ConnectionInformation {
            network_type: "IN".into(),
            address_type: "IP4".into(),
            address: Some(Address {
                address: "224.2.17.12".into(),
                ttl: Some(127),
                range: None,
            }),
        }),
        bandwidth: vec![
            Bandwidth {
                experimental: true,
                bandwidth_type: "YZ".to_string(),
                bandwidth: 128,
            },
            Bandwidth {
                experimental: false,
                bandwidth_type: "AS".to_string(),
                bandwidth: 12345,
            },
        ],
        time_descriptions: vec![
            TimeDescription {
                timing: Timing {
                    start_time: 2873397496,
                    stop_time: 2873404696,
                },
                repeat_times: vec![],
            },
            TimeDescription {
                timing: Timing {
                    start_time: 3034423619,
                    stop_time: 3042462419,
                },
                repeat_times: vec![RepeatTime {
                    interval: 604800,
                    duration: 3600,
                    offsets: vec![0, 90000],
                }],
            },
        ],
        time_zones: vec![
            TimeZone {
                adjustment_time: 2882844526,
                offset: -3600,
            },
            TimeZone {
                adjustment_time: 2898848070,
                offset: 0,
            },
        ],
        encryption_key: Some("prompt".to_string()),
        attributes: vec![
            Attribute::new(
                "candidate".to_string(),
                Some("0 1 UDP 2113667327 203.0.113.1 54400 typ host".to_string()),
            ),
            Attribute::new("recvonly".to_string(), None),
        ],
        media_descriptions: vec![
            MediaDescription {
                media_name: MediaName {
                    media: "audio".into(),
                    port: RangedPort {
                        value: 49170,
                        range: None,
                    },
                    protos: vec!["RTP".into(), "AVP".into()],
                    formats: vec!["0".into()],
                },
                media_title: Some("Vivamus a posuere nisl".to_string()),
                connection_information: Some(ConnectionInformation {
                    network_type: "IN".into(),
                    address_type: "IP4".into(),
                    address: Some(Address {
                        address: "203.0.113.1".into(),
                        ttl: None,
                        range: None,
                    }),
                }),
                bandwidth: vec![Bandwidth {
                    experimental: true,
                    bandwidth_type: "YZ".to_string(),
                    bandwidth: 128,
                }],
                encryption_key: Some("prompt".to_string()),
                attributes: vec![Attribute::new("sendrecv".to_string(), None)],
            },
            MediaDescription {
                media_name: MediaName {
                    media: "video".into(),
                    port: RangedPort {
                        value: 51372,
                        range: None,
                    },
                    protos: vec!["RTP".into(), "AVP".into()],
                    formats: vec!["99".into()],
                },
                media_title: None,
                connection_information: None,
                bandwidth: vec![],
                encryption_key: None,
                attributes: vec![Attribute::new(
                    "rtpmap".to_string(),
                    Some("99 h263-1998/90000".to_string()),
                )],
            },
        ],
    };

    let actual = sd.marshal();
    assert!(
        actual == CANONICAL_MARSHAL_SDP,
        "error:\n\nEXPECTED:\n{CANONICAL_MARSHAL_SDP}\nACTUAL:\n{actual}!!!!\n"
    );

    Ok(())
}

const BASE_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n";

const SESSION_INFORMATION_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
i=A Seminar on the session description protocol\r\n\
t=3034423619 3042462419\r\n";

// https://tools.ietf.org/html/rfc4566#section-5
// Parsers SHOULD be tolerant and also accept records terminated
// with a single newline character.
const SESSION_INFORMATION_SDPLFONLY: &str = "v=0\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\n\
s=SDP Seminar\n\
i=A Seminar on the session description protocol\n\
t=3034423619 3042462419\n";

// SessionInformationSDPCROnly = "v=0\r" +
// 	"o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r" +
// 	"s=SDP Seminar\r"
// 	"i=A Seminar on the session description protocol\r" +
// 	"t=3034423619 3042462419\r"

// Other SDP parsers (e.g. one in VLC media player) allow
// empty lines.
const SESSION_INFORMATION_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
\r\n\
s=SDP Seminar\r\n\
\r\n\
i=A Seminar on the session description protocol\r\n\
\r\n\
t=3034423619 3042462419\r\n\
\r\n";

const URI_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
u=http://www.example.com/seminars/sdp.pdf\r\n\
t=3034423619 3042462419\r\n";

const EMAIL_ADDRESS_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
e=j.doe@example.com (Jane Doe)\r\n\
t=3034423619 3042462419\r\n";

const PHONE_NUMBER_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
p=+1 617 555-6011\r\n\
t=3034423619 3042462419\r\n";

const SESSION_CONNECTION_INFORMATION_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
c=IN IP4 224.2.17.12/127\r\n\
t=3034423619 3042462419\r\n";

const SESSION_BANDWIDTH_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
b=X-YZ:128\r\n\
b=AS:12345\r\n\
t=3034423619 3042462419\r\n";

const TIMING_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n";

// Short hand time notation is converted into NTP timestamp format in
// seconds. Because of that unittest comparisons will fail as the same time
// will be expressed in different units.
const REPEAT_TIMES_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=604800 3600 0 90000\r\n\
r=3d 2h 0 21h\r\n";

const REPEAT_TIMES_SDPEXPECTED: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=604800 3600 0 90000\r\n\
r=259200 7200 0 75600\r\n";

const REPEAT_TIMES_OVERFLOW_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=604800 3600 0 90000\r\n\
r=106751991167301d 2h 0 21h\r\n";

const REPEAT_TIMES_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=604800 3600 0 90000\r\n\
r=259200 7200 0 75600\r\n\
\r\n";

// The expected value looks a bit different for the same reason as mentioned
// above regarding RepeatTimes.
const TIME_ZONES_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=2882844526 -1h 2898848070 0\r\n";

const TIME_ZONES_SDPEXPECTED: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
r=2882844526 -3600 2898848070 0\r\n";

const TIME_ZONES_SDP2: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
z=2882844526 -3600 2898848070 0\r\n";

const TIME_ZONES_SDP2EXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
z=2882844526 -3600 2898848070 0\r\n\
\r\n";

const SESSION_ENCRYPTION_KEY_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
k=prompt\r\n";

const SESSION_ENCRYPTION_KEY_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
k=prompt\r\n
\r\n";

const SESSION_ATTRIBUTES_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
a=rtpmap:96 opus/48000\r\n";

const MEDIA_NAME_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n";

const MEDIA_NAME_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n
\r\n";

// RFC 8866 section 5.14: the <proto> sub-field of the media ("m=") line is an
// extensible, IANA-registered token, not a closed set. These are all valid,
// registered transports that a strict allowlist wrongly rejects:
//   UDP/BFCP        (RFC 8856)
//   TCP/DTLS/SCTP   (RFC 8841, data channels over ICE-TCP)
//   UDP/UDT/IX, UDP/FEC, TCP/MRCPv2 (mirrors pion/sdp's real-world fixtures)
//   FOO             (a single unregistered token: accept-any must allow it too)
const MEDIA_NAME_UNCOMMON_PROTOS_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=application 3238 UDP/BFCP *\r\n\
m=application 9 TCP/DTLS/SCTP webrtc-datachannel\r\n\
m=application 2455 UDP/UDT/IX *\r\n\
m=application 50178 UDP/FEC *\r\n\
m=application 1544 TCP/MRCPv2 1\r\n\
m=audio 9 FOO 0\r\n";

// A genuinely malformed proto (an empty "/"-separated token) must still error.
const MEDIA_NAME_EMPTY_PROTO_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=audio 9 // 0\r\n";

// A real WebRTC offer generated by Safari 26.5.2 on macOS (captured via a local
// RTCPeerConnection.createOffer with audio + video transceivers and a data
// channel). Frozen here as a regression fixture: it must always parse.
const REAL_SAFARI_OFFER_SDP: &str = include_str!("testdata/safari_offer.sdp");

const MEDIA_TITLE_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
i=Vivamus a posuere nisl\r\n";

const MEDIA_CONNECTION_INFORMATION_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
c=IN IP4 203.0.113.1\r\n";

const MEDIA_CONNECTION_INFORMATION_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
c=IN IP4 203.0.113.1\r\n\
\r\n";

const MEDIA_DESCRIPTION_OUT_OF_ORDER_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
a=rtpmap:99 h263-1998/90000\r\n\
a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host\r\n\
c=IN IP4 203.0.113.1\r\n\
i=Vivamus a posuere nisl\r\n";

const MEDIA_DESCRIPTION_OUT_OF_ORDER_SDPACTUAL: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
i=Vivamus a posuere nisl\r\n\
c=IN IP4 203.0.113.1\r\n\
a=rtpmap:99 h263-1998/90000\r\n\
a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host\r\n";

const MEDIA_BANDWIDTH_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
b=X-YZ:128\r\n\
b=AS:12345\r\n";

const MEDIA_TRANSPORT_BANDWIDTH_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
b=AS:12345\r\n\
b=TIAS:12345\r\n";

const MEDIA_ENCRYPTION_KEY_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
k=prompt\r\n";

const MEDIA_ENCRYPTION_KEY_SDPEXTRA_CRLF: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
k=prompt\r\n\
\r\n";

const MEDIA_ATTRIBUTES_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=2873397496 2873404696\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 54400 RTP/SAVPF 0 96\r\n\
a=rtpmap:99 h263-1998/90000\r\n\
a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host\r\n\
a=rtcp-fb:97 ccm fir\r\n\
a=rtcp-fb:97 nack\r\n\
a=rtcp-fb:97 nack pli\r\n";

const CANONICAL_UNMARSHAL_SDP: &str = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
i=A Seminar on the session description protocol\r\n\
u=http://www.example.com/seminars/sdp.pdf\r\n\
e=j.doe@example.com (Jane Doe)\r\n\
p=+1 617 555-6011\r\n\
c=IN IP4 224.2.17.12/127\r\n\
b=X-YZ:128\r\n\
b=AS:12345\r\n\
t=2873397496 2873404696\r\n\
t=3034423619 3042462419\r\n\
r=604800 3600 0 90000\r\n\
z=2882844526 -3600 2898848070 0\r\n\
k=prompt\r\n\
a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host\r\n\
a=recvonly\r\n\
m=audio 49170 RTP/AVP 0\r\n\
i=Vivamus a posuere nisl\r\n\
c=IN IP4 203.0.113.1\r\n\
b=X-YZ:128\r\n\
k=prompt\r\n\
a=sendrecv\r\n\
m=video 51372 RTP/AVP 99\r\n\
a=rtpmap:99 h263-1998/90000\r\n";

#[test]
fn test_round_trip() -> Result<()> {
    let tests = vec![
        (
            "SessionInformationSDPLFOnly",
            SESSION_INFORMATION_SDPLFONLY,
            Some(SESSION_INFORMATION_SDP),
        ),
        (
            "SessionInformationSDPExtraCRLF",
            SESSION_INFORMATION_SDPEXTRA_CRLF,
            Some(SESSION_INFORMATION_SDP),
        ),
        ("SessionInformation", SESSION_INFORMATION_SDP, None),
        ("URI", URI_SDP, None),
        ("EmailAddress", EMAIL_ADDRESS_SDP, None),
        ("PhoneNumber", PHONE_NUMBER_SDP, None),
        (
            "RepeatTimesSDPExtraCRLF",
            REPEAT_TIMES_SDPEXTRA_CRLF,
            Some(REPEAT_TIMES_SDPEXPECTED),
        ),
        (
            "SessionConnectionInformation",
            SESSION_CONNECTION_INFORMATION_SDP,
            None,
        ),
        ("SessionBandwidth", SESSION_BANDWIDTH_SDP, None),
        ("SessionEncryptionKey", SESSION_ENCRYPTION_KEY_SDP, None),
        (
            "SessionEncryptionKeyExtraCRLF",
            SESSION_ENCRYPTION_KEY_SDPEXTRA_CRLF,
            Some(SESSION_ENCRYPTION_KEY_SDP),
        ),
        ("SessionAttributes", SESSION_ATTRIBUTES_SDP, None),
        (
            "TimeZonesSDP2ExtraCRLF",
            TIME_ZONES_SDP2EXTRA_CRLF,
            Some(TIME_ZONES_SDP2),
        ),
        ("MediaName", MEDIA_NAME_SDP, None),
        (
            "MediaNameExtraCRLF",
            MEDIA_NAME_SDPEXTRA_CRLF,
            Some(MEDIA_NAME_SDP),
        ),
        (
            "MediaNameUncommonProtos",
            MEDIA_NAME_UNCOMMON_PROTOS_SDP,
            None,
        ),
        ("MediaTitle", MEDIA_TITLE_SDP, None),
        (
            "MediaConnectionInformation",
            MEDIA_CONNECTION_INFORMATION_SDP,
            None,
        ),
        (
            "MediaConnectionInformationExtraCRLF",
            MEDIA_CONNECTION_INFORMATION_SDPEXTRA_CRLF,
            Some(MEDIA_CONNECTION_INFORMATION_SDP),
        ),
        (
            "MediaDescriptionOutOfOrder",
            MEDIA_DESCRIPTION_OUT_OF_ORDER_SDP,
            Some(MEDIA_DESCRIPTION_OUT_OF_ORDER_SDPACTUAL),
        ),
        ("MediaBandwidth", MEDIA_BANDWIDTH_SDP, None),
        (
            "MediaTransportBandwidth",
            MEDIA_TRANSPORT_BANDWIDTH_SDP,
            None,
        ),
        ("MediaEncryptionKey", MEDIA_ENCRYPTION_KEY_SDP, None),
        (
            "MediaEncryptionKeyExtraCRLF",
            MEDIA_ENCRYPTION_KEY_SDPEXTRA_CRLF,
            Some(MEDIA_ENCRYPTION_KEY_SDP),
        ),
        ("MediaAttributes", MEDIA_ATTRIBUTES_SDP, None),
        ("CanonicalUnmarshal", CANONICAL_UNMARSHAL_SDP, None),
    ];

    for (name, sdp_str, expected) in tests {
        let mut reader = Cursor::new(sdp_str.as_bytes());
        let sdp = SessionDescription::unmarshal(&mut reader);
        if let Ok(sdp) = sdp {
            let actual = sdp.marshal();
            if let Some(expected) = expected {
                assert_eq!(actual.as_str(), expected, "{name}\n{sdp_str}");
            } else {
                assert_eq!(actual.as_str(), sdp_str, "{name}\n{sdp_str}");
            }
        } else {
            panic!("{name}\n{sdp_str}");
        }
    }

    Ok(())
}

#[test]
fn test_unmarshal_repeat_times() -> Result<()> {
    let mut reader = Cursor::new(REPEAT_TIMES_SDP.as_bytes());
    let sdp = SessionDescription::unmarshal(&mut reader)?;
    let actual = sdp.marshal();
    assert_eq!(actual.as_str(), REPEAT_TIMES_SDPEXPECTED);
    Ok(())
}

#[test]
fn test_unmarshal_repeat_times_overflow() -> Result<()> {
    let mut reader = Cursor::new(REPEAT_TIMES_OVERFLOW_SDP.as_bytes());
    let result = SessionDescription::unmarshal(&mut reader);
    assert!(result.is_err());
    assert_eq!(
        Error::SdpInvalidValue("106751991167301d".to_owned()),
        result.unwrap_err()
    );
    Ok(())
}

#[test]
fn test_unmarshal_time_zones() -> Result<()> {
    let mut reader = Cursor::new(TIME_ZONES_SDP.as_bytes());
    let sdp = SessionDescription::unmarshal(&mut reader)?;
    let actual = sdp.marshal();
    assert_eq!(actual.as_str(), TIME_ZONES_SDPEXPECTED);
    Ok(())
}

#[test]
fn test_unmarshal_non_nil_address() -> Result<()> {
    let input = "v=0\r\no=0 0 0 IN IP4 0\r\ns=0\r\nc=IN IP4\r\nt=0 0\r\n";
    let mut reader = Cursor::new(input);
    let sdp = SessionDescription::unmarshal(&mut reader);
    if let Ok(sdp) = sdp {
        let output = sdp.marshal();
        assert_eq!(output.as_str(), input);
    } else {
        panic!("{}", input);
    }
    Ok(())
}

// RFC 8866 section 5.14: <proto> is an extensible, IANA-registered transport
// token, so the parser must accept protocols beyond the RTP/SAVPF set instead
// of rejecting them, and must round-trip them unchanged.
#[test]
fn test_unmarshal_media_uncommon_protos() -> Result<()> {
    let mut reader = Cursor::new(MEDIA_NAME_UNCOMMON_PROTOS_SDP.as_bytes());
    let sdp = SessionDescription::unmarshal(&mut reader)?;

    assert_eq!(sdp.media_descriptions.len(), 6);
    assert_eq!(
        sdp.media_descriptions[0].media_name.protos,
        vec!["UDP".to_owned(), "BFCP".to_owned()]
    );
    assert_eq!(
        sdp.media_descriptions[1].media_name.protos,
        vec!["TCP".to_owned(), "DTLS".to_owned(), "SCTP".to_owned()]
    );
    assert_eq!(
        sdp.media_descriptions[2].media_name.protos,
        vec!["UDP".to_owned(), "UDT".to_owned(), "IX".to_owned()]
    );
    // A single unregistered proto token is also accepted (was rejected before).
    assert_eq!(
        sdp.media_descriptions[5].media_name.protos,
        vec!["FOO".to_owned()]
    );

    let actual = sdp.marshal();
    assert_eq!(actual.as_str(), MEDIA_NAME_UNCOMMON_PROTOS_SDP);
    Ok(())
}

// A malformed proto with an empty "/"-separated token (e.g. "//") must still be
// rejected, so accepting unknown protos does not swallow genuinely broken input.
#[test]
fn test_unmarshal_media_empty_proto_errors() -> Result<()> {
    let mut reader = Cursor::new(MEDIA_NAME_EMPTY_PROTO_SDP.as_bytes());
    let result = SessionDescription::unmarshal(&mut reader);
    assert!(result.is_err());
    assert_eq!(Error::SdpInvalidValue("//".to_owned()), result.unwrap_err());
    Ok(())
}

// A genuine offer captured from Safari 26.5.2 on macOS must parse. Its m-lines
// use only UDP/TLS/RTP/SAVPF and UDP/DTLS/SCTP, so this passes with or without
// the proto-allowlist change -- it empirically confirms that the common Safari
// SDP already parses, and guards against future regressions on real browser
// output. We assert the parsed structure (the durable part) plus that the
// remarshaled output re-parses to the same shape (marshal sanity), rather than
// pinning the exact byte formatting of a captured file.
#[test]
fn test_unmarshal_real_safari_offer() -> Result<()> {
    let mut reader = Cursor::new(REAL_SAFARI_OFFER_SDP.as_bytes());
    let sdp = SessionDescription::unmarshal(&mut reader)?;

    assert_eq!(sdp.media_descriptions.len(), 3);
    assert_eq!(sdp.media_descriptions[0].media_name.media, "audio");
    assert_eq!(
        sdp.media_descriptions[0].media_name.protos,
        vec![
            "UDP".to_owned(),
            "TLS".to_owned(),
            "RTP".to_owned(),
            "SAVPF".to_owned()
        ]
    );
    assert_eq!(sdp.media_descriptions[1].media_name.media, "video");
    assert_eq!(sdp.media_descriptions[2].media_name.media, "application");
    assert_eq!(
        sdp.media_descriptions[2].media_name.protos,
        vec!["UDP".to_owned(), "DTLS".to_owned(), "SCTP".to_owned()]
    );

    // Marshalling produces output that re-parses to the same structure.
    let mut reader = Cursor::new(sdp.marshal().into_bytes());
    let reparsed = SessionDescription::unmarshal(&mut reader)?;
    assert_eq!(reparsed.media_descriptions.len(), 3);
    assert_eq!(
        reparsed.media_descriptions[2].media_name.protos,
        sdp.media_descriptions[2].media_name.protos
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// `unmarshal_slice`, and the scan that sizes the attribute lists before they are filled.

const TWO_SECTIONS: &str = "v=0\r\n\
o=- 1 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1\r\n\
a=ice-lite\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=sendrecv\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n\
a=rtpmap:96 VP8/90000\r\n";

#[test]
fn test_unmarshal_slice_matches_the_reader() {
    let from_slice = SessionDescription::unmarshal_slice(TWO_SECTIONS.as_bytes()).unwrap();
    let from_reader =
        SessionDescription::unmarshal(&mut std::io::Cursor::new(TWO_SECTIONS.as_bytes())).unwrap();
    assert_eq!(from_slice.marshal(), from_reader.marshal());
    assert_eq!(from_slice.marshal(), TWO_SECTIONS);
}

#[test]
fn test_unmarshal_reads_from_the_reader_position() {
    // The buffer is sized from what is left to read, not from the start of the stream.
    let mut reader = std::io::Cursor::new(format!("junk\n{TWO_SECTIONS}").into_bytes());
    reader.set_position(5);
    let parsed = SessionDescription::unmarshal(&mut reader).unwrap();
    assert_eq!(parsed.marshal(), TWO_SECTIONS);
}

#[test]
fn test_unmarshal_slice_rejects_what_the_reader_rejects() {
    for bad in [
        "",
        "v=0\r\n",
        "v=1\r\n",
        "garbage",
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n",
    ] {
        assert_eq!(
            SessionDescription::unmarshal_slice(bad.as_bytes()).is_err(),
            SessionDescription::unmarshal(&mut std::io::Cursor::new(bad.as_bytes())).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn test_attribute_lists_hold_exactly_the_attributes_of_each_section() {
    let parsed = SessionDescription::unmarshal_slice(TWO_SECTIONS.as_bytes()).unwrap();
    let keys = |attrs: &[Attribute]| attrs.iter().map(|a| a.key.to_string()).collect::<Vec<_>>();
    assert_eq!(keys(&parsed.attributes), ["group", "ice-lite"]);
    assert_eq!(
        keys(&parsed.media_descriptions[0].attributes),
        ["mid", "rtpmap", "sendrecv"]
    );
    assert_eq!(
        keys(&parsed.media_descriptions[1].attributes),
        ["mid", "rtpmap"]
    );
    // The m= line's formats were sized from the line too.
    assert_eq!(
        parsed.media_descriptions[1].media_name.formats,
        ["96", "97", "98"]
    );
}

#[test]
fn test_line_endings_and_look_alike_lines_do_not_miscount_attributes() {
    // Bare LF, an `a=` inside a value, a section without attributes, and `m=` inside a value.
    let sdp = "v=0\no=- 1 2 IN IP4 127.0.0.1\ns=-\nt=0 0\n\
               a=x:a=b\n\
               m=audio 9 RTP/AVP 0\n\
               i=a=not an attribute m=nor a section\n\
               m=video 9 RTP/AVP 96\n\
               a=y\n";
    let parsed = SessionDescription::unmarshal_slice(sdp.as_bytes()).unwrap();
    assert_eq!(parsed.attributes.len(), 1);
    assert_eq!(parsed.attributes[0].value.as_deref(), Some("a=b"));
    assert!(parsed.media_descriptions[0].attributes.is_empty());
    assert_eq!(parsed.media_descriptions[1].attributes.len(), 1);
}

#[test]
fn test_short_m_line_fields_are_stored_inline_and_long_ones_survive() {
    let long_proto = "UDP/TLS/RTP/SAVPF/WITH/A/RATHER/LONG/PROTOCOL/LIST";
    let sdp =
        format!("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 {long_proto} 0\r\n");
    let parsed = SessionDescription::unmarshal_slice(sdp.as_bytes()).unwrap();
    let name = &parsed.media_descriptions[0].media_name;
    assert_eq!(name.media, "audio");
    assert_eq!(name.protos.join("/"), long_proto);
    assert_eq!(name.formats, ["0"]);
}
