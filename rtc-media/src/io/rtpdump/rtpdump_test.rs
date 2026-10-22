//! rtpdump tests ported from pion/webrtc v4.2.24 `pkg/media/rtpdump` (`reader_test.go`,
//! `writer_test.go`, `rtpdump_test.go`), plus the malformed-input and pion-fixture tests the
//! issue asks for.

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

const VALID_PREAMBLE: &[u8] = b"#!rtpplay1.0 224.2.0.1/3456\n";

fn header(start: SystemTime, source: Ipv4Addr, port: u16) -> Header {
    Header {
        start,
        source,
        port,
    }
}

fn packet(offset: Duration, is_rtcp: bool, payload: &[u8]) -> Packet {
    Packet {
        offset,
        is_rtcp,
        payload: payload.to_vec(),
    }
}

/// pion's `TestReader` table.
#[test]
fn test_rtpdump_reader() {
    struct Case {
        name: &'static str,
        data: Vec<u8>,
        want_header: Header,
        want_packets: Vec<Packet>,
        want_err: bool,
    }

    let cases = vec![
        Case {
            name: "empty",
            data: vec![],
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "hashbang missing ip/port",
            data: [
                b"#!rtpplay1.0 \n".as_slice(),
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "hashbang missing port",
            data: [
                b"#!rtpplay1.0 0.0.0.0\n".as_slice(),
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "valid empty file",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x22,
                    0xB8, 0x00, 0x00,
                ][..],
            ]
            .concat(),
            want_header: header(
                UNIX_EPOCH + Duration::from_secs(1),
                Ipv4Addr::new(1, 1, 1, 1),
                8888,
            ),
            want_packets: vec![],
            want_err: false,
        },
        Case {
            name: "malformed packet header",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                &[0x00][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "short packet payload",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                // packet header len=1048575
                &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
                // packet payload
                &[0x00][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "empty packet payload",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                // packet header len=0
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![],
            want_err: true,
        },
        Case {
            name: "valid rtcp packet",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                // packet header len=20, pLen=0, off=1
                &[0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..],
                // packet payload (BYE)
                &[
                    0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
                ][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![packet(
                Duration::from_millis(1),
                true,
                &[
                    0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
                ],
            )],
            want_err: false,
        },
        Case {
            name: "truncated rtcp packet",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                // packet header len=9, pLen=0, off=1
                &[0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..],
                // invalid payload
                &[0x81][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![packet(Duration::from_millis(1), true, &[0x81])],
            want_err: false,
        },
        Case {
            name: "two valid packets",
            data: [
                VALID_PREAMBLE,
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ][..],
                // packet header len=20, pLen=0, off=1
                &[0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..],
                // packet payload (BYE)
                &[
                    0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
                ][..],
                // packet header len=33, pLen=25, off=2
                &[0x00, 0x21, 0x00, 0x19, 0x00, 0x00, 0x00, 0x02][..],
                // packet payload (RTP)
                &[
                    0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00,
                    0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x9e,
                ][..],
            ]
            .concat(),
            want_header: header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
            want_packets: vec![
                packet(
                    Duration::from_millis(1),
                    true,
                    &[
                        0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
                    ],
                ),
                packet(
                    Duration::from_millis(2),
                    false,
                    &[
                        0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82,
                        0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88,
                        0x9e,
                    ],
                ),
            ],
            want_err: false,
        },
    ];

    for case in cases {
        match Reader::new(Cursor::new(&case.data[..])) {
            Err(e) => {
                assert!(case.want_err, "{}: unexpected open error: {e}", case.name);
            }
            Ok((mut reader, hdr)) => {
                assert_eq!(hdr, case.want_header, "{}: header", case.name);
                let mut packets = Vec::new();
                let mut next_err: Option<Error> = None;
                loop {
                    match reader.next_packet() {
                        Ok(Some(p)) => packets.push(p),
                        Ok(None) => break,
                        Err(e) => {
                            next_err = Some(e);
                            break;
                        }
                    }
                }
                if case.want_err {
                    assert!(next_err.is_some(), "{}: expected an error", case.name);
                } else {
                    assert!(
                        next_err.is_none(),
                        "{}: unexpected error: {}",
                        case.name,
                        next_err.unwrap()
                    );
                }
                assert_eq!(packets, case.want_packets, "{}: packets", case.name);
            }
        }
    }
}

/// pion's `TestWriter`.
#[test]
fn test_rtpdump_writer() -> Result<()> {
    let mut buf = Vec::new();
    let mut writer = Writer::new(
        &mut buf,
        &header(
            UNIX_EPOCH + Duration::from_secs(9),
            Ipv4Addr::new(2, 2, 2, 2),
            2222,
        ),
    )?;
    writer.write_packet(&packet(Duration::from_millis(1), false, &[9]))?;

    let expected = [
        b"#!rtpplay1.0 2.2.2.2/2222\n".as_slice(),
        // header
        &[0x00, 0x00, 0x00, 0x09][..],
        &[0x00, 0x00, 0x00, 0x00][..],
        &[0x02, 0x02, 0x02, 0x02][..],
        &[0x08, 0xae, 0x00, 0x00][..],
        // packet header
        &[0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01][..],
        &[0x09][..],
    ]
    .concat();
    assert_eq!(buf, expected);
    Ok(())
}

/// pion's `TestRoundTrip`.
#[test]
fn test_rtpdump_round_trip() -> Result<()> {
    let packets = vec![
        packet(Duration::from_millis(1), false, &[9]),
        packet(Duration::from_millis(999), true, &[9]),
    ];
    let hdr = header(
        UNIX_EPOCH + Duration::from_secs(9),
        Ipv4Addr::new(2, 2, 2, 2),
        2222,
    );

    let mut buf = Vec::new();
    {
        let mut writer = Writer::new(&mut buf, &hdr)?;
        for pkt in &packets {
            writer.write_packet(pkt)?;
        }
    }

    let (mut reader, hdr2) = Reader::new(Cursor::new(&buf))?;
    assert_eq!(hdr, hdr2, "round trip: header");

    let mut packets2 = Vec::new();
    while let Some(pkt) = reader.next_packet()? {
        packets2.push(pkt);
    }
    assert_eq!(packets, packets2, "round trip: packets");
    Ok(())
}

/// pion's `TestHeaderRoundTrip`.
#[test]
fn test_rtpdump_header_round_trip() -> Result<()> {
    let headers = vec![
        header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0),
        header(
            // time.Date(2019, 3, 25, 1, 1, 1, 0, time.UTC)
            UNIX_EPOCH + Duration::from_secs(1_553_470_861),
            Ipv4Addr::new(1, 2, 3, 4),
            8080,
        ),
    ];
    for hdr in headers {
        let data = hdr.marshal()?;
        assert_eq!(Header::unmarshal(&data)?, hdr);
    }
    Ok(())
}

/// pion's `TestMarshalHeader`. The "nil source" case degenerates to the unspecified address
/// here, which marshals to the same sixteen zero bytes.
#[test]
fn test_rtpdump_marshal_header() -> Result<()> {
    let hdr = header(UNIX_EPOCH, Ipv4Addr::UNSPECIFIED, 0);
    let data = hdr.marshal()?;
    assert_eq!(
        data,
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]
    );
    Ok(())
}

/// pion's `TestPacketRoundTrip`.
#[test]
fn test_rtpdump_packet_round_trip() -> Result<()> {
    let packets = vec![
        packet(Duration::from_millis(0), false, &[0]),
        packet(Duration::from_millis(0), true, &[0]),
        packet(Duration::from_millis(123), false, &[1, 2, 3, 4]),
    ];
    for pkt in packets {
        let data = pkt.marshal()?;
        assert_eq!(Packet::unmarshal(&data)?, pkt);
    }
    Ok(())
}

/// The malformed-input cases the issue lists, one each.
#[test]
fn test_rtpdump_reader_rejects_truncated_text_header() {
    // A valid preamble line, but the file ends before the 36-byte window is full.
    let data = b"#!rtpplay1.0 1.2.3.4/5\n";
    assert!(Reader::new(Cursor::new(&data[..])).is_err());
}

#[test]
fn test_rtpdump_reader_rejects_wrong_magic() {
    let data = [b"#!rtpplay2.0 1.2.3.4/5\n".as_slice(), &[0u8; 16][..]].concat();
    assert!(Reader::new(Cursor::new(&data[..])).is_err());
}

#[test]
fn test_rtpdump_reader_rejects_record_shorter_than_its_header() {
    let data = [
        VALID_PREAMBLE,
        &[0u8; 16][..],
        // packet header len=4, less than the 8-byte record header
        &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
        &[0xff; 8][..],
    ]
    .concat();
    let (mut reader, _) = Reader::new(Cursor::new(&data[..])).unwrap();
    assert!(matches!(
        reader.next_packet(),
        Err(Error::ErrRtpDumpMalformed)
    ));
}

#[test]
fn test_rtpdump_reader_rejects_record_longer_than_the_file() {
    let data = [
        VALID_PREAMBLE,
        &[0u8; 16][..],
        // packet header len=16, but only 2 payload bytes follow
        &[0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01][..],
        &[0xaa, 0xbb][..],
    ]
    .concat();
    let (mut reader, _) = Reader::new(Cursor::new(&data[..])).unwrap();
    assert!(matches!(
        reader.next_packet(),
        Err(Error::ErrRtpDumpMalformed)
    ));
}

#[test]
fn test_rtpdump_reader_rejects_plen_bigger_than_length() {
    let data = [
        VALID_PREAMBLE,
        &[0u8; 16][..],
        // packet header len=9, pLen=25: the record claims more packet bytes than it holds
        &[0x00, 0x09, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01][..],
        &[0x90, 0x60][..],
    ]
    .concat();
    let (mut reader, _) = Reader::new(Cursor::new(&data[..])).unwrap();
    assert!(matches!(
        reader.next_packet(),
        Err(Error::ErrRtpDumpMalformed)
    ));
}

#[test]
fn test_rtpdump_reader_rejects_zero_length_payload() {
    let data = [
        VALID_PREAMBLE,
        &[0u8; 16][..],
        // packet header len=8: no payload bytes at all
        &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..],
    ]
    .concat();
    let (mut reader, _) = Reader::new(Cursor::new(&data[..])).unwrap();
    assert!(matches!(
        reader.next_packet(),
        Err(Error::ErrRtpDumpMalformed)
    ));
}

/// A dump written by pion's own writer (v4.2.24): the reader parses it into the same header and
/// packets, and this writer reproduces it byte for byte.
#[test]
fn test_rtpdump_pion_fixture_round_trip() -> Result<()> {
    let data = include_bytes!("testdata/pion.rtpdump");

    let (mut reader, hdr) = Reader::new(Cursor::new(&data[..]))?;
    assert_eq!(
        hdr,
        header(
            UNIX_EPOCH + Duration::from_secs(9) + Duration::from_micros(5_000),
            Ipv4Addr::new(2, 2, 2, 2),
            2222
        )
    );

    let mut packets = Vec::new();
    while let Some(pkt) = reader.next_packet()? {
        packets.push(pkt);
    }
    assert_eq!(
        packets,
        vec![
            packet(
                Duration::from_millis(1),
                false,
                &[
                    0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00,
                    0x01, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x98, 0x36, 0xbe, 0x88, 0x9e,
                ],
            ),
            packet(
                Duration::from_millis(2),
                true,
                &[
                    0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
                ],
            ),
            packet(
                Duration::from_millis(13_571_267),
                false,
                &[1, 2, 3, 4, 5, 6, 7, 8]
            ),
        ]
    );

    // Re-writing what was read reproduces the file exactly.
    let mut rewritten = Vec::new();
    {
        let mut writer = Writer::new(&mut rewritten, &hdr)?;
        for pkt in &packets {
            writer.write_packet(pkt)?;
        }
    }
    assert_eq!(rewritten, data);
    Ok(())
}
