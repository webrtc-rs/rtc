use super::record_layer_header::*;
use super::*;
use crate::change_cipher_spec::ChangeCipherSpec;

use std::io::{BufReader, BufWriter};

#[test]
fn test_udp_decode() -> Result<()> {
    let tests = vec![
        (
            "Change Cipher Spec, single packet",
            vec![
                0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
            ],
            vec![vec![
                0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
            ]],
            None,
        ),
        (
            "Change Cipher Spec, multi packet",
            vec![
                0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
                0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
            ],
            vec![
                vec![
                    0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01,
                    0x01,
                ],
                vec![
                    0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01,
                    0x01,
                ],
            ],
            None,
        ),
        (
            "Invalid packet length",
            vec![0x14, 0xfe],
            vec![],
            Some(Error::ErrInvalidPacketLength),
        ),
        (
            "Packet declared invalid length",
            vec![
                0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01,
            ],
            vec![],
            Some(Error::ErrInvalidPacketLength),
        ),
    ];

    for (name, data, wanted, wanted_err) in tests {
        let dtls_pkts = unpack_datagram(&data);
        if let Some(err) = wanted_err {
            if let Err(dtls) = dtls_pkts {
                assert_eq!(err.to_string(), dtls.to_string());
            } else {
                panic!("something wrong for {name} when wanted_err is Some");
            }
        } else if let Ok(pkts) = dtls_pkts {
            assert_eq!(
                wanted, pkts,
                "{name} UDP decode: got {pkts:?}, want {wanted:?}",
            );
        } else {
            panic!("something wrong for {name} when wanted_err is None");
        }
    }

    Ok(())
}

#[test]
fn test_record_layer_round_trip() -> Result<()> {
    let tests = vec![(
        "Change Cipher Spec, single packet",
        vec![
            0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
        ],
        RecordLayer {
            record_layer_header: RecordLayerHeader {
                content_type: ContentType::ChangeCipherSpec,
                protocol_version: ProtocolVersion {
                    major: 0xfe,
                    minor: 0xff,
                },
                epoch: 0,
                sequence_number: 18,
                content_len: 1,
            },
            content: Content::ChangeCipherSpec(ChangeCipherSpec {}),
        },
    )];

    for (name, data, want) in tests {
        let mut reader = BufReader::new(data.as_slice());
        let r = RecordLayer::unmarshal(&mut reader)?;

        assert_eq!(
            want, r,
            "{name} recordLayer.unmarshal: got {r:?}, want {want:?}"
        );

        let mut data2 = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(data2.as_mut());
            r.marshal(&mut writer)?;
        }
        assert_eq!(
            data, data2,
            "{name} recordLayer.marshal: got {data2:?}, want {data:?}"
        );
    }

    Ok(())
}

// Port of pion `pkg/protocol` `TestVersionEqual`.
#[test]
fn test_version_equal() {
    let tests = [
        (
            "same-1.0",
            ProtocolVersion {
                major: 0xfe,
                minor: 0xff,
            },
            ProtocolVersion {
                major: 0xfe,
                minor: 0xff,
            },
            true,
        ),
        (
            "same-1.2",
            PROTOCOL_VERSION1_2,
            PROTOCOL_VERSION1_2,
            true,
        ),
        (
            "same-1.3",
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfc,
            },
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfc,
            },
            true,
        ),
        (
            "diff-major",
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfd,
            },
            ProtocolVersion {
                major: 0xff,
                minor: 0xfd,
            },
            false,
        ),
        (
            "diff-minor",
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfd,
            },
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfc,
            },
            false,
        ),
        (
            "completely-diff",
            ProtocolVersion {
                major: 0x03,
                minor: 0x03,
            },
            ProtocolVersion {
                major: 0xfe,
                minor: 0xff,
            },
            false,
        ),
    ];

    for (name, a, b, want) in tests {
        assert_eq!(a.equal(b), want, "Equal({a:?},{b:?}) for {name}");
    }
}

// Port of pion `pkg/protocol` `TestIsSupportedBytes`: only DTLS 1.2 is supported.
#[test]
fn test_is_supported_bytes() {
    let cases = [
        (0xfe, 0xfd, true),  // DTLS 1.2
        (0xfe, 0xfc, false), // DTLS 1.3 (WIP)
        (0xfe, 0xff, false), // DTLS 1.0 not supported
        (0x03, 0x03, false), // TLS 1.2, not DTLS
        (0x00, 0x00, false),
    ];

    for (major, minor, want) in cases {
        assert_eq!(
            is_supported_bytes(major, minor),
            want,
            "IsSupportedBytes({major:#04x},{minor:#04x})"
        );
    }
}

// Port of pion `pkg/protocol` `TestIsSupportedVersion`.
#[test]
fn test_is_supported_version() {
    let cases = [
        (PROTOCOL_VERSION1_2, true),
        // DTLS 1.3 (WIP)
        (
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfc,
            },
            false,
        ),
        // DTLS 1.0, not supported
        (PROTOCOL_VERSION1_0, false),
        // TLS 1.2, not DTLS
        (
            ProtocolVersion {
                major: 0x03,
                minor: 0x03,
            },
            false,
        ),
    ];

    for (version, want) in cases {
        assert_eq!(is_supported_version(version), want, "IsSupportedVersion({version:?})");
    }
}

// Port of pion `pkg/protocol` `TestIsValidBytes`: feff (1.0), fefd (1.2) and fefc (1.3) are
// valid DTLS versions per RFC 9147 §5.3, whether or not they are supported.
#[test]
fn test_is_valid_bytes() {
    let cases = [
        (0xfe, 0xff, true),  // DTLS 1.0 (valid, though not supported)
        (0xfe, 0xfd, true),  // DTLS 1.2
        (0xfe, 0xfc, true),  // DTLS 1.3
        (0xfe, 0x00, false), // invalid
        (0x03, 0x03, false), // TLS 1.2, invalid
    ];

    for (major, minor, want) in cases {
        assert_eq!(
            is_valid_bytes(major, minor),
            want,
            "IsValidBytes({major:#04x},{minor:#04x})"
        );
    }
}

// Port of pion `pkg/protocol` `TestIsValidVersion`.
#[test]
fn test_is_valid_version() {
    let cases = [
        (PROTOCOL_VERSION1_0, true),
        (PROTOCOL_VERSION1_2, true),
        (
            ProtocolVersion {
                major: 0xfe,
                minor: 0xfc,
            },
            true,
        ),
        // invalid
        (
            ProtocolVersion {
                major: 0xfe,
                minor: 0x00,
            },
            false,
        ),
        // TLS 1.2
        (
            ProtocolVersion {
                major: 0x03,
                minor: 0x03,
            },
            false,
        ),
    ];

    for (version, want) in cases {
        assert_eq!(is_valid_version(version), want, "IsValidVersion({version:?})");
    }
}
