//! Ported from pion/dtls v3.1.15 `pkg/protocol/handshake/message_certificate_13_test.go`.
//!
//! pion generates the two `parseCertificateEntry` fixtures with `crypto/x509`; here the same
//! self-signed certificates come from `rcgen`, and the X.509 checks run through `x509-parser`.

use super::*;

use crate::extension::extension_server_name::*;
use crate::extension::*;

use der_parser::oid;
use der_parser::oid::Oid;
use std::io::{BufReader, BufWriter};

/// The X.509 signature-algorithm OID for ECDSA with SHA-256, which pion checks the fixture
/// certificate is signed with.
const OID_ECDSA_WITH_SHA256: Oid<'static> = oid!(1.2.840.10045.4.3.2);

/// The same certificate as `test_handshake_message_certificate` (DTLS 1.2) carries: pion's
/// 393-byte ECDSA fixture.
fn cert_der() -> Vec<u8> {
    vec![
        0x30, 0x82, 0x01, 0x85, 0x30, 0x82, 0x01, 0x2b, 0x02, 0x14, //
        0x7d, 0x00, 0xcf, 0x07, 0xfc, 0xe2, 0xb6, 0xb8, 0x3f, 0x72, 0xeb, 0x11, 0x36, 0x1b, 0xf6,
        0x39, //
        0xf1, 0x3c, 0x33, 0x41, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, //
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55,
        0x31, //
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d,
        0x53, //
        0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18,
        0x49, //
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73,
        0x20, //
        0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30,
        0x32, //
        0x35, 0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32,
        0x35, //
        0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, //
        0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, //
        0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f,
        0x06, //
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
        0x57, //
        0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30,
        0x59, //
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, //
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf9, 0xb1, 0x62, 0xd6, 0x07, 0xae,
        0xc3, //
        0x36, 0x34, 0xf5, 0xa3, 0x09, 0x39, 0x86, 0xe7, 0x3b, 0x59, 0xf7, 0x4a, 0x1d, 0xf4, 0x97,
        0x4f, //
        0x91, 0x40, 0x56, 0x1b, 0x3d, 0x6c, 0x5a, 0x38, 0x10, 0x15, 0x58, 0xf5, 0xa4, 0xcc, 0xdf,
        0xd5, //
        0xf5, 0x4a, 0x35, 0x40, 0x0f, 0x9f, 0x54, 0xb7, 0xe9, 0xe2, 0xae, 0x63, 0x83, 0x6a, 0x4c,
        0xfc, //
        0xc2, 0x5f, 0x78, 0xa0, 0xbb, 0x46, 0x54, 0xa4, 0xda, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, //
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x47, 0x1a, 0x5f,
        0x58, //
        0x2a, 0x74, 0x33, 0x6d, 0xed, 0xac, 0x37, 0x21, 0xfa, 0x76, 0x5a, 0x4d, 0x78, 0x68, 0x1a,
        0xdd, //
        0x80, 0xa4, 0xd4, 0xb7, 0x7f, 0x7d, 0x78, 0xb3, 0xfb, 0xf3, 0x95, 0xfb, 0x02, 0x21, 0x00,
        0xc0, //
        0x73, 0x30, 0xda, 0x2b, 0xc0, 0x0c, 0x9e, 0xb2, 0x25, 0x0d, 0x46, 0xb0, 0xbc, 0x66, 0x7f,
        0x71, //
        0x66, 0xbf, 0x16, 0xb3, 0x80, 0x78, 0xd0, 0x0c, 0xef, 0xcc, 0xf5, 0xc1, 0x15, 0x0f, 0x58,
    ]
}

fn marshal(message: &HandshakeMessageCertificate13) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        message.marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<HandshakeMessageCertificate13> {
    HandshakeMessageCertificate13::unmarshal(&mut BufReader::new(raw))
}

/// pion's `marshalUnmarshalMessageCertificate13AndVerifyMatch`.
fn marshal_unmarshal_and_verify_match(
    message: &HandshakeMessageCertificate13,
) -> Result<HandshakeMessageCertificate13> {
    let raw = marshal(message)?;
    let out = unmarshal(&raw)?;

    assert_eq!(
        out.certificate_request_context, message.certificate_request_context,
        "certificate_request_context must survive a round trip"
    );
    assert_eq!(
        out.certificate_list, message.certificate_list,
        "certificate_list must survive a round trip"
    );

    Ok(out)
}

/// pion's `TestHandshakeMessageCertificate13`.
#[test]
fn test_handshake_message_certificate_13() -> Result<()> {
    let cert_der = cert_der();

    struct Case {
        name: &'static str,
        raw_certificate: Vec<u8>,
        expected_context: Vec<u8>,
        expected_list_len: usize,
        expected_error: Option<Error>,
    }

    // "valid - no context, single cert, no extensions"
    let mut no_context = vec![
        0x00, // context length = 0
        0x00, 0x01, 0x8E, // certificate_list length = 398 (3 + 393 + 2)
        0x00, 0x01, 0x89, // cert_data length = 393
    ];
    no_context.extend_from_slice(&cert_der);
    no_context.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

    // "valid - with context, single cert, no extensions"
    let mut with_context = vec![
        0x02, // context length = 2
        0x01, 0x02, // context data
        0x00, 0x01, 0x8E, // certificate_list length = 398 (3 + 393 + 2)
        0x00, 0x01, 0x89, // cert_data length = 393
    ];
    with_context.extend_from_slice(&cert_der);
    with_context.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

    let cases = vec![
        Case {
            name: "valid - no context, single cert, no extensions",
            raw_certificate: no_context,
            expected_context: vec![],
            expected_list_len: 1,
            expected_error: None,
        },
        Case {
            name: "valid - with context, single cert, no extensions",
            raw_certificate: with_context,
            expected_context: vec![0x01, 0x02],
            expected_list_len: 1,
            expected_error: None,
        },
        Case {
            name: "valid - no context, empty cert list",
            raw_certificate: vec![
                0x00, // context length = 0
                0x00, 0x00, 0x00, // certificate_list length = 0
            ],
            expected_context: vec![],
            expected_list_len: 0,
            expected_error: None,
        },
        Case {
            name: "invalid - buffer too small",
            raw_certificate: vec![0x00],
            expected_context: vec![],
            expected_list_len: 0,
            expected_error: Some(Error::ErrBufferTooSmall),
        },
    ];

    for case in cases {
        let parsed = unmarshal(&case.raw_certificate);

        if let Some(expected) = case.expected_error {
            assert_eq!(parsed.unwrap_err(), expected, "case {}", case.name);
            continue;
        }
        let certificate = parsed.expect("a valid case must parse");

        assert_eq!(
            certificate.certificate_request_context, case.expected_context,
            "case {}: context must match",
            case.name
        );
        assert_eq!(
            certificate.certificate_list.len(),
            case.expected_list_len,
            "case {}: certificate_list length must match",
            case.name
        );

        // Verify certificate can be parsed
        if !certificate.certificate_list.is_empty() {
            let (_, parsed_certificate) = x509_parser::parse_x509_certificate(
                &certificate.certificate_list[0].certificate_data,
            )
            .map_err(|e| Error::Other(e.to_string()))?;
            assert_eq!(
                parsed_certificate.signature_algorithm.algorithm, OID_ECDSA_WITH_SHA256,
                "case {}: the fixture certificate is signed with ECDSA-SHA256",
                case.name
            );
        }

        let raw = marshal(&certificate)?;
        assert_eq!(
            raw, case.raw_certificate,
            "case {}: marshal must reproduce the fixture",
            case.name
        );
    }

    Ok(())
}

/// pion's `TestMessageCertificate13_Type`.
#[test]
fn message_certificate_13_type() {
    assert_eq!(
        HandshakeMessageCertificate13::default().handshake_type(),
        HandshakeType::Certificate
    );
}

/// pion's `TestMessageCertificate13_SingleCertNoExtensions`.
#[test]
fn message_certificate_13_single_cert_no_extensions() -> Result<()> {
    // Build (valid) message with a real DER-encoded certificate
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![0x01, 0x02, 0x03, 0x04],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: cert_der(),
            extensions: vec![],
        }],
    };

    let out = marshal_unmarshal_and_verify_match(&message)?;

    // Verify certificate is valid
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&out.certificate_list[0].certificate_data)
            .map_err(|e| Error::Other(e.to_string()))?;
    assert_eq!(
        certificate.signature_algorithm.algorithm,
        OID_ECDSA_WITH_SHA256
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_WithContext`.
#[test]
fn message_certificate_13_with_context() -> Result<()> {
    // Build (valid) message with non empty context
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![0x01, 0x02, 0x03, 0x04],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            extensions: vec![],
        }],
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificate13_MultipleCertificates`.
#[test]
fn message_certificate_13_multiple_certificates() -> Result<()> {
    // Build (valid) message with multiple certificates
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![
            CertificateEntry13 {
                certificate_data: vec![0x01, 0x02, 0x03],
                extensions: vec![],
            },
            CertificateEntry13 {
                certificate_data: vec![0x04, 0x05, 0x06, 0x07],
                extensions: vec![],
            },
            CertificateEntry13 {
                certificate_data: vec![0x08, 0x09],
                extensions: vec![],
            },
        ],
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificate13_MaxContextLength`.
#[test]
fn message_certificate_13_max_context_length() -> Result<()> {
    // Build (valid) message with context of exactly the max size
    let context: Vec<u8> = (0..CERT_13_CONTEXT_MAX_LENGTH as u8).collect();
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: context,
        certificate_list: vec![CertificateEntry13 {
            certificate_data: vec![0x00],
            extensions: vec![],
        }],
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificate13_EmptyCertificateList`.
#[test]
fn message_certificate_13_empty_certificate_list() -> Result<()> {
    // Build (valid) message with empty certificate list (empty certificate list is technically
    // valid in DTLS 1.3, e.g. when the client has no suitable certificate)
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![],
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificate13_ContextTooLong`.
#[test]
fn message_certificate_13_context_too_long() -> Result<()> {
    // Build (invalid) message with context exceeding the max size
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![0u8; CERT_13_CONTEXT_MAX_LENGTH + 1],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: vec![0x00],
            extensions: vec![],
        }],
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrCertificateRequestContextTooLong
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_EmptyCertData`.
#[test]
fn message_certificate_13_empty_cert_data() -> Result<()> {
    // Build (invalid) message with empty certificate data
    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: vec![],
            extensions: vec![],
        }],
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrInvalidCertificateEntry
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_CertDataAtMaxBoundary`.
#[test]
fn message_certificate_13_cert_data_at_max_boundary() -> Result<()> {
    // Test cert_data at exactly 2^24-1 bytes (max allowed per RFC). This fails because the
    // serialized entry exceeds the certificate_list limit: 3 + 0xffffff + 2 = 0x1000004.
    let cert_data: Vec<u8> = (0..MAX_UINT24).map(|i| i as u8).collect();

    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: cert_data,
            extensions: vec![],
        }],
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrCertificateListTooLong
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_CertDataJustBelowMaxBoundary`.
#[test]
fn message_certificate_13_cert_data_just_below_max_boundary() -> Result<()> {
    // Test cert_data at 2^24-1-5 bytes, which succeeds for a single cert with no extensions:
    // the serialized list is 3 + (0xffffff - 5) + 2 = 0xffffff, exactly at the limit.
    let cert_data: Vec<u8> = (0..MAX_UINT24 - 5).map(|i| i as u8).collect();

    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: cert_data,
            extensions: vec![],
        }],
    };

    let data = marshal(&message)?;

    // Verify round-trip
    let out = unmarshal(&data)?;
    assert_eq!(
        out.certificate_list[0].certificate_data.len(),
        message.certificate_list[0].certificate_data.len()
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_CertDataOneByteOverBoundary`.
#[test]
fn message_certificate_13_cert_data_one_byte_over_boundary() -> Result<()> {
    // Test cert_data at 2^24-1-4 bytes, one byte over the single-cert-no-ext limit: the
    // serialized list is 3 + (0xffffff - 4) + 2 = 0x1000000, past 2^24-1.
    let cert_data: Vec<u8> = (0..MAX_UINT24 - 4).map(|i| i as u8).collect();

    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: cert_data,
            extensions: vec![],
        }],
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrCertificateListTooLong
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_MultipleCertsExceedingBoundary`.
#[test]
fn message_certificate_13_multiple_certs_exceeding_boundary() -> Result<()> {
    // Test multiple certs that individually are fine but together exceed the limit: two certs
    // of ~8MB each total 2 * (3 + 0x800000 + 2) = 0x100000A, past 0xffffff.
    let cert_data1: Vec<u8> = (0..0x800000).map(|i| i as u8).collect();
    let cert_data2: Vec<u8> = (0..0x800000).map(|i| (i + 1) as u8).collect();

    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![
            CertificateEntry13 {
                certificate_data: cert_data1,
                extensions: vec![],
            },
            CertificateEntry13 {
                certificate_data: cert_data2,
                extensions: vec![],
            },
        ],
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrCertificateListTooLong
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_CertListAtExactBoundary`.
#[test]
fn message_certificate_13_cert_list_at_exact_boundary() -> Result<()> {
    // Test that we can marshal a certificate_list of exactly 2^24-1 bytes. Accounting for the
    // overhead (3 cert prefix + 2 extensions prefix), cert_data is 0xffffff - 5.
    let cert_data: Vec<u8> = (0..MAX_UINT24 - 5).map(|i| i as u8).collect();

    let message = HandshakeMessageCertificate13 {
        certificate_request_context: vec![],
        certificate_list: vec![CertificateEntry13 {
            certificate_data: cert_data,
            extensions: vec![],
        }],
    };

    let data = marshal(&message)?;

    // Verify the certificate_list is exactly at the boundary. The context is empty, so the
    // layout is [1 byte context_len][3 bytes cert_list_len][cert_list].
    let cert_list_len = (data[1] as usize) << 16 | (data[2] as usize) << 8 | data[3] as usize;
    assert_eq!(
        cert_list_len, MAX_UINT24,
        "certificate_list should be exactly at 2^24-1"
    );

    // Verify round-trip
    let out = unmarshal(&data)?;
    assert_eq!(
        out.certificate_list[0].certificate_data.len(),
        message.certificate_list[0].certificate_data.len()
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_UnmarshalBufferTooSmall`.
#[test]
fn message_certificate_13_unmarshal_buffer_too_small() -> Result<()> {
    // Define (invalid) serialized messages (data too small)
    let tests: [(&str, &[u8]); 4] = [
        ("empty", &[]),
        ("1 byte", &[0x00]),
        ("2 bytes", &[0x00, 0x00]),
        ("3 bytes", &[0x00, 0x00, 0x00]),
    ];
    for (name, data) in tests {
        assert_eq!(
            unmarshal(data).unwrap_err(),
            Error::ErrBufferTooSmall,
            "case {name} must be rejected as too small"
        );
    }

    Ok(())
}

/// pion's `TestMessageCertificate13_UnmarshalLengthMismatch`.
#[test]
fn message_certificate_13_unmarshal_length_mismatch() -> Result<()> {
    // Define (invalid) serialized message (certificate_list length says 10, but only 5 bytes
    // follow). Reading the length-prefixed list fails, as in pion's cryptobyte.
    let data = [
        0x00, // context length = 0
        0x00, 0x00, 0x0A, // certificate_list length = 10
        0x00, 0x00, 0x00, 0x00, 0x00, // only 5 bytes
    ];

    assert_eq!(
        unmarshal(&data).unwrap_err(),
        Error::ErrInvalidCertificateEntry
    );

    Ok(())
}

/// pion's `TestMessageCertificate13_UnmarshalInvalidCertEntry`.
#[test]
fn message_certificate_13_unmarshal_invalid_cert_entry() -> Result<()> {
    let tests: [(&str, &[u8]); 2] = [
        // cert_data length is 10, but only 4 bytes follow
        (
            "cert_data length mismatch",
            &[
                0x00, // context length = 0
                0x00, 0x00, 0x07, // certificate_list length = 7
                0x00, 0x00, 0x0A, // cert_data length = 10 (invalid)
                0xDE, 0xAD, 0xBE, 0xEF, // only 4 bytes
            ],
        ),
        // cert_data length is 0
        (
            "empty cert_data",
            &[
                0x00, // context length = 0
                0x00, 0x00, 0x05, // certificate_list length = 5
                0x00, 0x00, 0x00, // cert_data length = 0 (invalid - must be >= 1)
            ],
        ),
    ];

    for (name, data) in tests {
        assert_eq!(
            unmarshal(data).unwrap_err(),
            Error::ErrInvalidCertificateEntry,
            "case {name} must be rejected as an invalid certificate entry"
        );
    }

    Ok(())
}

/// Generates a self-signed certificate the way pion's two `parseCertificateEntry` tests do,
/// with the subject pion sets.
fn generated_certificate(
    common_name: &str,
    organization: &str,
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> Result<Vec<u8>> {
    let mut params = rcgen::CertificateParams::new(vec![common_name.to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, organization);
    let key_pair =
        rcgen::KeyPair::generate_for(algorithm).map_err(|e| Error::Other(e.to_string()))?;
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Other(e.to_string()))?;
    Ok(certificate.der().to_vec())
}

/// pion's `TestParseCertificateEntry_GeneratedCertificate`.
#[test]
fn parse_certificate_entry_generated_certificate() -> Result<()> {
    // Generate a self-signed certificate (pion: ECDSA P-256)
    let cert_der = generated_certificate(
        "test.example.com",
        "Test Org",
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )?;

    // Construct the wire format for parseCertificateEntry:
    // [3 bytes] cert_data length, [variable] cert_data, [2 bytes] extensions length.
    let mut data = (cert_der.len() as u32).to_be_bytes()[1..].to_vec();
    data.extend_from_slice(&cert_der);
    data.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

    // Parse the certificate entry
    let mut rest = data.as_slice();
    let entry = parse_certificate_13_entry(&mut rest)?;
    assert!(rest.is_empty(), "all data must be consumed");
    assert_eq!(entry.certificate_data, cert_der);
    assert!(entry.extensions.is_empty());

    // Verify we can parse it back as a valid X.509 certificate
    let (_, certificate) = x509_parser::parse_x509_certificate(&entry.certificate_data)
        .map_err(|e| Error::Other(e.to_string()))?;
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok());
    let organization = certificate
        .subject()
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok());
    assert_eq!(common_name, Some("test.example.com"));
    assert_eq!(organization, Some("Test Org"));

    Ok(())
}

/// pion's `TestParseCertificateEntry_GeneratedCertificateWithExtensions`.
#[test]
fn parse_certificate_entry_generated_certificate_with_extensions() -> Result<()> {
    // Generate a self-signed certificate. pion uses RSA-2048 here; the ring provider cannot
    // generate RSA keys, so the fixture is Ed25519 — the scenario, a generated certificate of a
    // second algorithm followed by extensions, is the same.
    let cert_der = generated_certificate("test2.example.com", "Test Org 2", &rcgen::PKCS_ED25519)?;

    // Create extensions for the certificate entry
    let extensions = vec![Extension::ServerName(ExtensionServerName {
        server_name: "test2.example.com".to_owned(),
    })];
    let mut extensions_data = vec![];
    marshal_extensions_block(&extensions, &mut extensions_data)?;

    // Construct wire format: cert_data length, cert_data, extensions (incl. 2-byte prefix)
    let mut data = (cert_der.len() as u32).to_be_bytes()[1..].to_vec();
    data.extend_from_slice(&cert_der);
    data.extend_from_slice(&extensions_data);

    // Parse it
    let mut rest = data.as_slice();
    let entry = parse_certificate_13_entry(&mut rest)?;
    assert!(rest.is_empty(), "all data must be consumed");
    assert_eq!(entry.certificate_data, cert_der);
    assert_eq!(entry.extensions.len(), 1);
    assert_eq!(
        entry.extensions[0].extension_value(),
        ExtensionValue::ServerName
    );

    // Verify the certificate is valid
    let (_, certificate) = x509_parser::parse_x509_certificate(&entry.certificate_data)
        .map_err(|e| Error::Other(e.to_string()))?;
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok());
    assert_eq!(common_name, Some("test2.example.com"));
    assert_eq!(
        certificate.public_key().algorithm.algorithm,
        crate::crypto::OID_ED25519
    );

    Ok(())
}
