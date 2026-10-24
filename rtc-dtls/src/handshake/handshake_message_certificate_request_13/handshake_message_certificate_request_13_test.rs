//! Ported from pion/dtls v3.1.15
//! `pkg/protocol/handshake/message_certificate_request_13_test.go`.

use super::*;

use crate::extension::extension_server_name::*;
use crate::extension::extension_supported_signature_algorithms::*;
use crate::signature_hash_algorithm::*;

use std::io::{BufReader, BufWriter};

fn marshal(message: &HandshakeMessageCertificateRequest13) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        message.marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<HandshakeMessageCertificateRequest13> {
    HandshakeMessageCertificateRequest13::unmarshal(&mut BufReader::new(raw))
}

fn signature_algorithms(algorithms: &[(HashAlgorithm, SignatureAlgorithm)]) -> Vec<Extension> {
    vec![Extension::SupportedSignatureAlgorithms(
        ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms: algorithms
                .iter()
                .map(|(hash, signature)| SignatureHashAlgorithm {
                    hash: *hash,
                    signature: *signature,
                })
                .collect(),
        },
    )]
}

/// pion's `marshalUnmarshalMessageCertificateRequest13AndVerifyMatch`.
fn marshal_unmarshal_and_verify_match(
    message: &HandshakeMessageCertificateRequest13,
) -> Result<HandshakeMessageCertificateRequest13> {
    let raw = marshal(message)?;
    let out = unmarshal(&raw)?;

    // Verify before/after marshal/unmarshal match
    assert_eq!(
        out.certificate_request_context, message.certificate_request_context,
        "certificate_request_context must survive a round trip"
    );
    assert_eq!(
        out.extensions, message.extensions,
        "extensions must survive a round trip"
    );

    // Verify the signature_algorithms extension survived
    assert!(
        out.extensions
            .iter()
            .any(|extension| extension.extension_value()
                == ExtensionValue::SupportedSignatureAlgorithms),
        "the signature_algorithms extension must be present after a round trip"
    );

    Ok(out)
}

/// pion's `TestHandshakeMessageCertificateRequest13`.
#[test]
fn test_handshake_message_certificate_request_13() -> Result<()> {
    struct Case {
        name: &'static str,
        raw_certificate_request: Vec<u8>,
        expected_context: Vec<u8>,
        expected_extensions: Vec<Extension>,
        expected_error: Option<Error>,
    }

    let cases = vec![
        Case {
            name: "valid - no context, single signature algorithm",
            raw_certificate_request: vec![
                0x00, // context length = 0
                0x00, 0x08, // extensions length = 8
                0x00, 0x0D, // extension type = signature_algorithms (13)
                0x00, 0x04, // extension length = 4
                0x00, 0x02, // signature_algorithms length = 2
                0x04, 0x03, // ECDSA-SHA256
            ],
            expected_context: vec![],
            expected_extensions: signature_algorithms(&[(
                HashAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
            )]),
            expected_error: None,
        },
        Case {
            name: "valid - with context, multiple signature algorithms",
            raw_certificate_request: vec![
                0x04, // context length = 4
                0x01, 0x02, 0x03, 0x04, // context data
                0x00, 0x0C, // extensions length = 12
                0x00, 0x0D, // extension type = signature_algorithms (13)
                0x00, 0x08, // extension length = 8
                0x00, 0x06, // signature_algorithms length = 6
                0x04, 0x03, // ECDSA-SHA256
                0x04, 0x01, // RSA-PKCS1-SHA256
                0x05, 0x03, // ECDSA-SHA384
            ],
            expected_context: vec![0x01, 0x02, 0x03, 0x04],
            expected_extensions: signature_algorithms(&[
                (HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa),
                (HashAlgorithm::Sha256, SignatureAlgorithm::Rsa),
                (HashAlgorithm::Sha384, SignatureAlgorithm::Ecdsa),
            ]),
            expected_error: None,
        },
        Case {
            name: "invalid - missing signature_algorithms",
            raw_certificate_request: vec![
                0x00, // context length = 0
                0x00, 0x00, // extensions length = 0
            ],
            expected_context: vec![],
            expected_extensions: vec![],
            expected_error: Some(Error::ErrMissingSignatureAlgorithmsExtension),
        },
        Case {
            name: "invalid - buffer too small",
            raw_certificate_request: vec![0x00],
            expected_context: vec![],
            expected_extensions: vec![],
            expected_error: Some(Error::ErrBufferTooSmall),
        },
    ];

    for case in cases {
        let parsed = unmarshal(&case.raw_certificate_request);

        if let Some(expected) = case.expected_error {
            assert_eq!(parsed.unwrap_err(), expected, "case {}", case.name);
            continue;
        }
        let request = parsed.expect("a valid case must parse");

        assert_eq!(
            request.certificate_request_context, case.expected_context,
            "case {}: context must match",
            case.name
        );
        assert_eq!(
            request.extensions, case.expected_extensions,
            "case {}: extensions must match",
            case.name
        );

        let raw = marshal(&request)?;
        assert_eq!(
            raw, case.raw_certificate_request,
            "case {}: marshal must reproduce the fixture",
            case.name
        );
    }

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_Type`.
#[test]
fn message_certificate_request_13_type() {
    assert_eq!(
        HandshakeMessageCertificateRequest13::default().handshake_type(),
        HandshakeType::CertificateRequest
    );
}

/// pion's `TestMessageCertificateRequest13_MinimalValid`.
#[test]
fn message_certificate_request_13_minimal_valid() -> Result<()> {
    // Build (valid) message with empty context
    let message = HandshakeMessageCertificateRequest13 {
        certificate_request_context: vec![],
        extensions: signature_algorithms(&[
            (HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa),
            (HashAlgorithm::Sha256, SignatureAlgorithm::Rsa),
        ]),
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_WithContext`.
#[test]
fn message_certificate_request_13_with_context() -> Result<()> {
    // Build (valid) message with non-empty context
    let message = HandshakeMessageCertificateRequest13 {
        certificate_request_context: vec![0x01, 0x02, 0x03, 0x04],
        extensions: signature_algorithms(&[(HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa)]),
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_MaxContextLength`.
#[test]
fn message_certificate_request_13_max_context_length() -> Result<()> {
    // Build (valid) message with context of exactly the max size
    let context: Vec<u8> = (0..CERT_REQ_13_CONTEXT_MAX_LENGTH as u8).collect();
    let message = HandshakeMessageCertificateRequest13 {
        certificate_request_context: context,
        extensions: signature_algorithms(&[(HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa)]),
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_MultipleExtensions`.
#[test]
fn message_certificate_request_13_multiple_extensions() -> Result<()> {
    // Build (valid) message with multiple extensions (signature_algorithms, which must be
    // present, and server_name)
    let mut extensions = signature_algorithms(&[
        (HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa),
        (HashAlgorithm::Sha384, SignatureAlgorithm::Ecdsa),
        (HashAlgorithm::Sha512, SignatureAlgorithm::Rsa),
    ]);
    extensions.push(Extension::ServerName(ExtensionServerName {
        server_name: "example.com".to_owned(),
    }));

    let message = HandshakeMessageCertificateRequest13 {
        certificate_request_context: vec![0x01, 0x02, 0x03, 0x04],
        extensions,
    };
    marshal_unmarshal_and_verify_match(&message)?;

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_ContextTooLong`.
#[test]
fn message_certificate_request_13_context_too_long() -> Result<()> {
    // Build (invalid) message with context exceeding the max size
    let message = HandshakeMessageCertificateRequest13 {
        certificate_request_context: vec![0u8; CERT_REQ_13_CONTEXT_MAX_LENGTH + 1],
        extensions: signature_algorithms(&[(HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa)]),
    };

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrCertificateRequestContextTooLong
    );

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_MissingSignatureAlgorithms`.
#[test]
fn message_certificate_request_13_missing_signature_algorithms() -> Result<()> {
    // Build (invalid) message with no signature_algorithms extension
    let message = HandshakeMessageCertificateRequest13::default();

    assert_eq!(
        marshal(&message).unwrap_err(),
        Error::ErrMissingSignatureAlgorithmsExtension
    );

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_UnmarshalMissingSignatureAlgorithms`.
#[test]
fn message_certificate_request_13_unmarshal_missing_signature_algorithms() -> Result<()> {
    // Define (invalid) serialized message (has no signature_algorithms extension)
    let data = [
        0x00, // context length = 0
        0x00, 0x00, // extensions length = 0
    ];

    assert_eq!(
        unmarshal(&data).unwrap_err(),
        Error::ErrMissingSignatureAlgorithmsExtension
    );

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_UnmarshalBufferTooSmall`.
#[test]
fn message_certificate_request_13_unmarshal_buffer_too_small() -> Result<()> {
    // Define (invalid) serialized messages (data too small). pion asserts only that each is an
    // error.
    let tests: [(&str, &[u8]); 3] = [
        ("empty", &[]),
        ("1 byte", &[0x00]),
        ("2 bytes", &[0x00, 0x00]),
    ];
    for (name, data) in tests {
        assert!(unmarshal(data).is_err(), "case {name} must be rejected");
    }

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_UnmarshalInvalidContext`.
#[test]
fn message_certificate_request_13_unmarshal_invalid_context() -> Result<()> {
    // Define (invalid) serialized message (data smaller than advertised context length)
    let data = [
        0x05, // context length = 5
        0x01, 0x02, 0x03, 0x04, // only 2 bytes
    ];

    assert_eq!(
        unmarshal(&data).unwrap_err(),
        Error::ErrInvalidCertificateRequestContext
    );

    Ok(())
}

/// pion's `TestMessageCertificateRequest13_UnmarshalInvalidExtensions`.
#[test]
fn message_certificate_request_13_unmarshal_invalid_extensions() -> Result<()> {
    let tests: [(&str, &[u8]); 2] = [
        // Only 1 byte of extensions after the context (< 2 bytes required)
        (
            "only 1 byte of extensions after context",
            &[
                0x01, // context length = 1
                0xFF, // context data
                0x00, // only 1 byte of extensions (< 2 bytes required)
            ],
        ),
        // Extensions length bytes truncated
        (
            "no extensions after empty context",
            &[
                0x02, // context length = 2
                0x01, 0x02, // context data
                0x00, // only 1 byte of extensions (< 2 bytes required)
            ],
        ),
    ];

    for (name, data) in tests {
        assert_eq!(
            unmarshal(data).unwrap_err(),
            Error::ErrInvalidExtensionsLength,
            "case {name} must be rejected as an invalid extensions block"
        );
    }

    Ok(())
}
