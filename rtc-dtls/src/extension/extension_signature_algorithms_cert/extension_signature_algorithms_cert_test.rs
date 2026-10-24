//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/signature_algorithms_cert_test.go`.

use super::*;

use crate::signature_hash_algorithm::{HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm};
use std::io::{BufReader, BufWriter};

fn sha256_ecdsa() -> SignatureHashAlgorithm {
    SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
    }
}

fn sha384_ecdsa() -> SignatureHashAlgorithm {
    SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha384,
        signature: SignatureAlgorithm::Ecdsa,
    }
}

fn sha512_ecdsa() -> SignatureHashAlgorithm {
    SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha512,
        signature: SignatureAlgorithm::Ecdsa,
    }
}

/// pion's `TestSignatureAlgorithmsCert`.
#[test]
fn signature_algorithms_cert() -> Result<()> {
    let raw_signature_algorithms_cert = [
        0x00, 0x32, // extension type: signature_algorithms_cert (50)
        0x00, 0x08, // extension length: 8 bytes
        0x00, 0x06, // signature hash algorithms length: 6 bytes
        0x04, 0x03, // SHA256, ECDSA
        0x05, 0x03, // SHA384, ECDSA
        0x06, 0x03, // SHA512, ECDSA
    ];
    let parsed_signature_algorithms_cert = ExtensionSignatureAlgorithmsCert {
        signature_hash_algorithms: vec![sha256_ecdsa(), sha384_ecdsa(), sha512_ecdsa()],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SignatureAlgorithmsCert(parsed_signature_algorithms_cert.clone())
            .marshal(&mut writer)?;
    }
    assert_eq!(raw, raw_signature_algorithms_cert, "marshal");

    let extension =
        match Extension::unmarshal(&mut BufReader::new(&raw_signature_algorithms_cert[..]))? {
            Extension::SignatureAlgorithmsCert(extension) => extension,
            _ => return Err(Error::ErrInvalidExtensionType),
        };
    assert_eq!(extension, parsed_signature_algorithms_cert, "unmarshal");
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertTypeValue`.
#[test]
fn signature_algorithms_cert_type_value() {
    let extension = ExtensionSignatureAlgorithmsCert::default();
    assert_eq!(
        extension.extension_value(),
        ExtensionValue::SignatureAlgorithmsCert
    );
    assert_eq!(extension.extension_value() as u16, 50);
}

/// pion's `TestSignatureAlgorithmsCertPSSSchemes`: PSS schemes use their full `u16` code point.
#[test]
fn signature_algorithms_cert_pss_schemes() -> Result<()> {
    let raw_extension_with_pss = [
        0x00, 0x32, // extension type: signature_algorithms_cert (50)
        0x00, 0x08, // extension length (8 bytes)
        0x00, 0x06, // algorithms length (6 bytes = 3 schemes)
        0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804)
        0x08, 0x05, // RSA_PSS_RSAE_SHA384 (0x0805)
        0x08, 0x09, // RSA_PSS_PSS_SHA256 (0x0809)
    ];
    let parsed_extension_with_pss = ExtensionSignatureAlgorithmsCert {
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssRsaeSha256,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::RsaPssRsaeSha384,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssPssSha256,
            },
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SignatureAlgorithmsCert(parsed_extension_with_pss.clone())
            .marshal(&mut writer)?;
    }
    assert_eq!(raw, raw_extension_with_pss);

    let roundtrip =
        match Extension::unmarshal(&mut BufReader::new(&raw_extension_with_pss[..]))? {
            Extension::SignatureAlgorithmsCert(roundtrip) => roundtrip,
            _ => return Err(Error::ErrInvalidExtensionType),
        };
    assert_eq!(roundtrip, parsed_extension_with_pss);
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertMixedPSSAndNonPSS`, including the Ed25519 code point
/// (0x0807) that sits inside the PSS range but is not PSS.
#[test]
fn signature_algorithms_cert_mixed_pss_and_non_pss() -> Result<()> {
    let raw_extension_mixed = [
        0x00, 0x32, // extension type: signature_algorithms_cert (50)
        0x00, 0x0a, // extension length (10 bytes)
        0x00, 0x08, // algorithms length (8 bytes = 4 schemes)
        0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804) - PSS
        0x04, 0x01, // RSA PKCS#1 with SHA256 - non-PSS
        0x04, 0x03, // ECDSA with SHA256 - non-PSS
        0x08, 0x07, // Ed25519 (0x0807) - not PSS despite being in the 0x08xx range
    ];
    let parsed_extension_mixed = ExtensionSignatureAlgorithmsCert {
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssRsaeSha256,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            },
            sha256_ecdsa(),
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Ed25519,
                signature: SignatureAlgorithm::Ed25519,
            },
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SignatureAlgorithmsCert(parsed_extension_mixed.clone()).marshal(&mut writer)?;
    }
    assert_eq!(raw, raw_extension_mixed);

    let roundtrip = match Extension::unmarshal(&mut BufReader::new(&raw_extension_mixed[..]))? {
        Extension::SignatureAlgorithmsCert(roundtrip) => roundtrip,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(roundtrip, parsed_extension_mixed);
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertRoundTrip`.
#[test]
fn signature_algorithms_cert_round_trip() -> Result<()> {
    let cases: Vec<(&str, Vec<SignatureHashAlgorithm>)> = vec![
        ("Empty", vec![]),
        (
            "Single algorithm",
            vec![SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            }],
        ),
        (
            "Multiple algorithms",
            vec![
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Rsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha384,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha512,
                    signature: SignatureAlgorithm::Ed25519,
                },
            ],
        ),
        (
            "RSA-PSS algorithms",
            vec![
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::RsaPssRsaeSha256,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha384,
                    signature: SignatureAlgorithm::RsaPssRsaeSha384,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha512,
                    signature: SignatureAlgorithm::RsaPssRsaeSha512,
                },
            ],
        ),
    ];

    for (name, algorithms) in cases {
        let extension = ExtensionSignatureAlgorithmsCert {
            signature_hash_algorithms: algorithms,
        };

        let mut raw = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
            Extension::SignatureAlgorithmsCert(extension.clone()).marshal(&mut writer)?;
        }

        let parsed = match Extension::unmarshal(&mut BufReader::new(&raw[..]))? {
            Extension::SignatureAlgorithmsCert(parsed) => parsed,
            _ => return Err(Error::ErrInvalidExtensionType),
        };
        assert_eq!(extension, parsed, "{name}: round trip failed");
    }
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertUnmarshalErrors`.
#[test]
fn signature_algorithms_cert_unmarshal_errors() -> Result<()> {
    // Empty data: no extension type to read.
    let extension = Extension::unmarshal(&mut BufReader::new(&[][..]));
    assert!(extension.is_err(), "empty data must be rejected");

    // Wrong extension type: data carrying type 13 is not a signature_algorithms_cert. The enum
    // dispatch parses it as the (valid) supported_signature_algorithms extension instead — pion's
    // per-type check, reproduced here as "never a SignatureAlgorithmsCert".
    let wrong_type = [
        0x00, 0x0d, // wrong extension type (13 instead of 50)
        0x00, 0x04, 0x00, 0x02, 0x04, 0x03,
    ];
    let extension = Extension::unmarshal(&mut BufReader::new(&wrong_type[..]));
    assert!(
        !matches!(
            extension,
            Ok(Extension::SignatureAlgorithmsCert(_))
        ),
        "wrong extension type must be rejected"
    );

    // Missing extension length. Module-level input is the body the Extension enum hands
    // over: [extension-data length][data].
    let extension =
        ExtensionSignatureAlgorithmsCert::unmarshal(&mut BufReader::new(&[][..]));
    assert!(matches!(extension, Err(Error::ErrBufferTooSmall)));

    // Missing algorithms length: the declared extension data never arrives.
    let extension = ExtensionSignatureAlgorithmsCert::unmarshal(&mut BufReader::new(&[
        0x00, 0x02, // extension data length: 2 bytes
    ][..]));
    assert!(matches!(extension, Err(Error::ErrBufferTooSmall)));

    // Truncated algorithm list.
    let extension = ExtensionSignatureAlgorithmsCert::unmarshal(&mut BufReader::new(&[
        0x00, 0x06, // extension data length: 6 bytes
        0x00, 0x04, // algorithms length: 4 bytes
        0x04, 0x03, // SHA256, ECDSA
        0x05, // incomplete second algorithm
    ][..]));
    assert!(matches!(extension, Err(Error::ErrBufferTooSmall)));

    // Declared algorithm length runs past the extension data.
    let extension = ExtensionSignatureAlgorithmsCert::unmarshal(&mut BufReader::new(&[
        0x00, 0x06, // extension data length: 6 bytes
        0x00, 0x06, // algorithms length: 6 bytes, but only 2 bytes follow
        0x04, 0x03, // SHA256, ECDSA
    ][..]));
    assert!(matches!(extension, Err(Error::ErrBufferTooSmall)));

    // Empty extension data: no algorithms length at all.
    let extension = ExtensionSignatureAlgorithmsCert::unmarshal(&mut BufReader::new(&[
        0x00, 0x00, // extension data length: 0
    ][..]));
    assert!(matches!(extension, Err(Error::ErrLengthMismatch)));
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertUnmarshalFiltering`: unknown algorithms are skipped.
#[test]
fn signature_algorithms_cert_unmarshal_filtering() -> Result<()> {
    let raw_data = [
        0x00, 0x32, // extension type: signature_algorithms_cert (50)
        0x00, 0x0a, // extension length: 10 bytes
        0x00, 0x08, // signature hash algorithms length: 8 bytes
        0x04, 0x03, // valid: SHA256, ECDSA
        0xFF, 0xFF, // invalid: unknown hash and signature
        0x05, 0x03, // valid: SHA384, ECDSA
        0x04, 0xFF, // invalid: SHA256 with unknown signature
    ];

    let extension = match Extension::unmarshal(&mut BufReader::new(&raw_data[..]))? {
        Extension::SignatureAlgorithmsCert(extension) => extension,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(
        extension.signature_hash_algorithms,
        vec![sha256_ecdsa(), sha384_ecdsa()],
        "only the two valid algorithms survive"
    );
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertDuplicateAlgorithms`: duplicates are preserved.
#[test]
fn signature_algorithms_cert_duplicate_algorithms() -> Result<()> {
    let extension = ExtensionSignatureAlgorithmsCert {
        signature_hash_algorithms: vec![
            sha256_ecdsa(),
            sha256_ecdsa(), // duplicate
            sha384_ecdsa(),
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SignatureAlgorithmsCert(extension.clone()).marshal(&mut writer)?;
    }

    let parsed = match Extension::unmarshal(&mut BufReader::new(&raw[..]))? {
        Extension::SignatureAlgorithmsCert(parsed) => parsed,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(
        parsed.signature_hash_algorithms.len(),
        extension.signature_hash_algorithms.len(),
        "no deduplication in the protocol"
    );
    Ok(())
}

/// pion's `TestSignatureAlgorithmsCertLargeList`.
#[test]
fn signature_algorithms_cert_large_list() -> Result<()> {
    let extension = ExtensionSignatureAlgorithmsCert {
        signature_hash_algorithms: vec![sha256_ecdsa(); 100],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SignatureAlgorithmsCert(extension.clone()).marshal(&mut writer)?;
    }

    let parsed = match Extension::unmarshal(&mut BufReader::new(&raw[..]))? {
        Extension::SignatureAlgorithmsCert(parsed) => parsed,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(parsed, extension);
    Ok(())
}
