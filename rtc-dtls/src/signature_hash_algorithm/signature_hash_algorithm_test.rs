use super::*;

#[test]
fn test_parse_signature_schemes() -> Result<()> {
    let tests = vec![
        (
            "Translate",
            vec![
                SignatureScheme::EcdsaWithP256AndSha256 as u16,
                SignatureScheme::EcdsaWithP384AndSha384 as u16,
                SignatureScheme::EcdsaWithP521AndSha512 as u16,
                SignatureScheme::Pkcs1WithSha256 as u16,
                SignatureScheme::Pkcs1WithSha384 as u16,
                SignatureScheme::Pkcs1WithSha512 as u16,
            ],
            vec![
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha384,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha512,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Rsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha384,
                    signature: SignatureAlgorithm::Rsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha512,
                    signature: SignatureAlgorithm::Rsa,
                },
            ],
            false,
            None,
        ),
        (
            "InvalidSignatureAlgorithm",
            vec![
                SignatureScheme::EcdsaWithP256AndSha256 as u16, // Valid
                0x04FF, // Invalid: unknown signature with SHA-256
            ],
            vec![],
            false,
            Some(Error::ErrInvalidSignatureAlgorithm),
        ),
        (
            "InvalidHashAlgorithm",
            vec![
                SignatureScheme::EcdsaWithP256AndSha256 as u16, // Valid
                0x0003,                                         // Invalid: ECDSA with MD2
            ],
            vec![],
            false,
            Some(Error::ErrInvalidHashAlgorithm),
        ),
        (
            "InsecureHashAlgorithmDenied",
            vec![
                SignatureScheme::EcdsaWithP256AndSha256 as u16, // Valid
                SignatureScheme::EcdsaWithSha1 as u16,          // Insecure
            ],
            vec![SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            }],
            false,
            None,
        ),
        (
            "InsecureHashAlgorithmAllowed",
            vec![
                SignatureScheme::EcdsaWithP256AndSha256 as u16, // Valid
                SignatureScheme::EcdsaWithSha1 as u16,          // Insecure
            ],
            vec![
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha1,
                    signature: SignatureAlgorithm::Ecdsa,
                },
            ],
            true,
            None,
        ),
        (
            "OnlyInsecureHashAlgorithm",
            vec![
                SignatureScheme::EcdsaWithSha1 as u16, // Insecure
            ],
            vec![],
            false,
            Some(Error::ErrNoAvailableSignatureSchemes),
        ),
        (
            "Translate",
            vec![SignatureScheme::Ed25519 as u16],
            vec![SignatureHashAlgorithm {
                hash: HashAlgorithm::Ed25519,
                signature: SignatureAlgorithm::Ed25519,
            }],
            false,
            None,
        ),
    ];

    for (name, inputs, expected, insecure_hashes, want_err) in tests {
        let output = parse_signature_schemes(&inputs, insecure_hashes);
        if let Some(err) = want_err {
            if let Err(output_err) = output {
                assert_eq!(
                    err.to_string(),
                    output_err.to_string(),
                    "Expected error: {err:?}, got: {output_err:?}"
                );
            } else {
                panic!("expect err, but got non-err for {name}");
            }
        } else if let Ok(output_val) = output {
            assert_eq!(
                expected, output_val,
                "Expected signatureHashAlgorithm:\n{expected:?}\ngot:\n{output_val:?}",
            );
        } else {
            panic!("expect non-err, but got err for {name}");
        }
    }

    Ok(())
}

// Port of pion `pkg/crypto/signature` `TestIsPSS`. The raw-value edge cases
// (`Algorithm(0x0807)` Ed25519 and `Algorithm(0x0808)` Ed448 inside the PSS value range) cannot
// be constructed here: `SignatureAlgorithm` is a closed enum whose non-PSS members keep their
// one-byte code points, so range confusion is impossible by construction.
#[test]
fn test_is_pss() {
    let tests = [
        (SignatureAlgorithm::RsaPssRsaeSha256, true),
        (SignatureAlgorithm::RsaPssRsaeSha384, true),
        (SignatureAlgorithm::RsaPssRsaeSha512, true),
        (SignatureAlgorithm::RsaPssPssSha256, true),
        (SignatureAlgorithm::RsaPssPssSha384, true),
        (SignatureAlgorithm::RsaPssPssSha512, true),
        (SignatureAlgorithm::Rsa, false),
        (SignatureAlgorithm::Ecdsa, false),
        (SignatureAlgorithm::Ed25519, false),
        (SignatureAlgorithm::Anonymous, false),
    ];

    for (alg, expected) in tests {
        assert_eq!(alg.is_pss(), expected, "IsPSS({alg:?})");
    }
}

// Port of pion `pkg/crypto/signature` `TestIsUnsupported`: the RSA_PSS_PSS family is parsed for
// interoperability but never negotiated.
#[test]
fn test_is_unsupported() {
    let tests = [
        (SignatureAlgorithm::RsaPssRsaeSha256, false),
        (SignatureAlgorithm::RsaPssRsaeSha384, false),
        (SignatureAlgorithm::RsaPssRsaeSha512, false),
        (SignatureAlgorithm::RsaPssPssSha256, true),
        (SignatureAlgorithm::RsaPssPssSha384, true),
        (SignatureAlgorithm::RsaPssPssSha512, true),
        (SignatureAlgorithm::Rsa, false),
        (SignatureAlgorithm::Ecdsa, false),
        (SignatureAlgorithm::Ed25519, false),
        (SignatureAlgorithm::Anonymous, false),
    ];

    for (alg, expected) in tests {
        assert_eq!(alg.is_unsupported(), expected, "IsUnsupported({alg:?})");
    }
}

// Port of pion `pkg/crypto/signature` `TestGetPSSHash`. Non-PSS algorithms yield the `0` code
// point, which pion spells `hash.None` and this crate `HashAlgorithm::Md2`.
#[test]
fn test_get_pss_hash() {
    let tests = [
        (SignatureAlgorithm::RsaPssRsaeSha256, HashAlgorithm::Sha256),
        (SignatureAlgorithm::RsaPssRsaeSha384, HashAlgorithm::Sha384),
        (SignatureAlgorithm::RsaPssRsaeSha512, HashAlgorithm::Sha512),
        (SignatureAlgorithm::RsaPssPssSha256, HashAlgorithm::Sha256),
        (SignatureAlgorithm::RsaPssPssSha384, HashAlgorithm::Sha384),
        (SignatureAlgorithm::RsaPssPssSha512, HashAlgorithm::Sha512),
        (SignatureAlgorithm::Rsa, HashAlgorithm::Md2),
        (SignatureAlgorithm::Ecdsa, HashAlgorithm::Md2),
        (SignatureAlgorithm::Ed25519, HashAlgorithm::Md2),
    ];

    for (alg, expected) in tests {
        assert_eq!(alg.get_pss_hash(), expected, "GetPSSHash({alg:?})");
    }
}

// Port of pion `pkg/crypto/hash` `TestExtractHashFromPSS`: RSA-PSS RSAE and PSS schemes map to
// their hash; everything else — including Ed25519 (0x0807) and Ed448 (0x0808) inside the PSS
// value range — maps to the `0` code point (`hash.None`, here `HashAlgorithm::Md2`).
#[test]
fn test_extract_hash_from_pss() {
    let tests: [(u16, HashAlgorithm); 12] = [
        // RSA-PSS-RSAE schemes
        (0x0804, HashAlgorithm::Sha256),
        (0x0805, HashAlgorithm::Sha384),
        (0x0806, HashAlgorithm::Sha512),
        // RSA-PSS-PSS schemes
        (0x0809, HashAlgorithm::Sha256),
        (0x080a, HashAlgorithm::Sha384),
        (0x080b, HashAlgorithm::Sha512),
        // Non-PSS schemes return the 0 code point
        (0x0807, HashAlgorithm::Md2), // Ed25519
        (0x0808, HashAlgorithm::Md2), // Ed448
        (0x0403, HashAlgorithm::Md2), // ECDSA_SHA256
        (0x0401, HashAlgorithm::Md2), // RSA_PKCS1_SHA256
        (0xFFFF, HashAlgorithm::Md2), // Unknown
        (0x0000, HashAlgorithm::Md2),
    ];

    for (scheme, expected) in tests {
        assert_eq!(
            extract_hash_from_pss(scheme),
            expected,
            "ExtractHashFromPSS({scheme:#06x})"
        );
    }
}

// Port of pion `pkg/crypto/signature` `TestAlgorithms`: every implemented signature algorithm —
// the PSS family and the legacy ones — is recognized by the scheme decoder. The 0x0808 code
// point (Ed448) is in the PSS value range but is not a member.
#[test]
fn test_signature_algorithms() -> Result<()> {
    let members = [
        (
            0x0400u16,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Anonymous,
            },
        ),
        (
            0x0401,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            },
        ),
        (
            0x0403,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
        ),
        (
            0x0807,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Ed25519,
                signature: SignatureAlgorithm::Ed25519,
            },
        ),
        (
            0x0804,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssRsaeSha256,
            },
        ),
        (
            0x0805,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::RsaPssRsaeSha384,
            },
        ),
        (
            0x0806,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha512,
                signature: SignatureAlgorithm::RsaPssRsaeSha512,
            },
        ),
        (
            0x0809,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssPssSha256,
            },
        ),
        (
            0x080a,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::RsaPssPssSha384,
            },
        ),
        (
            0x080b,
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha512,
                signature: SignatureAlgorithm::RsaPssPssSha512,
            },
        ),
    ];

    for (scheme, expected) in members {
        assert_eq!(SignatureHashAlgorithm::from_scheme(scheme)?, expected);
        // Each member re-encodes to its scheme value.
        assert_eq!(
            u16::from_be_bytes(expected.scheme_bytes()?),
            scheme,
            "scheme round-trip for {scheme:#06x}"
        );
    }

    // 0x0808 (Ed448) is in the PSS value range but not a member.
    assert!(matches!(
        SignatureHashAlgorithm::from_scheme(0x0808),
        Err(Error::ErrInvalidSignatureAlgorithm)
    ));

    Ok(())
}
