//! Ported from pion/dtls v3.1.15 `pkg/crypto/signaturehash/signaturehash_13_test.go`.
//!
//! The tests are named with the repo's `test_` prefix because a plain transliteration of
//! `TestAlgorithms13` would collide with the [`algorithms_13`](super::algorithms_13) function
//! this module imports.

use super::*;

/// pion's `TestAlgorithms13`.
#[test]
fn test_algorithms_13() {
    let algos = algorithms_13();

    // Verify we got expected number of algorithms
    // ECDSA (3) + Ed25519 (1) + RSA-PSS (3) + RSA PKCS#1 (3) = 10
    assert_eq!(
        algos.len(),
        10,
        "algorithms_13 should return 10 signature schemes"
    );

    // Verify ECDSA schemes come first (industry standard preference)
    assert_eq!(
        algos[0],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa
        }
    );
    assert_eq!(
        algos[1],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Ecdsa
        }
    );
    assert_eq!(
        algos[2],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Ecdsa
        }
    );

    // Verify Ed25519
    assert_eq!(
        algos[3],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::Ed25519
        }
    );

    // Verify RSA-PSS schemes (TLS 1.3 preference for RSA)
    assert_eq!(
        algos[4],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::RsaPssRsaeSha256
        }
    );
    assert_eq!(
        algos[5],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::RsaPssRsaeSha384
        }
    );
    assert_eq!(
        algos[6],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::RsaPssRsaeSha512
        }
    );

    // Verify RSA PKCS#1 v1.5 schemes come last (TLS 1.2 compatibility)
    assert_eq!(
        algos[7],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Rsa
        }
    );
    assert_eq!(
        algos[8],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Rsa
        }
    );
    assert_eq!(
        algos[9],
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Rsa
        }
    );
}

/// pion's `TestAlgorithms13_IncludesRSAPSS`.
#[test]
fn test_algorithms_13_includes_rsa_pss() {
    let algos = algorithms_13();

    // Verify DTLS 1.3 algorithms include RSA-PSS schemes
    let has_rsa_pss = algos.iter().any(|algo| algo.signature.is_pss());
    assert!(
        has_rsa_pss,
        "algorithms_13() should include RSA-PSS schemes"
    );

    // Verify we still have RSA PKCS#1 v1.5 for backward compatibility
    let has_rsa = algos
        .iter()
        .any(|algo| algo.signature == SignatureAlgorithm::Rsa);
    assert!(
        has_rsa,
        "algorithms_13() should include RSA PKCS#1 v1.5 for backward compatibility"
    );
}

/// pion's `TestAlgorithms13_RSAPSSBeforePKCS1`.
#[test]
fn test_algorithms_13_rsa_pss_before_pkcs1() {
    let algos = algorithms_13();

    // Find positions of first RSA-PSS and first RSA PKCS#1 schemes
    let first_rsa_pss = algos
        .iter()
        .position(|algo| algo.signature.is_pss())
        .expect("should find RSA-PSS schemes");
    let first_rsa = algos
        .iter()
        .position(|algo| algo.signature == SignatureAlgorithm::Rsa)
        .expect("should find RSA PKCS#1 schemes");

    // In TLS 1.3, RSA-PSS should be preferred over RSA PKCS#1 v1.5
    assert!(
        first_rsa_pss < first_rsa,
        "RSA-PSS schemes should come before RSA PKCS#1 in algorithms_13() for TLS 1.3 preference"
    );
}
