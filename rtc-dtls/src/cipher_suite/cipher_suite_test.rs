use super::*;

// Port of pion `TestCipherSuiteName`: the name of every implemented suite, and the hex fallback
// `0x%04X` for a code point no suite implements. The ECDHE-PSK row of pion's table is omitted:
// this crate implements no ECDHE-PSK suites, so there is no code point to name.
#[test]
fn test_cipher_suite_name() {
    let test_cases = [
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        ),
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256,
            "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        ),
        // pion constructs CipherSuiteID(0x0000); an unknown code point folds here carrying it.
        (CipherSuiteId::from(0x0000u16), "0x0000"),
    ];

    for (suite, expected) in test_cases {
        assert_eq!(suite.to_string(), expected, "CipherSuiteName({suite:?})");
    }
}

// Port of pion `TestAllCipherSuites`.
#[test]
fn test_all_cipher_suites() {
    assert!(!all_cipher_suites().is_empty());
}

// Port of pion `TestInsecureCipherSuites`: this crate implements no suite with security issues.
#[test]
fn test_insecure_cipher_suites() {
    assert!(
        insecure_cipher_suites().is_empty(),
        "Expected no insecure ciphersuites"
    );
}

// Port of pion `TestCipherSuites`: the public list mirrors `all_cipher_suites` entry for entry —
// same code point, same name, exactly one supported version (DTLS 1.2), and never insecure.
#[test]
fn test_cipher_suites() {
    let ours = all_cipher_suites();
    let theirs = cipher_suites();
    assert_eq!(ours.len(), theirs.len());

    for (i, s) in ours.iter().enumerate() {
        let name = s.to_string();
        let cipher = &theirs[i];
        assert_eq!(cipher.id, s.id(), "{name}: ID");
        assert_eq!(cipher.name, name, "{name}: Name");
        assert_eq!(
            cipher.supported_versions.len(),
            1,
            "{name}: Expected SupportedVersion to be 1"
        );
        assert_eq!(
            cipher.supported_versions[0], PROTOCOL_VERSION1_2,
            "{name}: Expected SupportedVersion to match"
        );
        assert!(!cipher.insecure, "{name}: Expected Insecure == false");
    }
}
