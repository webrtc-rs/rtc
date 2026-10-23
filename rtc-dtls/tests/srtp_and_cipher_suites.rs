//! `use_srtp` and cipher-suite selection, ported from pion/dtls v3.1.15 `TestSRTPConfiguration`
//! and `TestCipherSuiteConfiguration` (`conn_test.go`). The master-key-identifier cases wait for
//! MKI support (not implemented: the extension always carries an empty MKI).

mod common;

use common::*;
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile as P;
use shared::error::Error;

const SHA1_80: P = P::Srtp_Aes128_Cm_Hmac_Sha1_80;
const SHA1_32: P = P::Srtp_Aes128_Cm_Hmac_Sha1_32;

fn run(client: Vec<P>, server: Vec<P>) -> Outcome {
    handshake(
        builder().with_srtp_protection_profiles(client),
        builder()
            .with_certificates(vec![certificate()])
            .with_srtp_protection_profiles(server),
    )
}

/// The rows of `TestSRTPConfiguration` that do not involve an MKI.
#[test]
fn test_srtp_configuration() {
    // (name, client, server, expected profile when it succeeds)
    let ok_cases: Vec<(&str, Vec<P>, Vec<P>, P)> = vec![
        ("no SRTP in use", vec![], vec![], P::Unsupported),
        ("SRTP server only", vec![], vec![SHA1_80], P::Unsupported),
        ("both", vec![SHA1_80], vec![SHA1_80], SHA1_80),
        (
            "multiple suites",
            vec![SHA1_80, SHA1_32],
            vec![SHA1_80, SHA1_32],
            SHA1_80,
        ),
        (
            "multiple suites, server chooses",
            vec![SHA1_80, SHA1_32],
            vec![SHA1_32, SHA1_80],
            SHA1_32,
        ),
    ];
    for (name, client, server, expected) in ok_cases {
        let out = run(client, server);
        assert!(
            out.ok(),
            "{name}: {:?} / {:?}",
            out.client_error,
            out.server_error
        );
        assert_eq!(
            out.client_state().unwrap().srtp_protection_profile(),
            expected,
            "{name}: client"
        );
        assert_eq!(
            out.server_state().unwrap().srtp_protection_profile(),
            expected,
            "{name}: server"
        );
    }

    // "SRTP client only": the server has none to agree on; both sides fail, the client with the
    // server's fatal insufficient_security alert.
    let out = run(vec![SHA1_80], vec![]);
    assert!(!out.ok());
    assert!(matches!(
        out.server_error,
        Some(Error::ErrServerNoMatchingSrtpProfile)
    ));
    assert_eq!(out.alerts(Dir::ServerToClient), vec![(2, 71)]);
}

#[test]
fn test_srtp_keying_material_matches_on_both_sides() {
    let out = run(vec![SHA1_80], vec![SHA1_80]);
    assert!(out.ok());
    let client = out
        .client_state()
        .unwrap()
        .export_keying_material("EXTRACTOR-dtls_srtp", &[], 60)
        .unwrap()
        .into_bytes();
    let server = out
        .server_state()
        .unwrap()
        .export_keying_material("EXTRACTOR-dtls_srtp", &[], 60)
        .unwrap()
        .into_bytes();
    assert_eq!(client, server);
    assert_eq!(client.len(), 60);
    assert!(client.iter().any(|b| *b != 0));
}

use CipherSuiteId::*;

fn suites(client: Vec<CipherSuiteId>, server: Vec<CipherSuiteId>) -> Result<Outcome, Error> {
    try_handshake(
        builder().with_cipher_suites(client),
        builder()
            .with_certificates(vec![certificate()])
            .with_cipher_suites(server),
    )
}

/// `TestCipherSuiteConfiguration`.
#[test]
fn test_cipher_suite_configuration() {
    // No suites configured: the defaults interoperate.
    let out = suites(vec![], vec![]).unwrap();
    assert!(out.ok());

    // Matching suites negotiate that suite.
    for suite in [
        Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
        Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
        Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    ] {
        let out = suites(vec![suite], vec![suite]).unwrap();
        assert!(out.ok(), "{suite:?}");
        assert_eq!(
            out.client_state().unwrap().cipher_suite().unwrap().id(),
            suite
        );
        assert_eq!(
            out.server_state().unwrap().cipher_suite().unwrap().id(),
            suite
        );
    }

    // "CipherSuites mismatch": the server refuses with insufficient_security.
    let out = suites(
        vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
        vec![Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha],
    )
    .unwrap();
    assert!(!out.ok());
    assert!(matches!(
        out.server_error,
        Some(Error::ErrCipherSuiteNoIntersection)
    ));
    assert_eq!(out.alerts(Dir::ServerToClient), vec![(2, 71)]);

    // "Server supports subset of client suites".
    let out = suites(
        vec![
            Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        ],
        vec![Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha],
    )
    .unwrap();
    assert!(out.ok());
    assert_eq!(
        out.client_state().unwrap().cipher_suite().unwrap().id(),
        Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha
    );

    // "Invalid CipherSuite": a code point nobody implements cannot be configured.
    assert!(suites(vec![Unsupported], vec![Unsupported]).is_err());
}
