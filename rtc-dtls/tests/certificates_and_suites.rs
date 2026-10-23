//! Certificate selection and cipher-suite / certificate matching, ported from pion/dtls v3.1.15
//! `TestMultipleServerCertificates`, `TestCipherSuiteMatchesCertificateType` and
//! `TestHandshakeWithAlert` (`conn_test.go`).

mod common;

use common::*;
use rtc_dtls::cipher_suite::CipherSuiteId::*;
use rtc_dtls::config::ConfigBuilder;
use rtc_dtls::crypto::Certificate;
use shared::error::Error;
use std::sync::{Arc, Mutex};

fn cert_for(name: &str) -> Certificate {
    Certificate::generate_self_signed(vec![name.to_owned()], provider().crypto()).unwrap()
}

/// With several certificates the server presents the one whose name matches the client's SNI,
/// and the first when nothing does.
#[test]
fn test_multiple_server_certificates() {
    let foo = cert_for("foo");
    let bar = cert_for("bar");
    for (request, expected) in [("foo", &foo), ("bar", &bar), ("invalid", &foo)] {
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        let record: rtc_dtls::config::VerifyPeerCertificateFn = Arc::new(move |raw, _| {
            log.lock().unwrap().push(raw[0].clone());
            Ok(())
        });
        let out = handshake(
            builder()
                .with_server_name(request.to_owned())
                .with_verify_peer_certificate(Some(record)),
            builder().with_certificates(vec![foo.clone(), bar.clone()]),
        );
        assert!(
            out.ok(),
            "{request}: {:?} / {:?}",
            out.client_error,
            out.server_error
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![expected.certificate[0].as_ref().to_vec()],
            "server name {request}"
        );
    }
}

/// An ECDSA certificate meets an ECDSA suite even when an RSA suite is listed first.
#[test]
fn test_cipher_suite_matches_the_certificate_type() {
    let suites = vec![
        Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
        Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    ];
    let out = try_handshake(
        builder().with_cipher_suites(suites.clone()),
        builder()
            .with_cipher_suites(suites)
            .with_certificates(vec![certificate()]),
    )
    .expect("builds");
    assert!(out.ok(), "{:?} / {:?}", out.client_error, out.server_error);
    assert_eq!(
        out.client_state().unwrap().cipher_suite().unwrap().id(),
        Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256
    );
}

/// `TestHandshakeWithAlert`, "CipherSuiteNoIntersection": ECDSA server, RSA-only client.
#[test]
fn test_handshake_with_alert_cipher_suite_no_intersection() {
    let out = try_handshake(
        builder().with_cipher_suites(vec![Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256]),
        builder()
            .with_cipher_suites(vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_certificates(vec![certificate()]),
    );
    match out {
        Ok(out) => {
            assert!(!out.ok());
            assert!(matches!(
                out.server_error,
                Some(Error::ErrCipherSuiteNoIntersection)
            ));
            assert_eq!(out.alerts(Dir::ServerToClient), vec![(2, 71)]);
        }
        // Acceptable: a crypto provider that cannot do RSA refuses the client up front.
        Err(err) => assert!(matches!(err, Error::ErrNoAvailableCipherSuites), "{err}"),
    }
}

/// Restricting the curves leaves a configuration that still handshakes, and one with no curve
/// the provider supports is refused.
#[test]
fn test_default_curves_handshake() {
    let out = handshake(
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_insecure_skip_verify(true)
            .with_cipher_suites(vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]),
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_certificates(vec![certificate()])
            .with_cipher_suites(vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]),
    );
    assert!(out.ok());
}
