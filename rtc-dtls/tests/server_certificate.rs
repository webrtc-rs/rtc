//! How a client judges the server's certificate, ported from pion/dtls v3.1.15
//! `TestServerCertificate` (`conn_test.go`).

mod common;

use std::sync::Arc;

use common::*;
use rtc_dtls::config::ConfigBuilder;
use rustls::RootCertStore;
use shared::error::Error;

fn trusting(cert: &rtc_dtls::crypto::Certificate) -> ConfigBuilder {
    let mut store = RootCertStore::empty();
    store.add(cert.certificate[0].clone()).unwrap();
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_roots_cas(store)
}

fn server(cert: &rtc_dtls::crypto::Certificate) -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_certificates(vec![cert.clone()])
}

fn run(client: ConfigBuilder, server: ConfigBuilder) -> bool {
    match try_handshake(client, server) {
        Ok(out) => out.ok(),
        Err(_) => false,
    }
}

#[test]
fn test_server_certificate_verification() {
    let cert = certificate();

    // no_ca: nothing to verify against
    assert!(!run(
        ConfigBuilder::default().with_crypto_provider(provider()),
        server(&cert)
    ));
    // good_ca
    assert!(run(trusting(&cert), server(&cert)));
    // no_ca_skip_verify
    assert!(run(
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_insecure_skip_verify(true),
        server(&cert)
    ));
    // server_name matches a name in the certificate / does not
    assert!(run(
        trusting(&cert).with_server_name("localhost".to_owned()),
        server(&cert)
    ));
    assert!(!run(
        trusting(&cert).with_server_name("barfoo".to_owned()),
        server(&cert)
    ));
    // A certificate from somewhere else is not trusted.
    assert!(!run(trusting(&certificate()), server(&cert)));
}

#[test]
fn test_verify_peer_certificate_callback() {
    let cert = certificate();

    // good_ca_custom_verify_peer: the callback's refusal fails the handshake.
    let refuse: rtc_dtls::config::VerifyPeerCertificateFn =
        Arc::new(|_, _| Err(Error::Other("wrong cert".to_owned())));
    assert!(!run(
        trusting(&cert).with_verify_peer_certificate(Some(refuse)),
        server(&cert)
    ));

    // The callback sees the raw certificates, and the verified chain when verification ran.
    let seen = Arc::new(std::sync::Mutex::new(vec![]));
    let log = seen.clone();
    let record: rtc_dtls::config::VerifyPeerCertificateFn = Arc::new(move |raw, chain| {
        log.lock().unwrap().push((raw.len(), chain.len()));
        Ok(())
    });
    assert!(run(
        trusting(&cert).with_verify_peer_certificate(Some(record)),
        server(&cert)
    ));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "called once");
    assert_eq!(seen[0].0, 1, "one raw certificate");
    assert!(seen[0].1 >= 1, "a verified chain was handed over");

    // good_ca_skip_verify_custom_verify_peer: no verification, so no verified chain.
    let seen = Arc::new(std::sync::Mutex::new(vec![]));
    let log = seen.clone();
    let record: rtc_dtls::config::VerifyPeerCertificateFn = Arc::new(move |_, chain| {
        log.lock().unwrap().push(chain.len());
        Ok(())
    });
    assert!(run(
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_insecure_skip_verify(true)
            .with_verify_peer_certificate(Some(record)),
        server(&cert)
    ));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![0],
        "no chain without verification"
    );
}
