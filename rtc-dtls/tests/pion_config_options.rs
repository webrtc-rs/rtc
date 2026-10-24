//! Config callbacks and options ported from pion/dtls v3.1.15 `conn_test.go` (the
//! config-callbacks issue): the `TestPSK` VerifyConnection cases, the `TestClientCertificate`
//! VerifyConnection/GetCertificate/GetClientCertificate cases,
//! `TestCertificateVerifyHonorsLocalSignatureSchemes`, `TestSkipHelloVerify`,
//! `TestEllipticCurveConfiguration` and `TestHelloRandom`.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::config::{
    CertificateRequestInfo, ClientAuthType, ClientHelloInfo, ConfigBuilder, GetCertificateFn,
    GetClientCertificateFn, VerifyConnectionFn,
};
use rtc_dtls::crypto::Certificate;
use rtc_dtls::curve::named_curve::NamedCurve;
use rtc_dtls::handshake::HandshakeMessage;
use rtc_dtls::signature_hash_algorithm::{
    HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm, SignatureScheme,
};
use rtc_dtls::state::State;
use rustls::RootCertStore;
use shared::error::Error;

const PSK: [u8; 3] = [0xab, 0xc1, 0x23];

fn psk_pair() -> (ConfigBuilder, ConfigBuilder) {
    let server = builder()
        .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8])
        .with_psk(Some(Arc::new(|_hint: &[u8]| Ok(PSK.to_vec()))))
        .with_psk_identity_hint(Some(b"Test Identity".to_vec()));
    let client = builder()
        .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8])
        .with_psk(Some(Arc::new(|_hint: &[u8]| Ok(PSK.to_vec()))))
        .with_psk_identity_hint(Some(b"Client Identity".to_vec()));
    (client, server)
}

fn verify_connection_err() -> VerifyConnectionFn {
    Arc::new(|_state: &State| Err(Error::Other("verify failed".to_owned())))
}

fn verify_connection_ok() -> VerifyConnectionFn {
    Arc::new(|_state: &State| Ok(()))
}

/// The `(level, description)` bytes of a fatal alert.
fn fatal(description: u8) -> (u8, u8) {
    (2, description)
}

/// Every plaintext alert record a side sent, whatever epoch it rode: a client that alerts
/// after its ChangeCipherSpec sends the record at epoch 1, still unencrypted because the
/// handshake never completed.
fn any_epoch_alerts(out: &Outcome, dir: Dir) -> Vec<(u8, u8)> {
    let mut out_alerts = vec![];
    for (d, datagram) in &out.log {
        if *d != dir {
            continue;
        }
        let mut rest = &datagram[..];
        while rest.len() >= 13 {
            let content_type = rest[0];
            let len = u16::from_be_bytes([rest[11], rest[12]]) as usize;
            if rest.len() < 13 + len {
                break;
            }
            if content_type == 21 && len == 2 {
                out_alerts.push((rest[13], rest[14]));
            }
            rest = &rest[13 + len..];
        }
    }
    out_alerts
}

/// `TestPSK`, "Server identity specified - Server verify connection fails": the server's
/// callback error comes back locally and the client sees a fatal `bad_certificate` alert.
#[test]
fn test_psk_server_verify_connection_fails() {
    let (client, server) = psk_pair();
    let out = handshake(
        client,
        server.with_verify_connection(Some(verify_connection_err())),
    );

    assert!(!out.ok(), "the handshake must fail");
    let server_error = out.server_error.as_ref().expect("the server fails locally");
    assert!(
        server_error.to_string().contains("verify failed"),
        "server error carries the callback's error: {server_error}"
    );
    assert!(
        out.client_error.is_some(),
        "the client fails too, on the alert"
    );
    assert_eq!(
        out.alerts(Dir::ServerToClient),
        vec![fatal(42)], // fatal, bad_certificate
        "the peer receives a fatal bad_certificate alert"
    );
}

/// `TestPSK`, "Server identity specified - Client verify connection fails": mirrored — the
/// client's callback error stays local, the server sees the alert.
#[test]
fn test_psk_client_verify_connection_fails() {
    let (client, server) = psk_pair();
    let out = handshake(
        client.with_verify_connection(Some(verify_connection_err())),
        server,
    );

    assert!(!out.ok(), "the handshake must fail");
    let client_error = out.client_error.as_ref().expect("the client fails locally");
    assert!(
        client_error.to_string().contains("verify failed"),
        "client error carries the callback's error: {client_error}"
    );
    assert!(
        out.server_error.is_some(),
        "the server fails too, on the alert"
    );
    // The client alerts after its ChangeCipherSpec, so the record rides epoch 1.
    assert_eq!(
        any_epoch_alerts(&out, Dir::ClientToServer),
        vec![fatal(42)], // fatal, bad_certificate
        "the peer receives a fatal bad_certificate alert"
    );
}

/// `TestPSK` with VerifyConnection set on both sides and returning success: the handshake
/// completes and the callbacks ran.
#[test]
fn test_psk_verify_connection_success() {
    let (client, server) = psk_pair();
    let client_runs = Arc::new(Mutex::new(0u32));
    let server_runs = Arc::new(Mutex::new(0u32));
    let client_runs_cb = client_runs.clone();
    let server_runs_cb = server_runs.clone();

    let out = handshake(
        client.with_verify_connection(Some(Arc::new(move |_state: &State| {
            *client_runs_cb.lock().unwrap() += 1;
            Ok(())
        }) as VerifyConnectionFn)),
        server.with_verify_connection(Some(Arc::new(move |_state: &State| {
            *server_runs_cb.lock().unwrap() += 1;
            Ok(())
        }) as VerifyConnectionFn)),
    );

    assert!(
        out.ok(),
        "client: {:?}, server: {:?}",
        out.client_error,
        out.server_error
    );
    assert_eq!(*client_runs.lock().unwrap(), 1, "the client ran it once");
    assert_eq!(*server_runs.lock().unwrap(), 1, "the server ran it once");
    assert_eq!(
        out.server_state().unwrap().identity_hint,
        b"Client Identity".to_vec(),
        "the server state is still observable through the callback's &State"
    );
}

/// `TestClientCertificate`'s VerifyConnection case: the option composes with client-certificate
/// authentication — success when it returns `Ok`, failure (and a `bad_certificate` alert) when
/// it errors.
#[test]
fn test_client_certificate_verify_connection() {
    let server_cert = certificate();
    let client_cert = certificate();

    let client = |verify: Option<VerifyConnectionFn>| {
        builder()
            .with_certificates(vec![client_cert.clone()])
            .with_verify_connection(verify)
    };
    let server = |verify: Option<VerifyConnectionFn>| {
        let mut server_cas = RootCertStore::empty();
        server_cas
            .add(client_cert.certificate[0].clone())
            .expect("a valid root");
        builder()
            .with_certificates(vec![server_cert.clone()])
            .with_client_auth(ClientAuthType::RequireAndVerifyClientCert)
            .with_client_cas(server_cas)
            .with_verify_connection(verify)
    };

    let out = handshake(client(None), server(Some(verify_connection_ok())));
    assert!(
        out.ok(),
        "success path: {:?}/{:?}",
        out.client_error,
        out.server_error
    );

    let out = handshake(client(None), server(Some(verify_connection_err())));
    assert!(!out.ok(), "server-side failure aborts the handshake");
    assert!(
        out.server_error
            .as_ref()
            .is_some_and(|err| err.to_string().contains("verify failed")),
        "server error carries the callback's error: {:?}",
        out.server_error
    );
    assert_eq!(out.alerts(Dir::ServerToClient), vec![fatal(42)]);

    let out = handshake(client(Some(verify_connection_err())), server(None));
    assert!(!out.ok(), "client-side failure aborts the handshake");
    assert!(
        out.client_error
            .as_ref()
            .is_some_and(|err| err.to_string().contains("verify failed")),
        "client error carries the callback's error: {:?}",
        out.client_error
    );
    // The client alerts after its ChangeCipherSpec, so the record rides epoch 1.
    assert_eq!(any_epoch_alerts(&out, Dir::ClientToServer), vec![fatal(42)]);
}

/// `TestClientCertificate`'s GetClientCertificate case: the callback's certificate is what the
/// server sees, and a callback error fails the handshake with `handshake_failure` going out.
#[test]
fn test_client_certificate_get_client_certificate() {
    let server_cert = certificate();
    let client_cert = certificate();

    let mut server_cas = RootCertStore::empty();
    server_cas
        .add(client_cert.certificate[0].clone())
        .expect("a valid root");
    let server = builder()
        .with_certificates(vec![server_cert.clone()])
        .with_client_auth(ClientAuthType::RequireAndVerifyClientCert)
        .with_client_cas(server_cas);

    // Success: the callback supplies the certificate (none is configured!).
    let seen_info: Arc<Mutex<Option<CertificateRequestInfo>>> = Arc::new(Mutex::new(None));
    let seen = seen_info.clone();
    let callback_cert = client_cert.clone();
    let get_client_certificate: GetClientCertificateFn = Arc::new(move |info| {
        *seen.lock().unwrap() = Some(info.clone());
        Ok(callback_cert.clone())
    });
    let client = builder().with_get_client_certificate(Some(get_client_certificate));

    let out = handshake(client, server.clone());
    assert!(
        out.ok(),
        "callback certificate accepted: {:?}/{:?}",
        out.client_error,
        out.server_error
    );
    assert_eq!(
        out.server_state().unwrap().peer_certificates[0],
        client_cert.certificate[0].as_ref(),
        "the server saw the callback's certificate"
    );
    let info = seen_info.lock().unwrap().clone().expect("the callback ran");
    assert!(
        !info.signature_hash_algorithms.is_empty(),
        "the request's schemes reach the callback: {info:?}"
    );

    // Error: the callback refuses, the client sends a fatal handshake_failure.
    let get_client_certificate: GetClientCertificateFn =
        Arc::new(|_info: &CertificateRequestInfo| {
            Err(Error::Other("no certificate for you".to_owned()))
        });
    let client = builder().with_get_client_certificate(Some(get_client_certificate));
    let out = handshake(client, server);
    assert!(!out.ok(), "a refusing callback fails the handshake");
    assert!(
        out.client_error
            .as_ref()
            .is_some_and(|err| err.to_string().contains("no certificate for you")),
        "client error carries the callback's error: {:?}",
        out.client_error
    );
    assert_eq!(out.alerts(Dir::ClientToServer), vec![fatal(40)]); // fatal, handshake_failure
}

/// `TestServerCertificate`'s GetCertificate case and `TestHelloRandom`: the server's
/// `get_certificate` callback sees the ClientHello's SNI, cipher suites, signature schemes,
/// curves and random bytes; its answer is what the client verifies, `None` falls back to the
/// configured certificates, and an error aborts the handshake.
#[test]
fn test_get_certificate() {
    let foo_cert = Certificate::generate_self_signed(vec!["foo".to_owned()], provider().crypto())
        .expect("a certificate");
    let bar_cert = Certificate::generate_self_signed(vec!["bar".to_owned()], provider().crypto())
        .expect("a certificate");

    // Success: the callback answers SNI "foo" with the foo certificate even though only bar
    // is configured.
    let seen: Arc<Mutex<Vec<ClientHelloInfo>>> = Arc::new(Mutex::new(vec![]));
    let seen_cb = seen.clone();
    let callback_cert = foo_cert.clone();
    let get_certificate: GetCertificateFn = Arc::new(move |info| {
        seen_cb.lock().unwrap().push(info.clone());
        Ok(Some(callback_cert.clone()))
    });
    let server = builder()
        .with_certificates(vec![bar_cert.clone()])
        .with_get_certificate(Some(get_certificate));
    let client = builder()
        .with_server_name("foo".to_owned())
        .with_insecure_skip_verify(true);

    let out = handshake(client, server);
    assert!(
        out.ok(),
        "the callback's certificate completes the handshake: {:?}/{:?}",
        out.client_error,
        out.server_error
    );
    assert_eq!(
        out.client_state().unwrap().peer_certificates[0],
        foo_cert.certificate[0].as_ref(),
        "the client saw the certificate the callback chose"
    );
    let infos = seen.lock().unwrap();
    let info = infos.last().expect("the callback ran");
    assert_eq!(info.server_name, "foo", "SNI reaches the callback");
    assert!(
        !info.cipher_suites.is_empty(),
        "the offered cipher suites reach the callback"
    );
    assert!(
        !info.signature_schemes.is_empty(),
        "the offered signature schemes reach the callback"
    );
    assert!(
        info.elliptic_curves.contains(&NamedCurve::P256),
        "the offered curves reach the callback: {:?}",
        info.elliptic_curves
    );

    // None: falls back to the configured certificates.
    let get_certificate: GetCertificateFn = Arc::new(|_info: &ClientHelloInfo| Ok(None));
    let server = builder()
        .with_certificates(vec![bar_cert.clone()])
        .with_get_certificate(Some(get_certificate));
    let client = builder()
        .with_server_name("foo".to_owned())
        .with_insecure_skip_verify(true);
    let out = handshake(client, server);
    assert!(
        out.ok(),
        "None falls back: {:?}/{:?}",
        out.client_error,
        out.server_error
    );
    assert_eq!(
        out.client_state().unwrap().peer_certificates[0],
        bar_cert.certificate[0].as_ref(),
        "the fallback certificate was presented"
    );

    // Error: the handshake is refused with a fatal handshake_failure.
    let get_certificate: GetCertificateFn =
        Arc::new(|_info: &ClientHelloInfo| Err(Error::Other("no certificate".to_owned())));
    let server = builder()
        .with_certificates(vec![bar_cert.clone()])
        .with_get_certificate(Some(get_certificate));
    let client = builder()
        .with_server_name("foo".to_owned())
        .with_insecure_skip_verify(true);
    let out = handshake(client, server);
    assert!(!out.ok(), "a refusing callback fails the handshake");
    assert!(
        out.server_error
            .as_ref()
            .is_some_and(|err| err.to_string().contains("no certificate")),
        "server error carries the callback's error: {:?}",
        out.server_error
    );
    assert_eq!(out.alerts(Dir::ServerToClient), vec![fatal(40)]); // fatal, handshake_failure
}

/// `TestHelloRandom`: the client's hello random comes from the generator, and the bytes the
/// server's `get_certificate` sees match them.
#[test]
fn test_hello_random() {
    let random_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let seen_random: Arc<Mutex<Option<[u8; 28]>>> = Arc::new(Mutex::new(None));
    let seen = seen_random.clone();
    let server_certificate = certificate();
    let get_certificate: GetCertificateFn = Arc::new(move |info: &ClientHelloInfo| {
        *seen.lock().unwrap() = Some(info.random_bytes);
        Ok(Some(server_certificate.clone()))
    });

    let client = builder().with_hello_random_bytes_generator(Some(Arc::new(move || random_bytes)));
    // As in pion: a server whose only certificate source is the callback.
    let server = builder().with_get_certificate(Some(get_certificate));

    let mut out = handshake(client, server);
    assert!(
        out.ok(),
        "a generated random completes the handshake: {:?}/{:?}",
        out.client_error,
        out.server_error
    );
    assert_eq!(
        *seen_random.lock().unwrap(),
        Some(random_bytes),
        "the server's callback saw the generated bytes"
    );

    // And the application data flows over the derived keys, as in pion's read-back.
    let echoed = client_sends(&mut out, b"hello");
    assert_eq!(echoed, b"hello");
}

/// `TestSkipHelloVerify`: with `insecure_skip_verify_hello` the server answers a cookie-less
/// ClientHello directly — no HelloVerifyRequest crosses the wire — and application data flows.
#[test]
fn test_skip_hello_verify() {
    let client = builder();
    let server = builder()
        .with_certificates(vec![certificate()])
        .with_insecure_skip_verify_hello(true);

    let mut out = handshake(client, server);
    assert!(
        out.ok(),
        "the cookie exchange may be skipped: {:?}/{:?}",
        out.client_error,
        out.server_error
    );

    // No HelloVerifyRequest (handshake type 3) was sent.
    for (dir, datagram) in &out.log {
        if *dir != Dir::ServerToClient {
            continue;
        }
        for (message_type, _) in raw::handshake_messages(datagram) {
            assert_ne!(
                message_type, 3,
                "no HelloVerifyRequest may be sent with insecure_skip_verify_hello"
            );
        }
    }

    let echoed = client_sends(&mut out, b"hello");
    assert_eq!(echoed, b"hello", "application data flows");
}

/// `TestEllipticCurveConfiguration`: a configured curve list is offered in the caller's order,
/// and the default (unset) list is the crate's default.
#[test]
fn test_elliptic_curve_configuration() {
    let cases: Vec<(&str, Vec<NamedCurve>, Vec<NamedCurve>)> = vec![
        ("curve defaulting", vec![], vec![]),
        (
            "single curve",
            vec![NamedCurve::X25519],
            vec![NamedCurve::X25519],
        ),
        (
            "multiple curves",
            vec![NamedCurve::P384, NamedCurve::X25519],
            vec![NamedCurve::P384, NamedCurve::X25519],
        ),
    ];

    for (name, config_curves, handshake_curves) in cases {
        let client = builder().with_elliptic_curves(config_curves.clone());
        let server = builder()
            .with_certificates(vec![certificate()])
            .with_elliptic_curves(config_curves.clone());

        let out = handshake(client, server);
        assert!(
            out.ok(),
            "{name}: the handshake completes: {:?}/{:?}",
            out.client_error,
            out.server_error
        );

        // The first ClientHello carries the configured curves, in order.
        let first_hello = out
            .log
            .iter()
            .find(|(dir, _)| *dir == Dir::ClientToServer)
            .map(|(_, datagram)| datagram.clone())
            .expect("a ClientHello was sent");
        let offered = offered_curves(&first_hello);
        let expected: Vec<NamedCurve> = if handshake_curves.is_empty() {
            // pion's `defaultCurves`.
            vec![NamedCurve::X25519, NamedCurve::P256, NamedCurve::P384]
        } else {
            handshake_curves.clone()
        };
        assert_eq!(offered, expected, "{name}: the offered curves match");
    }
}

/// The `supported_elliptic_curves` (type 10) list of the first ClientHello on the wire.
fn offered_curves(datagram: &[u8]) -> Vec<NamedCurve> {
    let (_, body) = raw::handshake_messages(datagram)
        .into_iter()
        .find(|(message_type, _)| *message_type == 1)
        .expect("a ClientHello message");
    for (extension_type, data) in raw::hello_extensions(&body, false) {
        if extension_type == 10 && data.len() >= 2 {
            let count = u16::from_be_bytes([data[0], data[1]]) as usize / 2;
            return (0..count)
                .map(|i| {
                    let value = u16::from_be_bytes([data[2 + i * 2], data[3 + i * 2]]);
                    NamedCurve::from(value)
                })
                .collect();
        }
    }
    vec![]
}

/// `TestCertificateVerifyHonorsLocalSignatureSchemes`: the client picks its CertificateVerify
/// scheme by honoring its local policy while retaining the server's (hooked) preference order;
/// when nothing survives the intersection the handshake fails.
#[test]
fn test_certificate_verify_honors_local_signature_schemes() {
    struct Case {
        name: &'static str,
        requested: Vec<SignatureHashAlgorithm>,
        local: Vec<SignatureScheme>,
        insecure_hashes: bool,
        want: Option<HashAlgorithm>,
    }
    let ecdsa = |hash| SignatureHashAlgorithm {
        hash,
        signature: SignatureAlgorithm::Ecdsa,
    };
    let cases = vec![
        Case {
            name: "reject MD5",
            requested: vec![ecdsa(HashAlgorithm::Md5)],
            local: vec![],
            insecure_hashes: false,
            want: None,
        },
        Case {
            name: "reject SHA1",
            requested: vec![ecdsa(HashAlgorithm::Sha1)],
            local: vec![],
            insecure_hashes: false,
            want: None,
        },
        Case {
            name: "reject SHA224",
            requested: vec![ecdsa(HashAlgorithm::Sha224)],
            local: vec![],
            insecure_hashes: false,
            want: None,
        },
        Case {
            name: "reject excluded SHA384",
            requested: vec![ecdsa(HashAlgorithm::Sha384)],
            local: vec![SignatureScheme::EcdsaWithP256AndSha256],
            insecure_hashes: false,
            want: None,
        },
        Case {
            name: "skip weak hashes",
            requested: vec![
                ecdsa(HashAlgorithm::Md5),
                ecdsa(HashAlgorithm::Sha1),
                ecdsa(HashAlgorithm::Sha256),
            ],
            local: vec![],
            insecure_hashes: false,
            want: Some(HashAlgorithm::Sha256),
        },
        // pion's client signs P-256 with SHA-384 and expects SHA-384; the providers here
        // bind each ECDSA key to a single hash, so the peer's preference survives as a
        // walk of its list down to the first scheme the key can sign: SHA-256.
        Case {
            name: "retain peer preference",
            requested: vec![ecdsa(HashAlgorithm::Sha384), ecdsa(HashAlgorithm::Sha256)],
            local: vec![],
            insecure_hashes: false,
            want: Some(HashAlgorithm::Sha256),
        },
        // pion's client signs ECDSA with SHA-1 here (want: SHA1). `insecure_hashes` does let
        // SHA-1 through our filter too, but the providers bind each ECDSA key to a single
        // hash and refuse to sign SHA-1, so the walk finds nothing signable — the same
        // provider boundary the P-521 case in `client_certificate.rs` documents.
        Case {
            name: "explicit SHA1 opt in",
            requested: vec![ecdsa(HashAlgorithm::Sha1)],
            local: vec![
                SignatureScheme::EcdsaWithP256AndSha256,
                SignatureScheme::EcdsaWithSha1,
            ],
            insecure_hashes: true,
            want: None,
        },
    ];

    for case in cases {
        let server_cert = certificate();
        let client_cert = certificate();

        let client = builder()
            .with_certificates(vec![client_cert.clone()])
            .with_insecure_hashes(case.insecure_hashes)
            .with_signature_schemes(case.local.clone());
        let server = builder()
            .with_certificates(vec![server_cert.clone()])
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_insecure_hashes(true)
            .with_signature_schemes(vec![
                SignatureScheme::EcdsaWithP256AndSha256,
                SignatureScheme::EcdsaWithP384AndSha384,
                SignatureScheme::EcdsaWithSha1,
            ])
            .with_certificate_request_message_hook(Some(Arc::new(move |mut request| {
                request.set_signature_hash_algorithms(case.requested.clone());
                HandshakeMessage::CertificateRequest(request)
            })));

        let out = handshake(client, server);
        match case.want {
            None => {
                assert!(!out.ok(), "{}: the handshake must fail", case.name);
                assert!(
                    out.client_error.is_some(),
                    "{}: the client fails to pick a scheme",
                    case.name
                );
            }
            Some(want) => {
                assert!(
                    out.ok(),
                    "{}: the handshake completes: {:?}/{:?}",
                    case.name,
                    out.client_error,
                    out.server_error
                );
                // The CertificateVerify the server received names the expected hash.
                let verify_hash = client_certificate_verify_hash(&out.log);
                assert_eq!(
                    verify_hash, want as u8,
                    "{}: the CertificateVerify hash",
                    case.name
                );
            }
        }
    }
}

/// The hash byte of the client's CertificateVerify (handshake type 15) on the wire.
fn client_certificate_verify_hash(log: &[(Dir, Vec<u8>)]) -> u8 {
    for (dir, datagram) in log {
        if *dir != Dir::ClientToServer {
            continue;
        }
        for (message_type, body) in raw::handshake_messages(datagram) {
            if message_type == 15 && !body.is_empty() {
                return body[0];
            }
        }
    }
    panic!("no CertificateVerify was sent");
}
