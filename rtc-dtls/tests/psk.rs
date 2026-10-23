//! Pre-shared-key handshakes, ported from pion/dtls v3.1.15 `conn_test.go`: `TestPSK`,
//! `TestPSKHintFail`, `TestPSKMismatchNoRetransmitLoop`, `TestPSKServerKeyExchange`,
//! `TestPSKConfiguration` and `TestCertificateAndPSKServer`.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::config::{ClientAuthType, ConfigBuilder};
use shared::error::Error;

const PSK: [u8; 3] = [0xab, 0xc1, 0x23];

type Callback = Arc<dyn Fn(&[u8]) -> shared::error::Result<Vec<u8>> + Send + Sync>;
type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// A callback that insists on being handed `expected` and records what it was given.
fn expecting(expected: Option<Vec<u8>>) -> (Callback, Seen) {
    let seen = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    let callback = Arc::new(move |hint: &[u8]| {
        log.lock().unwrap().push(hint.to_vec());
        match &expected {
            Some(want) if want != hint => Err(Error::Other(format!(
                "unexpected hint {hint:02x?}, wanted {want:02x?}"
            ))),
            _ => Ok(PSK.to_vec()),
        }
    });
    (callback, seen)
}

fn psk_builder(suite: CipherSuiteId, callback: Callback, hint: Option<Vec<u8>>) -> ConfigBuilder {
    builder()
        .with_cipher_suites(vec![suite])
        .with_psk(Some(callback))
        .with_psk_identity_hint(hint)
}

/// `TestPSK`: the server's hint reaches the client's callback, the client's identity reaches the
/// server's callback and the server's state.
#[test]
fn test_psk_identities_are_exchanged() {
    for (name, server_hint, client_identity, suite) in [
        (
            "server identity specified",
            Some(b"Test Identity".to_vec()),
            b"Client Identity".to_vec(),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ),
        (
            "server identity nil",
            None,
            b"Client Identity".to_vec(),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ),
        (
            "client identity empty",
            None,
            vec![],
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ),
        (
            "gcm",
            Some(b"hint".to_vec()),
            b"id".to_vec(),
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
        ),
        (
            "ccm",
            None,
            b"id".to_vec(),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
        ),
    ] {
        let (client_cb, client_seen) = expecting(Some(server_hint.clone().unwrap_or_default()));
        let (server_cb, server_seen) = expecting(Some(client_identity.clone()));
        let out = handshake(
            psk_builder(suite, client_cb, Some(client_identity.clone())),
            psk_builder(suite, server_cb, server_hint.clone()),
        );
        assert!(
            out.ok(),
            "{name}: {:?} / {:?}",
            out.client_error,
            out.server_error
        );
        assert_eq!(
            out.server_state().unwrap().identity_hint,
            client_identity,
            "{name}: the server's state holds the client's identity"
        );
        assert_eq!(
            *server_seen.lock().unwrap(),
            vec![client_identity.clone()],
            "{name}"
        );
        // The client's callback is only asked when the server sent a hint.
        if let Some(hint) = server_hint {
            assert_eq!(*client_seen.lock().unwrap(), vec![hint], "{name}");
        }
    }
}

/// `TestPSKHintFail`: both callbacks refuse; both handshakes fail.
#[test]
fn test_psk_hint_fail() {
    let reject: Callback = Arc::new(|_| Err(Error::Other("PSK Rejected".to_owned())));
    let out = handshake(
        psk_builder(
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            reject.clone(),
            Some(vec![]),
        ),
        psk_builder(
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            reject,
            Some(vec![]),
        ),
    );
    assert!(!out.ok());
    // pion: the client fails with the callback's error; the server fails on the client's
    // fatal alert, which for a rejected PSK is internal_error (80).
    let client_error = out.client_error.as_ref().expect("client fails");
    assert!(
        client_error.to_string().contains("PSK Rejected"),
        "client: {client_error}"
    );
    assert!(out.server_error.is_some(), "server fails");
    assert_eq!(out.alerts(Dir::ClientToServer), vec![(2, 80)]);
}

/// `TestPSKMismatchNoRetransmitLoop`: different keys fail both sides, and neither goes on
/// retransmitting the failed flight forever.
#[test]
fn test_psk_mismatch_does_not_loop() {
    let client_cb: Callback = Arc::new(|_| Ok(b"client-psk".to_vec()));
    let server_cb: Callback = Arc::new(|_| Ok(b"server-psk".to_vec()));
    let mut out = handshake(
        psk_builder(
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            client_cb,
            Some(b"Client Identity".to_vec()),
        ),
        psk_builder(CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8, server_cb, None),
    );
    assert!(!out.ok());
    assert!(out.client_error.is_some() || out.server_error.is_some());

    let before = out.log.len();
    // Let a long time pass on both sides: a failed handshake must not keep retransmitting.
    let mut now = Instant::now();
    for _ in 0..50 {
        now += Duration::from_secs(5);
        let _ = out.client.handle_timeout(server_addr(), now);
        let _ = out.server.handle_timeout(client_addr(), now);
    }
    let mut sent = 0;
    while out.client.poll_transmit().is_some() {
        sent += 1;
    }
    while out.server.poll_transmit().is_some() {
        sent += 1;
    }
    assert!(before <= 20, "the handshake itself stayed short: {before}");
    assert!(sent <= 20, "no retransmit storm after failure: {sent}");
}

/// `TestPSKServerKeyExchange`: the server sends a ServerKeyExchange only when it has an identity
/// hint to give.
#[test]
fn test_psk_server_key_exchange_only_with_an_identity_hint() {
    for (set_identity, name) in [(true, "identity set"), (false, "identity not set")] {
        let (cb, _) = expecting(None);
        let hint = vec![0xab, 0xc1, 0x23];
        let out = handshake(
            psk_builder(
                CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
                cb.clone(),
                Some(hint.clone()),
            ),
            psk_builder(
                CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
                cb,
                set_identity.then_some(hint),
            ),
        );
        assert!(out.ok(), "{name}");
        assert_eq!(
            handshake_types(&out, Dir::ServerToClient).contains(&12),
            set_identity,
            "{name}: ServerKeyExchange (12)"
        );
    }
}

/// The handshake message types sent in `dir` in plaintext records (epoch 0).
fn handshake_types(out: &Outcome, dir: Dir) -> Vec<u8> {
    let mut types = vec![];
    for (d, datagram) in &out.log {
        if *d != dir {
            continue;
        }
        let mut rest = &datagram[..];
        while rest.len() >= 13 {
            let len = u16::from_be_bytes([rest[11], rest[12]]) as usize;
            if rest.len() < 13 + len {
                break;
            }
            let epoch = u16::from_be_bytes([rest[3], rest[4]]);
            if rest[0] == 22 && epoch == 0 {
                let mut payload = &rest[13..13 + len];
                while payload.len() >= 12 {
                    types.push(payload[0]);
                    let frag =
                        u32::from_be_bytes([0, payload[9], payload[10], payload[11]]) as usize;
                    if payload.len() < 12 + frag {
                        break;
                    }
                    payload = &payload[12 + frag..];
                }
            }
            rest = &rest[13 + len..];
        }
    }
    types
}

/// `TestPSKConfiguration`, the cases that exist as builder errors here.
#[test]
fn test_psk_configuration_errors() {
    let cb: Callback = Arc::new(|_| Ok(PSK.to_vec()));
    // "PSK and no identity specified": a client needs both.
    let err = builder()
        .with_psk(Some(cb.clone()))
        .build(true, None)
        .expect_err("client PSK without identity");
    assert!(matches!(err, Error::ErrPskAndIdentityMustBeSetForClient));
    // "No PSK and identity specified": an identity means nothing without a callback.
    for is_client in [true, false] {
        let err = builder()
            .with_psk_identity_hint(Some(vec![0]))
            .build(is_client, None)
            .expect_err("identity without PSK");
        assert!(matches!(err, Error::ErrIdentityNoPsk));
    }
    // A server needs a PSK callback or a certificate.
    let err = builder().build(false, None).expect_err("empty server");
    assert!(matches!(err, Error::ErrServerMustHaveCertificate));
    // A client holding both a certificate and a PSK callback is ambiguous.
    let err = builder()
        .with_psk(Some(cb))
        .with_psk_identity_hint(Some(vec![0]))
        .with_certificates(vec![certificate()])
        .build(true, None)
        .expect_err("client PSK and certificate");
    assert!(matches!(err, Error::ErrPskAndCertificate));
}

/// `TestCertificateAndPSKServer`: one server holding both a PSK callback and a certificate serves
/// either kind of client; the client-auth policy applies to certificate suites.
#[test]
fn test_certificate_and_psk_server() {
    struct Case {
        name: &'static str,
        client_psk: bool,
        client_auth: ClientAuthType,
        client_certificate: bool,
        want_server_error: bool,
    }
    let cases = [
        Case {
            name: "client uses PKI",
            client_psk: false,
            client_auth: ClientAuthType::NoClientCert,
            client_certificate: false,
            want_server_error: false,
        },
        Case {
            name: "client uses PSK",
            client_psk: true,
            client_auth: ClientAuthType::NoClientCert,
            client_certificate: false,
            want_server_error: false,
        },
        Case {
            name: "PSK with required client certificate",
            client_psk: true,
            client_auth: ClientAuthType::RequireAnyClientCert,
            client_certificate: false,
            want_server_error: false,
        },
        Case {
            name: "PSK with required verified client certificate",
            client_psk: true,
            client_auth: ClientAuthType::RequireAndVerifyClientCert,
            client_certificate: false,
            want_server_error: false,
        },
        Case {
            name: "certificate suite requires client certificate despite PSK callback",
            client_psk: false,
            client_auth: ClientAuthType::RequireAnyClientCert,
            client_certificate: false,
            want_server_error: true,
        },
        Case {
            name: "certificate suite requires verified client certificate despite PSK callback",
            client_psk: false,
            client_auth: ClientAuthType::RequireAndVerifyClientCert,
            client_certificate: false,
            want_server_error: true,
        },
        Case {
            name: "certificate suite accepts client certificate with PSK callback",
            client_psk: false,
            client_auth: ClientAuthType::RequireAnyClientCert,
            client_certificate: true,
            want_server_error: false,
        },
        Case {
            name: "certificate suite permits empty certificate when optional",
            client_psk: false,
            client_auth: ClientAuthType::RequestClientCert,
            client_certificate: false,
            want_server_error: false,
        },
    ];
    for case in cases {
        let (cb, _) = expecting(None);
        let mut client = builder()
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]);
        if case.client_psk {
            client = builder()
                .with_psk(Some(cb.clone()))
                .with_psk_identity_hint(Some(vec![0]))
                .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256]);
        }
        if case.client_certificate {
            client = client.with_certificates(vec![certificate()]);
        }
        let server = builder()
            .with_cipher_suites(vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            ])
            .with_psk(Some(cb))
            .with_certificates(vec![certificate()])
            .with_client_cas(rtc_dtls::config::gen_self_signed_root_cert())
            .with_client_auth(case.client_auth);
        let out = handshake(client, server);
        if case.want_server_error {
            assert!(
                matches!(out.server_error, Some(Error::ErrClientCertificateRequired)),
                "{}: {:?}",
                case.name,
                out.server_error
            );
            assert!(!out.ok(), "{}", case.name);
        } else {
            assert!(
                out.ok(),
                "{}: {:?} / {:?}",
                case.name,
                out.client_error,
                out.server_error
            );
        }
    }
}
