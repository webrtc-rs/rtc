//! Client-certificate policies, ported from pion/dtls v3.1.15 `TestClientCertificate`
//! (`conn_test.go`). The cases that need `VerifyConnection`, `GetCertificate` or
//! `GetClientCertificate` wait for those options (see the config-callbacks issue).

mod common;

use common::*;
use rtc_dtls::config::{ClientAuthType, ConfigBuilder};
use rtc_dtls::crypto::Certificate;
use rustls::RootCertStore;

fn roots(certificate: &Certificate) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store
        .add(certificate.certificate[0].clone())
        .expect("a self-signed certificate is a valid root");
    store
}

struct Case {
    name: &'static str,
    /// Whether the client holds a certificate.
    client_certificate: bool,
    auth: ClientAuthType,
    /// Whether the server is told which CAs to trust for client certificates.
    client_cas: bool,
    want_error: bool,
}

#[test]
fn test_client_certificate_policies() {
    use ClientAuthType::*;
    let server_cert = certificate();
    let client_cert = certificate();

    let case = |name, client_certificate, auth, client_cas, want_error| Case {
        name,
        client_certificate,
        auth,
        client_cas,
        want_error,
    };
    let cases = [
        case("NoClientCert", false, NoClientCert, true, false),
        case("NoClientCert_cert", true, NoClientCert, false, false),
        case(
            "RequestClientCert_cert",
            true,
            RequestClientCert,
            false,
            false,
        ),
        case(
            "RequestClientCert_no_cert",
            false,
            RequestClientCert,
            true,
            false,
        ),
        case(
            "RequireAnyClientCert",
            true,
            RequireAnyClientCert,
            false,
            false,
        ),
        case(
            "RequireAnyClientCert_error",
            false,
            RequireAnyClientCert,
            false,
            true,
        ),
        case(
            "VerifyClientCertIfGiven_no_cert",
            false,
            VerifyClientCertIfGiven,
            true,
            false,
        ),
        case(
            "VerifyClientCertIfGiven_cert",
            true,
            VerifyClientCertIfGiven,
            true,
            false,
        ),
        // The client's certificate is not signed by anything the server trusts.
        case(
            "VerifyClientCertIfGiven_error",
            true,
            VerifyClientCertIfGiven,
            false,
            true,
        ),
        case(
            "RequireAndVerifyClientCert",
            true,
            RequireAndVerifyClientCert,
            true,
            false,
        ),
        case(
            "RequireAndVerifyClientCert_no_cert",
            false,
            RequireAndVerifyClientCert,
            true,
            true,
        ),
    ];

    for c in cases {
        let mut client: ConfigBuilder = ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_roots_cas(roots(&server_cert));
        if c.client_certificate {
            client = client.with_certificates(vec![client_cert.clone()]);
        }
        let mut server = ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_certificates(vec![server_cert.clone()])
            .with_client_auth(c.auth);
        if c.client_cas {
            server = server.with_client_cas(roots(&client_cert));
        }

        let out = match try_handshake(client, server) {
            Ok(out) => out,
            Err(_) => {
                // A configuration that cannot verify what it is asked to verify is refused up
                // front, which is the strict form of pion's handshake failure.
                assert!(c.want_error, "{}: configuration refused", c.name);
                continue;
            }
        };

        if c.want_error {
            assert!(!out.ok(), "{}: an error was expected", c.name);
            continue;
        }
        assert!(
            out.ok(),
            "{}: {:?} / {:?}",
            c.name,
            out.client_error,
            out.server_error
        );

        // The client always learns the server's certificate.
        let seen_by_client = &out.client_state().unwrap().peer_certificates;
        assert_eq!(
            seen_by_client[0],
            server_cert.certificate[0].as_ref(),
            "{}",
            c.name
        );

        // The server learns the client's certificate exactly when one was demanded or given
        // under a policy that asks for it.
        let seen_by_server = &out.server_state().unwrap().peer_certificates;
        let asked = !matches!(c.auth, NoClientCert);
        if asked && c.client_certificate {
            assert_eq!(
                seen_by_server[0],
                client_cert.certificate[0].as_ref(),
                "{}: the client's certificate reached the server",
                c.name
            );
        } else {
            assert!(
                seen_by_server.is_empty(),
                "{}: no client certificate expected",
                c.name
            );
        }
    }
}

/// pion's `RequestClientCert_cert_sigscheme` restricts the server to ECDSA P-521/SHA-512 and
/// completes the handshake, signing a P-256 key with SHA-512. The crypto providers here do not
/// offer that combination (ring and aws-lc-rs sign P-256 with SHA-256 only), so such a
/// configuration is refused when it is built instead of failing mid-handshake.
#[test]
fn test_server_signature_schemes_its_key_cannot_sign_are_refused_up_front() {
    use rtc_dtls::signature_hash_algorithm::SignatureScheme;
    let err = ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_certificates(vec![certificate()])
        .with_signature_schemes(vec![SignatureScheme::EcdsaWithP521AndSha512])
        .build(false, None)
        .expect_err("a P-256 key cannot sign with P-521/SHA-512");
    assert!(
        matches!(
            err,
            shared::error::Error::ErrNoAvailableCipherSuites
                | shared::error::Error::ErrNoAvailableSignatureSchemes
        ),
        "{err}"
    );
}
