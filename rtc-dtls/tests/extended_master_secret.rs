//! Extended master secret negotiation ([RFC 7627]), ported from pion/dtls v3.1.15
//! `TestExtendedMasterSecret` (`conn_test.go`).
//!
//! [RFC 7627]: https://www.rfc-editor.org/rfc/rfc7627

mod common;

use common::*;
use rtc_dtls::config::ExtendedMasterSecretType::{self, Disable, Request, Require};
use shared::error::Error;

fn run(client: ExtendedMasterSecretType, server: ExtendedMasterSecretType) -> Outcome {
    handshake(
        builder().with_extended_master_secret(client),
        builder()
            .with_certificates(vec![certificate()])
            .with_extended_master_secret(server),
    )
}

#[test]
fn test_extended_master_secret_policies() {
    // (client, server, handshake succeeds)
    let table = [
        (Request, Request, true),
        (Request, Require, true),
        (Request, Disable, true),
        (Require, Request, true),
        (Require, Require, true),
        (Require, Disable, false),
        (Disable, Request, true),
        (Disable, Require, false),
        (Disable, Disable, true),
    ];
    for (client, server, ok) in table {
        let out = run(client, server);
        let name = format!("{client:?}_{server:?}");
        assert_eq!(
            out.ok(),
            ok,
            "{name}: {:?} / {:?}",
            out.client_error,
            out.server_error
        );
        if !ok {
            continue;
        }
        // The extension is used exactly when neither side disabled it.
        let used = client != Disable && server != Disable;
        assert_eq!(
            out.client_state().unwrap().extended_master_secret(),
            used,
            "{name}: client"
        );
        assert_eq!(
            out.server_state().unwrap().extended_master_secret(),
            used,
            "{name}: server"
        );
    }
}

/// "Require_Disable": the client refuses a server that does not support the extension, and the
/// server sees the client's `insufficient_security` alert.
#[test]
fn test_client_requires_ems_the_server_lacks() {
    let out = run(Require, Disable);
    assert!(matches!(
        out.client_error,
        Some(Error::ErrClientRequiredButNoServerEms)
    ));
    // The alert the client sent: fatal insufficient_security (71).
    assert_eq!(out.alerts(Dir::ClientToServer), vec![(2, 71)]);
}

/// "Disable_Require": the server refuses a client that does not offer the extension, with a
/// fatal `insufficient_security` alert.
#[test]
fn test_server_requires_ems_the_client_lacks() {
    let out = run(Disable, Require);
    assert!(matches!(
        out.server_error,
        Some(Error::ErrServerRequiredButNoClientEms)
    ));
    assert_eq!(out.alerts(Dir::ServerToClient), vec![(2, 71)]);
}
