//! ALPN ([RFC 7301]) negotiation, ported from pion/dtls v3.1.15 `TestALPNExtension`
//! (`conn_test.go`) and driven through the public sans-I/O API instead of Go's `dpipe`.
//!
//! [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301

mod common;

use common::*;
use shared::error::Error;

fn protos(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn run(client: &[&str], server: &[&str]) -> Outcome {
    handshake(
        builder().with_supported_protocols(protos(client)),
        builder()
            .with_certificates(vec![certificate()])
            .with_supported_protocols(protos(server)),
    )
}

/// "Negotiate a protocol": the one both offer, on both ends.
#[test]
fn test_alpn_negotiates_a_shared_protocol() {
    let out = run(&["http/1.1", "spd/1"], &["spd/1"]);
    assert!(out.ok());
    assert_eq!(out.client_state().unwrap().negotiated_protocol(), "spd/1");
    assert_eq!(out.server_state().unwrap().negotiated_protocol(), "spd/1");
}

/// "Server doesn't support any": no ALPN extension comes back, nothing is negotiated, and the
/// handshake still succeeds.
#[test]
fn test_alpn_server_without_protocols_negotiates_nothing() {
    let out = run(&["http/1.1", "spd/1"], &[]);
    assert!(out.ok());
    assert_eq!(out.client_state().unwrap().negotiated_protocol(), "");
    assert_eq!(out.server_state().unwrap().negotiated_protocol(), "");
}

/// The client offering nothing is fine too.
#[test]
fn test_alpn_client_without_protocols_negotiates_nothing() {
    let out = run(&[], &["spd/1"]);
    assert!(out.ok());
    assert_eq!(out.server_state().unwrap().negotiated_protocol(), "");
}

/// "Negotiate with higher server precedence": the server's order decides.
#[test]
fn test_alpn_server_precedence_wins() {
    let out = run(
        &["http/1.1", "spd/1", "http/3"],
        &["ssh/2", "http/3", "spd/1"],
    );
    assert!(out.ok());
    assert_eq!(out.client_state().unwrap().negotiated_protocol(), "http/3");
    assert_eq!(out.server_state().unwrap().negotiated_protocol(), "http/3");
}

/// "Empty intersection": the server refuses with a fatal `no_application_protocol` alert.
#[test]
fn test_alpn_empty_intersection_is_refused_with_an_alert() {
    let out = run(&["http/1.1", "http/3"], &["ssh/2", "spd/1"]);
    assert!(!out.ok());
    assert!(matches!(out.server_error, Some(Error::ErrAlpnNoAppProto)));
    let alerts = out.alerts(Dir::ServerToClient);
    assert_eq!(
        alerts,
        // fatal (2), no_application_protocol (120, RFC 7301 §3.2)
        vec![(2, 120)],
        "one fatal no_application_protocol alert"
    );
}

/// Application data flows over a connection that negotiated a protocol.
#[test]
fn test_alpn_connection_carries_data() {
    let mut out = run(&["spd/1"], &["spd/1"]);
    assert!(out.ok());
    assert_eq!(client_sends(&mut out, b"hello"), b"hello");
}

/// The builder refuses protocol names that cannot be sent.
#[test]
fn test_alpn_builder_rejects_unsendable_names() {
    for bad in [protos(&[""]), vec!["x".repeat(256)], protos(&["ok", ""])] {
        let err = builder()
            .with_supported_protocols(bad)
            .build(true, None)
            .expect_err("must be rejected");
        assert!(matches!(err, Error::ErrAlpnInvalidFormat));
    }
    assert!(
        builder()
            .with_supported_protocols(vec!["x".repeat(255)])
            .build(true, None)
            .is_ok()
    );
}

/// Rewrites the ALPN extension of the ServerHello in `datagram` to carry `names`, fixing every
/// length on the way. Returns whether a ServerHello with an ALPN extension was found.
fn rewrite_server_hello_alpn(datagram: &mut Vec<u8>, names: &[&str]) -> bool {
    let mut pos = 0;
    while pos + 13 <= datagram.len() {
        let record_len = u16::from_be_bytes([datagram[pos + 11], datagram[pos + 12]]) as usize;
        let body = pos + 13;
        // A plaintext handshake record holding a whole ServerHello (type 2).
        if datagram[pos] == 22 && datagram[body] == 2 {
            // Handshake header: type(1) length(3) message_seq(2) fragment_offset(3) fragment_length(3).
            let h = body + 12;
            // version(2) random(32) session_id(1+n) cipher_suite(2) compression(1) extensions(2+n)
            let sid = datagram[h + 34] as usize;
            let ext_len_at = h + 34 + 1 + sid + 2 + 1;
            let ext_len =
                u16::from_be_bytes([datagram[ext_len_at], datagram[ext_len_at + 1]]) as usize;
            let mut at = ext_len_at + 2;
            let end = at + ext_len;
            while at + 4 <= end {
                let kind = u16::from_be_bytes([datagram[at], datagram[at + 1]]);
                let len = u16::from_be_bytes([datagram[at + 2], datagram[at + 3]]) as usize;
                if kind == 16 {
                    let list: Vec<u8> = names
                        .iter()
                        .flat_map(|n| [&[n.len() as u8][..], n.as_bytes()].concat())
                        .collect();
                    let mut ext = vec![0, 16];
                    ext.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
                    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
                    ext.extend_from_slice(&list);
                    let delta = ext.len() as isize - (4 + len) as isize;
                    datagram.splice(at..at + 4 + len, ext);
                    let fix = |datagram: &mut Vec<u8>, at: usize, width: usize| {
                        let mut v = 0usize;
                        for b in &datagram[at..at + width] {
                            v = v << 8 | *b as usize;
                        }
                        let v = (v as isize + delta) as usize;
                        for (i, b) in datagram[at..at + width].iter_mut().enumerate() {
                            *b = (v >> (8 * (width - 1 - i))) as u8;
                        }
                    };
                    fix(datagram, ext_len_at, 2); // extensions length
                    fix(datagram, body + 1, 3); // handshake length
                    fix(datagram, body + 9, 3); // fragment length
                    fix(datagram, pos + 11, 2); // record length
                    return true;
                }
                at += 4 + len;
            }
        }
        pos = body + record_len;
    }
    false
}

fn configs(
    client: &[&str],
    server: &[&str],
) -> (
    rtc_dtls::config::HandshakeConfig,
    rtc_dtls::config::HandshakeConfig,
) {
    (
        builder()
            .with_supported_protocols(protos(client))
            .build(true, None)
            .unwrap(),
        builder()
            .with_certificates(vec![certificate()])
            .with_supported_protocols(protos(server))
            .build(false, None)
            .unwrap(),
    )
}

/// "Multiple protocols in ServerHello": a server answering with two names is a fatal
/// `internal_error` from the client, as in pion.
#[test]
fn test_alpn_client_rejects_several_protocols_in_server_hello() {
    let (client, server) = configs(&["http/1.1"], &["http/1.1"]);
    let mut rewrote = false;
    let out = handshake_tampered(client, server, |dir, datagram| {
        if dir == Dir::ServerToClient {
            rewrote |= rewrite_server_hello_alpn(datagram, &["http/1.1", "oops"]);
        }
    });
    assert!(rewrote, "the ServerHello was found and rewritten");
    assert!(!out.ok());
    assert!(matches!(
        out.client_error,
        Some(Error::ErrAlpnInvalidFormat)
    ));
    assert_eq!(out.alerts(Dir::ClientToServer), vec![(2, 80)]);
}

/// A server that picks a protocol the client never offered is an `illegal_parameter`.
#[test]
fn test_alpn_client_rejects_a_protocol_it_did_not_offer() {
    let (client, server) = configs(&["http/1.1"], &["http/1.1"]);
    let out = handshake_tampered(client, server, |dir, datagram| {
        if dir == Dir::ServerToClient {
            rewrite_server_hello_alpn(datagram, &["gopher"]);
        }
    });
    assert!(!out.ok());
    assert!(matches!(
        out.client_error,
        Some(Error::ErrAlpnInvalidFormat)
    ));
    assert_eq!(out.alerts(Dir::ClientToServer), vec![(2, 47)]);
}
