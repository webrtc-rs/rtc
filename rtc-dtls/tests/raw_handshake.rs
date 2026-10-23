//! Handshake behaviour observed from the wire with hand-built messages, ported from pion/dtls
//! v3.1.15 `conn_test.go`: `TestProtocolVersionValidation`, `TestMultipleHelloVerifyRequest`,
//! `TestRenegotationInfo`, `TestServerNameIndicationExtension`, `TestSupportedGroupsExtension`.

mod common;

use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use common::raw::*;
use common::*;
use rtc_dtls::endpoint::Endpoint;
use shared::TransportProtocol;
use shared::error::Error;

fn server_endpoint() -> Endpoint {
    let config = builder()
        .with_certificates(vec![certificate()])
        .build(false, None)
        .unwrap();
    Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(Arc::new(config)),
    )
}

fn feed(server: &mut Endpoint, datagram: Vec<u8>) -> Result<(), Error> {
    server
        .read(
            Instant::now(),
            client_addr(),
            None,
            BytesMut::from(&datagram[..]),
        )
        .map(|_| ())
}

fn drain(endpoint: &mut Endpoint) -> Vec<Vec<u8>> {
    let mut out = vec![];
    while let Some(t) = endpoint.poll_transmit() {
        out.push(t.message.to_vec());
    }
    out
}

/// The cookie in the HelloVerifyRequest (type 3) among `datagrams`.
fn cookie_of(datagrams: &[Vec<u8>]) -> Vec<u8> {
    for d in datagrams {
        for (kind, body) in handshake_messages(d) {
            if kind == 3 {
                let len = body[2] as usize;
                return body[3..3 + len].to_vec();
            }
        }
    }
    panic!("no HelloVerifyRequest in {datagrams:02x?}");
}

fn alert_records(datagrams: &[Vec<u8>]) -> usize {
    datagrams.iter().filter(|d| d.first() == Some(&21)).count()
}

/// Server, case "ClientHelloVersion": a ClientHello that claims DTLS 1.0 is refused with an
/// alert.
#[test]
fn test_server_refuses_a_client_hello_with_an_unsupported_version() {
    let mut server = server_endpoint();
    let mut hello = ClientHello::new(&[7u8; 20]);
    hello.version = [0xfe, 0xff];
    let err = feed(&mut server, hello.datagram(0)).expect_err("DTLS 1.0 is not supported");
    assert!(matches!(err, Error::ErrUnsupportedProtocolVersion), "{err}");
    assert!(
        alert_records(&drain(&mut server)) >= 1,
        "the peer must be sent an alert"
    );
}

/// Server, case "SecondsClientHelloVersion": the downgrade is also caught on the retry that
/// carries the cookie.
#[test]
fn test_server_refuses_a_downgraded_second_client_hello() {
    let mut server = server_endpoint();
    feed(&mut server, ClientHello::new(&[]).datagram(0)).unwrap();
    let cookie = cookie_of(&drain(&mut server));

    let mut hello = ClientHello::new(&cookie);
    hello.version = [0xfe, 0xff];
    let err = feed(&mut server, hello.datagram(1)).expect_err("downgrade refused");
    assert!(matches!(err, Error::ErrUnsupportedProtocolVersion), "{err}");
    assert!(alert_records(&drain(&mut server)) >= 1);
}

/// Client, case "ServerHelloVersion": a ServerHello claiming DTLS 1.0 is refused with an alert.
#[test]
fn test_client_refuses_a_server_hello_with_an_unsupported_version() {
    let config = builder().build(true, None).unwrap();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client
        .connect(Instant::now(), server_addr(), Arc::new(config), None)
        .unwrap();
    drain(&mut client);

    let feed_client = |client: &mut Endpoint, d: Vec<u8>| {
        client
            .read(Instant::now(), server_addr(), None, BytesMut::from(&d[..]))
            .map(|_| ())
    };
    // HelloVerifyRequest: version, cookie.
    let mut hvr = vec![0xfe, 0xfd, 20];
    hvr.extend_from_slice(&[9u8; 20]);
    feed_client(
        &mut client,
        record(22, 0, 0, &handshake_message(3, 0, &hvr)),
    )
    .unwrap();
    drain(&mut client);

    // ServerHello with version DTLS 1.0.
    let mut hello = vec![0xfe, 0xff];
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0); // session id
    hello.extend_from_slice(&ECDHE_ECDSA_GCM.to_be_bytes());
    hello.push(0); // compression
    let err = feed_client(
        &mut client,
        record(22, 0, 1, &handshake_message(2, 1, &hello)),
    )
    .expect_err("DTLS 1.0 ServerHello refused");
    assert!(matches!(err, Error::ErrUnsupportedProtocolVersion), "{err}");
    assert!(alert_records(&drain(&mut client)) >= 1);
}

/// `TestMultipleHelloVerifyRequest`: every new HelloVerifyRequest makes the client resend its
/// ClientHello with the newest cookie.
#[test]
fn test_client_follows_every_hello_verify_request() {
    let config = builder().build(true, None).unwrap();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client
        .connect(Instant::now(), server_addr(), Arc::new(config), None)
        .unwrap();

    let cookie_in_hello = |datagrams: &[Vec<u8>]| -> Vec<u8> {
        for d in datagrams {
            for (kind, body) in handshake_messages(d) {
                if kind == 1 {
                    let mut at = 2 + 32;
                    at += 1 + body[at] as usize;
                    let len = body[at] as usize;
                    return body[at + 1..at + 1 + len].to_vec();
                }
            }
        }
        panic!("no ClientHello");
    };

    assert_eq!(
        cookie_in_hello(&drain(&mut client)),
        Vec::<u8>::new(),
        "first hello: empty cookie"
    );
    for i in 0..2u64 {
        let cookie = vec![0x10 + i as u8; 20];
        let mut hvr = vec![0xfe, 0xfd, 20];
        hvr.extend_from_slice(&cookie);
        client
            .read(
                Instant::now(),
                server_addr(),
                None,
                BytesMut::from(&record(22, 0, i, &handshake_message(3, i as u16, &hvr))[..]),
            )
            .unwrap();
        assert_eq!(
            cookie_in_hello(&drain(&mut client)),
            cookie,
            "hello #{}",
            i + 2
        );
    }
}

/// `TestRenegotationInfo`: the server answers with renegotiation_info only when the ClientHello
/// carried the extension or the signalling cipher suite (RFC 5746 §3.6).
#[test]
fn test_server_answers_renegotiation_info_only_when_asked() {
    for (name, send_ext, scsv, expect) in [
        ("extension", true, false, true),
        ("SCSV", false, true, true),
        ("neither", false, false, false),
    ] {
        let mut server = server_endpoint();
        let mut hello = ClientHello::new(&[]);
        if send_ext {
            hello.extensions.push((0xff01, vec![0]));
        }
        if scsv {
            hello.cipher_suites.push(RENEGOTIATION_SCSV);
        }
        feed(&mut server, hello.datagram(0)).unwrap();
        let cookie = cookie_of(&drain(&mut server));

        let mut hello = ClientHello::new(&cookie);
        if send_ext {
            hello.extensions.push((0xff01, vec![0]));
        }
        if scsv {
            hello.cipher_suites.push(RENEGOTIATION_SCSV);
        }
        feed(&mut server, hello.datagram(1)).unwrap();
        let reply = drain(&mut server);
        let server_hello = reply
            .iter()
            .flat_map(|d| handshake_messages(d))
            .find(|(kind, _)| *kind == 2)
            .unwrap_or_else(|| panic!("{name}: no ServerHello"))
            .1;
        let has = hello_extensions(&server_hello, true)
            .iter()
            .any(|(kind, _)| *kind == 0xff01);
        assert_eq!(has, expect, "{name}");
    }
}

/// `TestSupportedGroupsExtension`: the ServerHello never carries `supported_groups`.
#[test]
fn test_server_hello_has_no_supported_groups() {
    let extensions = vec![
        // supported_groups: x25519, P-256, P-384
        (10u16, vec![0, 6, 0, 29, 0, 23, 0, 24]),
        // ec_point_formats: uncompressed
        (11u16, vec![1, 0]),
    ];
    let mut server = server_endpoint();
    let mut hello = ClientHello::new(&[]);
    hello.extensions = extensions.clone();
    feed(&mut server, hello.datagram(0)).unwrap();
    let cookie = cookie_of(&drain(&mut server));
    let mut hello = ClientHello::new(&cookie);
    hello.extensions = extensions;
    feed(&mut server, hello.datagram(1)).unwrap();
    let server_hello = drain(&mut server)
        .iter()
        .flat_map(|d| handshake_messages(d))
        .find(|(kind, _)| *kind == 2)
        .expect("ServerHello")
        .1;
    assert!(
        !hello_extensions(&server_hello, true)
            .iter()
            .any(|(kind, _)| *kind == 10),
        "supported_groups must not be sent in a ServerHello"
    );
}

/// `TestServerNameIndicationExtension`: a hostname is sent as SNI; an IP literal or an empty
/// name is not.
#[test]
fn test_client_sends_sni_for_hostnames_only() {
    for (name, expected) in [
        ("example.com", Some("example.com")),
        ("1.2.3.4", None),
        ("", None),
    ] {
        let config = builder()
            .with_server_name(name.to_owned())
            .build(true, None)
            .unwrap();
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        client
            .connect(Instant::now(), server_addr(), Arc::new(config), None)
            .unwrap();
        let hello = drain(&mut client)
            .iter()
            .flat_map(|d| handshake_messages(d))
            .find(|(kind, _)| *kind == 1)
            .expect("ClientHello")
            .1;
        let sni = hello_extensions(&hello, false)
            .into_iter()
            .find(|(kind, _)| *kind == 0)
            .map(|(_, data)| {
                // server_name_list: length(2) type(1) name_length(2) name
                String::from_utf8(data[5..].to_vec()).unwrap()
            });
        assert_eq!(sni.as_deref(), expected, "server name {name:?}");
    }
}
