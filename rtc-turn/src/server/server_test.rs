use super::*;
use crypto::default_provider;
use stun::textattrs::TextAttribute;

struct Users;

impl Authenticator for Users {
    fn credential_key(&self, username: &str, realm: &str) -> Option<Vec<u8>> {
        if username != "alice" && username != "bob" {
            return None;
        }
        MessageIntegrity::long_term_integrity_key(
            username.into(),
            realm.into(),
            "password".into(),
            default_provider().unwrap().crypto(),
        )
        .ok()
    }

    fn allow_peer(&self, _username: &str, peer: SocketAddr) -> bool {
        !peer.ip().is_multicast() && !peer.ip().is_unspecified()
    }
}

struct Fixture {
    server: Server,
    now: Instant,
    transport: TransportContext,
    nonce: String,
    key: Vec<u8>,
    id: AllocationId,
}

fn request(method: Method, username: &str, nonce: &str, attrs: &[Box<dyn Setter>]) -> Message {
    let provider = default_provider().unwrap();
    let mut request = Message::new();
    request.set_type(MessageType::new(method, CLASS_REQUEST));
    request.new_transaction_id().unwrap();
    request.write_header();
    for attr in attrs {
        attr.add_to(&mut request).unwrap();
    }
    TextAttribute::new(ATTR_USERNAME, username.into())
        .add_to(&mut request)
        .unwrap();
    TextAttribute::new(ATTR_REALM, "webrtc.rs".into())
        .add_to(&mut request)
        .unwrap();
    TextAttribute::new(ATTR_NONCE, nonce.into())
        .add_to(&mut request)
        .unwrap();
    let integrity = MessageIntegrity::new_long_term_integrity_with_provider(
        username.into(),
        "webrtc.rs".into(),
        "password".into(),
        provider.crypto(),
    )
    .unwrap();
    integrity.add_to(&mut request).unwrap();
    FINGERPRINT.add_to(&mut request).unwrap();
    request
}

fn response(server: &mut Server) -> Message {
    let Event::SendToClient { data, .. } = server.poll_event().expect("response") else {
        panic!("expected response");
    };
    message::decode(&data).unwrap()
}

fn error(response: &Message) -> ErrorCode {
    let mut error = ErrorCodeAttribute::default();
    error.get_from(response).unwrap();
    error.code
}

fn fixture_with_config(config: ServerConfig) -> Fixture {
    let now = Instant::now();
    let provider = default_provider().unwrap();
    let mut server = Server::new(config, Arc::new(Users), provider.clone(), now).unwrap();
    let transport = TransportContext {
        local_addr: "192.0.2.1:3478".parse().unwrap(),
        peer_addr: "192.0.2.10:12345".parse().unwrap(),
        ..Default::default()
    };
    let mut unauth = Message::new();
    unauth.set_type(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST));
    unauth.new_transaction_id().unwrap();
    unauth.write_header();
    server.handle_datagram(now, transport, &unauth.raw).unwrap();
    let challenge = response(&mut server);
    assert!(error(&challenge) == CODE_UNAUTHORIZED);
    let nonce = message::text(&challenge, ATTR_NONCE, 763).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    server
        .handle_datagram(now, transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay {
        allocation_id: id,
        family: AddressFamily::Ipv4,
        ..
    } = server.poll_event().unwrap()
    else {
        panic!("expected relay request");
    };
    server
        .complete_allocate(now, id, Ok("198.51.100.1:50000".parse().unwrap()))
        .unwrap();
    let mut success = response(&mut server);
    let key = Users.credential_key("alice", "webrtc.rs").unwrap();
    MessageIntegrity::check(&mut success, &key, provider.crypto()).unwrap();
    Fixture {
        server,
        now,
        transport,
        nonce,
        key,
        id,
    }
}

fn fixture() -> Fixture {
    fixture_with_config(ServerConfig::default())
}

fn permission(f: &mut Fixture, peer: SocketAddr) -> Message {
    let request = request(
        METHOD_CREATE_PERMISSION,
        "alice",
        &f.nonce,
        &[Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        })],
    );
    f.server
        .handle_datagram(f.now, f.transport, &request.raw)
        .unwrap();
    response(&mut f.server)
}

fn bind(f: &mut Fixture, peer: SocketAddr, number: u16) -> Message {
    let request = request(
        METHOD_CHANNEL_BIND,
        "alice",
        &f.nonce,
        &[
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(ChannelNumber(number)),
        ],
    );
    f.server
        .handle_datagram(f.now, f.transport, &request.raw)
        .unwrap();
    response(&mut f.server)
}

#[test]
fn allocate_replay_is_identical_and_does_not_extend_lifetime() {
    let mut f = fixture();
    let allocation = &f.server.allocations[&FiveTuple::from(f.transport)];
    let raw = allocation.allocate_request.clone();
    let expected = allocation.allocate_response.clone();
    let expiry = allocation.expires;
    // Replay still works after the general response-cache window.
    f.server
        .handle_datagram(f.now + Duration::from_secs(45), f.transport, &raw)
        .unwrap();
    let Event::SendToClient { data, .. } = f.server.poll_event().unwrap() else {
        panic!();
    };
    assert_eq!(&data[..], &expected);
    assert_eq!(f.server.allocation_count(), 1);
    assert_eq!(
        f.server.allocations[&FiveTuple::from(f.transport)].expires,
        expiry
    );
    let different = request(
        METHOD_ALLOCATE,
        "alice",
        &f.nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now + Duration::from_secs(45), f.transport, &different.raw)
        .unwrap();
    assert!(error(&response(&mut f.server)) == CODE_ALLOC_MISMATCH);
}

#[test]
fn refresh_zero_releases_once_and_replays_success() {
    let mut f = fixture();
    let delete = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.server
        .handle_datagram(f.now, f.transport, &delete.raw)
        .unwrap();
    assert!(
        matches!(f.server.poll_event(), Some(Event::ReleaseRelay { allocation_id }) if allocation_id == f.id)
    );
    let first = response(&mut f.server);
    assert_eq!(f.server.allocation_count(), 0);
    f.server
        .handle_datagram(f.now, f.transport, &delete.raw)
        .unwrap();
    assert_eq!(response(&mut f.server).raw, first.raw);
    assert!(f.server.poll_event().is_none());
}

#[test]
fn permissions_guard_both_directions_and_accept_zero_wire_port() {
    let mut f = fixture();
    let peer: SocketAddr = "203.0.113.1:9000".parse().unwrap();
    f.server
        .handle_peer_data(f.now, f.id, peer, b"blocked")
        .unwrap();
    assert!(f.server.poll_event().is_none());
    assert_eq!(
        permission(&mut f, SocketAddr::new(peer.ip(), 0)).typ.class,
        CLASS_SUCCESS_RESPONSE
    );
    f.server
        .handle_peer_data(f.now, f.id, peer, b"hello")
        .unwrap();
    let data = response(&mut f.server);
    assert_eq!(data.typ.method, METHOD_DATA);
    assert_eq!(data.get(ATTR_DATA).unwrap(), b"hello");
    let mut send = Message::new();
    send.set_type(MessageType::new(METHOD_SEND, CLASS_INDICATION));
    send.write_header();
    PeerAddress {
        ip: peer.ip(),
        port: peer.port(),
    }
    .add_to(&mut send)
    .unwrap();
    Data(b"reply".to_vec()).add_to(&mut send).unwrap();
    f.server
        .handle_datagram(f.now, f.transport, &send.raw)
        .unwrap();
    assert!(
        matches!(f.server.poll_event(), Some(Event::SendToPeer { data, peer: destination, .. }) if data == b"reply"[..] && destination == peer)
    );
    f.now += Duration::from_secs(300);
    f.server
        .handle_datagram(f.now, f.transport, &send.raw)
        .unwrap();
    f.server
        .handle_peer_data(f.now, f.id, peer, b"expired")
        .unwrap();
    assert!(f.server.poll_event().is_none());
}

#[test]
fn channels_use_rfc8656_range_and_cannot_rebind_live_peers() {
    let mut f = fixture();
    let peer = "203.0.113.1:9000".parse().unwrap();
    assert!(error(&bind(&mut f, peer, 0x5000)) == CODE_BAD_REQUEST);
    assert_eq!(bind(&mut f, peer, 0x4fff).typ.class, CLASS_SUCCESS_RESPONSE);
    assert!(error(&bind(&mut f, peer, 0x4000)) == CODE_BAD_REQUEST);
    assert!(error(&bind(&mut f, "203.0.113.2:9000".parse().unwrap(), 0x4fff)) == CODE_BAD_REQUEST);
    f.server
        .handle_peer_data(f.now, f.id, peer, b"abc")
        .unwrap();
    let Event::SendToClient { data, .. } = f.server.poll_event().unwrap() else {
        panic!();
    };
    assert_eq!(&data[..7], &[0x4f, 0xff, 0, 3, b'a', b'b', b'c']);
    let raw = [0x4f, 0xff, 0, 3, b'a', b'b', b'c'];
    // ChannelData bypasses permission checks in the client-to-peer direction.
    f.server
        .handle_datagram(f.now + Duration::from_secs(301), f.transport, &raw)
        .unwrap();
    assert!(
        matches!(f.server.poll_event(), Some(Event::SendToPeer { data, .. }) if data == b"abc"[..])
    );
}

#[test]
fn permission_batch_is_atomic_and_bounded() {
    let mut f = fixture_with_config(ServerConfig {
        max_permissions: 1,
        ..Default::default()
    });
    let batch = request(
        METHOD_CREATE_PERMISSION,
        "alice",
        &f.nonce,
        &[
            Box::new(PeerAddress {
                ip: "203.0.113.1".parse().unwrap(),
                port: 0,
            }),
            Box::new(PeerAddress {
                ip: "203.0.113.2".parse().unwrap(),
                port: 0,
            }),
        ],
    );
    f.server
        .handle_datagram(f.now, f.transport, &batch.raw)
        .unwrap();
    assert!(error(&response(&mut f.server)) == CODE_INSUFFICIENT_CAPACITY);
    assert!(
        f.server.allocations[&FiveTuple::from(f.transport)]
            .permissions
            .is_empty()
    );
}

#[test]
fn wrong_credentials_and_bad_hmac_do_not_mutate_allocation() {
    let mut f = fixture();
    let wrong = request(
        METHOD_REFRESH,
        "bob",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.server
        .handle_datagram(f.now, f.transport, &wrong.raw)
        .unwrap();
    assert!(error(&response(&mut f.server)) == CODE_WRONG_CREDENTIALS);
    let mut bad = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    // Alter one byte covered by HMAC and recompute only the unkeyed fingerprint.
    bad.raw[27] ^= 1;
    bad.raw.truncate(bad.raw.len() - 8);
    let size = bad.raw.len() - 20;
    bad.raw[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    bad.decode().unwrap();
    FINGERPRINT.add_to(&mut bad).unwrap();
    f.server
        .handle_datagram(f.now, f.transport, &bad.raw)
        .unwrap();
    assert!(error(&response(&mut f.server)) == CODE_UNAUTHORIZED);
    assert_eq!(f.server.allocation_count(), 1);
}

#[test]
fn malformed_integrity_and_authenticated_tail_are_rejected() {
    let mut f = fixture();
    let mut bad = Message::new();
    bad.set_type(MessageType::new(METHOD_REFRESH, CLASS_REQUEST));
    bad.write_header();
    bad.add(ATTR_MESSAGE_INTEGRITY, &[0]);
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &bad.raw)
            .is_err()
    );
    let mut tail = request(METHOD_REFRESH, "alice", &f.nonce, &[]);
    tail.raw.truncate(tail.raw.len() - 8);
    tail.length -= 8;
    tail.attributes.0.pop();
    Lifetime(Duration::ZERO).add_to(&mut tail).unwrap();
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &tail.raw)
            .is_err()
    );
    assert_eq!(f.server.allocation_count(), 1);
}

#[test]
fn stale_nonce_cannot_delete_allocation_and_challenges_retry() {
    let mut f = fixture_with_config(ServerConfig {
        nonce_lifetime: Duration::from_secs(1),
        ..Default::default()
    });
    let delete = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.now += Duration::from_secs(1);
    f.server
        .handle_datagram(f.now, f.transport, &delete.raw)
        .unwrap();
    let challenge = response(&mut f.server);
    assert!(error(&challenge) == CODE_STALE_NONCE);
    assert_eq!(f.server.allocation_count(), 1);
    let nonce = message::text(&challenge, ATTR_NONCE, 763).unwrap();
    let retry = request(
        METHOD_REFRESH,
        "alice",
        &nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.server
        .handle_datagram(f.now, f.transport, &retry.raw)
        .unwrap();
    assert!(matches!(
        f.server.poll_event(),
        Some(Event::ReleaseRelay { .. })
    ));
    assert_eq!(response(&mut f.server).typ.class, CLASS_SUCCESS_RESPONSE);
}

#[test]
fn pending_retransmit_and_cancelled_completion_are_safe() {
    let mut f = fixture();
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay { allocation_id, .. } = f.server.poll_event().unwrap() else {
        panic!();
    };
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    assert!(f.server.poll_event().is_none());
    f.now += Duration::from_secs(10);
    f.server.handle_timeout(f.now).unwrap();
    assert!(
        matches!(f.server.poll_event(), Some(Event::ReleaseRelay { allocation_id: id }) if id == allocation_id)
    );
    assert!(
        f.server
            .complete_allocate(
                f.now,
                allocation_id,
                Ok("198.51.100.1:50001".parse().unwrap())
            )
            .is_err()
    );
    assert_eq!(f.server.allocation_count(), 1);
}

#[test]
fn expiry_releases_even_when_output_queue_is_full() {
    let mut f = fixture_with_config(ServerConfig {
        max_events: 2,
        ..Default::default()
    });
    for _ in 0..2 {
        f.server
            .send_client(FiveTuple::from(f.transport), b"queued");
    }
    f.server
        .handle_timeout(f.now + Duration::from_secs(600))
        .unwrap();
    assert_eq!(f.server.allocation_count(), 0);
    assert_eq!(f.server.events.len(), 3);
    assert!(
        matches!(f.server.events.back(), Some(Event::ReleaseRelay { allocation_id }) if *allocation_id == f.id)
    );
}

#[test]
fn ipv6_relay_request_and_family_validation() {
    let mut f = fixture();
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[
            Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            }),
            Box::new(REQUESTED_FAMILY_IPV6),
        ],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay {
        allocation_id,
        family,
        ..
    } = f.server.poll_event().unwrap()
    else {
        panic!();
    };
    assert_eq!(family, AddressFamily::Ipv6);
    f.server
        .complete_allocate(
            f.now,
            allocation_id,
            Ok("[2001:db8::1]:50000".parse().unwrap()),
        )
        .unwrap();
    assert_eq!(response(&mut f.server).typ.class, CLASS_SUCCESS_RESPONSE);
}

#[test]
fn forged_nonce_and_cross_tuple_nonce_cannot_allocate() {
    let mut f = fixture();
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &f.nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    assert!(error(&response(&mut f.server)) == CODE_STALE_NONCE);
    assert!(f.server.pending.is_empty());
}

#[test]
fn unknown_required_attribute_returns_signed_420() {
    struct Unknown;
    impl Setter for Unknown {
        fn add_to(&self, message: &mut Message) -> Result<()> {
            message.add(AttrType(0x1234), &[0; 4]);
            Ok(())
        }
    }
    let mut f = fixture();
    let request = request(METHOD_REFRESH, "alice", &f.nonce, &[Box::new(Unknown)]);
    f.server
        .handle_datagram(f.now, f.transport, &request.raw)
        .unwrap();
    let mut response = response(&mut f.server);
    assert!(error(&response) == CODE_UNKNOWN_ATTRIBUTE);
    assert!(response.contains(ATTR_UNKNOWN_ATTRIBUTES));
    MessageIntegrity::check(&mut response, &f.key, default_provider().unwrap().crypto()).unwrap();
}

#[test]
fn existing_client_can_allocate_forward_and_release_without_network_io() {
    use crate::client::{Client, ClientConfig, Event as ClientEvent};
    use sansio::Protocol;
    use shared::TransportMessage;

    let now = Instant::now();
    let provider = default_provider().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let relay_address: SocketAddr = "127.0.0.1:50000".parse().unwrap();
    let mut server = Server::new(
        ServerConfig::default(),
        Arc::new(Users),
        provider.clone(),
        now,
    )
    .unwrap();
    let mut client = Client::new(
        ClientConfig {
            turn_serv_addr: server_addr.to_string(),
            local_addr: client_addr,
            username: "alice".into(),
            password: "password".into(),
            realm: "webrtc.rs".into(),
            ..Default::default()
        },
        provider,
    )
    .unwrap();
    let transport = TransportContext {
        local_addr: server_addr,
        peer_addr: client_addr,
        ..Default::default()
    };
    let mut id = None;

    // Feed packets directly between the real client and server, with no sockets or sleeps.
    fn drive(
        server: &mut Server,
        client: &mut Client,
        now: Instant,
        transport: TransportContext,
        relay: SocketAddr,
        id: &mut Option<AllocationId>,
    ) {
        for _ in 0..8 {
            let mut progressed = false;
            while let Some(packet) = client.poll_write() {
                server
                    .handle_datagram(now, transport, &packet.message)
                    .unwrap();
                progressed = true;
            }
            while let Some(event) = server.poll_event() {
                match event {
                    Event::AllocateRelay { allocation_id, .. } => {
                        *id = Some(allocation_id);
                        server
                            .complete_allocate(now, allocation_id, Ok(relay))
                            .unwrap();
                    }
                    Event::SendToClient { data, .. } => {
                        client
                            .handle_read(TransportMessage {
                                now,
                                transport: TransportContext {
                                    local_addr: transport.peer_addr,
                                    peer_addr: transport.local_addr,
                                    ..Default::default()
                                },
                                message: data,
                            })
                            .unwrap();
                    }
                    Event::ReleaseRelay { .. } => {}
                    Event::SendToPeer { .. } => panic!("unexpected data while driving control"),
                }
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
    }

    client.allocate(now).unwrap();
    drive(
        &mut server,
        &mut client,
        now,
        transport,
        relay_address,
        &mut id,
    );
    assert!(
        matches!(client.poll_event(), Some(ClientEvent::AllocateResponse(_, address)) if address == relay_address)
    );
    assert_eq!(server.allocation_count(), 1);
    client
        .relay(relay_address)
        .unwrap()
        .create_permission(now, peer)
        .unwrap();
    drive(
        &mut server,
        &mut client,
        now,
        transport,
        relay_address,
        &mut id,
    );
    assert!(
        matches!(client.poll_event(), Some(ClientEvent::CreatePermissionResponse(_, address)) if address == peer)
    );
    client
        .relay(relay_address)
        .unwrap()
        .send_to(now, b"outbound", peer)
        .unwrap();
    while let Some(packet) = client.poll_write() {
        server
            .handle_datagram(now, transport, &packet.message)
            .unwrap();
    }
    let mut forwarded = 0;
    while let Some(event) = server.poll_event() {
        match event {
            Event::SendToPeer {
                peer: address,
                data,
                ..
            } => {
                assert_eq!(address, peer);
                assert_eq!(&data[..], b"outbound");
                forwarded += 1;
            }
            Event::SendToClient { data, .. } => {
                client
                    .handle_read(TransportMessage {
                        now,
                        transport: TransportContext {
                            local_addr: client_addr,
                            peer_addr: server_addr,
                            ..Default::default()
                        },
                        message: data,
                    })
                    .unwrap();
            }
            event => panic!("unexpected event: {event:?}"),
        }
    }
    assert_eq!(forwarded, 1);
    server
        .handle_peer_data(now, id.unwrap(), peer, b"inbound")
        .unwrap();
    drive(
        &mut server,
        &mut client,
        now,
        transport,
        relay_address,
        &mut id,
    );
    assert!(
        matches!(client.poll_event(), Some(ClientEvent::DataIndicationOrChannelData(_, address, data)) if address == peer && data == b"inbound"[..])
    );
    client.relay(relay_address).unwrap().close(now).unwrap();
    drive(
        &mut server,
        &mut client,
        now,
        transport,
        relay_address,
        &mut id,
    );
    assert_eq!(server.allocation_count(), 0);
}

#[test]
fn queue_pressure_cannot_apply_a_refresh_without_its_response() {
    let mut f = fixture_with_config(ServerConfig {
        max_events: 2,
        ..Default::default()
    });
    let delete = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.server.send_client(FiveTuple::from(f.transport), b"busy");
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &delete.raw)
            .is_err()
    );
    assert_eq!(f.server.allocation_count(), 1);
    f.server.poll_event();
    f.server
        .handle_datagram(f.now, f.transport, &delete.raw)
        .unwrap();
    assert_eq!(f.server.allocation_count(), 0);
}

#[test]
fn close_is_idempotent_and_cannot_admit_new_requests() {
    let mut f = fixture();
    f.server.close();
    f.server.close();
    assert_eq!(f.server.events.len(), 1);
    f.server.poll_event();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &f.nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &allocate.raw)
            .is_err()
    );
    assert!(f.server.pending.is_empty());
}

#[test]
fn two_allocations_on_one_server_can_relay_to_each_other() {
    let mut f = fixture();
    let first_relay: SocketAddr = "198.51.100.1:50000".parse().unwrap();
    let second_relay: SocketAddr = "198.51.100.1:50001".parse().unwrap();
    let mut second_transport = f.transport;
    second_transport.peer_addr.set_port(12346);
    let nonce = f
        .server
        .nonce(f.now, FiveTuple::from(second_transport))
        .unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "bob",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, second_transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay {
        allocation_id: second_id,
        ..
    } = f.server.poll_event().unwrap()
    else {
        panic!();
    };
    f.server
        .complete_allocate(f.now, second_id, Ok(second_relay))
        .unwrap();
    assert_eq!(response(&mut f.server).typ.class, CLASS_SUCCESS_RESPONSE);
    assert_eq!(
        permission(&mut f, second_relay).typ.class,
        CLASS_SUCCESS_RESPONSE
    );
    let permit = request(
        METHOD_CREATE_PERMISSION,
        "bob",
        &nonce,
        &[Box::new(PeerAddress {
            ip: first_relay.ip(),
            port: 0,
        })],
    );
    f.server
        .handle_datagram(f.now, second_transport, &permit.raw)
        .unwrap();
    assert_eq!(response(&mut f.server).typ.class, CLASS_SUCCESS_RESPONSE);
    let mut send = Message::new();
    send.set_type(MessageType::new(METHOD_SEND, CLASS_INDICATION));
    send.write_header();
    PeerAddress {
        ip: second_relay.ip(),
        port: second_relay.port(),
    }
    .add_to(&mut send)
    .unwrap();
    Data(b"relay-to-relay".to_vec()).add_to(&mut send).unwrap();
    f.server
        .handle_datagram(f.now, f.transport, &send.raw)
        .unwrap();
    let Event::SendToPeer {
        allocation_id,
        peer,
        data,
    } = f.server.poll_event().unwrap()
    else {
        panic!();
    };
    assert_eq!(allocation_id, f.id);
    assert_eq!(peer, second_relay);
    // The host sends from the first relay socket to the second relay socket.
    f.server
        .handle_peer_data(f.now, second_id, first_relay, &data)
        .unwrap();
    let Event::SendToClient { transport, data } = f.server.poll_event().unwrap() else {
        panic!();
    };
    assert_eq!(transport.peer_addr, second_transport.peer_addr);
    assert_eq!(
        message::decode(&data).unwrap().get(ATTR_DATA).unwrap(),
        b"relay-to-relay"
    );
    // The same IP permission must not allow reflection onto the allocation's own socket.
    assert!(error(&bind(&mut f, first_relay, 0x4000)) == CODE_FORBIDDEN);
}

#[test]
fn failed_host_bind_replays_error_without_allocating_another_socket() {
    let mut f = fixture();
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay { allocation_id, .. } = f.server.poll_event().unwrap() else {
        panic!();
    };
    f.server
        .complete_allocate(f.now, allocation_id, Err(CODE_INSUFFICIENT_CAPACITY))
        .unwrap();
    let first = response(&mut f.server);
    assert!(error(&first) == CODE_INSUFFICIENT_CAPACITY);
    f.server
        .handle_datagram(f.now + Duration::from_secs(1), transport, &allocate.raw)
        .unwrap();
    assert_eq!(response(&mut f.server).raw, first.raw);
    assert!(f.server.pending.is_empty());
    assert!(f.server.poll_event().is_none());
    // A new transaction expresses a new allocation attempt, rather than a UDP retransmission.
    let retry = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now + Duration::from_secs(1), transport, &retry.raw)
        .unwrap();
    assert!(matches!(
        f.server.poll_event(),
        Some(Event::AllocateRelay { .. })
    ));
}

#[test]
fn authenticated_quota_error_stays_failed_after_capacity_is_released() {
    let mut f = fixture_with_config(ServerConfig {
        max_allocations_per_user: 1,
        ..Default::default()
    });
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    let first = response(&mut f.server);
    assert!(error(&first) == CODE_ALLOC_QUOTA_REACHED);
    let delete = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    f.server
        .handle_datagram(f.now, f.transport, &delete.raw)
        .unwrap();
    assert!(matches!(
        f.server.poll_event(),
        Some(Event::ReleaseRelay { .. })
    ));
    response(&mut f.server);
    assert_eq!(f.server.allocation_count(), 0);
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    assert_eq!(response(&mut f.server).raw, first.raw);
    assert!(f.server.pending.is_empty());
}

#[test]
fn signed_errors_do_not_consume_a_pending_bind_replay_reservation() {
    let mut f = fixture_with_config(ServerConfig {
        max_replay_entries: 2,
        ..Default::default()
    });
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let allocate = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    let Event::AllocateRelay { allocation_id, .. } = f.server.poll_event().unwrap() else {
        panic!();
    };
    let denied = request(
        METHOD_REFRESH,
        "alice",
        &f.nonce,
        &[Box::new(Lifetime(Duration::ZERO))],
    );
    // Dropping an unadmitted request avoids promising an error response that cannot be replayed.
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &denied.raw)
            .is_err()
    );
    assert_eq!(f.server.allocation_count(), 1);
    assert_eq!(f.server.cache.len(), 1);
    assert_eq!(f.server.pending.len(), 1);
    assert!(f.server.poll_event().is_none());
    f.server
        .complete_allocate(f.now, allocation_id, Err(CODE_INSUFFICIENT_CAPACITY))
        .unwrap();
    let first = response(&mut f.server);
    assert_eq!(f.server.cache.len(), 2);
    f.server
        .handle_datagram(f.now, transport, &allocate.raw)
        .unwrap();
    assert_eq!(response(&mut f.server).raw, first.raw);
}

fn with_transaction_id(message: &Message, id: TransactionId, key: &[u8]) -> Message {
    let mut result = Message::new();
    result.set_type(message.typ);
    result.transaction_id = id;
    result.write_header();
    for attr in &message.attributes.0 {
        if attr.typ != ATTR_MESSAGE_INTEGRITY && attr.typ != ATTR_FINGERPRINT {
            result.add(attr.typ, &attr.value);
        }
    }
    MessageIntegrity::new_raw_integrity_with_provider(
        key.to_vec(),
        default_provider().unwrap().crypto(),
    )
    .add_to(&mut result)
    .unwrap();
    FINGERPRINT.add_to(&mut result).unwrap();
    result
}

#[test]
fn pending_transaction_collision_cannot_poison_allocate_replay() {
    for method in [METHOD_ALLOCATE, METHOD_REFRESH, METHOD_BINDING] {
        let mut f = fixture();
        let mut transport = f.transport;
        transport.peer_addr.set_port(12346);
        let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
        let allocate = request(
            METHOD_ALLOCATE,
            "alice",
            &nonce,
            &[Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            })],
        );
        f.server
            .handle_datagram(f.now, transport, &allocate.raw)
            .unwrap();
        let Some(Event::AllocateRelay { allocation_id, .. }) = f.server.poll_event() else {
            panic!("expected pending allocation");
        };
        let collision = with_transaction_id(
            &request(
                method,
                "alice",
                &nonce,
                &[Box::new(Lifetime(Duration::from_secs(60)))],
            ),
            allocate.transaction_id,
            &f.key,
        );
        f.server
            .handle_datagram(f.now, transport, &collision.raw)
            .unwrap();
        assert!(
            f.server.poll_event().is_none(),
            "colliding method {method:?} must be discarded"
        );
        assert!(
            !f.server
                .cache
                .contains_key(&(FiveTuple::from(transport), allocate.transaction_id))
        );
        f.server
            .complete_allocate(
                f.now,
                allocation_id,
                Ok("198.51.100.1:50001".parse().unwrap()),
            )
            .unwrap();
        let success = response(&mut f.server);
        assert_eq!(success.typ.class, CLASS_SUCCESS_RESPONSE);
        f.server
            .handle_datagram(f.now, transport, &allocate.raw)
            .unwrap();
        assert_eq!(response(&mut f.server).raw, success.raw);
        assert_eq!(f.server.allocation_count(), 2);
    }
}

#[test]
fn active_transaction_collision_cannot_poison_allocate_replay() {
    for method in [METHOD_ALLOCATE, METHOD_REFRESH, METHOD_BINDING] {
        let mut f = fixture();
        let tuple = FiveTuple::from(f.transport);
        let original = message::decode(&f.server.allocations[&tuple].allocate_request).unwrap();
        let expected = f.server.allocations[&tuple].allocate_response.clone();
        let expiry = f.server.allocations[&tuple].expires;
        // The allocation retains its transaction after the short replay cache expires.
        f.now += Duration::from_secs(45);
        let collision = with_transaction_id(
            &request(
                method,
                "alice",
                &f.nonce,
                &[Box::new(Lifetime(Duration::ZERO))],
            ),
            original.transaction_id,
            &f.key,
        );
        f.server
            .handle_datagram(f.now, f.transport, &collision.raw)
            .unwrap();
        assert!(
            f.server.poll_event().is_none(),
            "colliding method {method:?} must be discarded"
        );
        assert_eq!(f.server.allocations[&tuple].expires, expiry);
        f.server
            .handle_datagram(f.now, f.transport, &original.raw)
            .unwrap();
        assert_eq!(response(&mut f.server).raw, expected);
    }
}

#[test]
fn configuration_rejects_fractional_lifetime_overruns() {
    let tick = Duration::from_nanos(1);
    for config in [
        ServerConfig {
            max_lifetime: Duration::from_secs(3600) + tick,
            ..Default::default()
        },
        ServerConfig {
            nonce_lifetime: Duration::from_secs(3600) + tick,
            ..Default::default()
        },
        ServerConfig {
            pending_lifetime: Duration::from_secs(60) + tick,
            ..Default::default()
        },
        ServerConfig {
            replay_lifetime: Duration::from_secs(600) + tick,
            ..Default::default()
        },
    ] {
        assert!(
            config.validate().is_err(),
            "over-limit config accepted: {config:?}"
        );
    }
}

type RequestAttributes = Vec<Box<dyn Setter>>;

struct WireAttribute(AttrType, Vec<u8>);
impl Setter for WireAttribute {
    fn add_to(&self, message: &mut Message) -> Result<()> {
        message.add(self.0, &self.1);
        Ok(())
    }
}

#[test]
fn allocate_validation_errors_are_signed_and_leave_no_pending_bind() {
    let cases: Vec<(RequestAttributes, ErrorCode)> = vec![
        (vec![], CODE_BAD_REQUEST),
        (
            vec![Box::new(RequestedTransport {
                protocol: crate::proto::PROTO_TCP,
            })],
            CODE_UNSUPPORTED_TRANS_PROTO,
        ),
        (
            vec![Box::new(WireAttribute(ATTR_REQUESTED_TRANSPORT, vec![17]))],
            CODE_BAD_REQUEST,
        ),
        (
            vec![
                Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                }),
                Box::new(WireAttribute(
                    ATTR_REQUESTED_ADDRESS_FAMILY,
                    vec![3, 0, 0, 0],
                )),
            ],
            CODE_BAD_REQUEST,
        ),
        (
            vec![
                Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                }),
                Box::new(WireAttribute(ATTR_LIFETIME, vec![0])),
            ],
            CODE_BAD_REQUEST,
        ),
        (
            vec![
                Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                }),
                Box::new(WireAttribute(ATTR_EVEN_PORT, vec![0])),
            ],
            CODE_UNKNOWN_ATTRIBUTE,
        ),
        (
            vec![
                Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                }),
                Box::new(WireAttribute(ATTR_RESERVATION_TOKEN, vec![0; 8])),
            ],
            CODE_UNKNOWN_ATTRIBUTE,
        ),
        (
            vec![
                Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                }),
                Box::new(WireAttribute(ATTR_DONT_FRAGMENT, vec![])),
            ],
            CODE_UNKNOWN_ATTRIBUTE,
        ),
    ];
    for (attrs, expected) in cases {
        let mut f = fixture();
        let mut transport = f.transport;
        transport.peer_addr.set_port(12346);
        let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
        let packet = request(METHOD_ALLOCATE, "alice", &nonce, &attrs);
        f.server
            .handle_datagram(f.now, transport, &packet.raw)
            .unwrap();
        let mut reply = response(&mut f.server);
        assert!(error(&reply) == expected);
        MessageIntegrity::check(&mut reply, &f.key, default_provider().unwrap().crypto()).unwrap();
        assert!(f.server.pending.is_empty());
        f.server
            .handle_datagram(f.now, transport, &packet.raw)
            .unwrap();
        assert_eq!(response(&mut f.server).raw, reply.raw);
    }
}

#[test]
fn permission_and_channel_errors_do_not_install_partial_state() {
    let cases: Vec<(Method, RequestAttributes, ErrorCode)> = vec![
        (METHOD_CREATE_PERMISSION, vec![], CODE_BAD_REQUEST),
        (
            METHOD_CREATE_PERMISSION,
            vec![Box::new(WireAttribute(ATTR_XOR_PEER_ADDRESS, vec![0]))],
            CODE_BAD_REQUEST,
        ),
        (
            METHOD_CREATE_PERMISSION,
            vec![Box::new(PeerAddress {
                ip: "::1".parse().unwrap(),
                port: 1,
            })],
            CODE_PEER_ADDR_FAMILY_MISMATCH,
        ),
        (
            METHOD_CREATE_PERMISSION,
            vec![Box::new(PeerAddress {
                ip: "224.0.0.1".parse().unwrap(),
                port: 1,
            })],
            CODE_FORBIDDEN,
        ),
        (
            METHOD_CHANNEL_BIND,
            vec![
                Box::new(ChannelNumber(0x4000)),
                Box::new(PeerAddress {
                    ip: "203.0.113.1".parse().unwrap(),
                    port: 0,
                }),
            ],
            CODE_FORBIDDEN,
        ),
        (
            METHOD_CHANNEL_BIND,
            vec![Box::new(PeerAddress {
                ip: "203.0.113.1".parse().unwrap(),
                port: 9000,
            })],
            CODE_BAD_REQUEST,
        ),
        (
            METHOD_REFRESH,
            vec![Box::new(REQUESTED_FAMILY_IPV6)],
            CODE_PEER_ADDR_FAMILY_MISMATCH,
        ),
        (
            METHOD_REFRESH,
            vec![Box::new(WireAttribute(
                ATTR_REQUESTED_ADDRESS_FAMILY,
                vec![0],
            ))],
            CODE_BAD_REQUEST,
        ),
        (
            METHOD_REFRESH,
            vec![Box::new(WireAttribute(ATTR_LIFETIME, vec![0]))],
            CODE_BAD_REQUEST,
        ),
    ];
    for (method, attrs, expected) in cases {
        let mut f = fixture();
        let tuple = FiveTuple::from(f.transport);
        let expiry = f.server.allocations[&tuple].expires;
        let packet = request(method, "alice", &f.nonce, &attrs);
        f.server
            .handle_datagram(f.now, f.transport, &packet.raw)
            .unwrap();
        assert!(error(&response(&mut f.server)) == expected);
        let allocation = &f.server.allocations[&tuple];
        assert!(allocation.permissions.is_empty());
        assert!(allocation.channels.is_empty());
        assert_eq!(allocation.expires, expiry);
    }
}

#[test]
fn invalid_relay_completion_releases_socket_and_replays_failure() {
    for address in [
        "0.0.0.0:50001",
        "224.0.0.1:50001",
        "198.51.100.1:0",
        "[2001:db8::1]:50001",
    ] {
        let mut f = fixture();
        let mut transport = f.transport;
        transport.peer_addr.set_port(12346);
        let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
        let packet = request(
            METHOD_ALLOCATE,
            "alice",
            &nonce,
            &[Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            })],
        );
        f.server
            .handle_datagram(f.now, transport, &packet.raw)
            .unwrap();
        let Some(Event::AllocateRelay { allocation_id, .. }) = f.server.poll_event() else {
            panic!()
        };
        f.server
            .complete_allocate(f.now, allocation_id, Ok(address.parse().unwrap()))
            .unwrap();
        assert!(
            matches!(f.server.poll_event(), Some(Event::ReleaseRelay { allocation_id: id }) if id == allocation_id)
        );
        let failed = response(&mut f.server);
        assert!(error(&failed) == CODE_INSUFFICIENT_CAPACITY);
        assert_eq!(f.server.allocation_count(), 1);
        f.server
            .handle_datagram(f.now, transport, &packet.raw)
            .unwrap();
        assert_eq!(response(&mut f.server).raw, failed.raw);
    }
}

#[test]
fn default_peer_policy_rejects_local_and_mapped_local_addresses() {
    struct Public;
    impl Authenticator for Public {
        fn credential_key(&self, _: &str, _: &str) -> Option<Vec<u8>> {
            None
        }
    }
    for peer in [
        "0.1.2.3:80",
        "0.0.0.0:80",
        "127.0.0.1:80",
        "10.0.0.1:80",
        "169.254.1.1:80",
        "224.0.0.1:80",
        "255.255.255.255:80",
        "240.0.0.1:80",
        "8.8.8.8:0",
        "[::]:80",
        "[::1]:80",
        "[fc00::1]:80",
        "[fe80::1]:80",
        "[ff02::1]:80",
        "[::ffff:127.0.0.1]:80",
    ] {
        assert!(
            !Public.allow_peer("alice", peer.parse().unwrap()),
            "allowed {peer}"
        );
    }
    for peer in [
        "8.8.8.8:53",
        "[2606:4700:4700::1111]:53",
        "[::ffff:8.8.8.8]:53",
    ] {
        assert!(
            Public.allow_peer("alice", peer.parse().unwrap()),
            "denied {peer}"
        );
    }
}

#[test]
fn protocol_adapter_preserves_actions_feedback_and_deadlines() {
    use sansio::Protocol;
    use shared::TaggedBytesMut;
    type Adapter = dyn Protocol<
            TaggedBytesMut,
            (),
            HostEvent,
            Rout = (),
            Wout = (),
            Eout = Event,
            Error = Error,
            Time = Instant,
        >;
    let mut f = fixture();
    let peer = "203.0.113.1:9000".parse().unwrap();
    permission(&mut f, peer);
    let adapter: &mut Adapter = &mut f.server;
    assert_eq!(
        adapter.poll_timeout(),
        Some(f.now + Duration::from_secs(40))
    );
    assert!(adapter.poll_read().is_none());
    adapter.handle_write(()).unwrap();
    assert!(adapter.poll_write().is_none());
    adapter
        .handle_event(HostEvent::PeerData {
            now: f.now,
            allocation_id: f.id,
            peer,
            data: BytesMut::from(&b"payload"[..]),
        })
        .unwrap();
    let Some(Event::SendToClient { data, transport }) = adapter.poll_event() else {
        panic!()
    };
    assert_eq!(transport.peer_addr, f.transport.peer_addr);
    assert_eq!(
        message::decode(&data).unwrap().get(ATTR_DATA).unwrap(),
        b"payload"
    );
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let packet = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    let adapter: &mut Adapter = &mut f.server;
    adapter
        .handle_read(TaggedBytesMut {
            now: f.now,
            transport,
            message: BytesMut::from(packet.raw.as_slice()),
        })
        .unwrap();
    let Some(Event::AllocateRelay { allocation_id, .. }) = adapter.poll_event() else {
        panic!()
    };
    adapter
        .handle_event(HostEvent::AllocationComplete {
            now: f.now,
            allocation_id,
            result: Ok("198.51.100.1:50001".parse().unwrap()),
        })
        .unwrap();
    assert!(matches!(
        adapter.poll_event(),
        Some(Event::SendToClient { .. })
    ));
    adapter
        .handle_timeout(f.now + Duration::from_secs(40))
        .unwrap();
    assert!(adapter.poll_timeout().unwrap() > f.now + Duration::from_secs(40));
    adapter.close().unwrap();
    let mut released = HashSet::new();
    while let Some(event) = adapter.poll_event() {
        let Event::ReleaseRelay { allocation_id } = event else {
            panic!()
        };
        assert!(released.insert(allocation_id));
    }
    assert_eq!(released, HashSet::from([f.id, allocation_id]));
    assert!(adapter.poll_timeout().is_none());
}

#[test]
fn malformed_datagrams_and_time_reversal_leave_allocation_intact() {
    let mut f = fixture();
    let original = f.server.allocations[&FiveTuple::from(f.transport)]
        .allocate_request
        .clone();
    let mut malformed = original.clone();
    malformed.push(0);
    for bytes in [vec![], vec![0; 19], malformed] {
        assert!(
            f.server
                .handle_datagram(f.now, f.transport, &bytes)
                .is_err()
        );
        assert!(f.server.poll_event().is_none());
    }
    let mut tcp = f.transport;
    tcp.transport_protocol = TransportProtocol::TCP;
    assert!(f.server.handle_datagram(f.now, tcp, &original).is_err());
    assert!(
        f.server
            .handle_timeout(f.now - Duration::from_secs(1))
            .is_err()
    );
    f.server.config.max_request_bytes = 20;
    assert!(
        f.server
            .handle_datagram(f.now, f.transport, &original)
            .is_err()
    );
    assert_eq!(f.server.allocation_count(), 1);
    assert!(f.server.poll_event().is_none());
}

#[test]
fn host_can_retire_one_allocation_even_when_output_is_full() {
    let mut f = fixture_with_config(ServerConfig {
        max_events: 2,
        ..Default::default()
    });
    for _ in 0..2 {
        f.server
            .send_client(FiveTuple::from(f.transport), b"queued");
    }
    f.server.close_allocation(f.id);
    f.server.close_allocation(f.id);
    f.server.close_allocation(AllocationId(u64::MAX));
    assert_eq!(f.server.allocation_count(), 0);
    assert_eq!(f.server.events.len(), 3);
    assert!(
        matches!(f.server.events.back(), Some(Event::ReleaseRelay { allocation_id }) if *allocation_id == f.id)
    );
    while f.server.poll_event().is_some() {}
    f.server
        .handle_peer_data(f.now, f.id, "203.0.113.1:9000".parse().unwrap(), b"late")
        .unwrap();
    assert!(f.server.poll_event().is_none());
}

#[test]
fn host_can_cancel_a_pending_relay_without_resurrection() {
    let mut f = fixture();
    let mut transport = f.transport;
    transport.peer_addr.set_port(12346);
    let nonce = f.server.nonce(f.now, FiveTuple::from(transport)).unwrap();
    let packet = request(
        METHOD_ALLOCATE,
        "alice",
        &nonce,
        &[Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    f.server
        .handle_datagram(f.now, transport, &packet.raw)
        .unwrap();
    let Some(Event::AllocateRelay { allocation_id, .. }) = f.server.poll_event() else {
        panic!()
    };
    f.server.close_allocation(allocation_id);
    f.server.close_allocation(allocation_id);
    assert!(
        matches!(f.server.poll_event(), Some(Event::ReleaseRelay { allocation_id: id }) if id == allocation_id)
    );
    assert!(f.server.poll_event().is_none());
    assert!(
        f.server
            .complete_allocate(
                f.now,
                allocation_id,
                Ok("198.51.100.1:50001".parse().unwrap())
            )
            .is_err()
    );
    assert!(f.server.pending.is_empty());
    assert_eq!(f.server.allocation_count(), 1);
}
