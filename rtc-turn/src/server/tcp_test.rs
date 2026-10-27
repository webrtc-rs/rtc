//! RFC 6062: TCP allocations, driven end to end — a real [`Client`] against a real [`Server`] on an
//! in-memory network, with the test standing in for the application that owns the sockets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

use stun::attributes::*;
use stun::message::*;

use super::{
    AuthCredentials, AuthHandler, AuthRequest, CONNECTION_BIND_TIMEOUT, PeerConnId,
    RelayAddressGenerator, RelayAddressGeneratorStatic, Server, ServerConfig, ServerEvent,
    generate_auth_key,
};
use crate::client::{Client, ClientConfig, Event};
use crate::proto::connid::ConnectionId;

const REALM: &str = "webrtc.rs";

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn server_addr() -> SocketAddr {
    "192.0.2.1:3478".parse().unwrap()
}

fn relay_addr() -> SocketAddr {
    "192.0.2.50:50000".parse().unwrap()
}

fn peer() -> SocketAddr {
    "203.0.113.9:6000".parse().unwrap()
}

fn users() -> Arc<dyn AuthHandler> {
    Arc::new(|req: &AuthRequest<'_>| {
        let password = match req.username {
            "user" => "pass",
            "other" => "pw2",
            _ => return None,
        };
        Some(AuthCredentials {
            user_id: req.username.to_owned(),
            key: generate_auth_key(req.username, req.realm, password, provider().crypto()).ok()?,
        })
    })
}

fn generator() -> Box<dyn RelayAddressGenerator> {
    Box::new(RelayAddressGeneratorStatic {
        relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
    })
}

fn client_at(local: &str, user: &str, pass: &str) -> Client {
    Client::new(
        ClientConfig {
            turn_serv_addr: server_addr().to_string(),
            local_addr: local.parse().unwrap(),
            transport_protocol: TransportProtocol::TCP,
            username: user.to_owned(),
            password: pass.to_owned(),
            realm: REALM.to_owned(),
            ..Default::default()
        },
        provider(),
    )
    .unwrap()
}

/// A server and clients on an in-memory network of TCP connections.
struct Net {
    server: Server,
    clients: Vec<Client>,
    now: Instant,
    /// Every server event, in order.
    events: Vec<ServerEvent>,
    /// Every client event, per client.
    client_events: Vec<Vec<Event>>,
    /// Treat the transport to the server as UDP, to see how it refuses a TCP allocation there.
    pretend_udp: bool,
}

impl Net {
    fn new() -> Self {
        let now = Instant::now();
        let config = ServerConfig::new(REALM, users(), generator(), provider());
        Self {
            server: Server::new(config, now).unwrap(),
            clients: vec![client_at("198.51.100.7:40000", "user", "pass")],
            now,
            events: vec![],
            client_events: vec![vec![]],
            pretend_udp: false,
        }
    }

    fn add_client(&mut self, local: &str, user: &str, pass: &str) -> usize {
        self.clients.push(client_at(local, user, pass));
        self.client_events.push(vec![]);
        self.clients.len() - 1
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        self.server.handle_timeout(self.now).unwrap();
        for c in &mut self.clients {
            c.handle_timeout(self.now).unwrap();
        }
        self.pump();
    }

    /// Moves messages both ways until the network is quiet. The application binds a TCP relay
    /// when asked, but leaves peer connections to the test.
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.clients.len() {
                while let Some(out) = self.clients[i].poll_write() {
                    moved = true;
                    let protocol = if self.pretend_udp {
                        TransportProtocol::UDP
                    } else {
                        TransportProtocol::TCP
                    };
                    self.server
                        .handle_read(TaggedBytesMut {
                            now: self.now,
                            transport: TransportContext {
                                local_addr: server_addr(),
                                peer_addr: out.transport.local_addr,
                                transport_protocol: protocol,
                                ecn: None,
                            },
                            message: out.message,
                        })
                        .unwrap();
                }
            }
            while let Some(event) = self.server.poll_event() {
                moved = true;
                if let ServerEvent::BindRelayTcp { id, .. } | ServerEvent::BindRelay { id, .. } =
                    &event
                {
                    self.server.relay_bound(*id, relay_addr(), self.now);
                }
                self.events.push(event);
            }
            while let Some(out) = self.server.poll_write() {
                moved = true;
                // A message to a client's address goes to the client that owns it; a data
                // connection's address belongs to whichever client opened it, so try each.
                for c in &mut self.clients {
                    let _ = c.handle_read(TaggedBytesMut {
                        now: self.now,
                        transport: out.transport,
                        message: BytesMut::from(&out.message[..]),
                    });
                }
            }
            for (i, c) in self.clients.iter_mut().enumerate() {
                while let Some(event) = c.poll_event() {
                    moved = true;
                    self.client_events[i].push(event);
                }
            }
            if !moved {
                break;
            }
        }
    }

    fn allocate_tcp(&mut self, client: usize) -> SocketAddr {
        self.clients[client].allocate_tcp(self.now).unwrap();
        self.pump();
        self.client_events[client]
            .iter()
            .find_map(|e| match e {
                Event::AllocateResponse(_, relayed) => Some(*relayed),
                _ => None,
            })
            .expect("the allocation succeeds")
    }

    /// The `ConnectPeer` the server has asked for and the application has not answered.
    fn pending_connect(&self) -> Option<(PeerConnId, SocketAddr, SocketAddr)> {
        self.events.iter().rev().find_map(|e| match e {
            ServerEvent::ConnectPeer { id, relay, peer } => Some((*id, *relay, *peer)),
            _ => None,
        })
    }

    fn client_error(&self, client: usize) -> Option<String> {
        self.client_events[client]
            .iter()
            .rev()
            .find_map(|e| match e {
                Event::ConnectError(_, err) | Event::ConnectionBindError(_, err) => {
                    Some(err.to_string())
                }
                _ => None,
            })
    }

    fn connect_response(&self, client: usize) -> Option<(SocketAddr, ConnectionId)> {
        self.client_events[client]
            .iter()
            .rev()
            .find_map(|e| match e {
                Event::ConnectResponse(_, peer, id) => Some((*peer, *id)),
                _ => None,
            })
    }

    /// Opens a peer connection through `Connect` and returns its server id and connection id.
    fn connect(&mut self, client: usize, to: SocketAddr) -> (PeerConnId, ConnectionId) {
        let relayed = relay_addr_advertised();
        self.clients[client]
            .relay(relayed)
            .unwrap()
            .connect(self.now, to)
            .unwrap();
        self.pump();
        let (id, from, wanted) = self
            .pending_connect()
            .expect("the server asks for a connection");
        assert_eq!(
            from,
            relay_addr(),
            "the connection is opened from the relay address"
        );
        assert_eq!(wanted, to);
        self.server.peer_connected(id, self.now);
        self.pump();
        let (_, connection_id) = self
            .connect_response(client)
            .expect("the client is told the id");
        (id, connection_id)
    }

    fn bind_data(&mut self, client: usize, connection_id: ConnectionId, local: &str) {
        let local: SocketAddr = local.parse().unwrap();
        self.clients[client]
            .relay(relay_addr_advertised())
            .unwrap()
            .connection_bind(self.now, connection_id, local)
            .unwrap();
        self.pump();
    }
}

/// The relayed address clients are told: the advertised IP with the bound port.
fn relay_addr_advertised() -> SocketAddr {
    "192.0.2.50:50000".parse().unwrap()
}

#[test]
fn a_tcp_allocation_asks_for_a_tcp_relay_and_answers_with_its_address() {
    let mut net = Net::new();
    let relayed = net.allocate_tcp(0);
    assert_eq!(relayed, relay_addr_advertised());
    assert!(
        net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindRelayTcp { .. })),
        "a TCP allocation binds a TCP listener, not a UDP socket: {:?}",
        net.events
    );
    assert!(
        !net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindRelay { .. })),
    );
    assert_eq!(net.server.allocation_count(), 1);
}

#[test]
fn a_udp_allocation_is_still_a_udp_relay() {
    let mut net = Net::new();
    net.clients[0].allocate(net.now).unwrap();
    net.pump();
    assert!(
        net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindRelay { .. }))
    );
    assert!(
        !net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindRelayTcp { .. }))
    );
}

#[test]
fn a_tcp_allocation_over_udp_is_refused_with_442() {
    let mut net = Net::new();
    net.pretend_udp = true;
    net.clients[0].allocate_tcp(net.now).unwrap();
    net.pump();
    let error = net.client_events[0]
        .iter()
        .find_map(|e| match e {
            Event::AllocateError(_, err) => Some(err.to_string()),
            _ => None,
        })
        .expect("the allocation is refused");
    assert!(
        error.contains("442"),
        "unsupported transport protocol: {error}"
    );
    assert_eq!(net.server.allocation_count(), 0);
}

#[test]
fn the_client_will_not_ask_for_a_tcp_allocation_over_udp() {
    let mut client = Client::new(
        ClientConfig {
            turn_serv_addr: server_addr().to_string(),
            local_addr: "198.51.100.7:40000".parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            username: "user".to_owned(),
            password: "pass".to_owned(),
            realm: REALM.to_owned(),
            ..Default::default()
        },
        provider(),
    )
    .unwrap();
    assert!(client.allocate_tcp(Instant::now()).is_err());
}

#[test]
fn connect_opens_a_peer_connection_and_connection_bind_attaches_a_data_connection() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (id, connection_id) = net.connect(0, peer());
    assert_ne!(connection_id.0, 0);
    assert!(net.server.has_peer_connection(id));

    net.bind_data(0, connection_id, "198.51.100.7:40001");
    assert!(
        net.client_events[0].iter().any(|e| matches!(
            e,
            Event::ConnectionBindResponse(_, cid) if *cid == connection_id
        )),
        "{:?}",
        net.client_events[0]
    );
    let bound = net.events.iter().find_map(|e| match e {
        ServerEvent::BindData { id, client, server } => Some((*id, *client, *server)),
        _ => None,
    });
    assert_eq!(
        bound,
        Some((id, "198.51.100.7:40001".parse().unwrap(), server_addr())),
        "the application is told which two connections to splice"
    );
    // The data connection is bound for good: the timeout no longer closes it.
    net.advance(CONNECTION_BIND_TIMEOUT * 2);
    assert!(net.server.has_peer_connection(id));
    assert!(
        !net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::ClosePeer(_)))
    );
}

#[test]
fn connect_grants_the_permission_to_hear_from_the_peer() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (id, _) = net.connect(0, peer());
    // The peer connecting back to the relay is accepted: Connect was the permission.
    let again = net.server.peer_accepted(relay_addr(), peer(), net.now);
    assert!(again.is_some());
    assert_ne!(again, Some(id));
}

#[test]
fn a_failed_connection_is_447() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .connect(net.now, peer())
        .unwrap();
    net.pump();
    let (id, _, _) = net.pending_connect().unwrap();
    net.server.peer_connect_failed(id, net.now);
    net.pump();
    let error = net.client_error(0).expect("the connect fails");
    assert!(error.contains("447"), "{error}");
    assert!(!net.server.has_peer_connection(id));
    assert!(
        net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::ClosePeer(closed) if *closed == id)),
        "the application stops connecting"
    );
}

#[test]
fn a_connection_the_application_never_opens_times_out_with_447() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .connect(net.now, peer())
        .unwrap();
    net.pump();
    let (id, _, _) = net.pending_connect().unwrap();
    net.advance(CONNECTION_BIND_TIMEOUT + Duration::from_secs(1));
    let error = net.client_error(0).expect("the connect fails");
    assert!(error.contains("447"), "{error}");
    assert!(!net.server.has_peer_connection(id));
    // A late report is not wanted.
    net.server.peer_connected(id, net.now);
    net.pump();
    assert!(
        net.events
            .iter()
            .filter(|e| matches!(e, ServerEvent::ClosePeer(c) if *c == id))
            .count()
            >= 2,
        "the late connection is told to close again"
    );
}

#[test]
fn a_second_connect_to_the_same_peer_is_446() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    net.connect(0, peer());
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .connect(net.now, peer())
        .unwrap();
    net.pump();
    let error = net.client_error(0).expect("the second connect fails");
    assert!(error.contains("446"), "{error}");

    // While the first is still being opened, too.
    let mut net = Net::new();
    net.allocate_tcp(0);
    for _ in 0..2 {
        net.clients[0]
            .relay(relay_addr_advertised())
            .unwrap()
            .connect(net.now, peer())
            .unwrap();
        net.pump();
    }
    assert!(net.client_error(0).unwrap().contains("446"));
}

#[test]
fn different_peers_get_different_connection_ids() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (_, first) = net.connect(0, peer());
    let (_, second) = net.connect(0, "203.0.113.10:6000".parse().unwrap());
    assert_ne!(first, second);
}

#[test]
fn a_peer_that_connects_in_is_announced_to_the_client() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    // The client permits the peer first (CreatePermission), as it would to hear from it.
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .create_permission(net.now, peer())
        .unwrap();
    net.pump();

    let id = net
        .server
        .peer_accepted(relay_addr(), peer(), net.now)
        .expect("a permitted peer is accepted");
    net.pump();
    let (cid, from) = net.client_events[0]
        .iter()
        .find_map(|e| match e {
            Event::ConnectionAttempt(cid, from) => Some((*cid, *from)),
            _ => None,
        })
        .expect("the client is told");
    assert_eq!(from, peer());

    // Binding a data connection to it accepts the peer.
    net.bind_data(0, cid, "198.51.100.7:40002");
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::BindData { id: bound, .. } if *bound == id
    )));
}

#[test]
fn a_peer_without_permission_is_not_accepted() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    assert_eq!(
        net.server.peer_accepted(relay_addr(), peer(), net.now),
        None
    );
    assert!(
        net.client_events[0]
            .iter()
            .all(|e| !matches!(e, Event::ConnectionAttempt(..)))
    );
    // Nor on a relay address that belongs to no allocation.
    assert_eq!(
        net.server
            .peer_accepted("192.0.2.50:1".parse().unwrap(), peer(), net.now),
        None
    );
}

#[test]
fn an_unclaimed_peer_connection_is_closed_after_the_timeout() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (id, _) = net.connect(0, peer());
    net.advance(CONNECTION_BIND_TIMEOUT - Duration::from_secs(1));
    assert!(net.server.has_peer_connection(id), "still within the wait");
    net.advance(Duration::from_secs(2));
    assert!(!net.server.has_peer_connection(id));
    assert!(
        net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::ClosePeer(closed) if *closed == id))
    );
}

#[test]
fn a_connection_id_is_not_a_capability() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (_, connection_id) = net.connect(0, peer());

    // Another user, with valid credentials of their own, learns the id and tries to bind it.
    let other = net.add_client("198.51.100.8:40000", "other", "pw2");
    net.clients[other].allocate_tcp(net.now).unwrap();
    net.pump();
    net.clients[other]
        .relay(relay_addr_advertised())
        .unwrap()
        .connection_bind(
            net.now,
            connection_id,
            "198.51.100.8:40001".parse().unwrap(),
        )
        .unwrap();
    net.pump();
    assert!(
        net.client_error(other).is_some(),
        "someone else's id is refused"
    );
    assert!(
        !net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindData { .. }))
    );

    // The owner still can.
    net.bind_data(0, connection_id, "198.51.100.7:40001");
    assert!(
        net.events
            .iter()
            .any(|e| matches!(e, ServerEvent::BindData { .. }))
    );
}

#[test]
fn an_unknown_connection_id_is_refused_and_a_bound_one_cannot_be_bound_twice() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    net.bind_data(0, ConnectionId(0xdead_beef), "198.51.100.7:40001");
    assert!(net.client_error(0).is_some());

    let (_, connection_id) = net.connect(0, peer());
    net.bind_data(0, connection_id, "198.51.100.7:40002");
    let binds = |net: &Net| {
        net.events
            .iter()
            .filter(|e| matches!(e, ServerEvent::BindData { .. }))
            .count()
    };
    assert_eq!(binds(&net), 1);
    net.bind_data(0, connection_id, "198.51.100.7:40003");
    assert_eq!(binds(&net), 1, "the id is spent");
    assert!(net.client_error(0).is_some());
}

#[test]
fn connect_on_a_udp_allocation_is_a_bad_request() {
    let mut net = Net::new();
    net.clients[0].allocate(net.now).unwrap();
    net.pump();
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .connect(net.now, peer())
        .unwrap();
    net.pump();
    let error = net.client_error(0).expect("refused");
    assert!(error.contains("400"), "{error}");
    assert!(net.pending_connect().is_none());
}

#[test]
fn ending_the_allocation_closes_its_peer_connections() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (first, _) = net.connect(0, peer());
    let (second, connection_id) = net.connect(0, "203.0.113.10:6000".parse().unwrap());
    net.bind_data(0, connection_id, "198.51.100.7:40001");

    let five = *net.server.allocations().next().unwrap();
    assert!(net.server.delete_allocation(&five));
    net.pump();
    for id in [first, second] {
        assert!(!net.server.has_peer_connection(id));
        assert!(
            net.events
                .iter()
                .any(|e| matches!(e, ServerEvent::ClosePeer(closed) if *closed == id)),
            "{id:?} is closed, bound or not"
        );
    }
    assert_eq!(net.server.peer_connection_count(), 0);
}

#[test]
fn the_application_can_report_a_peer_connection_closed() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    let (id, connection_id) = net.connect(0, peer());
    net.bind_data(0, connection_id, "198.51.100.7:40001");
    net.server.peer_closed(id);
    assert!(!net.server.has_peer_connection(id));
    // The peer may be connected to again.
    let (again, _) = net.connect(0, peer());
    assert_ne!(again, id);
}

/// Sends `build`'s request to the server the way a client that knew the nonce would: first
/// anonymously, to be told the nonce, then signed. Returns the server's answer to the signed one.
fn authenticated_request(
    net: &mut Net,
    from: SocketAddr,
    method: Method,
    extra: impl Fn() -> Vec<Box<dyn Setter>>,
) -> Message {
    use stun::fingerprint::FINGERPRINT;
    use stun::integrity::MessageIntegrity;
    use stun::textattrs::{Nonce, Realm, TextAttribute, Username};

    let ctx = TransportContext {
        local_addr: server_addr(),
        peer_addr: from,
        transport_protocol: TransportProtocol::TCP,
        ecn: None,
    };
    let send = |net: &mut Net, m: &Message| -> Message {
        net.server
            .handle_read(TaggedBytesMut {
                now: net.now,
                transport: ctx,
                message: BytesMut::from(&m.raw[..]),
            })
            .unwrap();
        let reply = net.server.poll_write().expect("the server answers");
        let mut parsed = Message::new();
        parsed.raw = reply.message.to_vec();
        parsed.decode().unwrap();
        parsed
    };
    let mut anonymous = Message::new();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(method, CLASS_REQUEST)),
    ];
    setters.extend(extra());
    anonymous.build(&setters).unwrap();
    let challenge = send(net, &anonymous);
    let nonce = Nonce::get_from_as(&challenge, ATTR_NONCE).unwrap();
    let realm = Realm::get_from_as(&challenge, ATTR_REALM).unwrap();

    let mut signed = Message::new();
    let crypto = provider();
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(method, CLASS_REQUEST)),
    ];
    setters.extend(extra());
    setters.push(Box::new(TextAttribute::new(
        ATTR_USERNAME,
        "user".to_owned(),
    )));
    setters.push(Box::new(realm));
    setters.push(Box::new(nonce));
    setters.push(Box::new(
        MessageIntegrity::new_long_term_integrity_with_provider(
            "user".to_owned(),
            REALM.to_owned(),
            "pass".to_owned(),
            crypto.crypto(),
        )
        .unwrap(),
    ));
    setters.push(Box::new(FINGERPRINT));
    signed.build(&setters).unwrap();
    let _ = Username::new(ATTR_USERNAME, String::new());
    send(net, &signed)
}

fn error_code_of(m: &Message) -> u16 {
    let mut code = stun::error_code::ErrorCodeAttribute::default();
    code.get_from(m).expect("an error response");
    code.code.0
}

#[test]
fn a_tcp_allocation_relays_no_datagrams() {
    use crate::proto::channum::ChannelNumber;
    use crate::proto::peeraddr::PeerAddress;
    use stun::message::METHOD_CHANNEL_BIND;

    let mut net = Net::new();
    net.allocate_tcp(0);
    let reply = authenticated_request(
        &mut net,
        "198.51.100.7:40000".parse().unwrap(),
        METHOD_CHANNEL_BIND,
        || {
            vec![
                Box::new(ChannelNumber(0x4001)),
                Box::new(PeerAddress {
                    ip: peer().ip(),
                    port: peer().port(),
                }),
            ]
        },
    );
    assert_eq!(reply.typ.class, CLASS_ERROR_RESPONSE);
    assert_eq!(error_code_of(&reply), 400, "a channel carries datagrams");
}

#[test]
fn a_tcp_allocation_does_not_take_udp_port_options() {
    use crate::proto::evenport::EvenPort;
    use crate::proto::reqtrans::RequestedTransport;

    let mut net = Net::new();
    let reply = authenticated_request(
        &mut net,
        "198.51.100.7:40000".parse().unwrap(),
        METHOD_ALLOCATE,
        || {
            vec![
                Box::new(RequestedTransport {
                    protocol: crate::proto::PROTO_TCP,
                }),
                Box::new(EvenPort::new(false)),
            ]
        },
    );
    assert_eq!(reply.typ.class, CLASS_ERROR_RESPONSE);
    assert_eq!(
        error_code_of(&reply),
        400,
        "an even port names a datagram port"
    );
    assert_eq!(net.server.allocation_count(), 0);
}

#[test]
fn an_allocation_holds_a_bounded_number_of_peer_connections() {
    use super::MAX_PEER_CONNECTIONS_PER_ALLOCATION as MAX;
    let mut net = Net::new();
    net.allocate_tcp(0);
    // Peers connecting in count too: permit a peer, then fill the allocation with its connections.
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .create_permission(net.now, peer())
        .unwrap();
    net.pump();
    for _ in 0..MAX {
        assert!(
            net.server
                .peer_accepted(relay_addr(), peer(), net.now)
                .is_some()
        );
    }
    assert_eq!(net.server.peer_connection_count(), MAX);
    assert!(
        net.server
            .peer_accepted(relay_addr(), peer(), net.now)
            .is_none(),
        "one connection too many is refused"
    );

    // So is a Connect.
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .connect(net.now, "203.0.113.20:6000".parse().unwrap())
        .unwrap();
    net.pump();
    let error = net.client_error(0).expect("the connect is refused");
    assert!(error.contains("486"), "allocation quota reached: {error}");
    assert!(net.pending_connect().is_none());

    // Closing one makes room.
    let any = net.server.peer_connection_ids().next().unwrap();
    net.server.peer_closed(any);
    assert!(
        net.server
            .peer_accepted(relay_addr(), peer(), net.now)
            .is_some()
    );
}

#[test]
fn a_datagram_addressed_to_a_tcp_relay_is_dropped() {
    let mut net = Net::new();
    net.allocate_tcp(0);
    net.clients[0]
        .relay(relay_addr_advertised())
        .unwrap()
        .create_permission(net.now, peer())
        .unwrap();
    net.pump();
    // A host that misroutes a UDP datagram for the relay address must not turn it into a Data
    // indication to the client.
    net.server
        .handle_read(TaggedBytesMut {
            now: net.now,
            transport: TransportContext {
                local_addr: relay_addr(),
                peer_addr: peer(),
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&b"unexpected"[..]),
        })
        .unwrap();
    assert!(net.server.poll_write().is_none());
}
