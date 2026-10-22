use super::*;
use crate::client::{Client, ClientConfig, Event};
use crate::proto::channum::ChannelNumber;
use crate::proto::data::Data;
use crate::proto::evenport::EvenPort;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::PeerAddress;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqfamily::{REQUESTED_FAMILY_IPV6, RequestedAddressFamily};
use crate::proto::reqtrans::RequestedTransport;
use crate::proto::rsrvtoken::ReservationToken;
use crate::proto::{PROTO_TCP, PROTO_UDP};
use sansio::Protocol;
use shared::TransportProtocol;
use std::net::Ipv4Addr;
use stun::attributes::*;
use stun::error_code::*;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::*;
use stun::textattrs::TextAttribute;
use stun::uattrs::UnknownAttributes;
use stun::xoraddr::XorMappedAddress;

const REALM: &str = "webrtc.rs";

fn crypto_provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn server_addr() -> SocketAddr {
    "192.0.2.1:3478".parse().unwrap()
}

fn client_addr() -> SocketAddr {
    "198.51.100.7:40000".parse().unwrap()
}

fn peer_addr() -> SocketAddr {
    "203.0.113.9:6000".parse().unwrap()
}

fn relay_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))
}

fn users() -> Arc<dyn AuthHandler> {
    Arc::new(|req: &AuthRequest<'_>| {
        let password = match req.username {
            "user" => "pass",
            "other" => "pw2",
            _ => return None,
        };
        let provider = crypto_provider();
        Some(AuthCredentials {
            user_id: req.username.to_owned(),
            key: generate_auth_key(req.username, req.realm, password, provider.crypto()).ok()?,
        })
    })
}

fn static_generator() -> Box<dyn RelayAddressGenerator> {
    Box::new(RelayAddressGeneratorStatic {
        relay_address: relay_ip(),
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
    })
}

/// How the pretend application treats `BindRelay`.
#[derive(Clone, Copy, PartialEq)]
enum Binding {
    Succeed,
    Fail,
    Ignore,
}

/// A server on an in-memory network: a clock, a client address, a peer, and relay sockets that
/// the harness "binds" on the server's behalf.
struct Net {
    server: Server,
    base: Instant,
    now: Instant,
    binding: Binding,
    next_port: u16,
    events: Vec<ServerEvent>,
    /// What the server sent out of a relay socket: (relay, peer, payload).
    to_peers: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// What the server sent to the client, not yet read.
    to_client: Vec<Vec<u8>>,
}

impl Net {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(tweak: impl FnOnce(&mut ServerConfig)) -> Self {
        let base = Instant::now();
        let mut config = ServerConfig::new(REALM, users(), static_generator(), crypto_provider());
        config.software = "turn-test".to_owned();
        tweak(&mut config);
        Self {
            server: Server::new(config, base).unwrap(),
            base,
            now: base,
            binding: Binding::Succeed,
            next_port: 50000,
            events: Vec::new(),
            to_peers: Vec::new(),
            to_client: Vec::new(),
        }
    }

    fn ctx(&self, local: SocketAddr, peer: SocketAddr) -> TransportContext {
        TransportContext {
            local_addr: local,
            peer_addr: peer,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        }
    }

    fn deliver(&mut self, from: SocketAddr, bytes: &[u8]) {
        self.deliver_to(server_addr(), from, bytes);
    }

    fn deliver_to(&mut self, local: SocketAddr, from: SocketAddr, bytes: &[u8]) {
        let msg = TaggedBytesMut {
            now: self.now,
            transport: self.ctx(local, from),
            message: BytesMut::from(bytes),
        };
        self.server.handle_read(msg).unwrap();
        self.settle();
    }

    /// Acts on the server's events and collects what it sent.
    fn settle(&mut self) {
        while let Some(event) = self.server.poll_event() {
            if let ServerEvent::BindRelay { id, plan } = &event {
                match self.binding {
                    Binding::Succeed => {
                        let port = self.next_port;
                        self.next_port += 1;
                        let local = SocketAddr::new(plan.bind.ip(), port);
                        self.server.relay_bound(*id, local, self.now);
                    }
                    Binding::Fail => self.server.relay_bind_failed(*id, self.now),
                    Binding::Ignore => {}
                }
            }
            self.events.push(event);
        }
        while let Some(out) = self.server.poll_write() {
            if out.transport.local_addr == server_addr() {
                assert_eq!(out.transport.peer_addr, client_addr());
                self.to_client.push(out.message.to_vec());
            } else {
                self.to_peers.push((
                    out.transport.local_addr,
                    out.transport.peer_addr,
                    out.message.to_vec(),
                ));
            }
        }
        // Binding a relay answers a request, which may itself raise more events.
        if self.server.poll_timeout().is_none() && self.server.events.is_empty() {
            return;
        }
        while let Some(event) = self.server.poll_event() {
            self.events.push(event);
        }
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        self.server.handle_timeout(self.now).unwrap();
        self.settle();
    }

    fn take_client_message(&mut self) -> Message {
        assert!(
            !self.to_client.is_empty(),
            "the server sent the client nothing"
        );
        let raw = self.to_client.remove(0);
        let mut m = Message::new();
        m.raw = raw;
        m.decode().unwrap();
        m
    }

    fn assert_silent(&self) {
        assert!(
            self.to_client.is_empty(),
            "the server unexpectedly answered the client"
        );
    }

    /// Sends `request` from the client and returns the server's answer.
    fn exchange(&mut self, request: &Message) -> Message {
        self.deliver(client_addr(), &request.raw);
        self.take_client_message()
    }

    fn nonce(&mut self) -> String {
        let probe = request(METHOD_ALLOCATE, vec![Box::new(udp())]);
        let response = self.exchange(&probe);
        TextAttribute::get_from_as(&response, ATTR_NONCE)
            .unwrap()
            .text
    }

    /// A request signed as `user` with the nonce the server handed out.
    fn signed(
        &mut self,
        user: &str,
        pass: &str,
        method: Method,
        extra: Vec<Box<dyn Setter>>,
    ) -> Message {
        let nonce = self.nonce();
        signed_request(user, pass, REALM, &nonce, method, extra)
    }

    fn allocate_raw(&mut self) -> Message {
        let req = self.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
        self.exchange(&req)
    }

    fn relayed_addr_of(response: &Message) -> SocketAddr {
        let mut relayed = RelayedAddress::default();
        relayed.get_from(response).unwrap();
        SocketAddr::new(relayed.ip, relayed.port)
    }
}

fn udp() -> RequestedTransport {
    RequestedTransport {
        protocol: PROTO_UDP,
    }
}

fn request(method: Method, extra: Vec<Box<dyn Setter>>) -> Message {
    let mut m = Message::new();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(method, CLASS_REQUEST)),
    ];
    setters.extend(extra);
    setters.push(Box::new(FINGERPRINT));
    m.build(&setters).unwrap();
    m
}

fn signed_request(
    user: &str,
    pass: &str,
    realm: &str,
    nonce: &str,
    method: Method,
    extra: Vec<Box<dyn Setter>>,
) -> Message {
    let provider = crypto_provider();
    let integrity = MessageIntegrity::new_long_term_integrity_with_provider(
        user.to_owned(),
        realm.to_owned(),
        pass.to_owned(),
        provider.crypto(),
    )
    .unwrap();
    let mut m = Message::new();
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(method, CLASS_REQUEST)),
    ];
    for e in extra {
        setters.push(e);
    }
    setters.push(Box::new(TextAttribute::new(ATTR_USERNAME, user.to_owned())));
    setters.push(Box::new(TextAttribute::new(ATTR_REALM, realm.to_owned())));
    setters.push(Box::new(TextAttribute::new(ATTR_NONCE, nonce.to_owned())));
    setters.push(Box::new(integrity));
    setters.push(Box::new(FINGERPRINT));
    m.build(&setters).unwrap();
    m
}

fn error_code(m: &Message) -> u16 {
    assert_eq!(
        m.typ.class, CLASS_ERROR_RESPONSE,
        "expected an error response, got {}",
        m.typ
    );
    let mut code = ErrorCodeAttribute::default();
    code.get_from(m).unwrap();
    code.code.0
}

fn permission_request(peers: &[SocketAddr]) -> Vec<Box<dyn Setter>> {
    peers
        .iter()
        .map(|p| -> Box<dyn Setter> {
            Box::new(PeerAddress {
                ip: p.ip(),
                port: p.port(),
            })
        })
        .collect()
}

fn channel_bind_request(number: u16, peer: SocketAddr) -> Vec<Box<dyn Setter>> {
    vec![
        Box::new(ChannelNumber(number)),
        Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }),
    ]
}

fn send_indication(peer: SocketAddr, payload: &[u8]) -> Message {
    let mut m = Message::new();
    m.build(&[
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(METHOD_SEND, CLASS_INDICATION)),
        Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }),
        Box::new(Data(payload.to_vec())),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    m
}

fn channel_data(number: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = number.to_be_bytes().to_vec();
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// An allocation, a permission for the peer, and the relay it lives on.
fn allocated_with_permission(net: &mut Net) -> SocketAddr {
    let response = net.allocate_raw();
    assert_eq!(response.typ.class, CLASS_SUCCESS_RESPONSE);
    let relayed = Net::relayed_addr_of(&response);
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr()]),
    );
    assert_eq!(net.exchange(&req).typ.class, CLASS_SUCCESS_RESPONSE);
    relayed
}

fn local_relay(net: &Net) -> SocketAddr {
    let five = net.server.allocations().next().copied().unwrap();
    net.server.allocations[&five].relay
}

// ---------------------------------------------------------------------------------------------
// Binding

#[test]
fn binding_request_is_answered_with_the_clients_address() {
    let mut net = Net::new();
    let reply = net.exchange(&request(METHOD_BINDING, vec![]));
    assert_eq!(reply.typ, BINDING_SUCCESS);
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(&reply).unwrap();
    assert_eq!(SocketAddr::new(mapped.ip, mapped.port), client_addr());
}

#[test]
fn responses_carry_software_and_a_valid_fingerprint() {
    let mut net = Net::new();
    let reply = net.exchange(&request(METHOD_BINDING, vec![]));
    assert_eq!(
        TextAttribute::get_from_as(&reply, ATTR_SOFTWARE)
            .unwrap()
            .text,
        "turn-test"
    );
    stun::fingerprint::FINGERPRINT.check(&reply).unwrap();
}

#[test]
fn garbage_and_unknown_requests_do_not_disturb_the_server() {
    let mut net = Net::new();
    net.deliver(client_addr(), b"not a turn message at all");
    net.deliver(client_addr(), &[0, 1, 0, 200, 1, 2, 3]);
    net.deliver(client_addr(), &channel_data(0x4000, b"nobody"));
    net.assert_silent();
    // A request for a method the server does not have is a Bad Request.
    let reply = net.exchange(&request(METHOD_CONNECT, vec![]));
    assert_eq!(error_code(&reply), 400);
}

// ---------------------------------------------------------------------------------------------
// Authentication

#[test]
fn unauthenticated_allocate_is_challenged() {
    let mut net = Net::new();
    let reply = net.exchange(&request(METHOD_ALLOCATE, vec![Box::new(udp())]));
    assert_eq!(error_code(&reply), 401);
    assert_eq!(
        TextAttribute::get_from_as(&reply, ATTR_REALM).unwrap().text,
        REALM
    );
    assert!(
        !TextAttribute::get_from_as(&reply, ATTR_NONCE)
            .unwrap()
            .text
            .is_empty()
    );
    assert!(!reply.contains(ATTR_MESSAGE_INTEGRITY));
}

#[test]
fn wrong_password_is_rejected_and_reported() {
    let mut net = Net::new();
    let nonce = net.nonce();
    let req = signed_request(
        "user",
        "nope",
        REALM,
        &nonce,
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    assert_eq!(error_code(&net.exchange(&req)), 401);
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::AuthFailed { username, .. } if username == "user"
    )));
    assert_eq!(net.server.allocation_count(), 0);
}

#[test]
fn unknown_user_is_rejected() {
    let mut net = Net::new();
    let nonce = net.nonce();
    let req = signed_request(
        "mallory",
        "x",
        REALM,
        &nonce,
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    assert_eq!(error_code(&net.exchange(&req)), 401);
}

#[test]
fn wrong_realm_is_rejected() {
    let mut net = Net::new();
    let nonce = net.nonce();
    let req = signed_request(
        "user",
        "pass",
        "elsewhere",
        &nonce,
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    assert_eq!(error_code(&net.exchange(&req)), 401);
}

#[test]
fn a_forged_nonce_is_stale() {
    let mut net = Net::new();
    let req = signed_request(
        "user",
        "pass",
        REALM,
        "not-a-nonce",
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    let reply = net.exchange(&req);
    assert_eq!(error_code(&reply), 438);
    assert!(TextAttribute::get_from_as(&reply, ATTR_NONCE).is_ok());
}

#[test]
fn an_old_nonce_goes_stale() {
    let mut net = Net::new();
    let nonce = net.nonce();
    net.advance(Duration::from_secs(2 * 3600));
    let req = signed_request(
        "user",
        "pass",
        REALM,
        &nonce,
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    assert_eq!(error_code(&net.exchange(&req)), 438);
}

#[test]
fn integrity_without_username_is_a_bad_request() {
    let mut net = Net::new();
    let provider = crypto_provider();
    let integrity =
        MessageIntegrity::new_raw_integrity_with_provider(b"k".to_vec(), provider.crypto());
    let mut m = Message::new();
    m.build(&[
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
        Box::new(udp()),
        Box::new(integrity),
    ])
    .unwrap();
    assert_eq!(error_code(&net.exchange(&m)), 400);
}

// ---------------------------------------------------------------------------------------------
// Allocate

#[test]
fn allocate_binds_a_relay_then_answers() {
    let mut net = Net::new();
    net.binding = Binding::Ignore;
    let req = net.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
    net.deliver(client_addr(), &req.raw);
    // The request waits for the application.
    net.assert_silent();
    let (id, plan) = net
        .events
        .iter()
        .find_map(|e| match e {
            ServerEvent::BindRelay { id, plan } => Some((*id, *plan)),
            _ => None,
        })
        .expect("a relay to bind");
    assert_eq!(plan.advertised_ip, relay_ip());

    net.server
        .relay_bound(id, SocketAddr::new(plan.bind.ip(), 51234), net.now);
    net.settle();
    let reply = net.take_client_message();
    assert_eq!(reply.typ, ALLOCATE_SUCCESS_FOR_TEST);
    // Peers are told the advertised address with the socket's port.
    assert_eq!(
        Net::relayed_addr_of(&reply),
        SocketAddr::new(relay_ip(), 51234)
    );
    let mut lifetime = Lifetime::default();
    lifetime.get_from(&reply).unwrap();
    assert_eq!(lifetime.0, DEFAULT_LIFETIME);
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(&reply).unwrap();
    assert_eq!(SocketAddr::new(mapped.ip, mapped.port), client_addr());
    assert!(reply.contains(ATTR_MESSAGE_INTEGRITY));
    assert_eq!(net.server.allocation_count(), 1);
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::AllocationCreated { user_id, .. } if user_id == "user"
    )));
}

const ALLOCATE_SUCCESS_FOR_TEST: MessageType = MessageType {
    method: METHOD_ALLOCATE,
    class: CLASS_SUCCESS_RESPONSE,
};

#[test]
fn a_retransmitted_allocate_gets_the_same_answer() {
    let mut net = Net::new();
    let req = net.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
    let first = net.exchange(&req);
    let again = net.exchange(&req);
    assert_eq!(first.typ.class, CLASS_SUCCESS_RESPONSE);
    assert_eq!(Net::relayed_addr_of(&first), Net::relayed_addr_of(&again));
    assert_eq!(net.server.allocation_count(), 1);
}

#[test]
fn a_second_allocate_on_the_same_five_tuple_is_a_mismatch() {
    let mut net = Net::new();
    assert_eq!(net.allocate_raw().typ.class, CLASS_SUCCESS_RESPONSE);
    assert_eq!(error_code(&net.allocate_raw()), 437);
    assert_eq!(net.server.allocation_count(), 1);
}

#[test]
fn allocate_while_pending_is_a_mismatch_but_a_retransmission_is_quiet() {
    let mut net = Net::new();
    net.binding = Binding::Ignore;
    let first = net.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
    net.deliver(client_addr(), &first.raw);
    net.deliver(client_addr(), &first.raw);
    net.assert_silent();
    let second = net.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
    net.deliver(client_addr(), &second.raw);
    assert_eq!(error_code(&net.take_client_message()), 437);
    let binds = net
        .events
        .iter()
        .filter(|e| matches!(e, ServerEvent::BindRelay { .. }))
        .count();
    assert_eq!(binds, 1, "a retransmission must not bind a second relay");
}

#[test]
fn allocate_needs_a_transport_and_it_must_be_udp() {
    let mut net = Net::new();
    let req = net.signed("user", "pass", METHOD_ALLOCATE, vec![]);
    assert_eq!(error_code(&net.exchange(&req)), 400);
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(RequestedTransport {
            protocol: PROTO_TCP,
        })],
    );
    assert_eq!(error_code(&net.exchange(&req)), 442);
}

#[test]
fn dont_fragment_is_refused_by_name() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![
            Box::new(udp()),
            Box::new(crate::proto::dontfrag::DontFragmentAttr),
        ],
    );
    let reply = net.exchange(&req);
    assert_eq!(error_code(&reply), 420);
    let mut unknown = UnknownAttributes(vec![]);
    unknown.get_from(&reply).unwrap();
    assert_eq!(unknown.0, vec![ATTR_DONT_FRAGMENT]);
}

struct RawAttr(AttrType, Vec<u8>);

impl Setter for RawAttr {
    fn add_to(&self, m: &mut Message) -> shared::error::Result<()> {
        m.add(self.0, &self.1);
        Ok(())
    }
}

#[test]
fn an_unknown_comprehension_required_attribute_is_refused_but_optional_ones_are_not() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![
            Box::new(udp()),
            Box::new(RawAttr(AttrType(0x00f1), vec![1, 2, 3, 4])),
        ],
    );
    let reply = net.exchange(&req);
    assert_eq!(error_code(&reply), 420);
    let mut unknown = UnknownAttributes(vec![]);
    unknown.get_from(&reply).unwrap();
    assert_eq!(unknown.0, vec![AttrType(0x00f1)]);

    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![
            Box::new(udp()),
            Box::new(RawAttr(AttrType(0x80f1), vec![1, 2, 3, 4])),
        ],
    );
    assert_eq!(net.exchange(&req).typ.class, CLASS_SUCCESS_RESPONSE);
}

#[test]
fn reservation_tokens_are_never_valid() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(ReservationToken(vec![7; 8]))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 508);
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![
            Box::new(udp()),
            Box::new(ReservationToken(vec![7; 8])),
            Box::new(EvenPort::new(false)),
        ],
    );
    assert_eq!(error_code(&net.exchange(&req)), 400);
}

#[test]
fn even_port_is_honoured_by_a_generator_that_can_choose() {
    let mut net = Net::with(|config| {
        config.relay_address_generator = Box::new(RelayAddressGeneratorPortRange {
            relay_address: relay_ip(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            min_port: 50000,
            max_port: 50100,
        });
    });
    net.binding = Binding::Ignore;
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(EvenPort::new(false))],
    );
    net.deliver(client_addr(), &req.raw);
    let plan = net
        .events
        .iter()
        .find_map(|e| match e {
            ServerEvent::BindRelay { plan, .. } => Some(*plan),
            _ => None,
        })
        .unwrap();
    assert_eq!(plan.bind.port() % 2, 0);
    assert!((50000..=50100).contains(&plan.bind.port()));
}

#[test]
fn reserving_the_next_port_is_refused_not_ignored() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(EvenPort::new(true))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 508);
}

#[test]
fn a_generator_that_cannot_pick_even_ports_means_insufficient_capacity() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(EvenPort::new(false))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 508);
}

#[test]
fn an_ipv6_relay_is_refused_when_only_ipv4_is_offered() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(REQUESTED_FAMILY_IPV6)],
    );
    assert_eq!(error_code(&net.exchange(&req)), 440);
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(RequestedAddressFamily(0x09))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 440);
}

#[test]
fn an_ipv6_relay_is_planned_when_offered() {
    let v6: IpAddr = "2001:db8::50".parse().unwrap();
    let mut net = Net::with(|config| {
        config.relay_address_generator = Box::new(RelayAddressGeneratorNone { address: v6 });
    });
    net.binding = Binding::Ignore;
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(REQUESTED_FAMILY_IPV6)],
    );
    net.deliver(client_addr(), &req.raw);
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::BindRelay { plan, .. } if plan.advertised_ip == v6
    )));
}

#[test]
fn the_quota_handler_limits_allocations() {
    let mut net = Net::with(|config| {
        config.quota_handler = Some(Arc::new(|_: &str, _: &str, _: SocketAddr| false));
    });
    assert_eq!(error_code(&net.allocate_raw()), 486);
}

#[test]
fn a_requested_lifetime_is_granted_up_to_the_maximum() {
    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![Box::new(udp()), Box::new(Lifetime(Duration::from_secs(30)))],
    );
    let reply = net.exchange(&req);
    let mut lifetime = Lifetime::default();
    lifetime.get_from(&reply).unwrap();
    assert_eq!(lifetime.0, Duration::from_secs(30));

    let mut net = Net::new();
    let req = net.signed(
        "user",
        "pass",
        METHOD_ALLOCATE,
        vec![
            Box::new(udp()),
            Box::new(Lifetime(Duration::from_secs(86_400))),
        ],
    );
    let reply = net.exchange(&req);
    lifetime.get_from(&reply).unwrap();
    assert_eq!(lifetime.0, MAX_ALLOCATION_LIFETIME);
}

#[test]
fn the_application_failing_to_bind_means_insufficient_capacity() {
    let mut net = Net::new();
    net.binding = Binding::Fail;
    assert_eq!(error_code(&net.allocate_raw()), 508);
    assert_eq!(net.server.allocation_count(), 0);
    // And the client may simply try again.
    net.binding = Binding::Succeed;
    assert_eq!(net.allocate_raw().typ.class, CLASS_SUCCESS_RESPONSE);
}

#[test]
fn a_relay_that_is_never_bound_times_out_and_a_late_bind_is_released() {
    let mut net = Net::new();
    net.binding = Binding::Ignore;
    let req = net.signed("user", "pass", METHOD_ALLOCATE, vec![Box::new(udp())]);
    net.deliver(client_addr(), &req.raw);
    let id = net
        .events
        .iter()
        .find_map(|e| match e {
            ServerEvent::BindRelay { id, .. } => Some(*id),
            _ => None,
        })
        .unwrap();
    net.advance(Duration::from_secs(6));
    assert_eq!(error_code(&net.take_client_message()), 508);
    net.events.clear();

    let late: SocketAddr = "127.0.0.1:51999".parse().unwrap();
    net.server.relay_bound(id, late, net.now);
    net.settle();
    assert!(net.events.contains(&ServerEvent::ReleaseRelay(late)));
    assert_eq!(net.server.allocation_count(), 0);
}

// ---------------------------------------------------------------------------------------------
// Refresh and expiry

#[test]
fn refresh_extends_the_allocation() {
    let mut net = Net::new();
    net.allocate_raw();
    net.advance(Duration::from_secs(9 * 60));
    let req = net.signed("user", "pass", METHOD_REFRESH, vec![]);
    let reply = net.exchange(&req);
    assert_eq!(reply.typ.class, CLASS_SUCCESS_RESPONSE);
    let mut lifetime = Lifetime::default();
    lifetime.get_from(&reply).unwrap();
    assert_eq!(lifetime.0, DEFAULT_LIFETIME);
    // Past the original expiry, still there.
    net.advance(Duration::from_secs(5 * 60));
    assert_eq!(net.server.allocation_count(), 1);
    net.advance(Duration::from_secs(6 * 60));
    assert_eq!(net.server.allocation_count(), 0);
}

#[test]
fn an_allocation_expires_without_a_refresh() {
    let mut net = Net::new();
    net.allocate_raw();
    let relay = local_relay(&net);
    net.advance(DEFAULT_LIFETIME - Duration::from_secs(1));
    assert_eq!(net.server.allocation_count(), 1);
    net.advance(Duration::from_secs(2));
    assert_eq!(net.server.allocation_count(), 0);
    assert!(net.events.contains(&ServerEvent::ReleaseRelay(relay)));
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::AllocationDeleted {
            reason: AllocationEnd::Expired,
            ..
        }
    )));
}

#[test]
fn refresh_with_zero_deletes() {
    let mut net = Net::new();
    net.allocate_raw();
    let relay = local_relay(&net);
    let req = net.signed(
        "user",
        "pass",
        METHOD_REFRESH,
        vec![Box::new(Lifetime(Duration::ZERO))],
    );
    let reply = net.exchange(&req);
    assert_eq!(reply.typ.class, CLASS_SUCCESS_RESPONSE);
    assert_eq!(net.server.allocation_count(), 0);
    assert!(net.events.contains(&ServerEvent::ReleaseRelay(relay)));
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::AllocationDeleted {
            reason: AllocationEnd::Deleted,
            ..
        }
    )));
}

#[test]
fn requests_without_an_allocation_are_mismatches() {
    let mut net = Net::new();
    for (method, extra) in [
        (METHOD_REFRESH, vec![]),
        (METHOD_CREATE_PERMISSION, permission_request(&[peer_addr()])),
        (
            METHOD_CHANNEL_BIND,
            channel_bind_request(0x4000, peer_addr()),
        ),
    ] {
        let req = net.signed("user", "pass", method, extra);
        assert_eq!(error_code(&net.exchange(&req)), 437, "{method}");
    }
}

#[test]
fn another_user_cannot_touch_an_allocation() {
    let mut net = Net::new();
    net.allocate_raw();
    let req = net.signed(
        "other",
        "pw2",
        METHOD_REFRESH,
        vec![Box::new(Lifetime(Duration::ZERO))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 441);
    assert_eq!(net.server.allocation_count(), 1);
}

// ---------------------------------------------------------------------------------------------
// Permissions and data

#[test]
fn a_permissioned_peer_can_be_sent_to_with_a_send_indication() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    let relay = local_relay(&net);
    net.deliver(client_addr(), &send_indication(peer_addr(), b"hello").raw);
    assert_eq!(net.to_peers, vec![(relay, peer_addr(), b"hello".to_vec())]);
}

#[test]
fn a_send_indication_without_permission_is_dropped() {
    let mut net = Net::new();
    net.allocate_raw();
    net.deliver(client_addr(), &send_indication(peer_addr(), b"hello").raw);
    assert!(net.to_peers.is_empty());
    // Permission is for the peer's IP, so another peer elsewhere stays blocked.
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr()]),
    );
    net.exchange(&req);
    let stranger: SocketAddr = "203.0.113.77:6000".parse().unwrap();
    net.deliver(client_addr(), &send_indication(stranger, b"hello").raw);
    assert!(net.to_peers.is_empty());
}

#[test]
fn permission_is_per_ip_not_per_port() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    let other_port = SocketAddr::new(peer_addr().ip(), 7777);
    net.deliver(client_addr(), &send_indication(other_port, b"hi").raw);
    assert_eq!(net.to_peers.len(), 1);
}

#[test]
fn a_send_indication_from_a_stranger_is_ignored() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    let stranger: SocketAddr = "198.51.100.99:1234".parse().unwrap();
    net.deliver(stranger, &send_indication(peer_addr(), b"hello").raw);
    assert!(net.to_peers.is_empty());
}

#[test]
fn permissions_expire() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    net.advance(PERMISSION_LIFETIME - Duration::from_secs(1));
    net.deliver(client_addr(), &send_indication(peer_addr(), b"one").raw);
    assert_eq!(net.to_peers.len(), 1);
    net.advance(Duration::from_secs(2));
    net.deliver(client_addr(), &send_indication(peer_addr(), b"two").raw);
    assert_eq!(net.to_peers.len(), 1, "the permission had lapsed");
}

#[test]
fn refreshing_a_permission_restarts_its_clock() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    net.advance(Duration::from_secs(4 * 60));
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr()]),
    );
    net.exchange(&req);
    net.advance(Duration::from_secs(4 * 60));
    net.deliver(client_addr(), &send_indication(peer_addr(), b"still").raw);
    assert_eq!(net.to_peers.len(), 1);
}

#[test]
fn create_permission_needs_a_peer() {
    let mut net = Net::new();
    net.allocate_raw();
    let req = net.signed("user", "pass", METHOD_CREATE_PERMISSION, vec![]);
    assert_eq!(error_code(&net.exchange(&req)), 400);
}

#[test]
fn create_permission_is_all_or_nothing() {
    let mut net = Net::new();
    net.allocate_raw();
    let v6: SocketAddr = "[2001:db8::9]:5000".parse().unwrap();
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr(), v6]),
    );
    assert_eq!(error_code(&net.exchange(&req)), 443);
    net.deliver(client_addr(), &send_indication(peer_addr(), b"x").raw);
    assert!(
        net.to_peers.is_empty(),
        "the acceptable peer must not be installed either"
    );
}

#[test]
fn create_permission_takes_several_peers() {
    let mut net = Net::new();
    net.allocate_raw();
    let second: SocketAddr = "203.0.113.10:1".parse().unwrap();
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr(), second]),
    );
    assert_eq!(net.exchange(&req).typ.class, CLASS_SUCCESS_RESPONSE);
    net.deliver(client_addr(), &send_indication(peer_addr(), b"a").raw);
    net.deliver(client_addr(), &send_indication(second, b"b").raw);
    assert_eq!(net.to_peers.len(), 2);
}

#[test]
fn the_permission_handler_can_forbid_peers() {
    let mut net = Net::with(|config| {
        config.permission_handler = Some(Arc::new(|_: SocketAddr, peer: IpAddr| {
            peer != peer_addr().ip()
        }));
    });
    net.allocate_raw();
    let req = net.signed(
        "user",
        "pass",
        METHOD_CREATE_PERMISSION,
        permission_request(&[peer_addr()]),
    );
    assert_eq!(error_code(&net.exchange(&req)), 403);
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        channel_bind_request(0x4000, peer_addr()),
    );
    assert_eq!(error_code(&net.exchange(&req)), 403);
}

#[test]
fn data_from_a_permissioned_peer_reaches_the_client_as_a_data_indication() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    let relay = local_relay(&net);
    net.deliver_to(relay, peer_addr(), b"from peer");
    assert_eq!(net.to_client.len(), 1);
    let m = {
        let raw = net.to_client.remove(0);
        let mut m = Message::new();
        m.raw = raw;
        m.decode().unwrap();
        m
    };
    assert_eq!(m.typ, MessageType::new(METHOD_DATA, CLASS_INDICATION));
    let mut peer = PeerAddress::default();
    peer.get_from(&m).unwrap();
    assert_eq!(SocketAddr::new(peer.ip, peer.port), peer_addr());
    let mut data = Data::default();
    data.get_from(&m).unwrap();
    assert_eq!(data.0, b"from peer");
}

#[test]
fn data_from_a_peer_without_permission_is_dropped() {
    let mut net = Net::new();
    net.allocate_raw();
    let relay = local_relay(&net);
    net.deliver_to(relay, peer_addr(), b"unwelcome");
    net.assert_silent();
}

// ---------------------------------------------------------------------------------------------
// Channels

fn bound_channel(net: &mut Net, number: u16) {
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        channel_bind_request(number, peer_addr()),
    );
    assert_eq!(net.exchange(&req).typ.class, CLASS_SUCCESS_RESPONSE);
}

#[test]
fn channel_data_flows_both_ways_once_bound() {
    let mut net = Net::new();
    net.allocate_raw();
    bound_channel(&mut net, 0x4001);
    let relay = local_relay(&net);

    // Client -> peer. Binding a channel also permits the peer.
    net.deliver(client_addr(), &channel_data(0x4001, b"ping"));
    assert_eq!(net.to_peers, vec![(relay, peer_addr(), b"ping".to_vec())]);

    // Peer -> client, as ChannelData now.
    net.deliver_to(relay, peer_addr(), b"pong");
    assert_eq!(net.to_client.len(), 1);
    assert_eq!(net.to_client[0], channel_data(0x4001, b"pong"));
}

#[test]
fn channel_data_over_tcp_is_padded() {
    let mut net = Net::new();
    net.allocate_raw();
    bound_channel(&mut net, 0x4001);
    let relay = local_relay(&net);
    // Re-do it over TCP: a separate five-tuple with its own allocation.
    let mut tcp_ctx = net.ctx(server_addr(), client_addr());
    tcp_ctx.transport_protocol = TransportProtocol::TCP;
    let nonce = net.nonce();
    let req = signed_request(
        "user",
        "pass",
        REALM,
        &nonce,
        METHOD_ALLOCATE,
        vec![Box::new(udp())],
    );
    net.server
        .handle_read(TaggedBytesMut {
            now: net.now,
            transport: tcp_ctx,
            message: BytesMut::from(&req.raw[..]),
        })
        .unwrap();
    net.settle();
    net.to_client.clear();
    assert_eq!(net.server.allocation_count(), 2);
    let tcp_five = net
        .server
        .allocations()
        .find(|f| f.protocol == TransportProtocol::TCP)
        .copied()
        .unwrap();
    let tcp_relay = net.server.allocations[&tcp_five].relay;
    assert_ne!(tcp_relay, relay);
    let nonce = net.nonce();
    for msg in [
        signed_request(
            "user",
            "pass",
            REALM,
            &nonce,
            METHOD_CREATE_PERMISSION,
            permission_request(&[peer_addr()]),
        ),
        signed_request(
            "user",
            "pass",
            REALM,
            &nonce,
            METHOD_CHANNEL_BIND,
            channel_bind_request(0x4002, peer_addr()),
        ),
    ] {
        net.server
            .handle_read(TaggedBytesMut {
                now: net.now,
                transport: tcp_ctx,
                message: BytesMut::from(&msg.raw[..]),
            })
            .unwrap();
    }
    net.settle();
    net.to_client.clear();
    net.deliver_to(tcp_relay, peer_addr(), b"abc");
    // Four-byte header, three bytes of payload, one byte of padding.
    assert_eq!(
        net.to_client[0],
        [0x40, 0x02, 0x00, 0x03, b'a', b'b', b'c', 0]
    );
}

#[test]
fn channel_numbers_are_validated() {
    let mut net = Net::new();
    net.allocate_raw();
    for number in [0x3fff, 0x8000, 0xffff, 0] {
        let req = net.signed(
            "user",
            "pass",
            METHOD_CHANNEL_BIND,
            channel_bind_request(number, peer_addr()),
        );
        assert_eq!(error_code(&net.exchange(&req)), 400, "channel {number:#x}");
    }
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        vec![Box::new(ChannelNumber(0x4000))],
    );
    assert_eq!(error_code(&net.exchange(&req)), 400);
}

#[test]
fn a_channel_and_a_peer_pair_up_one_to_one() {
    let mut net = Net::new();
    net.allocate_raw();
    bound_channel(&mut net, 0x4000);
    let other: SocketAddr = "203.0.113.20:9".parse().unwrap();
    // The number is taken by another peer.
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        channel_bind_request(0x4000, other),
    );
    assert_eq!(error_code(&net.exchange(&req)), 400);
    // The peer already has another number.
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        channel_bind_request(0x4001, peer_addr()),
    );
    assert_eq!(error_code(&net.exchange(&req)), 400);
    // Rebinding the same pair is a refresh.
    bound_channel(&mut net, 0x4000);
}

#[test]
fn a_channel_lapses_and_can_then_be_rebound_elsewhere() {
    // Longer-lived than the channel, so the allocation is still there when it lapses.
    let mut net =
        Net::with(|config| config.default_allocation_lifetime = Duration::from_secs(3600));
    net.allocate_raw();
    bound_channel(&mut net, 0x4000);
    net.advance(CHANNEL_BIND_LIFETIME + Duration::from_secs(1));
    let relay = local_relay(&net);
    net.deliver(client_addr(), &channel_data(0x4000, b"late"));
    assert!(net.to_peers.is_empty());
    let other: SocketAddr = "203.0.113.20:9".parse().unwrap();
    let req = net.signed(
        "user",
        "pass",
        METHOD_CHANNEL_BIND,
        channel_bind_request(0x4000, other),
    );
    assert_eq!(net.exchange(&req).typ.class, CLASS_SUCCESS_RESPONSE);
    net.deliver_to(relay, other, b"hi");
    assert_eq!(net.to_client[0], channel_data(0x4000, b"hi"));
}

#[test]
fn channel_data_on_an_unbound_channel_is_dropped() {
    let mut net = Net::new();
    allocated_with_permission(&mut net);
    net.deliver(client_addr(), &channel_data(0x4000, b"nope"));
    assert!(net.to_peers.is_empty());
}

#[test]
fn a_truncated_channel_data_message_is_dropped() {
    let mut net = Net::new();
    net.allocate_raw();
    bound_channel(&mut net, 0x4000);
    let mut truncated = channel_data(0x4000, b"abcdef");
    truncated.truncate(7);
    net.deliver(client_addr(), &truncated);
    assert!(net.to_peers.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Lifecycle

#[test]
fn delete_allocation_and_close_release_relays() {
    let mut net = Net::new();
    net.allocate_raw();
    let five = net.server.allocations().next().copied().unwrap();
    let relay = local_relay(&net);
    assert!(net.server.delete_allocation(&five));
    assert!(!net.server.delete_allocation(&five));
    net.settle();
    assert!(net.events.contains(&ServerEvent::ReleaseRelay(relay)));

    net.allocate_raw();
    net.events.clear();
    net.server.close().unwrap();
    net.settle();
    assert_eq!(net.server.allocation_count(), 0);
    assert!(net.events.iter().any(|e| matches!(
        e,
        ServerEvent::AllocationDeleted {
            reason: AllocationEnd::Closed,
            ..
        }
    )));
    assert!(net.server.poll_timeout().is_none());
}

#[test]
fn poll_timeout_tracks_the_next_deadline() {
    let mut net = Net::new();
    assert!(net.server.poll_timeout().is_none());
    allocated_with_permission(&mut net);
    // The permission (5 minutes) lapses before the allocation (10).
    let next = net.server.poll_timeout().unwrap();
    assert_eq!(next, net.base + PERMISSION_LIFETIME);
}

#[test]
fn a_relay_address_outside_the_family_is_rejected_by_validate() {
    let config = ServerConfig::new(
        REALM,
        users(),
        Box::new(RelayAddressGeneratorStatic {
            relay_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }),
        crypto_provider(),
    );
    assert!(Server::new(config, Instant::now()).is_err());
    let config = ServerConfig::new(
        String::new(),
        users(),
        static_generator(),
        crypto_provider(),
    );
    assert!(Server::new(config, Instant::now()).is_err());
}

// ---------------------------------------------------------------------------------------------
// Authentication helpers

#[test]
fn nonces_are_verifiable_and_expire() {
    let now = Instant::now();
    let manager = NonceManager::new(crypto_provider(), now);
    let nonce = manager.generate(now).unwrap();
    assert!(manager.validate(now, &nonce));
    assert!(manager.validate(now + Duration::from_secs(3599), &nonce));
    assert!(!manager.validate(now + Duration::from_secs(3601), &nonce));
    assert!(!manager.validate(now, "short"));
    let mut tampered = nonce.clone();
    tampered.replace_range(20..22, if &nonce[20..22] == "00" { "01" } else { "00" });
    assert!(!manager.validate(now, &tampered));
    // Another server's nonce is not ours.
    let other = NonceManager::new(crypto_provider(), now);
    assert!(!other.validate(now, &nonce));
}

#[test]
fn time_limited_credentials_work_until_they_expire() {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
    let make = |clock: Arc<std::sync::atomic::AtomicU64>| {
        LongTermCredentials::with_clock("secret", crypto_provider(), move || {
            clock.load(std::sync::atomic::Ordering::SeqCst)
        })
    };
    let issuer = make(clock.clone());
    let (username, password) = issuer.generate(Duration::from_secs(60)).unwrap();
    assert_eq!(username, "1000060");
    let handler = make(clock.clone()).auth_handler();
    fn request(username: &str) -> AuthRequest<'_> {
        AuthRequest {
            username,
            realm: REALM,
            src_addr: client_addr(),
            method: METHOD_ALLOCATE,
        }
    }
    let provider = crypto_provider();
    let expected = generate_auth_key(&username, REALM, &password, provider.crypto()).unwrap();
    let credentials = handler.auth(&request(&username)).unwrap();
    assert_eq!(credentials.key, expected);
    clock.store(1_000_061, std::sync::atomic::Ordering::SeqCst);
    assert!(handler.auth(&request(&username)).is_none());
    assert!(handler.auth(&request("not-a-number")).is_none());

    let (rest_user, _) = issuer
        .generate_rest("alice", Duration::from_secs(60))
        .unwrap();
    assert_eq!(rest_user, "1000121:alice");
    clock.store(1_000_000, std::sync::atomic::Ordering::SeqCst);
    let rest = make(clock).rest_auth_handler();
    assert_eq!(rest.auth(&request(&rest_user)).unwrap().user_id, "alice");
}

#[test]
fn relay_generators_plan_what_they_promise() {
    let v4 = relay_ip();
    let mut fixed = RelayAddressGeneratorStatic {
        relay_address: v4,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    fixed.validate().unwrap();
    let plan = fixed.plan(RelayFamily::V4, 0).unwrap();
    assert_eq!(plan.advertised_ip, v4);
    assert_eq!(plan.bind.port(), 0);
    assert!(fixed.plan(RelayFamily::V6, 0).is_err());
    assert!(fixed.plan_even(RelayFamily::V4).is_err());

    let mut ranged = RelayAddressGeneratorPortRange {
        relay_address: v4,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        min_port: 40000,
        max_port: 40010,
    };
    ranged.validate().unwrap();
    for _ in 0..200 {
        let port = ranged.plan(RelayFamily::V4, 0).unwrap().bind.port();
        assert!((40000..=40010).contains(&port));
        let even = ranged.plan_even(RelayFamily::V4).unwrap().bind.port();
        assert_eq!(even % 2, 0);
        assert!(
            (40000..40010).contains(&even),
            "the next port must be in range too"
        );
    }
    assert!(
        RelayAddressGeneratorPortRange {
            min_port: 5,
            max_port: 4,
            ..ranged
        }
        .validate()
        .is_err()
    );
}

// ---------------------------------------------------------------------------------------------
// End to end with the Rust client

struct ClientSide {
    client: Client,
}

impl ClientSide {
    fn new(user: &str, pass: &str) -> Self {
        let client = Client::new(
            ClientConfig {
                stun_serv_addr: String::new(),
                turn_serv_addr: server_addr().to_string(),
                local_addr: client_addr(),
                transport_protocol: TransportProtocol::UDP,
                username: user.to_owned(),
                password: pass.to_owned(),
                realm: String::new(),
                software: "rust-client".to_owned(),
                rto_in_ms: 200,
                allocation_refresh_interval_cap: None,
            },
            crypto_provider(),
        )
        .unwrap();
        Self { client }
    }

    /// Runs client and server against each other until neither has anything to say; returns the
    /// client's events.
    fn pump(&mut self, net: &mut Net) -> Vec<Event> {
        let mut events = Vec::new();
        for _ in 0..40 {
            let mut moved = false;
            while let Some(out) = self.client.poll_write() {
                moved = true;
                net.deliver(client_addr(), &out.message);
            }
            let inbox: Vec<Vec<u8>> = net.to_client.drain(..).collect();
            for raw in inbox {
                moved = true;
                self.client
                    .handle_read(TaggedBytesMut {
                        now: net.now,
                        transport: net.ctx(client_addr(), server_addr()),
                        message: BytesMut::from(&raw[..]),
                    })
                    .unwrap();
            }
            while let Some(event) = self.client.poll_event() {
                events.push(event);
            }
            if !moved {
                break;
            }
        }
        events
    }
}

fn allocate_with_client(net: &mut Net, side: &mut ClientSide) -> Result<SocketAddr> {
    side.client.allocate(net.now)?;
    for event in side.pump(net) {
        match event {
            Event::AllocateResponse(_, relayed) => return Ok(relayed),
            Event::AllocateError(_, err) => return Err(err),
            _ => {}
        }
    }
    Err(Error::Other("no answer".to_owned()))
}

#[test]
fn the_rust_client_allocates_through_the_server() {
    let mut net = Net::new();
    let mut side = ClientSide::new("user", "pass");
    let relayed = allocate_with_client(&mut net, &mut side).unwrap();
    assert_eq!(relayed.ip(), relay_ip());
    assert_eq!(net.server.allocation_count(), 1);
    assert_eq!(
        relayed,
        net.server
            .relayed_addr(&net.server.allocations().next().copied().unwrap())
            .unwrap()
    );
}

#[test]
fn the_rust_client_with_a_wrong_password_fails_to_allocate() {
    let mut net = Net::new();
    let mut side = ClientSide::new("user", "wrong");
    assert!(allocate_with_client(&mut net, &mut side).is_err());
    assert_eq!(net.server.allocation_count(), 0);
}

#[test]
fn the_rust_client_relays_data_to_and_from_a_peer() {
    let mut net = Net::new();
    let mut side = ClientSide::new("user", "pass");
    let relayed = allocate_with_client(&mut net, &mut side).unwrap();
    let relay = local_relay(&net);

    side.client
        .relay(relayed)
        .unwrap()
        .create_permission(net.now, peer_addr())
        .unwrap();
    let events = side.pump(&mut net);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::CreatePermissionResponse(_, p) if *p == peer_addr()))
    );

    // Client -> peer.
    side.client
        .relay(relayed)
        .unwrap()
        .send_to(net.now, b"hello peer", peer_addr())
        .unwrap();
    side.pump(&mut net);
    assert!(
        net.to_peers
            .iter()
            .any(|(from, to, data)| *from == relay && *to == peer_addr() && data == b"hello peer")
    );

    // Peer -> client. The client bound a channel after its first send, so by now it may arrive
    // either way; what matters is the bytes and the peer.
    net.deliver_to(relay, peer_addr(), b"hello client");
    let events = side.pump(&mut net);
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DataIndicationOrChannelData(_, peer, data) if *peer == peer_addr() && &data[..] == b"hello client"
    )));

    // Once the channel binding is in, traffic uses ChannelData both ways.
    side.client
        .relay(relayed)
        .unwrap()
        .send_to(net.now, b"again", peer_addr())
        .unwrap();
    side.pump(&mut net);
    net.deliver_to(relay, peer_addr(), b"and back");
    let events = side.pump(&mut net);
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DataIndicationOrChannelData(Some(_), peer, data) if *peer == peer_addr() && &data[..] == b"and back"
    )));
}

#[test]
fn the_rust_client_keeps_its_allocation_alive_by_refreshing() {
    let mut net = Net::new();
    let mut side = ClientSide::new("user", "pass");
    allocate_with_client(&mut net, &mut side).unwrap();
    for _ in 0..8 {
        // Advance to the client's next deadline and let both ends act on it.
        let next = side.client.poll_timeout().unwrap();
        net.now = next.max(net.now);
        net.server.handle_timeout(net.now).unwrap();
        side.client.handle_timeout(net.now).unwrap();
        side.pump(&mut net);
    }
    // Well past the first lifetime, the allocation survives because it was refreshed.
    assert!(net.now > net.base + DEFAULT_LIFETIME);
    assert_eq!(net.server.allocation_count(), 1);
}

#[test]
fn closing_the_rust_clients_relay_ends_the_allocation() {
    let mut net = Net::new();
    let mut side = ClientSide::new("user", "pass");
    let relayed = allocate_with_client(&mut net, &mut side).unwrap();
    side.client.relay(relayed).unwrap().close(net.now).unwrap();
    side.pump(&mut net);
    assert_eq!(net.server.allocation_count(), 0);
}
