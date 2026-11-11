//! A minimal nonblocking UDP host for the Sans-I/O TURN server.
//!
//! Run with `cargo run -p rtc-turn --example turn_server_udp -- --user alice=password`.
//! For remote clients, set --listen to an interface address and --public-ip to its advertised
//! address. Firewall the relay range and rate-limit the control listener before public use.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use rtc_turn::crypto::{RTCCryptoProvider, default_provider};
use rtc_turn::server::{AddressFamily, AllocationId, Authenticator, Event, Server, ServerConfig};
use shared::{TransportContext, TransportProtocol};
use stun::error_code::CODE_INSUFFICIENT_CAPACITY;
use stun::integrity::MessageIntegrity;

#[derive(Parser)]
#[command(about = "Host the Sans-I/O UDP TURN server on nonblocking std sockets")]
struct Options {
    #[arg(long, default_value = "127.0.0.1:3478")]
    listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1")]
    public_ip: IpAddr,
    #[arg(long, default_value = "webrtc.rs")]
    realm: String,
    #[arg(long, required = true, value_name = "USERNAME=PASSWORD")]
    user: Vec<String>,
    #[arg(long, default_value_t = 49152)]
    relay_min: u16,
    #[arg(long, default_value_t = 65535)]
    relay_max: u16,
    /// Explicitly permit private and loopback peers for development.
    #[arg(long)]
    allow_private_peers: bool,
}

struct Users {
    keys: HashMap<String, Vec<u8>>,
    allow_private: bool,
}

impl Authenticator for Users {
    fn credential_key(&self, username: &str, _realm: &str) -> Option<Vec<u8>> {
        self.keys.get(username).cloned()
    }

    fn allow_peer(&self, _username: &str, peer: SocketAddr) -> bool {
        if self.allow_private {
            return peer.port() != 0 && !peer.ip().is_unspecified() && !peer.ip().is_multicast();
        }
        // Use the trait's conservative default without duplicating it.
        struct PublicPeers;
        impl Authenticator for PublicPeers {
            fn credential_key(&self, _: &str, _: &str) -> Option<Vec<u8>> {
                None
            }
        }
        PublicPeers.allow_peer("", peer)
    }
}

fn bind_relay(options: &Options, family: AddressFamily) -> io::Result<UdpSocket> {
    if (family == AddressFamily::Ipv4) != options.public_ip.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "relay family unavailable",
        ));
    }
    // A wildcard relay can be advertised through a statically configured NAT mapping.
    let bind_ip: IpAddr = if family == AddressFamily::Ipv4 {
        "0.0.0.0"
    } else {
        "::"
    }
    .parse()
    .unwrap();
    for port in options.relay_min..=options.relay_max {
        match UdpSocket::bind(SocketAddr::new(bind_ip, port)) {
            Ok(socket) => {
                socket.set_nonblocking(true)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "relay range exhausted",
    ))
}

fn drain(
    server: &mut Server,
    listener: &UdpSocket,
    relays: &mut HashMap<AllocationId, UdpSocket>,
    options: &Options,
    now: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(event) = server.poll_event() {
        match event {
            Event::AllocateRelay {
                allocation_id,
                family,
                ..
            } => {
                match bind_relay(options, family) {
                    Ok(socket) => {
                        let address =
                            SocketAddr::new(options.public_ip, socket.local_addr()?.port());
                        // Retain ownership only after the core accepts completion.
                        if server
                            .complete_allocate(now, allocation_id, Ok(address))
                            .is_ok()
                        {
                            relays.insert(allocation_id, socket);
                        }
                    }
                    Err(_) => {
                        server.complete_allocate(
                            now,
                            allocation_id,
                            Err(CODE_INSUFFICIENT_CAPACITY),
                        )?;
                    }
                }
            }
            Event::ReleaseRelay { allocation_id } => {
                relays.remove(&allocation_id);
            }
            Event::SendToClient { transport, data } => {
                if let Err(error) = listener.send_to(&data, transport.peer_addr) {
                    eprintln!("Control datagram send failed: {error}");
                }
            }
            Event::SendToPeer {
                allocation_id,
                peer,
                data,
            } => {
                // Other allocations are valid peers when both clients use this TURN server.
                // Reject the listener and this allocation's own relay endpoint only.
                if peer == options.listen
                    || peer == SocketAddr::new(options.public_ip, listener.local_addr()?.port())
                    || relays.get(&allocation_id).is_some_and(|socket| {
                        socket.local_addr().is_ok_and(|address| {
                            SocketAddr::new(options.public_ip, address.port()) == peer
                        })
                    })
                {
                    continue;
                }
                if let Some(socket) = relays.get(&allocation_id)
                    && let Err(error) = socket.send_to(&data, peer)
                {
                    eprintln!("Relay datagram send failed: {error}");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn credentials(
    options: &Options,
    provider: &dyn RTCCryptoProvider,
) -> Result<Users, Box<dyn std::error::Error>> {
    let mut keys = HashMap::new();
    for entry in &options.user {
        let (username, password) = entry.split_once('=').ok_or("expected USERNAME=PASSWORD")?;
        if username.is_empty()
            || password.is_empty()
            || !username.is_ascii()
            || !password.is_ascii()
            || options.realm.is_empty()
            || !options.realm.is_ascii()
        {
            return Err(
                "example credentials require nonempty ASCII username, password and realm".into(),
            );
        }
        keys.insert(
            username.into(),
            MessageIntegrity::long_term_integrity_key(
                username.into(),
                options.realm.clone(),
                password.into(),
                provider.crypto(),
            )?,
        );
    }
    Ok(Users {
        keys,
        allow_private: options.allow_private_peers,
    })
}

// An unconnected UDP socket can report an asynchronous error for a previous send
// to an unreachable endpoint (notably WSAECONNRESET on Windows):
// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
// Yield this socket's
// work budget, rather than retrying immediately or terminating unrelated clients.
fn received_datagram(
    received: io::Result<(usize, SocketAddr)>,
) -> io::Result<Option<(usize, SocketAddr)>> {
    match received {
        Ok(datagram) => Ok(Some(datagram)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
            ) =>
        {
            eprintln!("UDP endpoint receive error: {error}");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn poll_sockets(
    server: &mut Server,
    listener: &UdpSocket,
    relays: &mut HashMap<AllocationId, UdpSocket>,
    options: &Options,
    now: Instant,
    buffer: &mut [u8],
    mut receive: impl FnMut(&UdpSocket, &mut [u8]) -> io::Result<(usize, SocketAddr)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener_address = listener.local_addr()?;
    // Bound work per iteration so a busy listener cannot starve relay sockets or timers.
    for _ in 0..64 {
        match received_datagram(receive(listener, buffer)) {
            Ok(Some((length, peer_addr))) => {
                let transport = TransportContext {
                    local_addr: listener_address,
                    peer_addr,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                };
                if let Err(error) = server.handle_datagram(now, transport, &buffer[..length]) {
                    eprintln!("Control datagram discarded: {error}");
                }
                drain(server, listener, relays, options, now)?;
            }
            Ok(None) => break,
            Err(error) => return Err(error.into()),
        }
    }
    let ids: Vec<_> = relays.keys().copied().collect();
    for id in ids {
        for _ in 0..16 {
            let received = relays
                .get(&id)
                .map(|socket| received_datagram(receive(socket, buffer)));
            match received {
                Some(Ok(Some((length, peer)))) => {
                    server.handle_peer_data(now, id, peer, &buffer[..length])?;
                    drain(server, listener, relays, options, now)?;
                }
                Some(Ok(None)) => break,
                Some(Err(error)) => {
                    eprintln!("Relay {id:?} receive failed; closing allocation: {error}");
                    server.close_allocation(id);
                    drain(server, listener, relays, options, now)?;
                    break;
                }
                None => break,
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    if options.relay_min == 0 || options.relay_min > options.relay_max {
        return Err("invalid relay port range".into());
    }
    let provider: Arc<dyn RTCCryptoProvider> = default_provider()?;
    let users = credentials(&options, provider.as_ref())?;
    let listener = UdpSocket::bind(options.listen)?;
    listener.set_nonblocking(true)?;
    let listener_address = listener.local_addr()?;
    let mut server = Server::new(
        ServerConfig {
            realm: options.realm.clone(),
            ..Default::default()
        },
        Arc::new(users),
        provider,
        Instant::now(),
    )?;
    let running = Arc::new(AtomicBool::new(true));
    let signal = running.clone();
    ctrlc::set_handler(move || {
        signal.store(false, Ordering::Relaxed);
    })?;
    let mut relays = HashMap::new();
    let mut buffer = vec![0; 65536];
    println!(
        "UDP TURN listening on {listener_address}; relay range {}-{}",
        options.relay_min, options.relay_max
    );
    while running.load(Ordering::Relaxed) {
        let now = Instant::now();
        server.handle_timeout(now)?;
        drain(&mut server, &listener, &mut relays, &options, now)?;
        poll_sockets(
            &mut server,
            &listener,
            &mut relays,
            &options,
            now,
            &mut buffer,
            UdpSocket::recv_from,
        )?;
        // This polling example favors readability. Production hosts should use readiness I/O
        // and schedule server.poll_timeout() with their chosen runtime.
        std::thread::sleep(Duration::from_millis(2));
    }
    server.close();
    drain(
        &mut server,
        &listener,
        &mut relays,
        &options,
        Instant::now(),
    )?;
    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use rtc_turn::proto::PROTO_UDP;
    use rtc_turn::proto::data::Data;
    use rtc_turn::proto::lifetime::Lifetime;
    use rtc_turn::proto::peeraddr::PeerAddress;
    use rtc_turn::proto::reqtrans::RequestedTransport;
    use stun::attributes::*;
    use stun::message::*;
    use stun::textattrs::TextAttribute;

    fn options() -> Options {
        Options::try_parse_from([
            "turn_server_udp",
            "--user",
            "alice=password",
            "--allow-private-peers",
        ])
        .unwrap()
    }

    #[test]
    fn credentials_enforce_the_documented_ascii_profile() {
        let provider = default_provider().unwrap();
        let mut options = options();
        for user in ["alice", "=password", "alice=", "alice=pa\u{00a0}ss"] {
            options.user = vec![user.into()];
            assert!(
                credentials(&options, provider.as_ref()).is_err(),
                "accepted {user}"
            );
        }
        options.user = vec!["alice=password=with=equals".into()];
        assert!(credentials(&options, provider.as_ref()).is_ok());
    }

    #[test]
    fn peer_policy_requires_explicit_private_network_opt_in() {
        let provider = default_provider().unwrap();
        let mut options = options();
        options.allow_private_peers = false;
        let public = credentials(&options, provider.as_ref()).unwrap();
        assert!(public.credential_key("missing", &options.realm).is_none());
        assert!(public.allow_peer("alice", "8.8.8.8:53".parse().unwrap()));
        assert!(!public.allow_peer("alice", "127.0.0.1:9000".parse().unwrap()));
        options.allow_private_peers = true;
        let private = credentials(&options, provider.as_ref()).unwrap();
        assert!(private.allow_peer("alice", "127.0.0.1:9000".parse().unwrap()));
        assert!(!private.allow_peer("alice", "224.0.0.1:9000".parse().unwrap()));
        assert!(!private.allow_peer("alice", "127.0.0.1:0".parse().unwrap()));
    }

    #[test]
    fn relay_binding_reports_family_and_port_exhaustion() {
        let mut options = options();
        assert_eq!(
            bind_relay(&options, AddressFamily::Ipv6)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
        let occupied = UdpSocket::bind("0.0.0.0:0").unwrap();
        options.relay_min = occupied.local_addr().unwrap().port();
        options.relay_max = options.relay_min;
        assert_eq!(
            bind_relay(&options, AddressFamily::Ipv4)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }

    fn receive(socket: &UdpSocket) -> Message {
        let mut raw = [0; 4096];
        let size = socket.recv(&mut raw).unwrap();
        let mut message = Message::new();
        message.unmarshal_binary(&raw[..size]).unwrap();
        message
    }

    fn authenticated(
        method: Method,
        nonce: &[u8],
        attrs: &[Box<dyn Setter>],
        key: &[u8],
    ) -> Message {
        let mut message = Message::new();
        message.set_type(MessageType::new(method, CLASS_REQUEST));
        message.new_transaction_id().unwrap();
        message.write_header();
        for attr in attrs {
            attr.add_to(&mut message).unwrap();
        }
        TextAttribute::new(ATTR_USERNAME, "alice".into())
            .add_to(&mut message)
            .unwrap();
        TextAttribute::new(ATTR_REALM, "webrtc.rs".into())
            .add_to(&mut message)
            .unwrap();
        message.add(ATTR_NONCE, nonce);
        MessageIntegrity::new_raw_integrity_with_provider(
            key.to_vec(),
            default_provider().unwrap().crypto(),
        )
        .add_to(&mut message)
        .unwrap();
        message
    }

    struct TestHost {
        server: Server,
        listener: UdpSocket,
        relays: HashMap<AllocationId, UdpSocket>,
        options: Options,
        now: Instant,
        key: Vec<u8>,
    }

    impl TestHost {
        fn new() -> Self {
            let provider = default_provider().unwrap();
            let mut options = options();
            options.relay_min = 0;
            options.relay_max = 0;
            let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            options.listen = listener.local_addr().unwrap();
            let users = credentials(&options, provider.as_ref()).unwrap();
            let key = users.credential_key("alice", &options.realm).unwrap();
            let now = Instant::now();
            let server =
                Server::new(ServerConfig::default(), Arc::new(users), provider, now).unwrap();
            Self {
                server,
                listener,
                relays: HashMap::new(),
                options,
                now,
                key,
            }
        }

        fn poll_with(
            &mut self,
            receive: impl FnMut(&UdpSocket, &mut [u8]) -> io::Result<(usize, SocketAddr)>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            poll_sockets(
                &mut self.server,
                &self.listener,
                &mut self.relays,
                &self.options,
                self.now,
                &mut [0; 65536],
                receive,
            )
        }

        fn add_client(&mut self, peer: SocketAddr) -> (UdpSocket, AllocationId) {
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut challenge = Message::new();
            challenge.set_type(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST));
            challenge.write_header();
            client.send_to(&challenge.raw, self.options.listen).unwrap();
            self.poll_with(UdpSocket::recv_from).unwrap();
            let nonce = receive(&client).get(ATTR_NONCE).unwrap();
            let previous: Vec<_> = self.relays.keys().copied().collect();
            let allocate = authenticated(
                METHOD_ALLOCATE,
                &nonce,
                &[Box::new(RequestedTransport {
                    protocol: PROTO_UDP,
                })],
                &self.key,
            );
            client.send_to(&allocate.raw, self.options.listen).unwrap();
            self.poll_with(UdpSocket::recv_from).unwrap();
            assert_eq!(receive(&client).typ.class, CLASS_SUCCESS_RESPONSE);
            let id = *self
                .relays
                .keys()
                .find(|id| !previous.contains(id))
                .unwrap();
            let permission = authenticated(
                METHOD_CREATE_PERMISSION,
                &nonce,
                &[Box::new(PeerAddress {
                    ip: peer.ip(),
                    port: 0,
                })],
                &self.key,
            );
            client
                .send_to(&permission.raw, self.options.listen)
                .unwrap();
            self.poll_with(UdpSocket::recv_from).unwrap();
            assert_eq!(receive(&client).typ.class, CLASS_SUCCESS_RESPONSE);
            (client, id)
        }

        fn relay_address(&self, id: AllocationId) -> SocketAddr {
            SocketAddr::new(
                self.options.public_ip,
                self.relays[&id].local_addr().unwrap().port(),
            )
        }
    }

    #[test]
    fn listener_endpoint_errors_preserve_other_clients_and_yield() {
        let mut host = TestHost::new();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_first, first_id) = host.add_client(peer.local_addr().unwrap());
        let (second, second_id) = host.add_client(peer.local_addr().unwrap());
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            peer.send_to(b"healthy", host.relay_address(second_id))
                .unwrap();
            let listener_address = host.options.listen;
            let mut calls = 0;
            host.poll_with(|socket, buffer| {
                if socket.local_addr()? == listener_address {
                    calls += 1;
                    return Err(io::Error::from(kind));
                }
                socket.recv_from(buffer)
            })
            .unwrap();
            assert_eq!(calls, 1, "must yield on a repeated error");
            assert_eq!(receive(&second).get(ATTR_DATA).unwrap(), b"healthy");
            assert_eq!(host.server.allocation_count(), 2);
            assert!(host.relays.contains_key(&first_id));
            // The next pass must still accept control traffic on the same socket.
            let mut binding = Message::new();
            binding.set_type(MessageType::new(METHOD_BINDING, CLASS_REQUEST));
            binding.write_header();
            second.send_to(&binding.raw, listener_address).unwrap();
            host.poll_with(UdpSocket::recv_from).unwrap();
            assert_eq!(receive(&second).typ.class, CLASS_SUCCESS_RESPONSE);
        }
    }

    #[test]
    fn relay_endpoint_errors_preserve_allocations_and_other_clients() {
        let mut host = TestHost::new();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (first, first_id) = host.add_client(peer.local_addr().unwrap());
        let (second, second_id) = host.add_client(peer.local_addr().unwrap());
        let failed_port = host.relay_address(first_id).port();
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            peer.send_to(b"other client", host.relay_address(second_id))
                .unwrap();
            let mut calls = 0;
            host.poll_with(|socket, buffer| {
                if socket.local_addr()?.port() == failed_port {
                    calls += 1;
                    return Err(io::Error::from(kind));
                }
                socket.recv_from(buffer)
            })
            .unwrap();
            assert_eq!(calls, 1, "must yield on a repeated error");
            assert_eq!(receive(&second).get(ATTR_DATA).unwrap(), b"other client");
            assert_eq!(host.server.allocation_count(), 2);
            assert!(host.relays.contains_key(&first_id));
        }
        // The errored socket must still forward on a subsequent pass.
        peer.send_to(b"recovered", host.relay_address(first_id))
            .unwrap();
        host.poll_with(UdpSocket::recv_from).unwrap();
        assert_eq!(receive(&first).get(ATTR_DATA).unwrap(), b"recovered");
    }

    #[test]
    fn fatal_relay_error_retires_only_its_allocation() {
        let mut host = TestHost::new();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_first, first_id) = host.add_client(peer.local_addr().unwrap());
        let (second, second_id) = host.add_client(peer.local_addr().unwrap());
        let failed_address = host.relay_address(first_id);
        peer.send_to(b"unaffected", host.relay_address(second_id))
            .unwrap();
        let mut calls = 0;
        host.poll_with(|socket, buffer| {
            if socket.local_addr()?.port() == failed_address.port() {
                calls += 1;
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            socket.recv_from(buffer)
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(receive(&second).get(ATTR_DATA).unwrap(), b"unaffected");
        assert_eq!(host.server.allocation_count(), 1);
        assert!(!host.relays.contains_key(&first_id));
        assert!(host.relays.contains_key(&second_id));
        assert!(
            UdpSocket::bind(failed_address).is_ok(),
            "failed socket was not closed"
        );
        peer.send_to(b"still serving", host.relay_address(second_id))
            .unwrap();
        host.poll_with(UdpSocket::recv_from).unwrap();
        assert_eq!(receive(&second).get(ATTR_DATA).unwrap(), b"still serving");
    }

    #[test]
    fn fatal_listener_error_is_propagated() {
        let mut host = TestHost::new();
        let listener_address = host.options.listen;
        let mut calls = 0;
        let error = host
            .poll_with(|socket, _| {
                assert_eq!(socket.local_addr().unwrap(), listener_address);
                calls += 1;
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn host_drains_allocation_forwarding_and_socket_release() {
        let provider = default_provider().unwrap();
        let mut options = options();
        // Bind ephemeral ports in this isolated host test rather than assuming a free range.
        options.relay_min = 0;
        options.relay_max = 0;
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        options.listen = listener.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let users = credentials(&options, provider.as_ref()).unwrap();
        let key = users.credential_key("alice", &options.realm).unwrap();
        let now = Instant::now();
        let mut server =
            Server::new(ServerConfig::default(), Arc::new(users), provider, now).unwrap();
        let transport = TransportContext {
            local_addr: options.listen,
            peer_addr: client.local_addr().unwrap(),
            ..Default::default()
        };
        let mut relays = HashMap::new();
        let mut challenge = Message::new();
        challenge.set_type(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST));
        challenge.write_header();
        server
            .handle_datagram(now, transport, &challenge.raw)
            .unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        let nonce = receive(&client).get(ATTR_NONCE).unwrap();
        let allocate = authenticated(
            METHOD_ALLOCATE,
            &nonce,
            &[Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            })],
            &key,
        );
        server
            .handle_datagram(now, transport, &allocate.raw)
            .unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        assert_eq!(receive(&client).typ.class, CLASS_SUCCESS_RESPONSE);
        assert_eq!(relays.len(), 1);
        let id = *relays.keys().next().unwrap();
        let permission = authenticated(
            METHOD_CREATE_PERMISSION,
            &nonce,
            &[Box::new(PeerAddress {
                ip: peer.local_addr().unwrap().ip(),
                port: 0,
            })],
            &key,
        );
        server
            .handle_datagram(now, transport, &permission.raw)
            .unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        assert_eq!(receive(&client).typ.class, CLASS_SUCCESS_RESPONSE);
        let mut send = Message::new();
        send.set_type(MessageType::new(METHOD_SEND, CLASS_INDICATION));
        send.write_header();
        PeerAddress {
            ip: peer.local_addr().unwrap().ip(),
            port: peer.local_addr().unwrap().port(),
        }
        .add_to(&mut send)
        .unwrap();
        Data(b"outbound".to_vec()).add_to(&mut send).unwrap();
        server.handle_datagram(now, transport, &send.raw).unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        let mut payload = [0; 32];
        let (size, from) = peer.recv_from(&mut payload).unwrap();
        assert_eq!(&payload[..size], b"outbound");
        assert_eq!(from.port(), relays[&id].local_addr().unwrap().port());
        server
            .handle_peer_data(now, id, peer.local_addr().unwrap(), b"inbound")
            .unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        assert_eq!(receive(&client).get(ATTR_DATA).unwrap(), b"inbound");
        let delete = authenticated(
            METHOD_REFRESH,
            &nonce,
            &[Box::new(Lifetime(Duration::ZERO))],
            &key,
        );
        server.handle_datagram(now, transport, &delete.raw).unwrap();
        drain(&mut server, &listener, &mut relays, &options, now).unwrap();
        assert_eq!(receive(&client).typ.class, CLASS_SUCCESS_RESPONSE);
        assert!(relays.is_empty());
        assert!(UdpSocket::bind(SocketAddr::new(options.public_ip, from.port())).is_ok());
    }
}
