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
        // Bound work per iteration so a busy listener cannot starve relay sockets or timers.
        for _ in 0..64 {
            match listener.recv_from(&mut buffer) {
                Ok((length, peer_addr)) => {
                    let transport = TransportContext {
                        local_addr: listener_address,
                        peer_addr,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    };
                    if let Err(error) = server.handle_datagram(now, transport, &buffer[..length]) {
                        eprintln!("Control datagram discarded: {error}");
                    }
                    drain(&mut server, &listener, &mut relays, &options, now)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let ids: Vec<_> = relays.keys().copied().collect();
        for id in ids {
            for _ in 0..16 {
                let received = relays.get(&id).map(|socket| socket.recv_from(&mut buffer));
                match received {
                    Some(Ok((length, peer))) => {
                        server.handle_peer_data(now, id, peer, &buffer[..length])?;
                        drain(&mut server, &listener, &mut relays, &options, now)?;
                    }
                    Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Some(Err(error)) => return Err(error.into()),
                    None => break,
                }
            }
        }
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
