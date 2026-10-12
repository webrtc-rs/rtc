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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    if options.relay_min == 0 || options.relay_min > options.relay_max {
        return Err("invalid relay port range".into());
    }
    let provider: Arc<dyn RTCCryptoProvider> = default_provider()?;
    let mut keys = HashMap::new();
    for entry in &options.user {
        let (username, password) = entry.split_once('=').ok_or("expected USERNAME=PASSWORD")?;
        if username.is_empty()
            || password.is_empty()
            || !username.is_ascii()
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
    let listener = UdpSocket::bind(options.listen)?;
    listener.set_nonblocking(true)?;
    let listener_address = listener.local_addr()?;
    let mut server = Server::new(
        ServerConfig {
            realm: options.realm.clone(),
            ..Default::default()
        },
        Arc::new(Users {
            keys,
            allow_private: options.allow_private_peers,
        }),
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
