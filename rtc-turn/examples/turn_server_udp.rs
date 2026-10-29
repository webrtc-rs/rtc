//! A TURN server over UDP, driving the Sans-I/O [`Server`] with tokio sockets.
//!
//! ```text
//! cargo run --package rtc-turn --example turn_server_udp -- --public-ip 127.0.0.1 --users user=pass
//! ```
//!
//! then, for instance, `turn_client_udp --user user=pass --ping`, or pion's own client.

use clap::Parser;
use rtc_turn::server::{
    AuthCredentials, AuthRequest, RelayAddressGeneratorStatic, Server, ServerConfig, ServerEvent,
    generate_auth_key,
};
use sansio::Protocol;
use shared::error::{Error, Result};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Parser)]
#[command(
    name = "TURN Server UDP",
    about = "An example of a TURN server over UDP"
)]
struct Cli {
    /// The address clients are told to send relayed traffic to.
    #[arg(long)]
    public_ip: IpAddr,
    /// The UDP port to listen on.
    #[arg(long, default_value_t = 3478)]
    port: u16,
    /// Credentials, as `user=pass[,user=pass...]`.
    #[arg(long)]
    users: String,
    /// The authentication realm.
    #[arg(long, default_value_t = String::from("webrtc.rs"))]
    realm: String,
    /// The lowest port relays bind to; with `--max-port`, the range a firewall must allow.
    #[arg(long)]
    min_port: Option<u16>,
    /// The highest port relays bind to.
    #[arg(long)]
    max_port: Option<u16>,
}

/// A datagram a relay socket received from a peer.
struct FromPeer {
    relay: SocketAddr,
    peer: SocketAddr,
    data: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let mut users = HashMap::new();
    for pair in cli.users.split(',') {
        let (user, pass) = pair
            .split_once('=')
            .ok_or_else(|| Error::Other("--users wants user=pass[,user=pass...]".to_owned()))?;
        users.insert(user.to_owned(), pass.to_owned());
    }

    // An application selects the crypto provider; library code never resolves a default.
    let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
    let key_provider = provider.clone();
    let auth = move |req: &AuthRequest<'_>| {
        let password = users.get(req.username)?;
        Some(AuthCredentials {
            user_id: req.username.to_owned(),
            key: generate_auth_key(req.username, req.realm, password, key_provider.crypto())
                .ok()?,
        })
    };

    let generator: Box<dyn rtc_turn::server::RelayAddressGenerator> =
        match (cli.min_port, cli.max_port) {
            (Some(min_port), Some(max_port)) => {
                Box::new(rtc_turn::server::RelayAddressGeneratorPortRange {
                    relay_address: cli.public_ip,
                    address: IpAddr::from([0, 0, 0, 0]),
                    min_port,
                    max_port,
                })
            }
            _ => Box::new(RelayAddressGeneratorStatic {
                relay_address: cli.public_ip,
                address: IpAddr::from([0, 0, 0, 0]),
            }),
        };

    let mut server = Server::new(
        ServerConfig::new(cli.realm, Arc::new(auth), generator, provider),
        Instant::now(),
    )?;

    let listener = UdpSocket::bind(("0.0.0.0", cli.port)).await?;
    let listen_addr = listener.local_addr()?;
    println!(
        "TURN server listening on {listen_addr}, relaying from {}",
        cli.public_ip
    );

    let (peer_tx, mut peer_rx) = mpsc::channel::<FromPeer>(1024);
    let mut relays: HashMap<SocketAddr, (Arc<UdpSocket>, JoinHandle<()>)> = HashMap::new();
    let mut buf = vec![0u8; 65_535];

    loop {
        // Act on what the server asked for, then send what it produced, until it has nothing more:
        // reporting a bound relay makes it produce the Allocate response.
        loop {
            let mut quiet = true;
            while let Some(event) = server.poll_event() {
                quiet = false;
                match event {
                    ServerEvent::BindRelay { id, plan } => match UdpSocket::bind(plan.bind).await {
                        Ok(socket) => {
                            let local = socket.local_addr()?;
                            let socket = Arc::new(socket);
                            let reader = {
                                let (socket, tx) = (socket.clone(), peer_tx.clone());
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65_535];
                                    while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                                        let data = buf[..n].to_vec();
                                        if tx
                                            .send(FromPeer {
                                                relay: local,
                                                peer,
                                                data,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                })
                            };
                            relays.insert(local, (socket, reader));
                            server.relay_bound(id, local, Instant::now());
                        }
                        Err(err) => {
                            eprintln!("could not bind a relay at {}: {err}", plan.bind);
                            server.relay_bind_failed(id, Instant::now());
                        }
                    },
                    ServerEvent::ReleaseRelay(addr) => {
                        if let Some((_, reader)) = relays.remove(&addr) {
                            reader.abort();
                        }
                    }
                    ServerEvent::AllocationCreated {
                        five_tuple,
                        user_id,
                        relayed_addr,
                    } => {
                        println!(
                            "allocation for {user_id} ({}) -> {relayed_addr}",
                            five_tuple.client
                        );
                    }
                    ServerEvent::AllocationDeleted { five_tuple, reason } => {
                        println!("allocation of {} ended: {reason:?}", five_tuple.client);
                    }
                    _ => {}
                }
            }
            while let Some(out) = server.poll_write() {
                quiet = false;
                let sent = match relays.get(&out.transport.local_addr) {
                    Some((socket, _)) => {
                        socket.send_to(&out.message, out.transport.peer_addr).await
                    }
                    None => {
                        listener
                            .send_to(&out.message, out.transport.peer_addr)
                            .await
                    }
                };
                if let Err(err) = sent {
                    eprintln!("send to {} failed: {err}", out.transport.peer_addr);
                }
            }
            if quiet {
                break;
            }
        }

        let deadline = server
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            received = listener.recv_from(&mut buf) => {
                let (n, client) = received?;
                server.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: listen_addr,
                        peer_addr: client,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: bytes::BytesMut::from(&buf[..n]),
                })?;
            }
            Some(from) = peer_rx.recv() => {
                server.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: from.relay,
                        peer_addr: from.peer,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: bytes::BytesMut::from(&from.data[..]),
                })?;
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                server.handle_timeout(Instant::now())?;
            }
        }
    }
}
