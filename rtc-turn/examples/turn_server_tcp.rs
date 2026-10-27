//! A TURN server over TCP with TCP allocations ([RFC 6062]), driving the Sans-I/O [`Server`] with
//! tokio sockets.
//!
//! ```text
//! cargo run --package rtc-turn --example turn_server_tcp -- --public-ip 127.0.0.1 --users user=pass
//! ```
//!
//! Clients connect over TCP and ask for a TCP allocation (pion's `AllocateTCP`, or
//! `Client::allocate_tcp`). The server owns no sockets, so this example does what each event asks:
//!
//! * `BindRelayTcp`: listen on the relay address, with address reuse so that connections to peers can
//!   be opened from the same local address; report each connection a peer makes to it.
//! * `ConnectPeer`: connect to the peer from the relay address.
//! * `BindData`: a client's second connection has been bound to a peer connection; copy bytes both
//!   ways between the two from now on.
//! * `ClosePeer`: drop the peer connection.
//!
//! [RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use clap::Parser;
use rtc_turn::proto::framing::frame_length;
use rtc_turn::server::{
    AuthCredentials, AuthRequest, PeerConnId, RelayAddressGeneratorStatic, Server, ServerConfig,
    ServerEvent, generate_auth_key,
};
use sansio::Protocol;
use shared::error::{Error, Result};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Parser)]
#[command(
    name = "TURN Server TCP",
    about = "A TURN server over TCP with TCP allocations (RFC 6062)"
)]
struct Cli {
    /// The address clients are told to have peers connect to.
    #[arg(long)]
    public_ip: IpAddr,
    /// The TCP port to listen on.
    #[arg(long, default_value_t = 3478)]
    port: u16,
    /// Credentials, as `user=pass[,user=pass...]`.
    #[arg(long)]
    users: String,
    /// The authentication realm.
    #[arg(long, default_value_t = String::from("webrtc.rs"))]
    realm: String,
}

/// What the tasks that own sockets tell the task that owns the server.
enum Msg {
    /// A client opened a connection to the server.
    ClientConnected(TcpStream),
    /// One whole TURN message read from a client connection.
    FromClient {
        client: SocketAddr,
        local: SocketAddr,
        frame: Vec<u8>,
    },
    /// A client connection ended.
    ClientGone(SocketAddr),
    /// A peer connected to the relay listening at `relay`.
    PeerAccepted {
        relay: SocketAddr,
        peer: SocketAddr,
        stream: TcpStream,
    },
    /// The connection to a peer a `Connect` asked for is open.
    PeerConnected { id: PeerConnId, stream: TcpStream },
    /// It could not be opened.
    PeerConnectFailed(PeerConnId),
}

/// What the server task tells a client connection's task.
enum ToClient {
    Write(Vec<u8>),
    /// The connection is now the data connection to this peer: copy bytes both ways.
    Splice(TcpStream),
}

/// A listening or connecting socket on `addr` that other sockets may share.
fn reusable(addr: SocketAddr) -> std::io::Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    Ok(socket)
}

/// Reads whole TURN messages from `stream` until it is spliced to a peer or closes.
async fn serve_client(
    mut stream: TcpStream,
    client: SocketAddr,
    local: SocketAddr,
    to_server: mpsc::UnboundedSender<Msg>,
    mut from_server: mpsc::UnboundedReceiver<ToClient>,
) {
    let mut pending = BytesMut::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            // Commands first: the server queues the response and then the splice together, and
            // a client may send data the moment it has the response.
            biased;
            command = from_server.recv() => match command {
                Some(ToClient::Write(bytes)) => {
                    if stream.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(ToClient::Splice(mut peer)) => {
                    // Bytes already read past the ConnectionBind request are the peer's.
                    if !pending.is_empty() && peer.write_all(&pending).await.is_err() {
                        break;
                    }
                    let _ = copy_bidirectional(&mut stream, &mut peer).await;
                    break;
                }
                None => break,
            },
            read = stream.read(&mut chunk) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                pending.extend_from_slice(&chunk[..n]);
                loop {
                    match frame_length(&pending) {
                        Ok(Some(len)) => {
                            let frame = pending.split_to(len).to_vec();
                            if to_server.send(Msg::FromClient { client, local, frame }).is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            let _ = to_server.send(Msg::ClientGone(client));
                            return;
                        }
                    }
                }
            }
        }
    }
    let _ = to_server.send(Msg::ClientGone(client));
}

/// Binds a listener at `plan_bind` that peers connect to; the relay is its local address.
async fn listen_for_peers(
    bind: SocketAddr,
    to_server: mpsc::UnboundedSender<Msg>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = reusable(bind)?.listen(1024)?;
    let relay = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            if to_server
                .send(Msg::PeerAccepted {
                    relay,
                    peer,
                    stream,
                })
                .is_err()
            {
                break;
            }
        }
    });
    Ok((relay, task))
}

/// Opens the connection a `Connect` asked for: from the relay address, to the peer.
fn connect_to_peer(
    id: PeerConnId,
    relay: SocketAddr,
    peer: SocketAddr,
    to_server: mpsc::UnboundedSender<Msg>,
) {
    tokio::spawn(async move {
        let connected = async {
            let socket = reusable(relay)?;
            tokio::time::timeout(Duration::from_secs(10), socket.connect(peer))
                .await
                .map_err(|_| std::io::ErrorKind::TimedOut)?
        };
        let _ = to_server.send(match connected.await {
            Ok(stream) => Msg::PeerConnected { id, stream },
            Err(err) => {
                eprintln!("could not connect {relay} -> {peer}: {err}");
                Msg::PeerConnectFailed(id)
            }
        });
    });
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
    let generator = Box::new(RelayAddressGeneratorStatic {
        relay_address: cli.public_ip,
        address: IpAddr::from([0, 0, 0, 0]),
    });
    let mut server = Server::new(
        ServerConfig::new(cli.realm, Arc::new(auth), generator, provider),
        Instant::now(),
    )?;

    let listener = TcpListener::bind(("0.0.0.0", cli.port)).await?;
    println!(
        "TURN server listening on {}, relaying from {}",
        listener.local_addr()?,
        cli.public_ip
    );

    let (to_server, mut inbox) = mpsc::unbounded_channel::<Msg>();
    {
        let to_server = to_server.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                if to_server.send(Msg::ClientConnected(stream)).is_err() {
                    break;
                }
            }
        });
    }

    let mut clients: HashMap<SocketAddr, mpsc::UnboundedSender<ToClient>> = HashMap::new();
    let mut listeners: HashMap<SocketAddr, JoinHandle<()>> = HashMap::new();
    let mut peers: HashMap<PeerConnId, TcpStream> = HashMap::new();

    loop {
        // Send what the server produced, then do what it asked for.
        while let Some(out) = server.poll_write() {
            if let Some(client) = clients.get(&out.transport.peer_addr) {
                let _ = client.send(ToClient::Write(out.message.to_vec()));
            }
        }
        while let Some(event) = server.poll_event() {
            match event {
                ServerEvent::BindRelayTcp { id, plan } => {
                    match listen_for_peers(plan.bind, to_server.clone()).await {
                        Ok((relay, task)) => {
                            listeners.insert(relay, task);
                            server.relay_bound(id, relay, Instant::now());
                        }
                        Err(err) => {
                            eprintln!("could not bind a relay at {}: {err}", plan.bind);
                            server.relay_bind_failed(id, Instant::now());
                        }
                    }
                }
                ServerEvent::ReleaseRelay(relay) => {
                    if let Some(task) = listeners.remove(&relay) {
                        task.abort();
                    }
                }
                ServerEvent::ConnectPeer { id, relay, peer } => {
                    connect_to_peer(id, relay, peer, to_server.clone());
                }
                ServerEvent::BindData { id, client, .. } => {
                    match (peers.remove(&id), clients.get(&client)) {
                        (Some(peer), Some(connection)) => {
                            let _ = connection.send(ToClient::Splice(peer));
                        }
                        _ => eprintln!("nothing to splice for {id:?}"),
                    }
                }
                ServerEvent::ClosePeer(id) => {
                    peers.remove(&id);
                }
                ServerEvent::AllocationCreated {
                    user_id,
                    relayed_addr,
                    ..
                } => {
                    println!("allocation for {user_id} -> {relayed_addr}");
                }
                ServerEvent::AllocationDeleted { five_tuple, reason } => {
                    println!("allocation of {} ended: {reason:?}", five_tuple.client);
                }
                _ => {}
            }
        }

        let deadline = server
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            Some(msg) = inbox.recv() => match msg {
                Msg::ClientConnected(stream) => {
                    let (Ok(client), Ok(local)) = (stream.peer_addr(), stream.local_addr()) else {
                        continue;
                    };
                    let (commands, from_server) = mpsc::unbounded_channel();
                    clients.insert(client, commands);
                    tokio::spawn(serve_client(stream, client, local, to_server.clone(), from_server));
                }
                Msg::FromClient { client, local, frame } => {
                    server.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: local,
                            peer_addr: client,
                            transport_protocol: TransportProtocol::TCP,
                            ecn: None,
                        },
                        message: BytesMut::from(&frame[..]),
                    })?;
                }
                Msg::ClientGone(client) => {
                    clients.remove(&client);
                }
                Msg::PeerAccepted { relay, peer, stream } => {
                    match server.peer_accepted(relay, peer, Instant::now()) {
                        Some(id) => {
                            peers.insert(id, stream);
                        }
                        None => drop(stream), // no permission, or the allocation is gone
                    }
                }
                Msg::PeerConnected { id, stream } => {
                    peers.insert(id, stream);
                    server.peer_connected(id, Instant::now());
                }
                Msg::PeerConnectFailed(id) => server.peer_connect_failed(id, Instant::now()),
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                server.handle_timeout(Instant::now())?;
            }
        }
    }
}
