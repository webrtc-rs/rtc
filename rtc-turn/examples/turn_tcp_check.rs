//! Checks a TURN server's TCP allocations ([RFC 6062]) end to end, with this crate's client.
//!
//! It allocates a TCP relay over a TCP connection to the server, has the server connect to a local
//! echo peer (`Connect`), opens a second connection to the server and binds it to that peer
//! connection (`ConnectionBind`), and then sends bytes down the second connection and checks the
//! peer echoes them back. Prints `status=PASS` and exits 0 on success; used to interoperate with
//! other TURN servers (pion's).
//!
//! ```text
//! turn_tcp_check --server 127.0.0.1:3478 --user user=pass
//! ```
//!
//! [RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use clap::Parser;
use rtc_turn::client::{Client, ClientConfig, Event};
use rtc_turn::proto::connid::ConnectionId;
use rtc_turn::proto::framing::frame_length;
use sansio::Protocol;
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};

#[derive(Parser)]
struct Cli {
    /// The TURN server, `host:port`.
    #[arg(long)]
    server: String,
    /// Credentials, `user=pass`.
    #[arg(long)]
    user: String,
    /// The realm; ignored if the server names its own.
    #[arg(long, default_value_t = String::from("webrtc.rs"))]
    realm: String,
    /// How many messages to send down the data connection.
    #[arg(long, default_value_t = 100)]
    count: usize,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 20)]
    timeout: u64,
}

/// A TCP connection to the server whose bytes are TURN messages.
struct Framed {
    stream: TcpStream,
    local: SocketAddr,
    pending: Vec<u8>,
}

impl Framed {
    fn connect(server: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(server)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_millis(2)))?;
        let local = stream.local_addr()?;
        Ok(Self {
            stream,
            local,
            pending: Vec::new(),
        })
    }

    /// The complete messages that have arrived.
    fn messages(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => return Err(Error::ErrConnClosed),
            Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(err) => return Err(err.into()),
        }
        let mut out = Vec::new();
        while let Some(len) = frame_length(&self.pending)? {
            out.push(self.pending.drain(..len).collect());
        }
        Ok(out)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (user, pass) = cli
        .user
        .split_once('=')
        .ok_or_else(|| Error::Other("--user wants user=pass".to_owned()))?;
    let server: SocketAddr = cli
        .server
        .parse()
        .map_err(|_| Error::Other("--server wants an address, host:port".to_owned()))?;

    // A peer that echoes every byte of every connection back.
    let peer_listener = TcpListener::bind("127.0.0.1:0")?;
    let peer_addr = peer_listener.local_addr()?;
    std::thread::spawn(move || {
        while let Ok((mut conn, _)) = peer_listener.accept() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 || conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });

    let mut control = Framed::connect(server)?;
    let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
    let mut client = Client::new(
        ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: cli.server.clone(),
            local_addr: control.local,
            transport_protocol: TransportProtocol::TCP,
            username: user.to_owned(),
            password: pass.to_owned(),
            realm: cli.realm,
            software: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: None,
        },
        provider,
    )?;
    client.allocate_tcp(Instant::now())?;

    let fail = |why: &str| -> Result<()> {
        println!("CLIENT result: status=FAIL error={why}");
        Err(Error::Other(why.to_owned()))
    };
    let deadline = Instant::now() + Duration::from_secs(cli.timeout);
    let mut relayed: Option<SocketAddr> = None;
    let mut data: Option<Framed> = None;
    let mut bound = false;

    while !bound {
        if Instant::now() >= deadline {
            return fail("timeout");
        }
        // Requests go out on the connection their local address names: the control connection, or
        // the new one a ConnectionBind is sent on.
        while let Some(out) = client.poll_write() {
            let connection = match data.as_mut() {
                Some(d) if out.transport.local_addr == d.local => &mut d.stream,
                _ => &mut control.stream,
            };
            connection.write_all(&out.message)?;
        }
        let mut incoming: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        incoming.extend(control.messages()?.into_iter().map(|m| (control.local, m)));
        if let Some(d) = data.as_mut() {
            incoming.extend(d.messages()?.into_iter().map(|m| (d.local, m)));
        }
        for (local, message) in incoming {
            client.handle_read(TransportMessage {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: local,
                    peer_addr: server,
                    transport_protocol: TransportProtocol::TCP,
                    ecn: None,
                },
                message: BytesMut::from(&message[..]),
            })?;
        }
        client.handle_timeout(Instant::now())?;

        while let Some(event) = client.poll_event() {
            match event {
                Event::AllocateResponse(_, addr) => {
                    relayed = Some(addr);
                    client.relay(addr)?.connect(Instant::now(), peer_addr)?;
                }
                Event::ConnectResponse(_, _, connection_id) => {
                    // The server connected to the peer; bind a new connection to it.
                    let connection = Framed::connect(server)?;
                    let relay = relayed.expect("allocated before connecting");
                    client.relay(relay)?.connection_bind(
                        Instant::now(),
                        connection_id,
                        connection.local,
                    )?;
                    data = Some(connection);
                }
                Event::ConnectionBindResponse(_, ConnectionId(_)) => bound = true,
                Event::AllocateError(_, err)
                | Event::ConnectError(_, err)
                | Event::ConnectionBindError(_, err) => return fail(&err.to_string()),
                Event::TransactionTimeout(_) => return fail("request timed out"),
                _ => {}
            }
        }
    }

    // The bound connection is now a plain byte pipe to the peer.
    let mut data = data.expect("bound").stream;
    data.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (mut echoed, mut mismatched) = (0usize, 0usize);
    for i in 0..cli.count {
        let payload = format!("ping-{i}");
        data.write_all(payload.as_bytes())?;
        let mut got = vec![0u8; payload.len()];
        data.read_exact(&mut got)?;
        if got == payload.as_bytes() {
            echoed += 1;
        } else {
            mismatched += 1;
        }
    }
    let pass = echoed == cli.count && mismatched == 0;
    println!(
        "CLIENT result: sent={} echoed={echoed}/{} mismatched={mismatched} status={}",
        cli.count,
        cli.count,
        if pass { "PASS" } else { "FAIL" }
    );
    if pass { Ok(()) } else { Err(Error::ErrTimeout) }
}
