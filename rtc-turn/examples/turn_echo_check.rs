//! Allocates a relay on a TURN server, and checks it carries traffic both ways.
//!
//! A local "peer" socket echoes whatever reaches it; this client sends a few datagrams to it
//! through the relay, and the echoes must come back through the relay too. Prints
//! `status=PASS` and exits 0 on success; used to interoperate with other TURN servers (pion's).
//!
//! ```text
//! turn_echo_check --server 127.0.0.1:3478 --user user=pass
//! ```

use bytes::BytesMut;
use clap::Parser;
use rtc_turn::client::{Client, ClientConfig, Event};
use sansio::Protocol;
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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
    /// How many datagrams to send.
    #[arg(long, default_value_t = 100)]
    count: usize,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 20)]
    timeout: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (user, pass) = cli
        .user
        .split_once('=')
        .ok_or_else(|| Error::Other("--user wants user=pass".to_owned()))?;

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let local_addr = socket.local_addr()?;
    let peer = UdpSocket::bind("127.0.0.1:0")?;
    peer.set_read_timeout(Some(Duration::from_millis(1)))?;
    let peer_addr = peer.local_addr()?;

    let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
    let mut client = Client::new(
        ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: cli.server.clone(),
            local_addr,
            transport_protocol: TransportProtocol::UDP,
            username: user.to_owned(),
            password: pass.to_owned(),
            realm: cli.realm,
            software: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: None,
        },
        provider,
    )?;

    client.allocate(Instant::now())?;
    let deadline = Instant::now() + Duration::from_secs(cli.timeout);
    let mut relayed: Option<SocketAddr> = None;
    let mut permitted = false;
    let (mut sent, mut echoed, mut mismatched) = (0usize, 0usize, 0usize);
    let mut buf = vec![0u8; 2048];
    let mut next_send = Instant::now();

    while echoed + mismatched < cli.count && Instant::now() < deadline {
        while let Some(out) = client.poll_write() {
            socket.send_to(&out.message, out.transport.peer_addr)?;
        }
        while let Some(event) = client.poll_event() {
            match event {
                Event::AllocateResponse(_, addr) => {
                    relayed = Some(addr);
                    client
                        .relay(addr)?
                        .create_permission(Instant::now(), peer_addr)?;
                }
                Event::CreatePermissionResponse(_, _) => permitted = true,
                Event::AllocateError(_, err) | Event::CreatePermissionError(_, err) => {
                    println!(
                        "CLIENT result: sent={sent} echoed={echoed} mismatched={mismatched} status=FAIL error={err}"
                    );
                    return Err(err);
                }
                Event::TransactionTimeout(_) => {
                    println!(
                        "CLIENT result: sent={sent} echoed={echoed} mismatched={mismatched} status=FAIL error=timeout"
                    );
                    return Err(Error::ErrTimeout);
                }
                Event::DataIndicationOrChannelData(_, from, data) => {
                    if from == peer_addr && data.starts_with(b"ping-") {
                        echoed += 1;
                    } else {
                        mismatched += 1;
                    }
                }
                _ => {}
            }
        }

        // The peer echoes whatever the relay forwards to it, back to the relay.
        if let Ok((n, from)) = peer.recv_from(&mut buf) {
            peer.send_to(&buf[..n], from)?;
        }

        if let (Some(addr), true) = (relayed, permitted)
            && sent < cli.count
            && Instant::now() >= next_send
        {
            let payload = format!("ping-{sent}");
            client
                .relay(addr)?
                .send_to(Instant::now(), payload.as_bytes(), peer_addr)?;
            sent += 1;
            next_send = Instant::now() + Duration::from_millis(5);
        }

        socket.set_read_timeout(Some(Duration::from_millis(1)))?;
        if let Ok((n, from)) = socket.recv_from(&mut buf) {
            client.handle_read(TransportMessage {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr,
                    peer_addr: from,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(&buf[..n]),
            })?;
        }
        client.handle_timeout(Instant::now())?;
    }

    let pass = echoed == cli.count && mismatched == 0;
    println!(
        "CLIENT result: sent={sent} echoed={echoed}/{} mismatched={mismatched} status={}",
        cli.count,
        if pass { "PASS" } else { "FAIL" }
    );
    client.close()?;
    if pass { Ok(()) } else { Err(Error::ErrTimeout) }
}
