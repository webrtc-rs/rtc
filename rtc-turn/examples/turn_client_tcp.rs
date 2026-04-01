use bytes::BytesMut;
use clap::Parser;
use log::trace;
use rtc_turn::client::*;
use sansio::Protocol;
use shared::error::{Error, Result};
use shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::str::FromStr;
use std::time::{Duration, Instant};

// First, start turn server with TCP support:
//
// Option 1: webrtc-rs/webrtc/turn/examples/turn_server_tcp:
//  RUST_LOG=trace cargo run --color=always --package turn --example turn_server_tcp -- --public-ip 127.0.0.1 --users user=pass
//
// Option 2: coturn (reference TURN server):
//  turnserver --lt-cred-mech --user user:pass --realm webrtc.rs --no-dtls --no-tls
//
// Then, start this example:
//   RUST_LOG=trace cargo run --color=always --package rtc-turn --example turn_client_tcp -- --host 127.0.0.1 --user user=pass

#[derive(Parser)]
#[command(name = "TURN Client TCP")]
#[command(author = "Brainwires <brainwires@github>")]
#[command(version = "0.1.0")]
#[command(about = "An example of TURN Client over TCP (RFC 6062)", long_about = None)]
struct Cli {
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 3478)]
    port: u16,
    #[arg(long)]
    user: String,
    #[arg(long, default_value_t = format!("webrtc.rs"))]
    realm: String,

    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("INFO"))]
    log_level: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.debug {
        let log_level = log::LevelFilter::from_str(&cli.log_level).unwrap();
        env_logger::Builder::new()
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{}:{} [{}] {} - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.level(),
                    chrono::Local::now().format("%H:%M:%S.%6f"),
                    record.args()
                )
            })
            .filter(None, log_level)
            .init();
    }

    let host = cli.host;
    let port = cli.port;
    let user = cli.user;
    let cred: Vec<&str> = user.splitn(2, '=').collect();
    let realm = cli.realm;

    let turn_server_addr = format!("{host}:{port}");

    // Connect a TCP socket to the TURN server.
    // Unlike UDP, the TURN client over TCP uses a single persistent connection.
    let mut stream = TcpStream::connect(&turn_server_addr)?;
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr()?;

    println!("TCP connected: {} → {}", local_addr, peer_addr);

    // Configure the TCP stream for non-blocking reads in the polling loop.
    stream.set_nonblocking(true)?;
    let mut stream_write = stream.try_clone()?;

    let cfg = ClientConfig {
        stun_serv_addr: turn_server_addr.clone(),
        turn_serv_addr: turn_server_addr,
        local_addr,
        transport_protocol: TransportProtocol::TCP,
        username: cred[0].to_string(),
        password: cred[1].to_string(),
        realm: realm.to_string(),
        software: String::new(),
        rto_in_ms: 0,
    };

    let mut client = Client::new(cfg)?;

    // Allocate a relay socket on the TURN server (over TCP).
    let allocate_tid = client.allocate()?;
    let mut relayed_addr = None;

    let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(1);
    println!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });

    // RFC 4571 decoder for inbound TCP frames.
    let mut decoder = TcpFrameDecoder::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match stop_rx.try_recv() {
            Ok(_) => break,
            Err(err) => {
                if err.is_disconnected() {
                    break;
                }
            }
        };

        // Flush outbound TURN messages (each wrapped in a 2-byte length prefix per RFC 4571).
        while let Some(transmit) = client.poll_write() {
            let framed = frame_packet(&transmit.message);
            stream_write.write_all(&framed)?;
            trace!(
                "tcp.sent {} bytes to {}",
                transmit.message.len(),
                transmit.transport.peer_addr
            );
        }

        // Process TURN events.
        while let Some(event) = client.poll_event() {
            match event {
                Event::TransactionTimeout(_) => return Err(Error::ErrTimeout),
                Event::BindingResponse(_, reflexive_addr) => {
                    println!("reflexive address {}", reflexive_addr);
                }
                Event::BindingError(_, err) => return Err(err),
                Event::AllocateResponse(tid, addr) => {
                    println!("relayed address {}", addr);
                    if relayed_addr.is_none() {
                        assert_eq!(tid, allocate_tid);
                        relayed_addr = Some(addr);
                        println!(
                            "TURN relay allocated over TCP: {}  (refresh will keep it alive)",
                            addr
                        );
                    }
                }
                Event::AllocateError(_, err) => return Err(err),
                Event::CreatePermissionResponse(tid, peer_addr) => {
                    println!("CreatePermission for peer addr {} is granted (tid={:?})", peer_addr, tid);
                }
                Event::CreatePermissionError(_, err) => return Err(err),
                Event::DataIndicationOrChannelData(_, from, data) => {
                    println!("relay read: {:?} from {}", &data[..], from);
                    // Echo back
                    if let Some(&relay_addr) = relayed_addr.as_ref() {
                        client.relay(relay_addr)?.send_to(&data[..], from)?;
                    }
                }
            }
        }

        // Compute next timeout.
        let mut eto = Instant::now() + Duration::from_millis(100);
        if let Some(to) = client.poll_timeout() {
            if to < eto {
                eto = to;
            }
        }
        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        // Non-blocking read from TCP socket.
        // RFC 4571: each TURN message is prefixed with a 2-byte big-endian length.
        match read_tcp_input(&mut stream, &mut buf, &mut decoder) {
            Some(data) => {
                trace!(
                    "tcp.recv {} bytes from {}",
                    data.len(),
                    peer_addr
                );
                let msg = TransportMessage {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr,
                        transport_protocol: TransportProtocol::TCP,
                        ecn: None,
                    },
                    message: BytesMut::from(data.as_slice()),
                };
                client.handle_read(msg)?;
            }
            None => {
                // No complete frame yet — sleep briefly to avoid busy-polling.
                if !delay_from_now.is_zero() {
                    std::thread::sleep(std::cmp::min(
                        delay_from_now,
                        Duration::from_millis(5),
                    ));
                }
            }
        }

        // Drive time forward.
        client.handle_timeout(Instant::now())?;
    }

    client.close()
}

/// Read from a non-blocking TCP stream, decode RFC 4571 frames.
/// Returns the next complete TURN message payload (without the 2-byte length header),
/// or `None` if no complete frame is available yet.
fn read_tcp_input(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    decoder: &mut TcpFrameDecoder,
) -> Option<Vec<u8>> {
    // Drain available bytes into the decoder.
    loop {
        match stream.read(buf.as_mut_slice()) {
            Ok(0) => break, // EOF
            Ok(n) => decoder.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => {
                eprintln!("TCP read error: {e}");
                break;
            }
        }
    }
    decoder.next_packet()
}
