use bytes::BytesMut;
use clap::Parser;
use log::trace;
use rtc_turn::client::*;
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use std::io::{ErrorKind, Write};
use std::net::UdpSocket;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

// RUST_LOG=trace cargo run --color=always --package rtc-turn --example turn_client_udp -- --host 127.0.0.1 --user user=pass --ping

#[derive(Parser)]
#[command(name = "TURN Client UDP")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of TURN Client UDP", long_about = None)]
struct Cli {
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 3478)]
    port: u16,
    #[arg(long)]
    user: String,
    #[arg(long, default_value_t = format!("webrtc.rs"))]
    realm: String,
    #[arg(long)]
    ping: bool,

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
    let _ping = cli.ping;
    let realm = cli.realm;

    // TURN client won't create a local listening socket by itself.
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let pinger = UdpSocket::bind("127.0.0.1:0")?;

    let local_addr = socket.local_addr()?;
    let peer_addr = pinger.local_addr()?;
    let mut pinger = Some(pinger);

    let turn_server_addr = format!("{host}:{port}");

    let cfg = ClientConfig {
        stun_serv_addr: turn_server_addr.clone(),
        turn_serv_addr: turn_server_addr,
        local_addr,
        transport_protocol: TransportProtocol::UDP,
        username: cred[0].to_string(),
        password: cred[1].to_string(),
        realm: realm.to_string(),
        software: String::new(),
        rto_in_ms: 0,
    };

    let mut client = Client::new(cfg)?;

    // Allocate a relay socket on the TURN state.
    let allocate_tid = client.allocate()?;
    let mut relayed_addr = None;
    let mut create_permission_tid = None;
    // Send BindingRequest to learn our external IP
    //let binding_tid = client.send_binding_request()?;

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

    let mut buf = vec![0u8; 2048];
    loop {
        match stop_rx.try_recv() {
            Ok(_) => break,
            Err(err) => {
                if err.is_disconnected() {
                    break;
                }
            }
        };

        while let Some(transmit) = client.poll_transmit() {
            socket.send_to(&transmit.message, transmit.transport.peer_addr)?;
            trace!(
                "socket.sent {} to {}",
                transmit.message.len(),
                transmit.transport.peer_addr
            );
        }

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
                        if let Some(id) = client.relay(addr)?.create_permission(peer_addr)? {
                            create_permission_tid = Some(id);
                        } else {
                            assert!(false, "create_permission failed");
                        }
                    } else {
                        assert!(false, "relayed address is not none");
                    }
                }
                Event::AllocateError(_, err) => return Err(err),
                Event::CreatePermissionResponse(tid, peer_addr) => {
                    println!("CreatePermission for peer addr {} is granted", peer_addr);
                    if let Some(id) = create_permission_tid {
                        assert_eq!(tid, id);

                        do_ping_test(pinger.take(), relayed_addr.clone())
                    } else {
                        assert!(false, "create_permission_tid is none");
                    }
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

        let mut eto = Instant::now() + Duration::from_millis(100);
        if let Some(to) = client.poll_timout() {
            if to < eto {
                eto = to;
            }
        }

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            client.handle_timeout(Instant::now());
            continue;
        }

        socket
            .set_read_timeout(Some(delay_from_now))
            .expect("setting socket read timeout");

        if let Some(transmit) = read_socket_input(&socket, &mut buf) {
            trace!(
                "read_socket_input {} from {}",
                transmit.message.len(),
                transmit.transport.peer_addr
            );
            client.handle_transmit(transmit)?;
        }

        // Drive time forward in all clients.
        client.handle_timeout(Instant::now());
    }

    client.close();

    Ok(())
}

fn read_socket_input(socket: &UdpSocket, buf: &mut [u8]) -> Option<TransportMessage<BytesMut>> {
    match socket.recv_from(buf) {
        Ok((n, peer_addr)) => {
            return Some(TransportMessage {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: socket.local_addr().unwrap(),
                    peer_addr,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(&buf[..n]),
            });
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout(). One for windows, one for the rest.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => None,
            _ => panic!("UdpSocket read failed: {e:?}"),
        },
    }
}

fn do_ping_test(pinger: Option<UdpSocket>, relayed_addr: Option<RelayedAddr>) {
    // Set up pinger socket (pingerConn)
    //println!("bind...");

    // Punch a UDP hole for the relay_conn by sending a data to the mapped_addr.
    // This will trigger a TURN client to generate a permission request to the
    // TURN state. After this, packets from the IP address will be accepted by
    // the TURN state.
    //println!("relay_conn send hello to mapped_addr {}", mapped_addr);
    /*client
       .relay(relayed_addr)
       .send_to("Hello".as_bytes(), reflexive_addr)?;
    */
    if let (Some(pinger), Some(relayed_addr)) = (pinger, relayed_addr) {
        // Start read-loop on pingerConn
        thread::spawn(move || {
            let mut buf = vec![0u8; 1500];

            for i in 0..10 {
                let msg = "12345678910".to_owned(); //format!("{:?}", tokio::time::Instant::now());
                println!(
                    "sending {}th msg={} with size={} to {}",
                    i,
                    msg,
                    msg.as_bytes().len(),
                    relayed_addr
                );
                pinger.send_to(msg.as_bytes(), relayed_addr).unwrap();

                let (n, from) = match pinger.recv_from(&mut buf) {
                    Ok((n, from)) => (n, from),
                    Err(_) => break,
                };

                let msg = match String::from_utf8(buf[..n].to_vec()) {
                    Ok(msg) => msg,
                    Err(_) => break,
                };

                println!("pinger read-loop: {msg} from {from}");

                // For simplicity, this example does not wait for the pong (reply).
                // Instead, sleep 1 second.
                thread::sleep(Duration::from_secs(1));
            }
            println!("ping completed");
        });
    }
}
