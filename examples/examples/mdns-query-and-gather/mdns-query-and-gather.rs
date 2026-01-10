use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{fs, io::Write, str::FromStr};
use tokio::{net::UdpSocket, sync::broadcast};

use rtc::ice::mdns::MulticastDnsMode;
use rtc::mdns::{MDNS_PORT, MulticastSocket};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::shared::error::Error;
use rtc::{peer_connection::sdp::RTCSessionDescription, peer_connection::transport::RTCIceServer};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

#[derive(Parser)]
#[command(name = "mdns-query-and-gather")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.0.0")]
#[command(about = "An example of mDNS query and gather", long_about = None)]
struct Cli {
    #[arg(short, long)]
    client: bool,
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    input_sdp_file: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let port = cli.port;
    let is_client = cli.client;
    let input_sdp_file = cli.input_sdp_file;
    let output_log_file = cli.output_log_file;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    if cli.debug {
        env_logger::Builder::new()
            .target(if !output_log_file.is_empty() {
                Target::Pipe(Box::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(output_log_file)?,
                ))
            } else {
                Target::Stdout
            })
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

    let (stop_tx, stop_rx) = broadcast::channel::<()>(1);
    let (_message_tx, message_rx) = broadcast::channel::<RTCMessage>(8);
    let (_event_tx, event_rx) = broadcast::channel::<RTCEvent>(8);

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

    if let Err(err) = run(
        stop_rx,
        message_rx,
        event_rx,
        port,
        input_sdp_file,
        is_client,
    )
    .await
    {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: broadcast::Receiver<()>,
    mut message_rx: broadcast::Receiver<RTCMessage>,
    mut event_rx: broadcast::Receiver<RTCEvent>,
    port: u16,
    input_sdp_file: String,
    is_client: bool,
) -> Result<()> {
    let mdns_udp_socket = UdpSocket::from_std(MulticastSocket::new().into_std()?)?;

    let pc_local_ip = signal::get_local_ip();
    let pc_udp_socket = UdpSocket::bind(SocketAddr::new(pc_local_ip, port)).await?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(if is_client {
        RTCDtlsRole::Client
    } else {
        RTCDtlsRole::Server
    })?;
    setting_engine.set_multicast_dns_mode(MulticastDnsMode::QueryAndGather);
    setting_engine.set_multicast_dns_timeout(Some(Duration::from_secs(10)));
    setting_engine
        .set_multicast_dns_local_name("webrtc-rs-hides-local-ip-by-mdns.local".to_string());
    setting_engine.set_multicast_dns_local_ip(Some(pc_local_ip));

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Wait for the offer to be pasted
    let line = if input_sdp_file.is_empty() {
        signal::must_read_stdin()?
    } else {
        fs::read_to_string(&input_sdp_file)?
    };
    let desc_data = signal::decode(line.as_str())?;
    let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;
    println!("Offer received: {}", offer);

    // Set the remote SessionDescription
    peer_connection.set_remote_description(offer)?;

    // Add local candidate
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: pc_local_ip.to_string(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    peer_connection.add_local_candidate(local_candidate_init)?;

    // Create an answer
    let answer = peer_connection.create_answer(None)?;

    // Sets the LocalDescription
    peer_connection.set_local_description(answer)?;

    // Output the answer in base64 so we can paste it in browser
    if let Some(local_desc) = peer_connection.local_description() {
        println!("answer created: {}", local_desc);
        let json_str = serde_json::to_string(local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("{b64}");
    } else {
        println!("generate local_description failed!");
        return Err(Error::ErrPeerConnLocalDescriptionNil.into());
    }

    println!("listening {}...", pc_udp_socket.local_addr()?);

    let mut mdns_buf = vec![0; 2000];
    let mut pc_buf = vec![0; 2000];
    'EventLoop: loop {
        while let Some(msg) = peer_connection.poll_write() {
            if msg.transport.peer_addr.port() == MDNS_PORT {
                match mdns_udp_socket
                    .send_to(&msg.message, msg.transport.peer_addr)
                    .await
                {
                    Ok(n) => {
                        trace!(
                            "socket write to {} with bytes {}",
                            msg.transport.peer_addr, n
                        );
                    }
                    Err(err) => {
                        error!(
                            "socket write to {} with error {}",
                            msg.transport.peer_addr, err
                        );
                    }
                }
            } else {
                match pc_udp_socket
                    .send_to(&msg.message, msg.transport.peer_addr)
                    .await
                {
                    Ok(n) => {
                        trace!(
                            "socket write to {} with bytes {}",
                            msg.transport.peer_addr, n
                        );
                    }
                    Err(err) => {
                        error!(
                            "socket write to {} with error {}",
                            msg.transport.peer_addr, err
                        );
                    }
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    println!("ICE Connection State has changed: {ice_connection_state}");
                    if ice_connection_state == RTCIceConnectionState::Failed {
                        eprintln!("ICE Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(data_channel_event) => {
                    println!("OnDataChannel event: {:?}", data_channel_event);
                    match data_channel_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            let dc = peer_connection
                                .data_channel(channel_id)
                                .ok_or(Error::ErrDataChannelClosed)?;
                            println!("Data channel '{}'-'{}' open", dc.label(), dc.id());
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(channel_id, data_channel_message) => {
                    let mut dc = peer_connection
                        .data_channel(channel_id)
                        .ok_or(Error::ErrDataChannelClosed)?;
                    let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                    println!(
                        "Message from DataChannel '{}': '{}', Echoing back",
                        dc.label(),
                        msg_str
                    );
                    dc.send_text(msg_str)?;
                }
            }
        }

        // Poll peer_connection to get next timeout
        let eto = peer_connection
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            peer_connection.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                trace!("pipeline socket exit loop");
                break 'EventLoop;
            }
            res = message_rx.recv() => {
                match res {
                    Ok(message) => {
                        peer_connection.handle_write(message)?;
                    }
                    Err(err) => {
                        eprintln!("write_rx error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
            res = event_rx.recv() => {
                match res {
                    Ok(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    Err(err) => {
                        eprintln!("event_rx error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
            _ = timer.as_mut() => {
                peer_connection.handle_timeout(Instant::now())?;
            }
            res = pc_udp_socket.recv_from(&mut pc_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes", n);
                        peer_connection.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: pc_udp_socket.local_addr()?,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&pc_buf[..n]),
                        })?;
                    }
                    Err(err) => {
                        eprintln!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
            res = mdns_udp_socket.recv_from(&mut mdns_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes", n);
                        peer_connection.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: mdns_udp_socket.local_addr()?,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&mdns_buf[..n]),
                        })?;
                    }
                    Err(err) => {
                        eprintln!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    peer_connection.close()?;

    Ok(())
}
