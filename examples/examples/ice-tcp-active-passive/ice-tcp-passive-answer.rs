// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//! ice-tcp-active-answer demonstrates the answering side with TCP passive candidates.
//!
//! This example shows:
//! - TCP passive candidate creation (accepts incoming TCP connections)
//! - TCP framing (RFC 4571) for ICE messages
//! - Signaling via HTTP with the offer side

use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use log::{error, info};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "ice-tcp-active-answer")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "ICE TCP passive answerer - accepts TCP connections", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("0.0.0.0:8443"))]
    tcp_address: String,
    #[arg(long, default_value_t = format!("0.0.0.0:60000"))]
    http_address: String,
    #[arg(long, default_value_t = format!("localhost:50000"))]
    offer_address: String,
}

// Commands from HTTP server to event loop
enum Command {
    AddIceCandidate(RTCIceCandidateInit),
    SetRemoteDescription(
        RTCSessionDescription,
        tokio::sync::oneshot::Sender<RTCSessionDescription>,
    ),
}

async fn signal_candidate(addr: &str, c: &RTCIceCandidateInit) -> Result<()> {
    let payload = c.candidate.clone();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/candidate"))
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(payload))?;

    let _ = Client::new().request(req).await?;
    Ok(())
}

async fn remote_handler(
    req: Request<Body>,
    cmd_tx: mpsc::Sender<Command>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/candidate") => {
            let candidate =
                match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
                    Ok(s) => s.to_owned(),
                    Err(e) => {
                        let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok(response);
                    }
                };

            let _ = cmd_tx
                .send(Command::AddIceCandidate(RTCIceCandidateInit {
                    candidate,
                    ..Default::default()
                }))
                .await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }

        (&Method::POST, "/sdp") => {
            let sdp_str = match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?)
            {
                Ok(s) => s.to_owned(),
                Err(e) => {
                    let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            let sdp = match serde_json::from_str::<RTCSessionDescription>(&sdp_str) {
                Ok(s) => s,
                Err(e) => {
                    let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            // Create oneshot channel for response
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();

            let _ = cmd_tx
                .send(Command::SetRemoteDescription(sdp, response_tx))
                .await;

            // Wait for answer
            match response_rx.await {
                Ok(answer) => {
                    let json = serde_json::to_string(&answer).unwrap();
                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .body(Body::from(json))
                        .unwrap())
                }
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to get answer"))
                    .unwrap()),
            }
        }
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.debug {
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
            .filter(None, log::LevelFilter::Trace)
            .init();
    }

    let offer_addr = cli.offer_address.clone();

    // Start TCP listener for ICE connections (passive mode)
    let tcp_listener = TcpListener::bind(&cli.tcp_address).await?;
    let tcp_local = tcp_listener.local_addr()?;
    println!("TCP passive listener at {}", tcp_local);

    // Create channel for HTTP server to send commands to event loop
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(100);

    // Start HTTP server
    println!("HTTP server listening on http://{}", cli.http_address);
    let http_addr = SocketAddr::from_str(&cli.http_address)?;
    tokio::spawn(async move {
        let make_svc = make_service_fn(move |_| {
            let cmd_tx = cmd_tx.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| remote_handler(req, cmd_tx.clone())))
            }
        });
        let server = Server::bind(&http_addr).serve(make_svc);
        if let Err(e) = server.await {
            eprintln!("HTTP server error: {e}");
        }
    });

    println!("Waiting for offer from http://{}", cli.offer_address);
    println!("Press ctrl-c to stop");

    // State
    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut tcp_stream: Option<TcpStream> = None;
    let mut local_addr: Option<SocketAddr> = None;
    let mut data_channel_id: Option<u16> = None;
    let mut last_send = Instant::now();
    let mut buf = vec![0u8; 2000];
    let mut tcp_decoder = TcpFrameDecoder::new();

    loop {
        if let Some(pc) = peer_connection.as_mut() {
            // Poll writes - send packets via TCP with framing
            while let Some(msg) = pc.poll_write() {
                if let Some(ref mut stream) = tcp_stream {
                    let framed = frame_packet(&msg.message);
                    if let Err(e) = stream.write_all(&framed).await {
                        error!("TCP write error: {}", e);
                    }
                }
            }

            // Poll events
            while let Some(event) = pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                        println!("[Answer] ICE Connection State: {}", state);
                        if state == RTCIceConnectionState::Failed {
                            println!("[Answer] ICE Connection failed");
                        }
                    }
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        println!("[Answer] Peer Connection State: {}", state);
                        if state == RTCPeerConnectionState::Connected {
                            println!("[Answer] Connected!");
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            if let Some(dc) = pc.data_channel(channel_id) {
                                println!(
                                    "[Answer] Data channel '{}'-'{}' open",
                                    dc.label(),
                                    dc.id()
                                );
                                data_channel_id = Some(channel_id);
                                last_send = Instant::now();
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            // Poll reads (data channel messages)
            while let Some(message) = pc.poll_read() {
                match message {
                    RTCMessage::RtpPacket(_, _) => {}
                    RTCMessage::RtcpPacket(_, _) => {}
                    RTCMessage::DataChannelMessage(_channel_id, data_channel_message) => {
                        let msg_str = String::from_utf8(data_channel_message.data.to_vec())
                            .unwrap_or_default();
                        println!("[Answer] Message from DataChannel: '{}'", msg_str);
                    }
                }
            }

            // Send periodic messages through data channel
            if let Some(channel_id) = data_channel_id {
                if Instant::now().duration_since(last_send) >= Duration::from_secs(3) {
                    if let Some(mut dc) = pc.data_channel(channel_id) {
                        let message = format!("[Answer] {}", chrono::Local::now());
                        if let Err(e) = dc.send_text(message) {
                            println!("[Answer] DataChannel send error: {}", e);
                            data_channel_id = None;
                        }
                        last_send = Instant::now();
                    }
                }
            }

            // Get next timeout
            let timeout = pc
                .poll_timeout()
                .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
            let delay = timeout.saturating_duration_since(Instant::now());

            if delay.is_zero() {
                pc.handle_timeout(Instant::now()).ok();
                continue;
            }

            let timer = tokio::time::sleep(delay.min(Duration::from_millis(100)));
            tokio::pin!(timer);

            tokio::select! {
                _ = timer => {
                    pc.handle_timeout(Instant::now()).ok();
                }
                // Handle TCP data with framing
                result = async {
                    if let Some(ref mut stream) = tcp_stream {
                        stream.read(&mut buf).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match result {
                        Ok(n) if n > 0 => {
                            tcp_decoder.extend_from_slice(&buf[..n]);
                            while let Some(packet) = tcp_decoder.next_packet() {
                                if let Some(local) = local_addr {
                                    let peer_addr = tcp_stream.as_ref()
                                        .and_then(|s| s.peer_addr().ok())
                                        .unwrap_or_else(|| SocketAddr::from_str("0.0.0.0:0").unwrap());

                                    pc.handle_read(TaggedBytesMut {
                                        now: Instant::now(),
                                        transport: TransportContext {
                                            local_addr: local,
                                            peer_addr,
                                            ecn: None,
                                            transport_protocol: TransportProtocol::TCP,
                                        },
                                        message: BytesMut::from(&packet[..]),
                                    }).ok();
                                }
                            }
                        }
                        Ok(_) => {
                            info!("TCP connection closed");
                            tcp_stream = None;
                            tcp_decoder.clear();
                        }
                        Err(e) => {
                            error!("TCP read error: {}", e);
                            tcp_stream = None;
                            tcp_decoder.clear();
                        }
                    }
                }
                // Accept new TCP connections
                Ok((stream, addr)) = tcp_listener.accept() => {
                    println!("[Answer] New TCP connection from {}", addr);
                    if tcp_stream.is_none() {
                        tcp_stream = Some(stream);
                    } else {
                        info!("Already have a TCP connection, dropping new one");
                    }
                }
                // Handle commands
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Command::AddIceCandidate(candidate) => {
                            println!("[Answer] Adding remote candidate: {}", candidate.candidate);
                            if let Err(e) = pc.add_remote_candidate(candidate) {
                                error!("Failed to add candidate: {}", e);
                            }
                        }
                        Command::SetRemoteDescription(_, response_tx) => {
                            error!("Received offer while already connected");
                            let _ = response_tx.send(RTCSessionDescription::default());
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!();
                    break;
                }
            }
        } else {
            // No peer connection yet, wait for offer
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Command::SetRemoteDescription(offer, response_tx) => {
                            println!("[Answer] Received offer, creating peer connection with TCP passive candidate");

                            // Use 127.0.0.1 for local testing if bound to 0.0.0.0
                            let candidate_ip: std::net::IpAddr = if tcp_local.ip().is_unspecified() {
                                "127.0.0.1".parse().unwrap()
                            } else {
                                tcp_local.ip()
                            };
                            local_addr = Some(SocketAddr::new(candidate_ip, tcp_local.port()));

                            let mut setting_engine = SettingEngine::default();
                            setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
                            setting_engine.set_network_types(vec![
                                ice::network_type::NetworkType::Tcp4,
                                ice::network_type::NetworkType::Tcp6,
                            ]);

                            let config = RTCConfigurationBuilder::new()
                                .with_setting_engine(setting_engine)
                                .build();

                            let mut pc = RTCPeerConnection::new(config)?;
                            println!("[Answer] Created peer connection");

                            // Set remote description
                            println!("[Answer] set_remote_description {}", offer);
                            pc.set_remote_description(offer)?;

                            // Create TCP passive candidate
                            let candidate = CandidateHostConfig {
                                base_config: CandidateConfig {
                                    network: "tcp".to_owned(),
                                    address: candidate_ip.to_string(),
                                    port: tcp_local.port(),
                                    component: 1,
                                    ..Default::default()
                                },
                                tcp_type: ice::tcp_type::TcpType::Passive,
                            }
                            .new_candidate_host()?;
                            let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
                            println!("[Answer] TCP passive candidate: {}", local_candidate_init.candidate);

                            // Add local candidate BEFORE create_answer
                            pc.add_local_candidate(local_candidate_init.clone())?;

                            // Create and set answer
                            let answer = pc.create_answer(None)?;
                            pc.set_local_description(answer.clone())?;
                            println!("[Answer] set_local_description {}", answer);

                            // Send answer back
                            let _ = response_tx.send(answer);

                            // Signal our candidate to the offer side
                            let offer_addr_clone = offer_addr.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if let Err(e) = signal_candidate(&offer_addr_clone, &local_candidate_init).await {
                                    error!("Failed to signal candidate: {}", e);
                                }
                            });

                            peer_connection = Some(pc);
                        }
                        Command::AddIceCandidate(_) => {
                            // Ignore candidates before peer connection exists
                        }
                    }
                }
                // Accept TCP connections even before peer connection exists
                Ok((stream, addr)) = tcp_listener.accept() => {
                    println!("[Answer] New TCP connection from {} (before peer connection)", addr);
                    if tcp_stream.is_none() {
                        tcp_stream = Some(stream);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!();
                    break;
                }
            }
        }
    }

    if let Some(mut pc) = peer_connection {
        pc.close()?;
    }

    Ok(())
}
