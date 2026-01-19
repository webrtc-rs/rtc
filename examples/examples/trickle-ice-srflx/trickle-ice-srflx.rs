// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//! trickle-ice demonstrates the Trickle ICE APIs.
//!
//! ICE is the subsystem WebRTC uses to establish connectivity.
//! Trickle ICE is the process of sharing addresses as soon as they are gathered.
//! This parallelizes establishing a connection with a remote peer and starting
//! sessions with TURN servers.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use futures_util::{SinkExt, StreamExt};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Response, Server, StatusCode};
use ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use log::{error, info, trace};
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
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, RTCIceCandidate};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::{client::*, message::*, xoraddr::*};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{fs::OpenOptions, io::Write, str::FromStr};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "trickle-ice-srflx")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of how to add ServerReflexive (STUN) type local candidate.", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
}

static INDEX: &str = "examples/examples/trickle-ice-srflx/index.html";

// Messages from WebSocket handler
#[derive(Debug)]
enum WsMessage {
    Offer(RTCSessionDescription),
    IceCandidate(RTCIceCandidateInit),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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

    // Start HTTP server in background
    tokio::spawn(run_http_server());

    println!("Open http://localhost:8080 to access this demo");
    println!("Press ctrl-c to stop");

    let (srflx_tx, srflx_rx) = tokio::sync::mpsc::channel::<(XorMappedAddress, SocketAddr)>(8);

    let stun_server = "stun.l.google.com:19302".to_owned();

    // gather ServerReflexive candidate
    tokio::spawn(run_srflx_gather(srflx_tx, stun_server.clone()));

    // Run the main event loop with WebSocket handling
    run_main_loop(srflx_rx, stun_server).await
}

async fn run_http_server() {
    let addr = SocketAddr::from_str("0.0.0.0:8080").unwrap();
    let make_svc = make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(|req| async move {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/") | (&Method::GET, "/index.html") => {
                    match tokio::fs::read_to_string(INDEX).await {
                        Ok(content) => Ok::<_, hyper::Error>(
                            Response::builder()
                                .header("Content-Type", "text/html")
                                .body(Body::from(content))
                                .unwrap(),
                        ),
                        Err(_) => Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::from("Not Found"))
                            .unwrap()),
                    }
                }
                _ => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("Not Found"))
                    .unwrap()),
            }
        }))
    });

    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await {
        eprintln!("HTTP server error: {e}");
    }
}

async fn run_srflx_gather(
    srflx_tx: tokio::sync::mpsc::Sender<(XorMappedAddress, SocketAddr)>,
    stun_server: String,
) -> shared::error::Result<()> {
    let conn = std::net::UdpSocket::bind("0:0")?;
    println!("Local address: {}", conn.local_addr()?);

    println!("Connecting to: {stun_server}");
    conn.connect(stun_server)?;

    let mut client = ClientBuilder::new().build(
        conn.local_addr()?,
        conn.peer_addr()?,
        TransportProtocol::UDP,
    )?;

    let mut msg = rtc::stun::message::Message::new();
    msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;
    client.handle_write(msg)?;
    while let Some(transmit) = client.poll_write() {
        conn.send(&transmit.message)?;
    }

    let mut buf = vec![0u8; 1500];
    let n = conn.recv(&mut buf)?;
    client.handle_read(TaggedBytesMut {
        now: Instant::now(),
        transport: TransportContext {
            local_addr: conn.local_addr()?,
            peer_addr: conn.peer_addr()?,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&buf[..n]),
    })?;

    if let Some(event) = client.poll_event() {
        let msg = event.result?;
        let mut xor_addr = XorMappedAddress::default();
        xor_addr.get_from(&msg)?;
        println!("Got response: {xor_addr}");

        if let Err(err) = srflx_tx.send((xor_addr, conn.local_addr()?)).await {
            eprintln!("Failed to send srflx message: {err}");
        }
    }

    client.close()
}

async fn run_main_loop(
    mut srflx_rx: tokio::sync::mpsc::Receiver<(XorMappedAddress, SocketAddr)>,
    stun_server: String,
) -> Result<()> {
    // WebSocket server listener (separate port for WebSocket)
    let ws_listener = TcpListener::bind("0.0.0.0:8081").await?;
    println!("WebSocket server listening on ws://localhost:8081");

    // Note: The index.html needs to connect to port 8081 for WebSocket
    // Or we need to modify it. For now, let's update the HTML.

    // State for the main loop
    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut udp_socket: Option<UdpSocket> = None;
    let mut local_addr: Option<SocketAddr> = None;
    let mut data_channel_id: Option<u16> = None;
    let mut last_send = Instant::now();
    let mut ws_stream: Option<WebSocketStream<TcpStream>> = None;
    let mut buf = vec![0; 2000];

    loop {
        // Process peer connection if it exists
        if let Some(pc) = peer_connection.as_mut() {
            // Poll writes
            while let Some(msg) = pc.poll_write() {
                if let Some(sock) = udp_socket.as_ref() {
                    if let Err(e) = sock.send_to(&msg.message, msg.transport.peer_addr).await {
                        error!("Socket write error: {}", e);
                    }
                }
            }

            // Poll events
            while let Some(event) = pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                        println!("ICE Connection State has changed: {}", state);
                        if state == RTCIceConnectionState::Failed {
                            println!("ICE Connection failed");
                        }
                    }
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        println!("Peer Connection State has changed: {}", state);
                        if state == RTCPeerConnectionState::Failed {
                            println!("Peer Connection failed");
                        } else if state == RTCPeerConnectionState::Connected {
                            println!("Peer Connection connected!");
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            if let Some(dc) = pc.data_channel(channel_id) {
                                println!(
                                    "{} - Data channel '{}'-'{}' open",
                                    chrono::Local::now().format("%H:%M:%S"),
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
                        println!("Message from DataChannel: '{}'", msg_str);
                    }
                }
            }

            // Send periodic messages through data channel (every 3 seconds)
            if let Some(channel_id) = data_channel_id {
                if Instant::now().duration_since(last_send) >= Duration::from_secs(3) {
                    if let Some(mut dc) = pc.data_channel(channel_id) {
                        let message = chrono::Local::now().to_string();
                        if let Err(e) = dc.send_text(message) {
                            println!(
                                "{} - DataChannel closed, stopping send loop: {}",
                                chrono::Local::now().format("%H:%M:%S"),
                                e
                            );
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
                // Handle UDP data
                res = async {
                    if let Some(sock) = udp_socket.as_ref() {
                        sock.recv_from(&mut buf).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Ok((n, peer_addr)) = res {
                        if let Some(local) = local_addr {
                            pc.handle_read(TaggedBytesMut {
                                now: Instant::now(),
                                transport: TransportContext {
                                    local_addr: local,
                                    peer_addr,
                                    ecn: None,
                                    transport_protocol: TransportProtocol::UDP,
                                },
                                message: BytesMut::from(&buf[..n]),
                            }).ok();
                        }
                    }
                }
                srflx = srflx_rx.recv() => {
                    if let Some((srflx, laddr)) = srflx {
                        // Now that both local and remote descriptions are set,
                        // gather and add local host candidate (simulates trickle ICE gathering)
                        let candidate = CandidateServerReflexiveConfig{
                            base_config: CandidateConfig {
                                network: "udp".to_owned(),
                                address: srflx.ip.to_string(),
                                port: srflx.port,
                                component: 1,
                                ..Default::default()
                            },
                            rel_addr: laddr.ip().to_string(),
                            rel_port: laddr.port(),
                            ..Default::default()
                        }
                        .new_candidate_server_reflexive()?;
                        let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;

                        // Add to peer connection after SDP exchange
                        pc.add_local_candidate(local_candidate_init.clone())?;
                        println!("Added local ServerReflexive ICE candidate: {}", local_candidate_init.candidate);

                        // Send answer to browser
                        if let Some(ref mut ws) = ws_stream {
                            // Send our local ICE candidate to browser (trickle ICE)
                            let json = serde_json::to_string(&local_candidate_init)?;
                            info!("Sending local ICE candidate: {}", local_candidate_init.candidate);
                            ws.send(Message::Text(json.into())).await?;
                        }
                    }
                }
                // Handle WebSocket messages
                msg = async {
                    if let Some(ref mut ws) = ws_stream {
                        ws.next().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Some(ws_msg) = parse_ws_message(&text) {
                                match ws_msg {
                                    WsMessage::IceCandidate(candidate) => {
                                        println!("Adding remote ICE candidate: {}", candidate.candidate);
                                        if let Err(e) = pc.add_remote_candidate(candidate) {
                                            eprintln!("Failed to add ICE candidate: {}", e);
                                        }
                                    }
                                    WsMessage::Offer(_) => {
                                        error!("Received offer while already connected");
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            info!("WebSocket closed, cleaning up");
                            ws_stream = None;
                            peer_connection = None;
                            udp_socket = None;
                            local_addr = None;
                            data_channel_id = None;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            ws_stream = None;
                        }
                        _ => {}
                    }
                }
                // Accept new WebSocket connections
                Ok((stream, addr)) = ws_listener.accept() => {
                    info!("New WebSocket connection from {}", addr);
                    // Only accept if we don't have an active connection
                    if ws_stream.is_none() {
                        match tokio_tungstenite::accept_async(stream).await {
                            Ok(ws) => {
                                ws_stream = Some(ws);
                                info!("WebSocket handshake completed");
                            }
                            Err(e) => error!("WebSocket handshake failed: {}", e),
                        }
                    } else {
                        info!("Rejecting connection, already have active WebSocket");
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
                // Handle WebSocket messages (waiting for offer)
                msg = async {
                    if let Some(ref mut ws) = ws_stream {
                        ws.next().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Some(ws_msg) = parse_ws_message(&text) {
                                match ws_msg {
                                    WsMessage::Offer(offer) => {
                                        println!("Received offer, creating peer connection");

                                        // Create UDP socket
                                        let sock = UdpSocket::bind("127.0.0.1:0").await?;
                                        let local = sock.local_addr()?;
                                        local_addr = Some(local);
                                        println!("Bound to {}", local);

                                        let mut setting_engine = SettingEngine::default();
                                        setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

                                        let config = RTCConfigurationBuilder::new()
                                            .with_ice_servers(vec![RTCIceServer {
                                                urls: vec![format!("stun:{}", stun_server)],
                                                ..Default::default()
                                            }])
                                            .with_setting_engine(setting_engine)
                                            .build();

                                        let mut pc = RTCPeerConnection::new(config)?;
                                        println!("Created peer connection");

                                        // Set remote description
                                        println!("Setting remote description {}", offer);
                                        pc.set_remote_description(offer)?;

                                        // Create answer
                                        let answer = pc.create_answer(None)?;
                                        pc.set_local_description(answer.clone())?;
                                        println!("Created and set answer {}", answer);

                                        // Now that both local and remote descriptions are set,
                                        // gather and add local host candidate (simulates trickle ICE gathering)
                                        /*let candidate = CandidateHostConfig {
                                            base_config: CandidateConfig {
                                                network: "udp".to_owned(),
                                                address: local.ip().to_string(),
                                                port: local.port(),
                                                component: 1,
                                                ..Default::default()
                                            },
                                            ..Default::default()
                                        }
                                        .new_candidate_host()?;
                                        let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;

                                        // Add to peer connection after SDP exchange
                                        pc.add_local_candidate(local_candidate_init.clone())?;
                                        println!("Added local ICE candidate: {}", local_candidate_init.candidate);*/

                                        // Send answer to browser
                                        if let Some(ref mut ws) = ws_stream {
                                            let json = serde_json::to_string(&answer)?;
                                            info!("Sending SDP answer");
                                            ws.send(Message::Text(json.into())).await?;

                                            // Send our local ICE candidate to browser (trickle ICE)
                                            /*let json = serde_json::to_string(&local_candidate_init)?;
                                            info!("Sending local ICE candidate: {}", local_candidate_init.candidate);
                                            ws.send(Message::Text(json.into())).await?;*/
                                        }

                                        peer_connection = Some(pc);
                                        udp_socket = Some(sock);
                                    }
                                    WsMessage::IceCandidate(candidate) => {
                                        info!("Received ICE candidate before offer, ignoring: {}", candidate.candidate);
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            info!("WebSocket closed");
                            ws_stream = None;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            ws_stream = None;
                        }
                        _ => {}
                    }
                }
                // Accept new WebSocket connections
                Ok((stream, addr)) = ws_listener.accept() => {
                    info!("New WebSocket connection from {}", addr);
                    if ws_stream.is_none() {
                        match tokio_tungstenite::accept_async(stream).await {
                            Ok(ws) => {
                                ws_stream = Some(ws);
                                info!("WebSocket handshake completed");
                            }
                            Err(e) => error!("WebSocket handshake failed: {}", e),
                        }
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

fn parse_ws_message(text: &str) -> Option<WsMessage> {
    // Try to parse as SessionDescription first
    if let Ok(offer) = serde_json::from_str::<RTCSessionDescription>(text) {
        if !offer.sdp.is_empty() {
            return Some(WsMessage::Offer(offer));
        }
    }

    // Try to parse as ICE candidate
    if let Ok(candidate) = serde_json::from_str::<RTCIceCandidateInit>(text) {
        if !candidate.candidate.is_empty() {
            return Some(WsMessage::IceCandidate(candidate));
        }
    }

    trace!("Unknown WebSocket message: {}", text);
    None
}
