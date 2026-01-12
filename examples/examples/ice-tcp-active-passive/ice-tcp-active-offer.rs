// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//! ice-tcp-active-offer demonstrates the offering side with TCP active candidates.
//!
//! This example shows:
//! - TCP active candidate creation (initiates outgoing TCP connections)
//! - TCP framing (RFC 4571) for ICE messages
//! - Signaling via HTTP with the answer side
//!
//! Key difference from TCP passive:
//! - Active candidates don't have a listening port
//! - The application initiates TCP connections to remote passive candidates

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
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "ice-tcp-active-offer")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "ICE TCP active offerer - initiates TCP connections", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("0.0.0.0:50000"))]
    http_address: String,
    #[arg(long, default_value_t = format!("localhost:60000"))]
    answer_address: String,
}

// Commands from HTTP server to event loop
enum Command {
    AddIceCandidate(RTCIceCandidateInit),
    SetRemoteDescription(RTCSessionDescription),
}

// Parsed remote candidate info for TCP connection
#[derive(Debug, Clone)]
struct RemoteTcpCandidate {
    address: String,
    port: u16,
}

fn parse_tcp_passive_candidate(candidate: &str) -> Option<RemoteTcpCandidate> {
    // Parse ICE candidate string like:
    // "candidate:... udp/tcp ... <ip> <port> typ host tcptype passive"
    let parts: Vec<&str> = candidate.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    // Check if it's a TCP candidate
    let transport = parts.get(2)?;
    if !transport.eq_ignore_ascii_case("tcp") {
        return None;
    }

    // Check if it's passive type
    if !candidate.contains("tcptype passive") {
        return None;
    }

    let address = parts.get(4)?.to_string();
    let port: u16 = parts.get(5)?.parse().ok()?;

    Some(RemoteTcpCandidate { address, port })
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

            println!("[Offer] Received answer from remote peer");
            let _ = cmd_tx.send(Command::SetRemoteDescription(sdp)).await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
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

    let answer_addr = cli.answer_address.clone();

    // Configure for TCP only
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_network_types(vec![
        ice::network_type::NetworkType::Tcp4,
        ice::network_type::NetworkType::Tcp6,
    ]);

    let config = RTCConfigurationBuilder::new()
        .with_setting_engine(setting_engine)
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Create a datachannel with label 'data'
    let _ = peer_connection.create_data_channel("data", None)?;

    // Create TCP active candidate
    // Active candidates use port 9 (discard) as a placeholder - they don't listen
    // The actual connection is initiated by the application when a remote passive candidate is received
    let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: local_ip.to_string(),
            port: 9, // Port 9 is the "discard" port, used as placeholder for active candidates
            component: 1,
            ..Default::default()
        },
        tcp_type: ice::tcp_type::TcpType::Active,
    }
    .new_candidate_host()?;

    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    println!(
        "[Offer] TCP active candidate: {}",
        local_candidate_init.candidate
    );

    // Add local candidate BEFORE create_offer
    peer_connection.add_local_candidate(local_candidate_init.clone())?;

    // Create an offer to send to the other process
    let offer = peer_connection.create_offer(None)?;
    peer_connection.set_local_description(offer.clone())?;
    println!("[Offer] set_local_description {}", offer);

    // Create channel for HTTP server to send commands to event loop
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(100);

    // Start HTTP server
    println!(
        "[Offer] HTTP server listening on http://{}",
        cli.http_address
    );
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

    // Give the HTTP server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send offer to answer server
    println!(
        "[Offer] Sending offer to answer server at http://{}/sdp",
        answer_addr
    );
    let payload = serde_json::to_string(&offer)?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{answer_addr}/sdp"))
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(payload))?;

    let resp = Client::new().request(req).await?;
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let answer: RTCSessionDescription = serde_json::from_slice(&body_bytes)?;
    println!("[Offer] Received answer {}", answer);
    peer_connection.set_remote_description(answer)?;

    // Send local candidate
    tokio::time::sleep(Duration::from_millis(100)).await;
    let signal_addr = cli.answer_address.clone();
    let candidate_to_send = local_candidate_init.clone();
    let payload = candidate_to_send.candidate.clone();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{signal_addr}/candidate"))
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(payload))?;
    let _ = Client::new().request(req).await?;
    println!("[Offer] Sent local candidate");

    println!("[Offer] Press ctrl-c to stop");

    // State
    let mut tcp_stream: Option<TcpStream> = None;
    let mut local_addr: Option<SocketAddr> = None;
    let mut data_channel_id: Option<u16> = None;
    let mut last_send = Instant::now();
    let mut buf = vec![0u8; 2000];
    let mut tcp_decoder = TcpFrameDecoder::new();
    let mut pending_remote_candidates: Vec<RemoteTcpCandidate> = Vec::new();

    loop {
        // Poll writes - send packets via TCP with framing
        while let Some(msg) = peer_connection.poll_write() {
            if let Some(ref mut stream) = tcp_stream {
                let framed = frame_packet(&msg.message);
                if let Err(e) = stream.write_all(&framed).await {
                    error!("TCP write error: {}", e);
                }
            }
        }

        // Poll events
        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    println!("[Offer] ICE Connection State: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        println!("[Offer] ICE Connection failed");
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("[Offer] Peer Connection State: {}", state);
                    if state == RTCPeerConnectionState::Connected {
                        println!("[Offer] Connected!");
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(channel_id) => {
                        if let Some(dc) = peer_connection.data_channel(channel_id) {
                            println!("[Offer] Data channel '{}'-'{}' open", dc.label(), dc.id());
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
        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(_channel_id, data_channel_message) => {
                    let msg_str =
                        String::from_utf8(data_channel_message.data.to_vec()).unwrap_or_default();
                    println!("[Offer] Message from DataChannel: '{}'", msg_str);
                }
            }
        }

        // Try to connect to pending remote TCP passive candidates
        if tcp_stream.is_none() && !pending_remote_candidates.is_empty() {
            let candidate = pending_remote_candidates.remove(0);
            let target = format!("{}:{}", candidate.address, candidate.port);
            println!(
                "[Offer] Connecting to remote TCP passive candidate: {}",
                target
            );

            match TcpStream::connect(&target).await {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()?;
                    let local = stream.local_addr()?;
                    println!("[Offer] TCP connection established to {}", peer_addr);
                    local_addr = Some(local);
                    tcp_stream = Some(stream);
                }
                Err(e) => {
                    error!("[Offer] Failed to connect to {}: {}", target, e);
                }
            }
        }

        // Send periodic messages through data channel
        if let Some(channel_id) = data_channel_id {
            if Instant::now().duration_since(last_send) >= Duration::from_secs(3) {
                if let Some(mut dc) = peer_connection.data_channel(channel_id) {
                    let message = format!("[Offer] {}", chrono::Local::now());
                    if let Err(e) = dc.send_text(message) {
                        println!("[Offer] DataChannel send error: {}", e);
                        data_channel_id = None;
                    }
                    last_send = Instant::now();
                }
            }
        }

        // Get next timeout
        let timeout = peer_connection
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let delay = timeout.saturating_duration_since(Instant::now());

        if delay.is_zero() {
            peer_connection.handle_timeout(Instant::now()).ok();
            continue;
        }

        let timer = tokio::time::sleep(delay.min(Duration::from_millis(100)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer => {
                peer_connection.handle_timeout(Instant::now()).ok();
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

                                peer_connection.handle_read(TaggedBytesMut {
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
            // Handle commands from HTTP server
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    Command::AddIceCandidate(candidate_init) => {
                        println!("[Offer] Adding remote candidate: {}", candidate_init.candidate);

                        // Check if this is a TCP passive candidate we should connect to
                        if let Some(remote_tcp) = parse_tcp_passive_candidate(&candidate_init.candidate) {
                            println!("[Offer] Found TCP passive candidate: {}:{}", remote_tcp.address, remote_tcp.port);
                            pending_remote_candidates.push(remote_tcp);
                        }

                        if let Err(e) = peer_connection.add_remote_candidate(candidate_init) {
                            error!("Failed to add candidate: {}", e);
                        }
                    }
                    Command::SetRemoteDescription(sdp) => {
                        if let Err(e) = peer_connection.set_remote_description(sdp) {
                            error!("Failed to set remote description: {}", e);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    peer_connection.close()?;

    Ok(())
}
