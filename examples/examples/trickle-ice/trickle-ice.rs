//! trickle-ice demonstrates the comprehensive Trickle ICE APIs.
//!
//! ICE is the subsystem WebRTC uses to establish connectivity.
//! Trickle ICE is the process of sharing addresses as soon as they are gathered.
//! This parallelizes establishing a connection with a remote peer and starting
//! sessions with STUN/TURN servers.
//!
//! This example demonstrates gathering all three types of ICE candidates:
//! - Host candidates (local network addresses)
//! - Server Reflexive candidates (via STUN)
//! - Relay candidates (via TURN)

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use futures_util::{SinkExt, StreamExt};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Response, Server, StatusCode};
use ice::candidate::candidate_host::CandidateHostConfig;
use ice::candidate::candidate_relay::CandidateRelayConfig;
use ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use log::{error, info, trace, warn};
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
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::{client::*, message::*, xoraddr::*};
use rtc::turn::client::{
    Client as TurnClient, ClientConfig as TurnClientConfig, Event as TurnEvent,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{fs::OpenOptions, io::Write, str::FromStr};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "trickle-ice")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "A comprehensive example of Trickle ICE with Host, ServerReflexive (STUN), and Relay (TURN) candidates.", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,

    // STUN server configuration
    #[arg(long, default_value_t = format!("stun.l.google.com:19302"))]
    stun_server: String,

    // TURN server configuration (optional)
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    turn_host: String,
    #[arg(long, default_value_t = 3478)]
    turn_port: u16,
    #[arg(long, default_value_t = format!("user=pass"))]
    turn_user: String,
    #[arg(long, default_value_t = format!("webrtc.rs"))]
    turn_realm: String,

    // Candidate type flags
    #[arg(long, default_value_t = false)]
    enable_host: bool,
    #[arg(long, default_value_t = false)]
    enable_srflx: bool,
    #[arg(long, default_value_t = false)]
    enable_relay: bool,
}

static INDEX: &str = "examples/examples/trickle-ice/index.html";

// Messages from WebSocket handler
#[derive(Debug)]
enum WsMessage {
    Offer(RTCSessionDescription),
    IceCandidate(RTCIceCandidateInit),
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let output_log_file = cli.output_log_file.clone();
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
    println!("ICE Candidate Types:");
    println!(
        "  - Host: {}",
        if cli.enable_host {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  - ServerReflexive (STUN): {}",
        if cli.enable_srflx {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  - Relay (TURN): {}",
        if cli.enable_relay {
            "enabled"
        } else {
            "disabled"
        }
    );
    if !cli.enable_host && !cli.enable_srflx && !cli.enable_relay {
        println!("All candidate types are disabled! Let's fallback to use Host type");
        cli.enable_host = true;
    }

    println!("Press ctrl-c to stop");

    // Run the main event loop with WebSocket handling
    run_main_loop(cli).await
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

async fn run_main_loop(cli: Cli) -> Result<()> {
    // WebSocket server listener (separate port for WebSocket)
    let ws_listener = TcpListener::bind("0.0.0.0:8081").await?;
    println!("WebSocket server listening on ws://localhost:8081");

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = udp_socket.local_addr()?;
    println!("UDP socket bound to: {}", local_addr);

    // Initialize STUN client if srflx is enabled
    let mut stun_client: Option<Client> = None;
    let mut stun_server_addr: Option<SocketAddr> = None;
    let mut stun_xor_addr: Option<XorMappedAddress> = None;
    let mut srflx_candidate_added = false;

    if cli.enable_srflx {
        // Resolve STUN server address
        use tokio::net::lookup_host;
        let mut addrs = lookup_host(&cli.stun_server).await?;
        if let Some(addr) = addrs.next() {
            stun_server_addr = Some(addr);
            println!("Resolved STUN server {} to {}", cli.stun_server, addr);

            let transport_context = TransportContext::default();
            let client = ClientBuilder::new().build(
                local_addr,
                transport_context.peer_addr,
                TransportProtocol::UDP,
            )?;
            let mut msg = rtc::stun::message::Message::new();
            msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;

            stun_client = Some(client);
            if let Some(ref mut client) = stun_client {
                client.handle_write(msg)?;
            }
        } else {
            warn!("Failed to resolve STUN server: {}", cli.stun_server);
        }
    }

    // Initialize TURN client if relay is enabled
    let mut turn_client: Option<TurnClient> = None;
    let mut turn_server_addr: Option<SocketAddr> = None;
    let mut allocate_tid: Option<TransactionId> = None;
    let mut relay_addr: Option<SocketAddr> = None;
    let mut relay_candidate_added = false;
    let mut pending_permissions: std::collections::HashMap<TransactionId, SocketAddr> =
        std::collections::HashMap::new();
    let mut granted_permissions: std::collections::HashSet<SocketAddr> =
        std::collections::HashSet::new();

    if cli.enable_relay && !cli.turn_host.is_empty() && !cli.turn_user.is_empty() {
        let cred: Vec<&str> = cli.turn_user.splitn(2, '=').collect();
        if cred.len() == 2 {
            let turn_server_str = format!("{}:{}", cli.turn_host, cli.turn_port);

            // Resolve TURN server address
            use tokio::net::lookup_host;
            let mut addrs = lookup_host(&turn_server_str as &str).await?;
            if let Some(addr) = addrs.next() {
                turn_server_addr = Some(addr);
                println!(
                    "Connecting to TURN server: {} (resolved to {})",
                    turn_server_str, addr
                );

                let cfg = TurnClientConfig {
                    stun_serv_addr: turn_server_str.clone(),
                    turn_serv_addr: turn_server_str.clone(),
                    local_addr,
                    transport_protocol: TransportProtocol::UDP,
                    username: cred[0].to_string(),
                    password: cred[1].to_string(),
                    realm: cli.turn_realm.to_string(),
                    software: String::new(),
                    rto_in_ms: 0,
                };

                let mut client = TurnClient::new(cfg)?;
                let tid = client.allocate()?;
                allocate_tid = Some(tid);
                turn_client = Some(client);
            } else {
                warn!("Failed to resolve TURN server: {}", turn_server_str);
            }
        } else {
            warn!("Invalid TURN credentials format. Use: username=password");
        }
    } else if cli.enable_relay {
        warn!("Relay enabled but TURN server not configured. Use --turn-host and --turn-user");
    }

    // State for the main loop
    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut data_channel_id: Option<u16> = None;
    let mut last_send = Instant::now();
    let mut ws_stream: Option<WebSocketStream<TcpStream>> = None;
    let mut buf = vec![0; 2000];
    let mut host_candidate_added = false;

    loop {
        // Process STUN client if active
        if let Some(ref mut client) = stun_client {
            while let Some(transmit) = client.poll_write() {
                if let Some(stun_addr) = stun_server_addr {
                    udp_socket.send_to(&transmit.message, stun_addr).await?;
                    trace!(
                        "STUN client sent {} bytes to {}",
                        transmit.message.len(),
                        stun_addr
                    );
                }
            }

            let mut close_stun = false;
            while let Some(event) = client.poll_event() {
                match event.result {
                    Ok(msg) => {
                        if stun_xor_addr.is_none() {
                            let mut xor_addr = XorMappedAddress::default();
                            if xor_addr.get_from(&msg).is_ok() {
                                println!("Got STUN response: {}", xor_addr);

                                // Store it first
                                stun_xor_addr = Some(XorMappedAddress {
                                    ip: xor_addr.ip,
                                    port: xor_addr.port,
                                });

                                // Add srflx candidate if peer connection exists
                                if let Some(pc) = peer_connection.as_mut() {
                                    if !srflx_candidate_added {
                                        if let Err(e) = add_srflx_candidate(
                                            pc,
                                            xor_addr,
                                            local_addr,
                                            &mut ws_stream,
                                        )
                                        .await
                                        {
                                            error!("Failed to add srflx candidate: {}", e);
                                        } else {
                                            srflx_candidate_added = true;
                                        }
                                    }
                                }

                                close_stun = true;
                            }
                        }
                    }
                    Err(e) => {
                        error!("STUN error: {}", e);
                        close_stun = true;
                    }
                }
            }

            if close_stun {
                client.close()?;
                stun_client = None;
            }
        }

        // Process TURN client if active
        if let Some(ref mut client) = turn_client {
            // Poll TURN client writes
            while let Some(transmit) = client.poll_write() {
                udp_socket
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await?;
                trace!(
                    "TURN client sent {} bytes to {}",
                    transmit.message.len(),
                    transmit.transport.peer_addr
                );
            }

            // Poll TURN client events
            while let Some(event) = client.poll_event() {
                match event {
                    TurnEvent::TransactionTimeout(_) => {
                        error!("TURN transaction timeout");
                    }
                    TurnEvent::AllocateResponse(tid, addr) => {
                        if Some(tid) == allocate_tid {
                            println!("TURN allocation successful, relay address: {}", addr);
                            relay_addr = Some(addr);

                            // Add relay candidate if peer connection exists
                            if let Some(pc) = peer_connection.as_mut() {
                                if !relay_candidate_added {
                                    if let Err(e) =
                                        add_relay_candidate(pc, addr, local_addr, &mut ws_stream)
                                            .await
                                    {
                                        error!("Failed to add relay candidate: {}", e);
                                    } else {
                                        relay_candidate_added = true;
                                    }
                                }
                            }
                        }
                    }
                    TurnEvent::AllocateError(_, err) => {
                        error!("TURN allocation error: {}", err);
                    }
                    TurnEvent::CreatePermissionResponse(tid, peer_addr) => {
                        if pending_permissions.remove(&tid).is_some() {
                            println!("CreatePermission for peer addr {} is granted", peer_addr);
                            granted_permissions.insert(peer_addr);
                        }
                    }
                    TurnEvent::CreatePermissionError(_, err) => {
                        error!("CreatePermission error: {}", err);
                    }
                    TurnEvent::DataIndicationOrChannelData(_, from, data) => {
                        trace!("TURN relay received {} bytes from {}", data.len(), from);
                        // Forward to peer connection
                        if let Some(pc) = peer_connection.as_mut() {
                            if let Some(relay) = relay_addr {
                                pc.handle_read(TaggedBytesMut {
                                    now: Instant::now(),
                                    transport: TransportContext {
                                        local_addr: relay,
                                        peer_addr: from,
                                        ecn: None,
                                        transport_protocol: TransportProtocol::UDP,
                                    },
                                    message: BytesMut::from(&data[..]),
                                })?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Process peer connection if it exists
        if let Some(pc) = peer_connection.as_mut() {
            // Poll writes
            while let Some(msg) = pc.poll_write() {
                // If TURN relay is active and has permission, use it
                if let (Some(ref mut client), Some(relay)) = (turn_client.as_mut(), relay_addr) {
                    if granted_permissions.contains(&msg.transport.peer_addr) {
                        if let Err(err) = client
                            .relay(relay)?
                            .send_to(&msg.message, msg.transport.peer_addr)
                        {
                            error!("TURN relay send error: {}", err);
                        } else {
                            trace!(
                                "Sent {} bytes via TURN relay to {}",
                                msg.message.len(),
                                msg.transport.peer_addr
                            );
                        }
                        continue;
                    } else {
                        // Relay mode but no permission yet - drop packet
                        trace!(
                            "No TURN permission yet for peer {}, dropping packet",
                            msg.transport.peer_addr
                        );
                        continue;
                    }
                }

                // Otherwise, send directly via UDP (only if relay is not active)
                if let Err(err) = udp_socket
                    .send_to(&msg.message, msg.transport.peer_addr)
                    .await
                {
                    error!("udp_socket write error: {}", err);
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

            // Get next timeout - consider peer connection, STUN, and TURN
            let mut timeout = pc
                .poll_timeout()
                .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

            if let Some(ref mut client) = stun_client {
                if let Some(stun_timeout) = client.poll_timeout() {
                    if stun_timeout < timeout {
                        timeout = stun_timeout;
                    }
                }
            }

            if let Some(ref mut client) = turn_client {
                if let Some(turn_timeout) = client.poll_timeout() {
                    if turn_timeout < timeout {
                        timeout = turn_timeout;
                    }
                }
            }

            let delay = timeout.saturating_duration_since(Instant::now());

            if delay.is_zero() {
                pc.handle_timeout(Instant::now()).ok();
                if let Some(ref mut client) = stun_client {
                    client.handle_timeout(Instant::now()).ok();
                }
                if let Some(ref mut client) = turn_client {
                    client.handle_timeout(Instant::now()).ok();
                }
                continue;
            }

            let timer = tokio::time::sleep(delay.min(Duration::from_millis(100)));
            tokio::pin!(timer);

            tokio::select! {
                _ = timer => {
                    pc.handle_timeout(Instant::now()).ok();
                    if let Some(ref mut client) = stun_client {
                        client.handle_timeout(Instant::now()).ok();
                    }
                    if let Some(ref mut client) = turn_client {
                        client.handle_timeout(Instant::now()).ok();
                    }
                }
                // Handle UDP data
                res = udp_socket.recv_from(&mut buf) => {
                    if let Ok((n, peer_addr)) = res {
                        trace!("udp_socket read {} bytes from {}", n, peer_addr);

                        // Check if this is STUN response
                        if let Some(ref mut client) = stun_client {
                            if let Some(stun_addr) = stun_server_addr {
                                if peer_addr == stun_addr {
                                    client.handle_read(TaggedBytesMut {
                                        now: Instant::now(),
                                        transport: TransportContext {
                                            local_addr,
                                            peer_addr,
                                            transport_protocol: TransportProtocol::UDP,
                                            ecn: None,
                                        },
                                        message: BytesMut::from(&buf[..n]),
                                    })?;
                                    continue;
                                }
                            }
                        }

                        // Check if this is TURN response
                        if let Some(ref mut client) = turn_client {
                            if let Some(turn_addr) = turn_server_addr {
                                if peer_addr == turn_addr {
                                    client.handle_read(TaggedBytesMut {
                                        now: Instant::now(),
                                        transport: TransportContext {
                                            local_addr,
                                            peer_addr,
                                            ecn: None,
                                            transport_protocol: TransportProtocol::UDP,
                                        },
                                        message: BytesMut::from(&buf[..n]),
                                    })?;
                                    continue;
                                }
                            }
                        }

                        // Otherwise, it's WebRTC data
                        pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        })?;
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

                                        // Extract peer address and create TURN permission if needed
                                        if let (Some(ref mut client), Some(relay)) = (turn_client.as_mut(), relay_addr) {
                                            if let Some(addr) = extract_address_from_candidate(&candidate.candidate) {
                                                if !granted_permissions.contains(&addr) &&
                                                   !pending_permissions.values().any(|&v| v == addr) {
                                                    if let Some(tid) = client.relay(relay)?.create_permission(addr)? {
                                                        pending_permissions.insert(tid, addr);
                                                        println!("Requesting TURN permission for peer {}", addr);
                                                    }
                                                }
                                            }
                                        }

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
            // No peer connection yet, wait for offer - but still process STUN/TURN
            let mut timeout = Instant::now() + Duration::from_millis(100);

            if let Some(ref mut client) = stun_client {
                if let Some(stun_timeout) = client.poll_timeout() {
                    if stun_timeout < timeout {
                        timeout = stun_timeout;
                    }
                }
            }

            if let Some(ref mut client) = turn_client {
                if let Some(turn_timeout) = client.poll_timeout() {
                    if turn_timeout < timeout {
                        timeout = turn_timeout;
                    }
                }
            }

            let delay = timeout.saturating_duration_since(Instant::now());
            if delay.is_zero() {
                if let Some(ref mut client) = stun_client {
                    client.handle_timeout(Instant::now()).ok();
                }
                if let Some(ref mut client) = turn_client {
                    client.handle_timeout(Instant::now()).ok();
                }
                continue;
            }

            let timer = tokio::time::sleep(delay);
            tokio::pin!(timer);

            tokio::select! {
                _ = timer => {
                    if let Some(ref mut client) = stun_client {
                        client.handle_timeout(Instant::now()).ok();
                    }
                    if let Some(ref mut client) = turn_client {
                        client.handle_timeout(Instant::now()).ok();
                    }
                }
                // Handle UDP data for STUN/TURN
                res = udp_socket.recv_from(&mut buf) => {
                    if let Ok((n, peer_addr)) = res {
                        trace!("udp_socket read {} bytes from {}", n, peer_addr);

                        // Check if this is STUN response
                        if let Some(ref mut client) = stun_client {
                            if let Some(stun_addr) = stun_server_addr {
                                if peer_addr == stun_addr {
                                    client.handle_read(TaggedBytesMut {
                                        now: Instant::now(),
                                        transport: TransportContext {
                                            local_addr,
                                            peer_addr,
                                            transport_protocol: TransportProtocol::UDP,
                                            ecn: None,
                                        },
                                        message: BytesMut::from(&buf[..n]),
                                    })?;
                                }
                            }
                        }

                        // Check if this is TURN response
                        if let Some(ref mut client) = turn_client {
                            if let Some(turn_addr) = turn_server_addr {
                                if peer_addr == turn_addr {
                                    client.handle_read(TaggedBytesMut {
                                        now: Instant::now(),
                                        transport: TransportContext {
                                            local_addr,
                                            peer_addr,
                                            ecn: None,
                                            transport_protocol: TransportProtocol::UDP,
                                        },
                                        message: BytesMut::from(&buf[..n]),
                                    })?;
                                }
                            }
                        }
                    }
                }
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

                                        let mut setting_engine = SettingEngine::default();
                                        setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

                                        let mut ice_servers = vec![];
                                        if cli.enable_srflx {
                                            ice_servers.push(RTCIceServer {
                                                urls: vec![format!("stun:{}", cli.stun_server)],
                                                ..Default::default()
                                            });
                                        }
                                        if cli.enable_relay && !cli.turn_host.is_empty() && !cli.turn_user.is_empty() {
                                            let cred: Vec<&str> = cli.turn_user.splitn(2, '=').collect();
                                            if cred.len() == 2 {
                                                ice_servers.push(RTCIceServer {
                                                    urls: vec![format!("turn:{}:{}?transport=udp", cli.turn_host, cli.turn_port)],
                                                    username: cred[0].to_string(),
                                                    credential: cred[1].to_string(),
                                                    ..Default::default()
                                                });
                                            }
                                        }

                                        let config = RTCConfigurationBuilder::new()
                                            .with_ice_servers(ice_servers)

                                            .build();

                                        let mut pc = RTCPeerConnectionBuilder::new().with_configuration(config)
                                         .with_setting_engine(setting_engine).build()?;
                                        println!("Created peer connection");

                                        // Set remote description
                                        println!("Setting remote description");
                                        pc.set_remote_description(offer)?;

                                        // Create answer
                                        let answer = pc.create_answer(None)?;
                                        pc.set_local_description(answer.clone())?;
                                        println!("Created and set answer");

                                        // Add all available candidates
                                        let mut candidates_to_send = vec![];

                                        // Host candidate
                                        if cli.enable_host && !host_candidate_added {
                                            match add_host_candidate_internal(&mut pc, local_addr) {
                                                Ok(cand) => {
                                                    candidates_to_send.push(cand);
                                                    host_candidate_added = true;
                                                    println!("Added local Host ICE candidate");
                                                }
                                                Err(e) => error!("Failed to add host candidate: {}", e),
                                            }
                                        }

                                        // ServerReflexive candidate (if STUN completed)
                                        if cli.enable_srflx && !srflx_candidate_added {
                                            if let Some(ref xor_addr) = stun_xor_addr {
                                                let xor_copy = XorMappedAddress { ip: xor_addr.ip, port: xor_addr.port };
                                                match add_srflx_candidate_internal(&mut pc, xor_copy, local_addr) {
                                                    Ok(cand) => {
                                                        candidates_to_send.push(cand);
                                                        srflx_candidate_added = true;
                                                        println!("Added local ServerReflexive ICE candidate");
                                                    }
                                                    Err(e) => error!("Failed to add srflx candidate: {}", e),
                                                }
                                            } else {
                                                println!("STUN not yet completed, srflx candidate will be added later");
                                            }
                                        }

                                        // Relay candidate (if TURN completed)
                                        if cli.enable_relay && !relay_candidate_added {
                                            if let Some(relay) = relay_addr {
                                                match add_relay_candidate_internal(&mut pc, relay, local_addr) {
                                                    Ok(cand) => {
                                                        candidates_to_send.push(cand);
                                                        relay_candidate_added = true;
                                                        println!("Added local Relay ICE candidate");
                                                    }
                                                    Err(e) => error!("Failed to add relay candidate: {}", e),
                                                }
                                            } else {
                                                println!("TURN not yet allocated, relay candidate will be added later");
                                            }
                                        }

                                        // Send answer and all gathered candidates to browser
                                        if let Some(ref mut ws) = ws_stream {
                                            let json = serde_json::to_string(&answer)?;
                                            info!("Sending SDP answer");
                                            ws.send(Message::Text(json.into())).await?;

                                            for candidate in candidates_to_send {
                                                let json = serde_json::to_string(&candidate)?;
                                                info!("Sending local ICE candidate: {}", candidate.candidate);
                                                ws.send(Message::Text(json.into())).await?;
                                            }
                                        }

                                        peer_connection = Some(pc);
                                    }
                                    WsMessage::IceCandidate(_) => {
                                        info!("Received ICE candidate before offer, ignoring");
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

    if let Some(mut client) = turn_client {
        client.close()?;
    }

    Ok(())
}

// Helper function to add host candidate
fn add_host_candidate_internal(
    pc: &mut RTCPeerConnection,
    local_addr: SocketAddr,
) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    pc.add_local_candidate(local_candidate_init.clone())?;
    Ok(local_candidate_init)
}

// Helper function to add srflx candidate
fn add_srflx_candidate_internal(
    pc: &mut RTCPeerConnection,
    xor_addr: XorMappedAddress,
    local_addr: SocketAddr,
) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: xor_addr.ip.to_string(),
            port: xor_addr.port,
            component: 1,
            ..Default::default()
        },
        rel_addr: local_addr.ip().to_string(),
        rel_port: local_addr.port(),
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;

    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    pc.add_local_candidate(local_candidate_init.clone())?;
    Ok(local_candidate_init)
}

async fn add_srflx_candidate(
    pc: &mut RTCPeerConnection,
    xor_addr: XorMappedAddress,
    local_addr: SocketAddr,
    ws_stream: &mut Option<WebSocketStream<TcpStream>>,
) -> Result<()> {
    let local_candidate_init = add_srflx_candidate_internal(pc, xor_addr, local_addr)?;
    println!(
        "Added local ServerReflexive ICE candidate: {}",
        local_candidate_init.candidate
    );

    // Send to browser via WebSocket
    if let Some(ws) = ws_stream {
        let json = serde_json::to_string(&local_candidate_init)?;
        info!(
            "Sending local ICE candidate: {}",
            local_candidate_init.candidate
        );
        ws.send(Message::Text(json.into())).await?;
    }
    Ok(())
}

// Helper function to add relay candidate
fn add_relay_candidate_internal(
    pc: &mut RTCPeerConnection,
    relay_addr: SocketAddr,
    relay_local_addr: SocketAddr,
) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: relay_addr.ip().to_string(),
            port: relay_addr.port(),
            component: 1,
            ..Default::default()
        },
        rel_addr: relay_local_addr.ip().to_string(),
        rel_port: relay_local_addr.port(),
        ..Default::default()
    }
    .new_candidate_relay()?;

    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    pc.add_local_candidate(local_candidate_init.clone())?;
    Ok(local_candidate_init)
}

async fn add_relay_candidate(
    pc: &mut RTCPeerConnection,
    relay_addr: SocketAddr,
    relay_local_addr: SocketAddr,
    ws_stream: &mut Option<WebSocketStream<TcpStream>>,
) -> Result<()> {
    let local_candidate_init = add_relay_candidate_internal(pc, relay_addr, relay_local_addr)?;
    println!(
        "Added local Relay ICE candidate: {}",
        local_candidate_init.candidate
    );

    // Send to browser via WebSocket
    if let Some(ws) = ws_stream {
        let json = serde_json::to_string(&local_candidate_init)?;
        info!(
            "Sending local ICE candidate: {}",
            local_candidate_init.candidate
        );
        ws.send(Message::Text(json.into())).await?;
    }
    Ok(())
}

// Helper function to extract IP:port from ICE candidate string
fn extract_address_from_candidate(candidate_str: &str) -> Option<SocketAddr> {
    // ICE candidate format: "candidate:... typ ... <IP> <port> ..."
    let parts: Vec<&str> = candidate_str.split_whitespace().collect();

    // Find IP address and port in the candidate string
    // Typical format: "candidate:<foundation> <component> <protocol> <priority> <IP> <port> typ <type>"
    if parts.len() >= 6 {
        if let (Ok(ip), Ok(port)) = (
            parts[4].parse::<std::net::IpAddr>(),
            parts[5].parse::<u16>(),
        ) {
            return Some(SocketAddr::new(ip, port));
        }
    }

    None
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
