//! trickle-ice-relay demonstrates the Trickle ICE APIs with TURN relay candidates.
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
use ice::candidate::candidate_relay::CandidateRelayConfig;
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
use rtc::stun::message::TransactionId;
use rtc::turn::client::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{fs::OpenOptions, io::Write, str::FromStr};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "trickle-ice-relay")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of how to add Relay (TURN) type local candidate.", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    turn_host: String,
    #[arg(long, default_value_t = 3478)]
    turn_port: u16,
    #[arg(long, default_value_t = format!("user=pass"))]
    turn_user: String,
    #[arg(long, default_value_t = format!("webrtc.rs"))]
    turn_realm: String,
}

static INDEX: &str = "examples/examples/trickle-ice-relay/index.html";

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

    // Run the main event loop with WebSocket handling
    run_main_loop(cli.turn_host, cli.turn_port, cli.turn_user, cli.turn_realm).await
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

async fn run_main_loop(
    turn_host: String,
    turn_port: u16,
    turn_user: String,
    turn_realm: String,
) -> Result<()> {
    // WebSocket server listener (separate port for WebSocket)
    let ws_listener = TcpListener::bind("0.0.0.0:8081").await?;
    println!("WebSocket server listening on ws://localhost:8081");

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = udp_socket.local_addr()?;

    // Parse TURN credentials
    let cred: Vec<&str> = turn_user.splitn(2, '=').collect();
    if cred.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid TURN credentials format. Use: username=password"
        ));
    }

    let turn_server_addr = format!("{}:{}", turn_host, turn_port);
    println!(
        "Connecting to TURN server: {} with local_addr: {}",
        turn_server_addr, local_addr
    );

    // Initialize TURN client
    let cfg = ClientConfig {
        stun_serv_addr: turn_server_addr.clone(),
        turn_serv_addr: turn_server_addr,
        local_addr,
        transport_protocol: TransportProtocol::UDP,
        username: cred[0].to_string(),
        password: cred[1].to_string(),
        realm: turn_realm.to_string(),
        software: String::new(),
        rto_in_ms: 0,
    };

    let mut turn_client = Client::new(cfg)?;
    let allocate_tid = turn_client.allocate()?;
    let mut relay_addr: Option<SocketAddr> = None;
    let relay_local_addr = local_addr;
    let mut relay_candidate_added = false;
    let mut pending_permissions: std::collections::HashMap<TransactionId, SocketAddr> =
        std::collections::HashMap::new();
    let mut granted_permissions: std::collections::HashSet<SocketAddr> =
        std::collections::HashSet::new();

    // State for the main loop
    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut data_channel_id: Option<u16> = None;
    let mut last_send = Instant::now();
    let mut ws_stream: Option<WebSocketStream<TcpStream>> = None;
    let mut buf = vec![0; 2000];

    loop {
        // Process TURN client
        // Poll TURN client writes
        while let Some(transmit) = turn_client.poll_write() {
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
        while let Some(event) = turn_client.poll_event() {
            match event {
                Event::TransactionTimeout(_) => {
                    error!("TURN transaction timeout");
                }
                Event::AllocateResponse(tid, addr) => {
                    if tid == allocate_tid {
                        println!("TURN allocation successful, relay address: {}", addr);
                        relay_addr = Some(addr);

                        // If peer connection already exists and we haven't added the relay candidate yet, add it now
                        if let Some(pc) = peer_connection.as_mut() {
                            if !relay_candidate_added {
                                match add_relay_candidate(pc, addr, relay_local_addr) {
                                    Ok(local_candidate_init) => {
                                        relay_candidate_added = true;
                                        println!(
                                            "Added local Relay ICE candidate: {}",
                                            local_candidate_init.candidate
                                        );

                                        // Send to browser via WebSocket
                                        if let Some(ref mut ws) = ws_stream {
                                            if let Ok(json) =
                                                serde_json::to_string(&local_candidate_init)
                                            {
                                                info!(
                                                    "Sending local ICE candidate: {}",
                                                    local_candidate_init.candidate
                                                );
                                                if let Err(e) =
                                                    ws.send(Message::Text(json.into())).await
                                                {
                                                    error!(
                                                        "Failed to send relay candidate to browser: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => error!("Failed to add relay candidate: {}", e),
                                }
                            }
                        }
                    }
                }
                Event::AllocateError(_, err) => {
                    error!("TURN allocation error: {}", err);
                }
                Event::CreatePermissionResponse(tid, peer_addr) => {
                    if pending_permissions.remove(&tid).is_some() {
                        println!("CreatePermission for peer addr {} is granted", peer_addr);
                        granted_permissions.insert(peer_addr);
                    }
                }
                Event::CreatePermissionError(_, err) => {
                    error!("CreatePermission error: {}", err);
                }
                Event::DataIndicationOrChannelData(_, from, data) => {
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

        // Process peer connection if it exists
        if let Some(pc) = peer_connection.as_mut() {
            // Poll writes - send through TURN relay if permission is granted for that peer
            while let Some(msg) = pc.poll_write() {
                if let Some(relay) = relay_addr {
                    // Check if we have permission for this peer
                    if granted_permissions.contains(&msg.transport.peer_addr) {
                        // Send through TURN relay
                        if let Err(err) = turn_client
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
                    } else {
                        trace!(
                            "No permission yet for peer {}, queuing data",
                            msg.transport.peer_addr
                        );
                    }
                } else {
                    error!("Cannot send: relay not allocated");
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
                        println!("Data Channel {} - send {}", channel_id, message);
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

            // Get next timeout - consider both peer connection and TURN client
            let mut timeout = pc
                .poll_timeout()
                .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

            if let Some(turn_timeout) = turn_client.poll_timeout() {
                if turn_timeout < timeout {
                    timeout = turn_timeout;
                }
            }

            let delay = timeout.saturating_duration_since(Instant::now());

            if delay.is_zero() {
                pc.handle_timeout(Instant::now()).ok();
                turn_client.handle_timeout(Instant::now()).ok();
                continue;
            }

            let timer = tokio::time::sleep(delay.min(Duration::from_millis(100)));
            tokio::pin!(timer);

            tokio::select! {
                _ = timer => {
                    pc.handle_timeout(Instant::now()).ok();
                    turn_client.handle_timeout(Instant::now()).ok();
                }
                // Handle UDP data - goes to TURN client which will generate events
                res = udp_socket.recv_from(&mut buf) => {
                    if let Ok((n, peer_addr)) = res {
                        trace!("udp_socket read {} bytes from {} to {}", n, peer_addr, local_addr);
                        turn_client.handle_read(TaggedBytesMut {
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

                                        // Extract peer address from candidate
                                        if let Some(addr) = extract_address_from_candidate(&candidate.candidate) {
                                            // Check if we've already requested/granted permission for this address
                                            if !granted_permissions.contains(&addr) &&
                                               !pending_permissions.values().any(|&v| v == addr) {
                                                println!("Extracted new remote peer address: {}", addr);

                                                // Create permission if relay is allocated
                                                if let Some(relay) = relay_addr {
                                                    if let Some(tid) = turn_client.relay(relay)?.create_permission(addr)? {
                                                        pending_permissions.insert(tid, addr);
                                                        println!("Requesting permission for peer {}", addr);
                                                    }
                                                } else {
                                                    trace!("Relay not yet allocated, cannot create permission");
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
            // No peer connection yet, wait for offer - but still process TURN events
            // Get next timeout for TURN client
            let mut timeout = Instant::now() + Duration::from_millis(100);
            if let Some(turn_timeout) = turn_client.poll_timeout() {
                if turn_timeout < timeout {
                    timeout = turn_timeout;
                }
            }

            let delay = timeout.saturating_duration_since(Instant::now());
            if delay.is_zero() {
                turn_client.handle_timeout(Instant::now()).ok();
                continue;
            }

            let timer = tokio::time::sleep(delay);
            tokio::pin!(timer);

            tokio::select! {
                _ = timer => {
                    turn_client.handle_timeout(Instant::now()).ok();
                }
                // Handle UDP data for TURN client
                res = udp_socket.recv_from(&mut buf) => {
                    if let Ok((n, peer_addr)) = res {
                        trace!("udp_socket read {} bytes from {}", n, peer_addr);
                        turn_client.handle_read(TaggedBytesMut {
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

                                        let config = RTCConfigurationBuilder::new()
                                            .with_ice_servers(vec![RTCIceServer {
                                                urls: vec![format!("turn:{}:{}?transport=udp", turn_host, turn_port)],
                                                username: cred[0].to_string(),
                                                credential: cred[1].to_string(),
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
                                        // gather and add local relay candidate (simulates trickle ICE gathering)
                                        // Only add if relay is already allocated
                                        if let Some(relay) = relay_addr {
                                            if !relay_candidate_added {
                                                match add_relay_candidate(&mut pc, relay, relay_local_addr) {
                                                    Ok(local_candidate_init) => {
                                                        relay_candidate_added = true;
                                                        println!("Added local Relay ICE candidate: {}", local_candidate_init.candidate);

                                                        // Send answer to browser
                                                        if let Some(ref mut ws) = ws_stream {
                                                            let json = serde_json::to_string(&answer)?;
                                                            info!("Sending SDP answer");
                                                            ws.send(Message::Text(json.into())).await?;

                                                            // Send our local ICE candidate to browser (trickle ICE)
                                                            let json = serde_json::to_string(&local_candidate_init)?;
                                                            info!("Sending local ICE candidate: {}", local_candidate_init.candidate);
                                                            ws.send(Message::Text(json.into())).await?;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to add relay candidate: {}", e);
                                                        // Still send answer even if relay candidate failed
                                                        if let Some(ref mut ws) = ws_stream {
                                                            let json = serde_json::to_string(&answer)?;
                                                            info!("Sending SDP answer");
                                                            ws.send(Message::Text(json.into())).await?;
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            println!("Relay address not yet allocated, will add candidate when ready");
                                            // Send answer immediately, relay candidate will be trickled later
                                            if let Some(ref mut ws) = ws_stream {
                                                let json = serde_json::to_string(&answer)?;
                                                info!("Sending SDP answer");
                                                ws.send(Message::Text(json.into())).await?;
                                            }
                                        }

                                        peer_connection = Some(pc);
                                    }
                                    WsMessage::IceCandidate(_candidate) => {
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

    turn_client.close()?;

    Ok(())
}

// Helper function to add relay candidate to peer connection
fn add_relay_candidate(
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
