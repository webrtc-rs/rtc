//! perfect-negotiation demonstrates Perfect Negotiation pattern at application level.
//!
//! Perfect Negotiation is a design pattern that allows both peers to use identical code
//! for connection setup, with automatic collision detection and resolution.
//!
//! This example demonstrates:
//! - Application-level PerfectNegotiationHandler wrapper around RTCPeerConnection
//! - Bidirectional calling (either peer can initiate)
//! - Collision detection and automatic rollback
//! - Polite/impolite role assignment
//! - Symmetric peer code (same logic for both peers)
//! - WebSocket signaling with simulated network conditions
//!
//! The key innovation is that BOTH peers run the exact same negotiation logic,
//! unlike traditional WebRTC examples where one peer is the "offerer" and the
//! other is the "answerer".

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Response, Server, StatusCode};
use log::{error, info, trace, warn};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCPeerConnectionIceEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtc::peer_connection::state::{RTCPeerConnectionState, RTCSignalingState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "perfect-negotiation")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "Demonstrates Perfect Negotiation pattern at application level", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
}

static INDEX: &str = "examples/examples/perfect-negotiation/index.html";

/// Signaling message types exchanged between peers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum SignalingMessage {
    #[serde(rename = "description")]
    Description { description: RTCSessionDescription },
    #[serde(rename = "candidate")]
    Candidate { candidate: RTCIceCandidateInit },
    #[serde(rename = "message")]
    Message { message: String },
}

/// Status update message sent to browser
#[derive(Debug, Clone, Serialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    state: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
}

impl StatusMessage {
    fn new(state: &str, message: &str) -> Self {
        Self {
            msg_type: "status".to_string(),
            state: state.to_string(),
            message: message.to_string(),
            level: None,
        }
    }
}

/// Application-level Perfect Negotiation handler
///
/// This wrapper implements the Perfect Negotiation pattern around RTCPeerConnection
/// using only the spec-compliant primitives provided by the library.
///
/// Key responsibilities:
/// - Collision detection using signaling state
/// - Automatic rollback for polite peer
/// - Offer/answer coordination
/// - Graceful handling of race conditions
struct PerfectNegotiationHandler {
    pc: RTCPeerConnection,
    polite: bool,
    is_making_offer: bool,
    ignore_offer: bool,
    signaling_state: RTCSignalingState,
}

impl PerfectNegotiationHandler {
    /// Create a new Perfect Negotiation handler
    ///
    /// # Arguments
    /// * `pc` - The RTCPeerConnection instance to wrap
    /// * `polite` - Whether this peer is polite (yields on collision) or impolite
    fn new(pc: RTCPeerConnection, polite: bool) -> Self {
        Self {
            pc,
            polite,
            is_making_offer: false,
            ignore_offer: false,
            signaling_state: RTCSignalingState::Stable,
        }
    }

    /// Handle remote description from peer
    ///
    /// Implements Perfect Negotiation collision detection and resolution:
    /// - Detects offer collisions
    /// - Polite peer rolls back and accepts remote offer
    /// - Impolite peer ignores remote offer
    ///
    /// Returns Some(answer) if an answer was created and needs to be sent
    fn handle_remote_description_with_response(
        &mut self,
        description: RTCSessionDescription,
        local_addr: SocketAddr,
    ) -> Result<Option<RTCSessionDescription>> {
        let role = if self.polite { "POLITE" } else { "IMPOLITE" };
        info!(
            "[{}] Received remote {:?} description",
            role, description.sdp_type
        );

        // Collision detection: both peers sent offer simultaneously
        let offer_collision = description.sdp_type == RTCSdpType::Offer
            && (self.is_making_offer || self.signaling_state != RTCSignalingState::Stable);

        // Ignore offer if we're impolite and there's a collision
        self.ignore_offer = !self.polite && offer_collision;

        if self.ignore_offer {
            warn!(
                "[{}] Ignoring remote offer due to collision (impolite)",
                role
            );
            return Ok(None);
        }

        // If polite and collision, rollback our offer
        if self.polite && offer_collision {
            warn!("[{}] Collision detected, rolling back local offer", role);

            // Create rollback description (empty SDP per WebRTC spec)
            let mut rollback = RTCSessionDescription::default();
            rollback.sdp_type = RTCSdpType::Rollback;
            rollback.sdp = String::new(); // Spec: SDP omitted or empty for rollback

            self.pc.set_local_description(rollback)?;

            // Update our signaling state after rollback
            self.signaling_state = RTCSignalingState::Stable;
        }

        // Set the remote description
        self.pc.set_remote_description(description.clone())?;

        // Debug: Check if received SDP contains candidates
        if description.sdp.contains("candidate:") {
            info!(
                "[{}] Received SDP contains {} candidates",
                role,
                description.sdp.matches("candidate:").count()
            );
        } else {
            info!("[{}] Received SDP does NOT contain any candidates", role);
        }

        // Update our tracked state based on the description type
        // This must be done before checking if we need to answer
        self.signaling_state = match description.sdp_type {
            RTCSdpType::Offer => RTCSignalingState::HaveRemoteOffer,
            RTCSdpType::Answer => RTCSignalingState::Stable,
            _ => self.signaling_state, // Keep current state for other types
        };

        // If we received an offer, create and return an answer
        if self.signaling_state == RTCSignalingState::HaveRemoteOffer {
            // Add local ICE candidate BEFORE creating answer so it's included in SDP
            self.add_local_host_candidate(local_addr)?;

            let answer = self.pc.create_answer(None)?;
            self.pc.set_local_description(answer.clone())?;
            info!("[{}] Creating answer", role);
            self.signaling_state = RTCSignalingState::Stable; // Answer completes negotiation
            return Ok(Some(answer));
        }

        Ok(None)
    }

    /// Handle remote ICE candidate
    ///
    /// Ignores candidates if we're currently ignoring an offer.
    fn handle_remote_candidate(&mut self, candidate: RTCIceCandidateInit) -> Result<()> {
        if self.ignore_offer {
            trace!(
                "[{}] Ignoring ICE candidate (ignoring offer)",
                if self.polite { "POLITE" } else { "IMPOLITE" }
            );
            return Ok(());
        }

        self.pc.add_remote_candidate(candidate)?;
        Ok(())
    }

    /// Update signaling state (called when event received)
    fn update_signaling_state(&mut self, state: RTCSignalingState) {
        self.signaling_state = state;
    }

    /// Create and add local ICE candidate to peer connection
    /// For localhost testing, always use 127.0.0.1 instead of 0.0.0.0
    fn add_local_host_candidate(&mut self, local_addr: SocketAddr) -> Result<()> {
        // Use 127.0.0.1 for localhost connections instead of 0.0.0.0
        let _ice_addr = if local_addr.ip().is_unspecified() {
            format!("127.0.0.1:{}", local_addr.port())
        } else {
            local_addr.to_string()
        };

        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "127.0.0.1".to_string(), // Always use 127.0.0.1 for localhost
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;

        let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
        self.pc.add_local_candidate(local_candidate_init)?;
        info!(
            "[{}] Added local ICE candidate 127.0.0.1:{}",
            if self.polite { "POLITE" } else { "IMPOLITE" },
            local_addr.port()
        );
        Ok(())
    }

    /// Get mutable reference to the underlying peer connection
    fn peer_connection(&mut self) -> &mut RTCPeerConnection {
        &mut self.pc
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.debug { "trace" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    println!(
        "Open\n- http://localhost:8080/polite\n- http://localhost:8080/impolite\n in two browser tabs"
    );
    println!("Click 'Connect' in EITHER browser to create data channel and start connection");
    println!("  - Try clicking in BOTH browsers quickly to test collision handling!");
    println!("After connection, click 'Renegotiate' to test renegotiation collision handling");
    println!("Press ctrl-c to stop");

    // Start HTTP server for serving web pages
    tokio::spawn(async {
        if let Err(e) = run_http_server().await {
            error!("HTTP server error: {}", e);
        }
    });

    // Start WebSocket signaling server
    run_signaling_server().await
}

/// Run HTTP server for serving demo web pages
async fn run_http_server() -> Result<()> {
    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(move |req| async move {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/polite") | (&Method::GET, "/impolite") => {
                    let html = std::fs::read_to_string(INDEX)?;
                    Ok::<_, anyhow::Error>(
                        Response::builder()
                            .header("Content-Type", "text/html")
                            .body(Body::from(html))
                            .unwrap(),
                    )
                }
                _ => Ok::<_, anyhow::Error>(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::from("Not Found"))
                        .unwrap(),
                ),
            }
        }))
    });

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("HTTP server listening on http://{}", addr);

    Server::bind(&addr).serve(make_service).await?;

    Ok(())
}

/// Run WebSocket signaling server that coordinates two peers
async fn run_signaling_server() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    info!("WebSocket signaling server listening on ws://localhost:8081");

    // Create channels for inter-peer communication
    let (polite_to_impolite_tx, polite_to_impolite_rx) = tokio::sync::mpsc::channel::<String>(100);
    let (impolite_to_polite_tx, impolite_to_polite_rx) = tokio::sync::mpsc::channel::<String>(100);

    // Accept polite peer and start processing immediately
    let (polite_stream, _) = listener.accept().await?;
    let polite_ws = tokio_tungstenite::accept_async(polite_stream).await?;
    info!("Polite peer connected");

    let polite_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            if let Err(e) = run_peer(
                true,
                polite_ws,
                impolite_to_polite_rx,
                polite_to_impolite_tx,
            )
            .await
            {
                error!("Polite peer error: {}", e);
            }
        })
    });

    // Accept impolite peer and start processing immediately
    let (impolite_stream, _) = listener.accept().await?;
    let impolite_ws = tokio_tungstenite::accept_async(impolite_stream).await?;
    info!("Impolite peer connected");

    let impolite_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            if let Err(e) = run_peer(
                false,
                impolite_ws,
                polite_to_impolite_rx,
                impolite_to_polite_tx,
            )
            .await
            {
                error!("Impolite peer error: {}", e);
            }
        })
    });

    // Wait for both peers to complete
    polite_handle.join().expect("Polite peer thread panicked");
    impolite_handle
        .join()
        .expect("Impolite peer thread panicked");

    Ok(())
}

/// Run a single peer with Perfect Negotiation
///
/// This function demonstrates the key feature of Perfect Negotiation:
/// THE EXACT SAME CODE runs for both peers, with only the `polite` flag differing.
async fn run_peer(
    polite: bool,
    mut ws: WebSocketStream<TcpStream>,
    mut peer_rx: tokio::sync::mpsc::Receiver<String>,
    peer_tx: tokio::sync::mpsc::Sender<String>,
) -> Result<()> {
    let role = if polite { "POLITE" } else { "IMPOLITE" };
    info!("[{}] Starting peer", role);

    // Create UDP socket for media - bind to localhost for local testing
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = udp_socket.local_addr()?;
    info!("[{}] UDP socket bound to {}", role, local_addr);

    // Configure peer connection
    let setting_engine = SettingEngine::default();
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .build()?;

    // Don't create data channel yet - wait for user to click "Connect"
    // This makes the "Connect" button meaningful

    // Wrap in Perfect Negotiation handler
    let mut negotiation = PerfectNegotiationHandler::new(pc, polite);

    let mut last_timeout = Instant::now();
    let mut _peer_addr: Option<SocketAddr> = None;
    let mut buf = BytesMut::with_capacity(2048);
    buf.resize(2048, 0);
    let mut pending_negotiation = false;
    let mut data_channel_id: Option<u16> = None;
    let mut data_channel_created = false;

    loop {
        // Get next timeout from peer connection
        let peer_timeout_instant = negotiation.peer_connection().poll_timeout();
        let peer_timeout = peer_timeout_instant
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100)); // Default 100ms if no timeout

        if peer_timeout > Duration::from_secs(1) {
            info!(
                "[{}] poll_timeout returned long duration: {:?}",
                role, peer_timeout
            );
        }

        let timeout_duration = DEFAULT_TIMEOUT_DURATION
            .checked_sub(last_timeout.elapsed())
            .unwrap_or(Duration::ZERO);

        // Use the shorter of peer timeout or connection timeout
        // But cap at 100ms to ensure we poll frequently for DTLS handshake
        let sleep_duration = peer_timeout
            .min(timeout_duration)
            .min(Duration::from_millis(100));

        tokio::select! {
            // Handle peer connection events (driven by peer timeout)
            _ = tokio::time::sleep(sleep_duration) => {
                // Call handle_timeout to drive DTLS handshake, retransmissions, etc.
                negotiation.peer_connection().handle_timeout(Instant::now()).ok();

                // Poll peer connection events
                while let Some(event) = negotiation.peer_connection().poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnNegotiationNeededEvent => {
                            info!("[{}] Negotiation needed", role);
                            pending_negotiation = true;
                        }
                        RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent { candidate, ..}) => {
                            info!("[{}] ICE candidate: {}:{}", role, candidate.address, candidate.port);
                            let candidate_init = candidate.to_json()?;
                            let msg = SignalingMessage::Candidate { candidate: candidate_init };
                            let json = serde_json::to_string(&msg)?;

                            // Send to OTHER peer via relay channel
                            peer_tx.send(json.clone()).await.ok();

                            // Also send to browser for display
                            ws.send(Message::Text(json.into())).await?;
                        }
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            info!("[{}] Peer connection state: {:?}", role, state);

                            // Send status to browser
                            let status_msg = match state {
                                RTCPeerConnectionState::Connected => {
                                    info!("[{}] ✓ Peer connection connected!", role);
                                    StatusMessage::new("connected", "Peer connection connected!")
                                }
                                RTCPeerConnectionState::Connecting => {
                                    StatusMessage::new("connecting", "Connecting to peer...")
                                }
                                RTCPeerConnectionState::Failed => {
                                    StatusMessage::new("disconnected", "Connection failed")
                                }
                                RTCPeerConnectionState::Disconnected => {
                                    StatusMessage::new("disconnected", "Disconnected from peer")
                                }
                                _ => StatusMessage::new("connecting", &format!("State: {:?}", state))
                            };
                            let json = serde_json::to_string(&status_msg)?;
                            ws.send(Message::Text(json.into())).await.ok();
                        }
                        RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
                            negotiation.update_signaling_state(state);
                            info!("[{}] Signaling state: {:?}", role, state);
                        }
                        RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
                            match dc_event {
                                RTCDataChannelEvent::OnOpen(channel_id) => {
                                    data_channel_id = Some(channel_id);
                                    if let Some(dc) = negotiation.peer_connection().data_channel(channel_id) {
                                        info!("[{}] Data channel '{}-{}' opened", role, dc.label(), dc.id());
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }

                // Handle pending negotiation
                if pending_negotiation {
                    pending_negotiation = false;

                    // Only create offer if we're stable (Perfect Negotiation requirement)
                    if negotiation.signaling_state != RTCSignalingState::Stable {
                        info!("[{}] Skipping offer creation - not stable (state: {:?})", role, negotiation.signaling_state);
                        continue;
                    }

                    // Mark that we're making an offer (for collision detection)
                    negotiation.is_making_offer = true;

                    // Add local ICE candidate BEFORE creating offer so it's included in SDP
                    negotiation.add_local_host_candidate(local_addr)?;

                    let offer = negotiation.peer_connection().create_offer(None)?;
                    negotiation.peer_connection().set_local_description(offer.clone())?;

                    // Update our state tracker immediately
                    negotiation.signaling_state = RTCSignalingState::HaveLocalOffer;
                    negotiation.is_making_offer = false;

                    info!("[{}] Sending Offer", role);
                    let msg = SignalingMessage::Description { description: offer };
                    let json = serde_json::to_string(&msg)?;

                    // Send to OTHER Rust peer via relay channel
                    info!("[{}] >>> Relaying offer via channel to other peer", role);
                    if let Err(e) = peer_tx.send(json.clone()).await {
                        error!("[{}] Failed to relay to other peer: {}", role, e);
                    }

                    // Also send to browser
                    ws.send(Message::Text(json.into())).await?;
                }

                // Poll write (send buffered data)
                while let Some(msg) = negotiation.peer_connection().poll_write() {
                    udp_socket.send_to(&msg.message, msg.transport.peer_addr).await?;
                    trace!("[{}] Sent {} bytes to {}", role, msg.message.len(), msg.transport.peer_addr);
                }

                // Poll read (data channel messages)
                while let Some(message) = negotiation.peer_connection().poll_read() {
                    match message {
                        RTCMessage::DataChannelMessage(channel_id, data_channel_message) => {
                            let msg_str = String::from_utf8(data_channel_message.data.to_vec())
                                .unwrap_or_default();
                            info!("[{}] Received on channel {}: {}", role, channel_id, msg_str);

                            // Send to browser
                            let data_msg = serde_json::json!({
                                "type": "data",
                                "message": msg_str
                            });
                            ws.send(Message::Text(serde_json::to_string(&data_msg)?.into())).await.ok();
                        }
                        _ => {}
                    }
                }

                // Check timeout
                if last_timeout.elapsed() > DEFAULT_TIMEOUT_DURATION {
                    info!("[{}] Timeout reached", role);
                    break;
                }
            }

            // Handle WebSocket messages
            Some(msg) = ws.next() => {
                let msg = msg?;
                if let Message::Text(text) = msg {
                    let text_str = text.to_string();

                    // Handle control messages (plain text commands)
                    if text_str == "connect" {
                        info!("[{}] Received 'connect' command - creating data channel and initiating connection", role);

                        // Create data channel on first connect (both peers create one - tests collision)
                        if !data_channel_created {
                            let dc_label = format!("data-{}", role.to_lowercase());
                            negotiation.peer_connection().create_data_channel(&dc_label, None)?;
                            data_channel_created = true;
                            info!("[{}] Created data channel '{}'", role, dc_label);
                            // Creating data channel triggers OnNegotiationNeeded automatically
                        } else {
                            info!("[{}] Data channel already exists, use 'renegotiate' instead", role);
                        }
                        continue;
                    }

                    if text_str == "renegotiate" {
                        info!("[{}] Received 'renegotiate' command - initiating renegotiation", role);
                        pending_negotiation = true;
                        continue;
                    }

                    // Try to parse as JSON signaling message
                    match serde_json::from_str::<SignalingMessage>(&text_str) {
                        Ok(signal_msg) => {
                            match signal_msg {
                                SignalingMessage::Description { description } => {
                                    let response = negotiation.handle_remote_description_with_response(description, local_addr)?;
                                    if let Some(answer) = response {
                                        info!("[{}] Sending Answer", role);
                                        let msg = SignalingMessage::Description { description: answer };
                                        let json = serde_json::to_string(&msg)?;

                                        // Send to OTHER peer via relay channel
                                        peer_tx.send(json.clone()).await.ok();

                                        // Also send to browser for display
                                        ws.send(Message::Text(json.into())).await?;
                                    }
                                }
                                SignalingMessage::Candidate { candidate } => {
                                    trace!("[{}] Received remote ICE candidate", role);
                                    negotiation.handle_remote_candidate(candidate)?;
                                }
                                SignalingMessage::Message { message } => {
                                    info!("[{}] Received message from browser: {}", role, message);
                                    // Send message through data channel if open
                                    if let Some(ch_id) = data_channel_id {
                                        if let Some(mut dc) = negotiation.peer_connection().data_channel(ch_id) {
                                            if let Err(e) = dc.send_text(message) {
                                                error!("[{}] Failed to send message: {}", role, e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[{}] Failed to parse WebSocket message as JSON: {} - message: {}", role, e, text_str);
                        }
                    }
                }
            }

            // Handle messages from OTHER peer (via relay channel)
            Some(peer_msg) = peer_rx.recv() => {
                info!("[{}] Received message from other peer via relay channel!", role);

                // Parse and handle signaling message from other peer
                if let Ok(signal_msg) = serde_json::from_str::<SignalingMessage>(&peer_msg) {
                    match signal_msg {
                        SignalingMessage::Description { description } => {
                            let response = negotiation.handle_remote_description_with_response(description, local_addr)?;
                            if let Some(answer) = response {
                                info!("[{}] Sending Answer", role);
                                let msg = SignalingMessage::Description { description: answer };
                                let json = serde_json::to_string(&msg)?;

                                // Send to OTHER peer via relay channel
                                peer_tx.send(json.clone()).await.ok();

                                // Also send to browser for display
                                ws.send(Message::Text(json.into())).await?;
                            }
                        }
                        SignalingMessage::Candidate { candidate } => {
                            trace!("[{}] Received remote ICE candidate from peer", role);
                            negotiation.handle_remote_candidate(candidate)?;
                        }
                        SignalingMessage::Message { message } => {
                            info!("[{}] Received message from other peer: {}", role, message);
                            // This shouldn't happen in relay - messages should go via data channel
                            // But handle it anyway for robustness
                        }
                    }
                }
            }

            // Handle UDP packets
            res = udp_socket.recv_from(&mut buf) => {
                if let Ok((n, src_addr)) = res {
                    _peer_addr = Some(src_addr);

                    let pc = negotiation.peer_connection();
                    pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr: src_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    })?;

                    last_timeout = Instant::now();
                }
            }

            _ = tokio::time::sleep(timeout_duration) => {
                info!("[{}] Connection timeout", role);
                break;
            }
        }
    }

    info!("[{}] Peer shutdown", role);
    Ok(())
}
