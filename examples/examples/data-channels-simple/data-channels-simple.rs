//! data-channels-simple is a simple datachannel demo with HTTP signaling server.
//!
//! This example demonstrates:
//! - HTTP server for WebRTC signaling
//! - Browser-based DataChannel communication
//! - ICE candidate exchange via HTTP endpoints
//! - Real-time messaging between browser and Rust server

use anyhow::Result;
use bytes::BytesMut;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info, trace};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::transport::{RTCIceCandidateInit, RTCIceServer};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day
const DEMO_HTML: &str = include_str!("demo.html");

/// Shared state for HTTP handlers
struct AppState {
    offer_tx: mpsc::Sender<(
        RTCSessionDescription,
        mpsc::Sender<Result<RTCSessionDescription, String>>,
    )>,
    candidate_tx: mpsc::Sender<RTCIceCandidateInit>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Channels for communication between HTTP handlers and WebRTC event loop
    let (offer_tx, offer_rx) = mpsc::channel::<(
        RTCSessionDescription,
        mpsc::Sender<Result<RTCSessionDescription, String>>,
    )>(1);
    let (candidate_tx, candidate_rx) = mpsc::channel::<RTCIceCandidateInit>(16);

    let state = Arc::new(Mutex::new(AppState {
        offer_tx,
        candidate_tx,
    }));

    // Start HTTP server in background
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    info!("Signaling server started on http://{}", addr);

    let state_clone = state.clone();
    tokio::spawn(async move {
        let make_svc = make_service_fn(move |_| {
            let state = state_clone.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| handle_request(req, state.clone())))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }
    });

    // Run WebRTC event loop in main task (RTCPeerConnection is not Send)
    run_webrtc(offer_rx, candidate_rx).await
}

/// Handle HTTP requests
async fn handle_request(
    req: Request<Body>,
    state: Arc<Mutex<AppState>>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve demo HTML
        (&Method::GET, "/") => Ok(Response::builder()
            .header("Content-Type", "text/html")
            .body(Body::from(DEMO_HTML))
            .unwrap()),

        // Handle SDP offer
        (&Method::POST, "/offer") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
            let body_str = String::from_utf8_lossy(&body_bytes);

            let offer: RTCSessionDescription = match serde_json::from_str(&body_str) {
                Ok(o) => o,
                Err(e) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(e.to_string()))
                        .unwrap());
                }
            };

            // Create response channel
            let (response_tx, mut response_rx) = mpsc::channel(1);

            // Send offer to WebRTC loop
            {
                let state = state.lock().await;
                if state.offer_tx.send((offer, response_tx)).await.is_err() {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("WebRTC loop not running"))
                        .unwrap());
                }
            }

            // Wait for answer
            match response_rx.recv().await {
                Some(Ok(answer)) => {
                    let json = serde_json::to_string(&answer).unwrap();
                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .body(Body::from(json))
                        .unwrap())
                }
                Some(Err(e)) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(e))
                    .unwrap()),
                None => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("No response from WebRTC"))
                    .unwrap()),
            }
        }

        // Handle ICE candidate
        (&Method::POST, "/candidate") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
            let body_str = String::from_utf8_lossy(&body_bytes);

            let candidate: RTCIceCandidateInit = match serde_json::from_str(&body_str) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(e.to_string()))
                        .unwrap());
                }
            };

            let state = state.lock().await;
            if state.candidate_tx.send(candidate).await.is_err() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("WebRTC loop not running"))
                    .unwrap());
            }

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        }

        // 404 for other routes
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}

/// Run the WebRTC event loop
async fn run_webrtc(
    mut offer_rx: mpsc::Receiver<(
        RTCSessionDescription,
        mpsc::Sender<Result<RTCSessionDescription, String>>,
    )>,
    mut candidate_rx: mpsc::Receiver<RTCIceCandidateInit>,
) -> Result<()> {
    // Bind UDP socket for WebRTC traffic
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    info!("WebRTC UDP socket bound to {}", local_addr);

    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut buf = vec![0u8; 2000];

    loop {
        // Process peer connection if we have one
        let mut should_close = false;
        let mut pending_sends: Vec<(BytesMut, SocketAddr)> = Vec::new();

        if let Some(pc) = peer_connection.as_mut() {
            // Poll for outgoing packets
            while let Some(msg) = pc.poll_write() {
                pending_sends.push((msg.message.into(), msg.transport.peer_addr));
            }

            // Poll for events
            while let Some(event) = pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        info!("Connection state: {}", state);
                        if state == RTCPeerConnectionState::Failed {
                            error!("Connection failed, closing peer connection");
                            should_close = true;
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            if let Some(mut dc) = pc.data_channel(channel_id) {
                                info!("DataChannel '{}' opened (Server)", dc.label());
                                if let Err(e) = dc.send_text("Hello from Rust server!".to_string())
                                {
                                    error!("Failed to send greeting: {}", e);
                                }
                            }
                        }
                        RTCDataChannelEvent::OnClose(channel_id) => {
                            info!("DataChannel {} closed", channel_id);
                        }
                        _ => {}
                    },
                    RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
                        info!("New ICE candidate: {:?}", ice_event.candidate.address);
                    }
                    _ => {}
                }
            }

            // Poll for incoming messages
            while let Some(message) = pc.poll_read() {
                if let RTCMessage::DataChannelMessage(channel_id, dc_message) = message {
                    if let Some(dc) = pc.data_channel(channel_id) {
                        let msg_str = String::from_utf8_lossy(&dc_message.data);
                        info!("Received from '{}': {}", dc.label(), msg_str);
                    }
                }
            }
        }

        // Send pending packets
        for (data, addr) in pending_sends {
            match socket.send_to(&data, addr).await {
                Ok(n) => trace!("Sent {} bytes to {}", n, addr),
                Err(e) => error!("Failed to send: {}", e),
            }
        }

        // Close peer connection if needed
        if should_close {
            peer_connection = None;
        }

        // Calculate timeout
        let timeout_duration = peer_connection
            .as_mut()
            .and_then(|pc| pc.poll_timeout())
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(DEFAULT_TIMEOUT_DURATION);

        let timer = tokio::time::sleep(timeout_duration);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            // Handle new offer from HTTP handler
            Some((offer, response_tx)) = offer_rx.recv() => {
                info!("Received offer from browser");

                match create_peer_connection(local_addr, offer) {
                    Ok((pc, answer)) => {
                        peer_connection = Some(pc);
                        let _ = response_tx.send(Ok(answer)).await;
                    }
                    Err(e) => {
                        let _ = response_tx.send(Err(e.to_string())).await;
                    }
                }
            }

            // Handle ICE candidate from HTTP handler
            Some(candidate) = candidate_rx.recv() => {
                if let Some(pc) = peer_connection.as_mut() {
                    if let Err(e) = pc.add_remote_candidate(candidate) {
                        error!("Failed to add ICE candidate: {}", e);
                    }
                }
            }

            // Handle timeout
            _ = &mut timer => {
                if let Some(pc) = peer_connection.as_mut() {
                    if let Err(e) = pc.handle_timeout(Instant::now()) {
                        error!("Timeout handling error: {}", e);
                    }
                }
            }

            // Handle incoming UDP packet
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer_addr)) => {
                        trace!("Received {} bytes from {}", n, peer_addr);
                        if let Some(pc) = peer_connection.as_mut() {
                            if let Err(e) = pc.handle_read(TaggedBytesMut {
                                now: Instant::now(),
                                transport: TransportContext {
                                    local_addr,
                                    peer_addr,
                                    ecn: None,
                                    transport_protocol: TransportProtocol::UDP,
                                },
                                message: BytesMut::from(&buf[..n]),
                            }) {
                                error!("Error handling packet: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Socket receive error: {}", e);
                    }
                }
            }
        }
    }
}

/// Create a new peer connection and process the offer
fn create_peer_connection(
    local_addr: SocketAddr,
    offer: RTCSessionDescription,
) -> Result<(RTCPeerConnection, RTCSessionDescription)> {
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Set remote description (the offer)
    peer_connection.set_remote_description(offer)?;

    // Add local ICE candidate
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
    peer_connection.add_local_candidate(local_candidate_init)?;

    // Create answer
    let answer = peer_connection.create_answer(None)?;

    // Set local description
    peer_connection.set_local_description(answer.clone())?;

    Ok((peer_connection, answer))
}
