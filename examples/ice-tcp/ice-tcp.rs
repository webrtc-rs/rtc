//! ice-tcp demonstrates sansio RTC's ICE TCP abilities.
//!
//! This example shows how to use ICE over TCP instead of UDP.
//! ICE TCP is useful when UDP is blocked by firewalls.
//!
//! Key concepts demonstrated:
//! - TCP candidate creation (passive type)
//! - TCP framing (RFC 4571) for ICE messages
//! - Managing TCP connections for ICE
//! - Using TCP-only network types

use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);
const TCP_PORT: u16 = 8443;
const HTTP_PORT: u16 = 8080;

#[derive(Parser)]
#[command(name = "ice-tcp")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of ICE over TCP", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
}

static INDEX: &str = "examples/examples/ice-tcp/index.html";

// Message types for communication between HTTP handler and main loop
enum SignalingMessage {
    Offer(
        RTCSessionDescription,
        tokio::sync::oneshot::Sender<RTCSessionDescription>,
    ),
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

    // Channel for signaling messages
    let (signaling_tx, signaling_rx) = mpsc::channel::<SignalingMessage>(10);

    // Start TCP listener for ICE connections
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", TCP_PORT)).await?;
    println!("Listening for ICE TCP at 0.0.0.0:{}", TCP_PORT);

    // Start HTTP server
    let signaling_tx_clone = signaling_tx.clone();
    tokio::spawn(run_http_server(signaling_tx_clone));

    println!("Open http://localhost:{} to access this demo", HTTP_PORT);
    println!("Press ctrl-c to stop");

    // Run main event loop
    run_main_loop(signaling_rx, tcp_listener).await
}

async fn run_http_server(signaling_tx: mpsc::Sender<SignalingMessage>) {
    let signaling_tx = Arc::new(signaling_tx);

    let make_svc = make_service_fn(move |_| {
        let signaling_tx = Arc::clone(&signaling_tx);
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let signaling_tx = Arc::clone(&signaling_tx);
                async move { handle_http_request(req, signaling_tx).await }
            }))
        }
    });

    let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", HTTP_PORT)).unwrap();
    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("HTTP server error: {}", e);
    }
}

async fn handle_http_request(
    req: Request<Body>,
    signaling_tx: Arc<mpsc::Sender<SignalingMessage>>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => {
            match tokio::fs::read_to_string(INDEX).await {
                Ok(content) => Ok(Response::builder()
                    .header("Content-Type", "text/html")
                    .body(Body::from(content))
                    .unwrap()),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("Not Found"))
                    .unwrap()),
            }
        }
        (&Method::POST, "/doSignaling") => {
            // Read request body
            let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
            let offer: RTCSessionDescription = match serde_json::from_slice(&body_bytes) {
                Ok(o) => o,
                Err(e) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(format!("Invalid offer: {}", e)))
                        .unwrap());
                }
            };

            // Create oneshot channel for response
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();

            // Send offer to main loop
            if signaling_tx
                .send(SignalingMessage::Offer(offer, response_tx))
                .await
                .is_err()
            {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Signaling channel closed"))
                    .unwrap());
            }

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
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}

async fn run_main_loop(
    mut signaling_rx: mpsc::Receiver<SignalingMessage>,
    tcp_listener: TcpListener,
) -> Result<()> {
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
                            // Feed data to decoder
                            tcp_decoder.extend_from_slice(&buf[..n]);

                            // Process all complete packets
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
                    info!("New TCP connection from {}", addr);
                    if tcp_stream.is_none() {
                        tcp_stream = Some(stream);
                    } else {
                        info!("Already have a TCP connection, dropping new one");
                    }
                }
                // Handle signaling messages
                Some(msg) = signaling_rx.recv() => {
                    match msg {
                        SignalingMessage::Offer(_offer, response_tx) => {
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
                Some(msg) = signaling_rx.recv() => {
                    match msg {
                        SignalingMessage::Offer(offer, response_tx) => {
                            println!("Received offer, creating peer connection with TCP candidates");

                            // Get local address for TCP candidate
                            let tcp_local = tcp_listener.local_addr()?;
                            println!("TCP listener address: {}", tcp_local);

                            // Use 127.0.0.1 for local testing if bound to 0.0.0.0
                            let candidate_ip: std::net::IpAddr = if tcp_local.ip().is_unspecified() {
                                "127.0.0.1".parse().unwrap()
                            } else {
                                tcp_local.ip()
                            };
                            // Set local_addr to match the candidate IP
                            local_addr = Some(SocketAddr::new(candidate_ip, tcp_local.port()));

                            let mut setting_engine = SettingEngine::default();
                            setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

                            let config = RTCConfigurationBuilder::new()

                                .build();

                            let mut pc = RTCPeerConnectionBuilder::new().with_configuration(config)  .with_setting_engine(setting_engine).build()?;
                            println!("Created peer connection");

                            // Set remote description
                            println!("Setting remote description {}", offer);
                            pc.set_remote_description(offer)?;

                            // Create TCP passive candidate using the same IP
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
                            println!("TCP passive candidate: {}", local_candidate_init.candidate);

                            // Add local candidate BEFORE create_answer (sansio RTC pattern)
                            pc.add_local_candidate(local_candidate_init)?;

                            // Create and set answer - includes the TCP candidate in SDP
                            let answer = pc.create_answer(None)?;
                            println!("Answer with TCP candidate: {}", answer);
                            pc.set_local_description(answer.clone())?;

                            // Send answer back via HTTP
                            let _ = response_tx.send(answer);

                            peer_connection = Some(pc);
                        }
                    }
                }
                // Accept TCP connections even before peer connection exists
                Ok((stream, addr)) = tcp_listener.accept() => {
                    println!("New TCP connection from {} (before peer connection)", addr);
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
