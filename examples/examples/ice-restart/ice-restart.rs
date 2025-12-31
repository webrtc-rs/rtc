use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::error;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::codec::{BytesCodec, FramedRead};

use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::session_description::RTCSessionDescription;
use rtc::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::peer_connection::RTCPeerConnection;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "ice-restart")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of ice-restart", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
}

static INDEX: &str = "examples/examples/ice-restart/index.html";
static NOTFOUND: &[u8] = b"Not Found";

// Commands from HTTP server to event loop
enum Command {
    DoSignaling {
        offer: RTCSessionDescription,
        response_tx: mpsc::Sender<RTCSessionDescription>,
    },
}

/// HTTP status code 404
fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(NOTFOUND.into())
        .unwrap()
}

async fn simple_file_send(filename: &str) -> Result<Response<Body>, hyper::Error> {
    // Serve a file by asynchronously reading it by chunks using tokio-util crate.

    if let Ok(file) = tokio::fs::File::open(filename).await {
        let stream = FramedRead::new(file, BytesCodec::new());
        let body = Body::wrap_stream(stream);
        return Ok(Response::new(body));
    }

    Ok(not_found())
}

// HTTP Listener
async fn remote_handler(
    req: Request<Body>,
    cmd_tx: mpsc::Sender<Command>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => simple_file_send(INDEX).await,

        (&Method::POST, "/doSignaling") => do_signaling(req, cmd_tx).await,

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

// do_signaling exchanges all state of the local PeerConnection and is called
// every time a video is added or removed
async fn do_signaling(
    req: Request<Body>,
    cmd_tx: mpsc::Sender<Command>,
) -> Result<Response<Body>, hyper::Error> {
    let sdp_str = match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
        Ok(s) => s.to_owned(),
        Err(e) => {
            eprintln!("Failed to parse SDP: {}", e);
            let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    };

    let offer = match serde_json::from_str::<RTCSessionDescription>(&sdp_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to deserialize SDP: {}", e);
            let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    };

    // Create response channel
    let (response_tx, mut response_rx) = mpsc::channel(1);

    // Send command to event loop
    if let Err(e) = cmd_tx
        .send(Command::DoSignaling { offer, response_tx })
        .await
    {
        eprintln!("Failed to send command: {}", e);
        let mut response = Response::new(Body::from("Internal Server Error"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(response);
    }

    // Wait for response from event loop
    let answer = match tokio::time::timeout(Duration::from_secs(10), response_rx.recv()).await {
        Ok(Some(answer)) => answer,
        Ok(None) => {
            eprintln!("Event loop closed channel");
            let mut response = Response::new(Body::from("Internal Server Error"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
        Err(_) => {
            eprintln!("Timeout waiting for answer");
            let mut response = Response::new(Body::from("Request Timeout"));
            *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
            return Ok(response);
        }
    };

    let payload = match serde_json::to_string(&answer) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to serialize answer: {}", e);
            let mut response = Response::new(Body::from("Internal Server Error"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    };

    let response = Response::builder()
        .header("content-type", "application/json")
        .status(StatusCode::OK)
        .body(Body::from(payload))
        .unwrap();

    Ok(response)
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

    // Create channel for HTTP server to send commands to event loop
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(100);

    // Start HTTP server
    println!("Open http://localhost:8080 to access this demo");
    let http_server = tokio::spawn(async move {
        let addr = SocketAddr::from_str("0.0.0.0:8080").unwrap();
        let make_svc = make_service_fn(move |_| {
            let cmd_tx = cmd_tx.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| remote_handler(req, cmd_tx.clone())))
            }
        });
        let server = Server::bind(&addr).serve(make_svc);
        if let Err(e) = server.await {
            eprintln!("server error: {e}");
        }
    });

    // Give the HTTP server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Prepare peer connection (will be created on first signaling)
    let mut peer_connection: Option<RTCPeerConnection> = None;
    let mut socket: Option<UdpSocket> = None;
    let mut local_addr: Option<SocketAddr> = None;
    let mut data_channel_opened = None;
    let mut last_send = Instant::now();

    println!("Press ctrl-c to stop");

    let mut buf = vec![0; 2000];

    'EventLoop: loop {
        // Process peer connection if it exists
        if let Some(pc) = peer_connection.as_mut() {
            // Poll writes
            while let Some(msg) = pc.poll_write() {
                if let Some(sock) = socket.as_ref() {
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
                                    "Data channel '{}'-'{}' open",
                                    dc.label().unwrap_or_default(),
                                    dc.id()
                                );
                                data_channel_opened = Some(channel_id);
                                last_send = Instant::now();
                            }
                        }
                        RTCDataChannelEvent::OnMessage(_channel_id, message) => {
                            let msg_str =
                                String::from_utf8(message.data.to_vec()).unwrap_or_default();
                            println!("Message from DataChannel: '{}'", msg_str);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            // Send periodic messages through data channel
            if let Some(channel_id) = data_channel_opened {
                if Instant::now().duration_since(last_send) >= Duration::from_secs(3) {
                    if let Some(mut dc) = pc.data_channel(channel_id) {
                        let message = format!("{:?}", Instant::now());
                        let _ = dc.send_text(message);
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
                res = async {
                    if let Some(sock) = socket.as_ref() {
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
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Command::DoSignaling { offer, response_tx } => {
                            println!("Received ICE restart signaling request");

                            // For ICE restart, we process the new offer
                            println!("Set remote description {} for ICE restart", offer);
                            pc.set_remote_description(offer)?;

                            let answer = pc.create_answer(None)?;
                            pc.set_local_description(answer.clone())?;
                            println!("Created and set answer {} for ICE restart", answer);

                            // Send answer back to HTTP handler
                            let _ = response_tx.send(answer).await;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!();
                    break 'EventLoop;
                }
            }
        } else {
            // No peer connection yet, wait for commands
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Command::DoSignaling { offer, response_tx } => {
                            println!("Received signaling request");

                            // Create peer connection
                            let sock = UdpSocket::bind("127.0.0.1:0").await?;
                            let local = sock.local_addr()?;
                            local_addr = Some(local);
                            println!("Bound to {}", local);

                            let mut setting_engine = SettingEngine::default();
                            setting_engine.set_answering_dtls_role(DTLSRole::Client)?;

                            let config = RTCConfigurationBuilder::new()
                                .with_ice_servers(vec![RTCIceServer {
                                    urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                                    ..Default::default()
                                }])
                                .with_setting_engine(setting_engine)
                                .build();

                            let mut pc = RTCPeerConnection::new(config)?;
                            println!("Created peer connection");

                            // Add local candidate
                            let candidate = CandidateHostConfig {
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
                            pc.add_local_candidate(local_candidate_init)?;

                            // Process the offer
                            println!("Set remote description {}", offer);
                            pc.set_remote_description(offer)?;

                            let answer = pc.create_answer(None)?;
                            pc.set_local_description(answer.clone())?;
                            println!("Created and set answer {}", answer);

                            // Send answer back to HTTP handler
                            let _ = response_tx.send(answer).await;

                            peer_connection = Some(pc);
                            socket = Some(sock);
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!();
                    break 'EventLoop;
                }
            }
        }
    }

    http_server.abort();
    if let Some(mut pc) = peer_connection {
        pc.close()?;
    }

    Ok(())
}
