use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use log::error;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::shared::util::math_rand_alpha;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "data-channels-answer")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.0.0")]
#[command(about = "An example of WebRTC-rs data-channels-Answer", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("localhost:50000"))]
    offer_address: String,
    #[arg(long, default_value_t = format!("0.0.0.0:60000"))]
    answer_address: String,
}

// Commands from HTTP server to event loop
enum Command {
    AddIceCandidate(RTCIceCandidateInit),
    SetRemoteDescription(RTCSessionDescription),
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

// HTTP Listener to get ICE Credentials/Candidate from remote Peer
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
                        eprintln!("Failed to parse candidate: {}", e);
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
                    eprintln!("Failed to parse SDP: {}", e);
                    let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            let sdp = match serde_json::from_str::<RTCSessionDescription>(&sdp_str) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to deserialize SDP: {}", e);
                    let mut response = Response::new(Body::from(format!("Bad Request: {}", e)));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

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

    let offer_addr = cli.offer_address.clone();
    let answer_addr = cli.answer_address;

    // Prepare the configuration
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Get local candidates
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
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

    // Create channel for HTTP server to send commands to event loop
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(100);

    // Start HTTP server
    println!("Listening on http://{answer_addr}");
    let http_server = tokio::spawn(async move {
        let addr = SocketAddr::from_str(&answer_addr).unwrap();
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

    // Run event loop
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    let mut buf = vec![0; 2000];
    let mut data_channel_opened = None;
    let mut last_send = Instant::now();
    let mut pending_candidates = vec![local_candidate_init.clone()];

    println!("Press ctrl-c to stop");
    println!("Waiting for offer from http://{offer_addr}...");

    'EventLoop: loop {
        // Poll writes
        while let Some(msg) = peer_connection.poll_write() {
            if let Err(e) = socket.send_to(&msg.message, msg.transport.peer_addr).await {
                error!("Socket write error: {}", e);
            }
        }

        // Poll events
        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Peer Connection State has changed: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        println!("Peer Connection has gone to failed exiting");
                        let _ = stop_tx.try_send(());
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(channel_id) => {
                        if let Some(dc) = peer_connection.data_channel(channel_id) {
                            println!(
                                "Data channel '{}'-'{}' open. Random messages will now be sent every 5 seconds",
                                dc.label().unwrap_or_default(),
                                dc.id()
                            );
                            data_channel_opened = Some(channel_id);
                            last_send = Instant::now();
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(_channel_id, data_channel_message) => {
                    let msg_str =
                        String::from_utf8(data_channel_message.data.to_vec()).unwrap_or_default();
                    println!("Message from DataChannel: '{}'", msg_str);
                }
            }
        }

        // Send periodic messages
        if let Some(channel_id) = data_channel_opened {
            if Instant::now().duration_since(last_send) >= Duration::from_secs(5) {
                if let Some(mut dc) = peer_connection.data_channel(channel_id) {
                    let message = math_rand_alpha(15);
                    println!("Sending '{}'", message);
                    let _ = dc.send_text(message);
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

        let timer = tokio::time::sleep(delay);
        tokio::pin!(timer);

        tokio::select! {
            _ = timer => {
                peer_connection.handle_timeout(Instant::now()).ok();
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    Command::AddIceCandidate(candidate) => {
                        if let Err(e) = peer_connection.add_local_candidate(candidate) {
                            eprintln!("Failed to add ICE candidate: {}", e);
                        }
                    }
                    Command::SetRemoteDescription(sdp) => {
                        if let Err(e) = peer_connection.set_remote_description(sdp) {
                            eprintln!("Failed to set remote description: {}", e);
                        } else {
                            println!("Remote description (offer) set successfully");

                            // Add local candidate
                            if let Err(e) = peer_connection.add_local_candidate(local_candidate_init.clone()) {
                                eprintln!("Failed to add local candidate: {}", e);
                            }

                            // Create answer
                            match peer_connection.create_answer(None) {
                                Ok(answer) => {
                                    if let Err(e) = peer_connection.set_local_description(answer.clone()) {
                                        eprintln!("Failed to set local description: {}", e);
                                    } else {
                                        println!("Created and set answer, sending to offer");
                                        // Send answer back to offer
                                        let payload = match serde_json::to_string(&answer) {
                                            Ok(p) => p,
                                            Err(e) => {
                                                eprintln!("Failed to serialize answer: {}", e);
                                                continue;
                                            }
                                        };

                                        let req = match Request::builder()
                                            .method(Method::POST)
                                            .uri(format!("http://{}/sdp", offer_addr))
                                            .header("content-type", "application/json; charset=utf-8")
                                            .body(Body::from(payload)) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                eprintln!("Failed to build request: {}", e);
                                                continue;
                                            }
                                        };

                                        if let Err(e) = Client::new().request(req).await {
                                            eprintln!("Failed to send answer: {}", e);
                                        } else {
                                            println!("Answer sent successfully");
                                        }

                                        // Send any pending candidates
                                        for candidate in pending_candidates.drain(..) {
                                            if let Err(e) = signal_candidate(&offer_addr, &candidate).await {
                                                eprintln!("Failed to signal candidate: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to create answer: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, peer_addr)) = res {
                    peer_connection.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    }).ok();
                }
            }
            _ = stop_rx.recv() => {
                break 'EventLoop;
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                break 'EventLoop;
            }
        }
    }

    http_server.abort();
    peer_connection.close()?;

    Ok(())
}
