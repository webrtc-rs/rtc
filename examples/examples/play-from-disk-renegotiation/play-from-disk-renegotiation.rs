use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{debug, error, trace};
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media_stream::track::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_VP8};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::session_description::RTCSessionDescription;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::state::signaling_state::RTCSignalingState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::peer_connection::RTCPeerConnection;
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::rtp_codec::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Notify,
};
use tokio_util::codec::{BytesCodec, FramedRead};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const RTP_OUTBOUND_MTU: usize = 1200;

enum PeerConnectionCommand {
    SetRemoteDescription(
        RTCSessionDescription,
        tokio::sync::oneshot::Sender<Result<RTCSessionDescription>>,
    ),
    AddTrack(SSRC, tokio::sync::oneshot::Sender<Result<RTCRtpSenderId>>),
    RemoveTrack(tokio::sync::oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
struct AppState {
    command_tx: Sender<PeerConnectionCommand>,
    message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
    codec: RTCRtpCodecParameters,
    video_file: Arc<Mutex<Option<String>>>,
    connection_notify: Arc<Notify>,
    // Track active video streaming tasks by sender_id
    streaming_tasks:
        Arc<Mutex<std::collections::HashMap<RTCRtpSenderId, tokio::sync::oneshot::Sender<()>>>>,
}

static INDEX: &str = "examples/examples/play-from-disk-renegotiation/index.html";
static NOTFOUND: &[u8] = b"Not Found";

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

// HTTP Listener to get ICE Credentials/Candidate from remote Peer
async fn remote_handler(
    req: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => simple_file_send(INDEX).await,

        (&Method::POST, "/createPeerConnection") => create_peer_connection(req, state).await,

        (&Method::POST, "/addVideo") => add_video(req, state).await,

        (&Method::POST, "/removeVideo") => remove_video(req, state).await,

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
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    let sdp_str = match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
        Ok(s) => s.to_owned(),
        Err(err) => panic!("{}", err),
    };
    let offer = match serde_json::from_str::<RTCSessionDescription>(&sdp_str) {
        Ok(s) => s,
        Err(err) => panic!("{}", err),
    };

    // Send command to set remote description and get answer
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if let Err(err) = state
        .command_tx
        .send(PeerConnectionCommand::SetRemoteDescription(
            offer,
            response_tx,
        ))
        .await
    {
        eprintln!(
            "Failed to send command (event loop may have exited): {}",
            err
        );
        let mut response = Response::new(Body::from("Event loop closed"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(response);
    }

    let answer = match response_rx.await {
        Ok(Ok(answer)) => answer,
        Ok(Err(err)) => {
            eprintln!("Failed to create answer: {}", err);
            let mut response =
                Response::new(Body::from(format!("Failed to create answer: {}", err)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
        Err(err) => {
            eprintln!("Failed to receive response: {}", err);
            let mut response = Response::new(Body::from("Failed to receive response"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    };

    let payload = match serde_json::to_string(&answer) {
        Ok(p) => p,
        Err(err) => panic!("{}", err),
    };

    let mut response = match Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(payload))
    {
        Ok(res) => res,
        Err(err) => panic!("{}", err),
    };

    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

// Create peer connection
async fn create_peer_connection(
    r: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    println!("PeerConnection has been created");
    do_signaling(r, state).await
}

// Add a single video track
async fn add_video(r: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    // Generate a new SSRC for this track
    let ssrc = rand::random::<u32>();

    // Send command to add track
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if let Err(err) = state
        .command_tx
        .send(PeerConnectionCommand::AddTrack(ssrc, response_tx))
        .await
    {
        eprintln!(
            "Failed to send command (event loop may have exited): {}",
            err
        );
        let mut response = Response::new(Body::from("Event loop closed"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(response);
    }

    let rtp_sender_id = match response_rx.await {
        Ok(Ok(id)) => id,
        Ok(Err(err)) => {
            eprintln!("Failed to add track: {}", err);
            let mut response = Response::new(Body::from(format!("Failed to add track: {}", err)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
        Err(err) => {
            eprintln!("Failed to receive response: {}", err);
            let mut response = Response::new(Body::from("Failed to receive response"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    };

    let video_file: Option<String> = {
        let vf = state.video_file.lock().await;
        vf.clone()
    };

    if let Some(video_file) = video_file {
        let notify = state.connection_notify.clone();
        let message_tx = state.message_tx.clone();
        let codec = state.codec.clone();

        // Create a cancellation channel for this streaming task
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // Store the cancellation sender
        {
            let mut tasks = state.streaming_tasks.lock().await;
            tasks.insert(rtp_sender_id, cancel_tx);
        }

        let streaming_tasks = state.streaming_tasks.clone();
        tokio::spawn(async move {
            if let Err(err) = stream_video(
                (ssrc, codec),
                video_file,
                rtp_sender_id,
                notify,
                message_tx,
                cancel_rx,
            )
            .await
            {
                eprintln!("video streaming error: {}", err);
            }
            // Remove self from tracking when done
            let mut tasks = streaming_tasks.lock().await;
            tasks.remove(&rtp_sender_id);
        });
    }

    println!("Video track has been added");
    do_signaling(r, state).await
}

// Remove a single sender
async fn remove_video(
    r: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    // Send command to remove track
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if let Err(err) = state
        .command_tx
        .send(PeerConnectionCommand::RemoveTrack(response_tx))
        .await
    {
        eprintln!(
            "Failed to send command (event loop may have exited): {}",
            err
        );
        let mut response = Response::new(Body::from("Event loop closed"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(response);
    }

    match response_rx.await {
        Ok(Ok(_)) => {
            println!("Video track has been removed");
        }
        Ok(Err(err)) => {
            eprintln!("Failed to remove track: {}", err);
            let mut response =
                Response::new(Body::from(format!("Failed to remove track: {}", err)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
        Err(err) => {
            eprintln!("Failed to receive response: {}", err);
            let mut response = Response::new(Body::from("Failed to receive response"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    };

    do_signaling(r, state).await
}

#[derive(Parser)]
#[command(name = "play-from-disk-renegotiation")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of play-from-disk-renegotiation.")]
struct Cli {
    #[arg(short, long)]
    client: bool,
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(short, long)]
    video: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
    let is_client = cli.client;
    let output_log_file = cli.output_log_file;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    let video_file = cli.video;

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

    let video_file_state = Arc::new(Mutex::new(video_file.clone()));

    if let Some(video_path) = &video_file {
        if !Path::new(video_path).exists() {
            return Err(anyhow::anyhow!("video file: '{}' not exist", video_path));
        }
    }

    let (stop_tx, stop_rx) = channel::<()>(1);

    println!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.try_send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });

    if let Err(err) = run(stop_rx, host, port, is_client, video_file_state).await {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: Receiver<()>,
    host: String,
    port: u16,
    is_client: bool,
    video_file: Arc<Mutex<Option<String>>>,
) -> Result<()> {
    // Everything below is the RTC API! Thanks for using it ❤️.
    let socket = UdpSocket::bind(format!("{host}:{port}")).await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(if is_client {
        DTLSRole::Client
    } else {
        DTLSRole::Server
    })?;

    // Create a MediaEngine object to configure the supported codec
    let mut media_engine = MediaEngine::default();

    let video_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 96,
        ..Default::default()
    };

    // Setup the video codec
    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    /*TODO:
    // Create a InterceptorRegistry. This is the user configurable RTP/RTCP Pipeline.
    // This provides NACKs, RTCP Reports and other features. If you use `webrtc.NewPeerConnection`
    // this is enabled by default. If you are manually managing You MUST create a InterceptorRegistry
    // for each PeerConnection.
    let mut registry = Registry::new();

    // Use the default set of Interceptors
    registry = register_default_interceptors(registry, &mut m)?;
    */

    // Create RTC peer connection configuration
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Add local candidate
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

    println!("listening {}...", socket.local_addr()?);

    let (message_tx, mut message_rx) = channel::<(RTCRtpSenderId, rtp::Packet)>(8);
    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);
    let (command_tx, mut command_rx) = channel::<PeerConnectionCommand>(8);

    let connection_notify = Arc::new(Notify::new());
    let streaming_tasks = Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Create app state
    let app_state = Arc::new(AppState {
        command_tx: command_tx.clone(),
        message_tx: message_tx.clone(),
        codec: video_codec,
        video_file,
        connection_notify: connection_notify.clone(),
        streaming_tasks: streaming_tasks.clone(),
    });

    let app_state_clone = app_state.clone();
    tokio::spawn(async move {
        println!("Open http://localhost:8080 to access this demo");

        let addr = SocketAddr::from_str("0.0.0.0:8080").unwrap();
        let service = make_service_fn(move |_| {
            let state = app_state_clone.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| remote_handler(req, state.clone())))
            }
        });
        let server = Server::bind(&addr).serve(service);
        if let Err(e) = server.await {
            eprintln!("server error: {e}");
        }
    });

    let mut buf = vec![0; 2000];
    'EventLoop: loop {
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!(
                        "socket write to {} with bytes {}",
                        msg.transport.peer_addr,
                        n
                    );
                }
                Err(err) => {
                    error!(
                        "socket write to {} with error {}",
                        msg.transport.peer_addr, err
                    );
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    println!("ICE Connection State has changed: {ice_connection_state}");
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    } else if peer_connection_state == RTCPeerConnectionState::Connected {
                        println!("Peer Connection State has gone to connected!");
                    }
                }
                RTCPeerConnectionEvent::OnSignalingStateChangeEvent(signaling_state) => {
                    println!("Signaling State has changed: {signaling_state}");
                    if signaling_state == RTCSignalingState::Stable {
                        connection_notify.notify_waiters();
                    }
                }
                _ => {}
            }
        }

        // Poll peer_connection to get next timeout
        let eto = peer_connection
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            peer_connection.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                trace!("pipeline socket exit loop");
                break 'EventLoop;
            }
            res = command_rx.recv() => {
                match res {
                    Some(PeerConnectionCommand::SetRemoteDescription(offer, response_tx)) => {
                        // Set the remote SessionDescription
                        println!("Received Offer={}", offer);
                        if let Err(err) = peer_connection.set_remote_description(offer) {
                            let _ = response_tx.send(Err(err.into()));
                            continue;
                        }

                        // Create an answer
                        let answer = match peer_connection.create_answer(None) {
                            Ok(answer) => answer,
                            Err(err) => {
                                let _ = response_tx.send(Err(err.into()));
                                continue;
                            }
                        };

                        // Sets the LocalDescription
                        println!("Created Answer={}", answer);
                        if let Err(err) = peer_connection.set_local_description(answer.clone()) {
                            let _ = response_tx.send(Err(err.into()));
                            continue;
                        }

                        let _ = response_tx.send(Ok(answer));
                    }
                    Some(PeerConnectionCommand::AddTrack(ssrc, response_tx)) => {
                        let video_track = MediaStreamTrack::new(
                            format!("webrtc-rs-stream-id-{}", rand::random::<u32>()),
                            format!("webrtc-rs-track-id-{}", rand::random::<u32>()),
                            format!("webrtc-rs-track-label-{}", rand::random::<u32>()),
                            RtpCodecKind::Video,
                            None, // rid
                            ssrc,
                            app_state.codec.rtp_codec.clone(),
                        );

                        match peer_connection.add_track(video_track) {
                            Ok(rtp_sender_id) => {
                                let _ = response_tx.send(Ok(rtp_sender_id));
                            }
                            Err(err) => {
                                let _ = response_tx.send(Err(err.into()));
                            }
                        }
                    }
                    Some(PeerConnectionCommand::RemoveTrack(response_tx)) => {
                        // Get the first sender and remove it
                        let senders: Vec<RTCRtpSenderId> = peer_connection.get_senders().collect();
                        if !senders.is_empty() {
                            let sender_id = senders[0];
                            println!("Removing sender: {:?}", sender_id);

                            // Cancel the streaming task for this sender
                            if let Some(cancel_tx) = {
                                let mut tasks = app_state.streaming_tasks.lock().await;
                                tasks.remove(&sender_id)
                            } {
                                let _ = cancel_tx.send(());
                                println!("Cancelled video streaming task for sender: {:?}", sender_id);
                            }

                            match peer_connection.remove_track(sender_id) {
                                Ok(_) => {
                                    let _ = response_tx.send(Ok(()));
                                }
                                Err(err) => {
                                    let _ = response_tx.send(Err(err.into()));
                                }
                            }
                        } else {
                            let _ = response_tx.send(Ok(()));
                        }
                    }
                    None => {
                        eprintln!("command_rx.recv() is closed");
                        break 'EventLoop;
                    }
                }
            }
            res = message_rx.recv() => {
                match res {
                    Some((rtp_sender_id, packet)) => {
                        let mut rtp_sender = peer_connection
                            .rtp_sender(rtp_sender_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        debug!("sending rtp packet with media_ssrc={}", packet.header.ssrc);
                        rtp_sender.write_rtp(packet)?;
                    }
                    None => {
                        eprintln!("message_rx.recv() is closed");
                        break 'EventLoop;
                    }
                }
            }
            res = event_rx.recv() => {
                match res {
                    Some(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    None => {
                        eprintln!("event_rx.recv() is closed");
                        break 'EventLoop;
                    }
                }
            }
            _ = timer.as_mut() => {
                peer_connection.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes", n);
                        peer_connection.handle_read(TaggedBytesMut {
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
                    Err(err) => {
                        eprintln!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    peer_connection.close()?;

    Ok(())
}

async fn stream_video(
    (ssrc, codec): (SSRC, RTCRtpCodecParameters),
    video_file_name: String,
    video_sender_id: RTCRtpSenderId,
    video_notify_rx: Arc<Notify>,
    video_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    // Wait for connection established
    video_notify_rx.notified().await;

    println!("play video from disk file {video_file_name}");

    let mut packetizer = rtp::packetizer::new_packetizer(
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    //TODO: packetizer.enable_abs_send_time(ext_id);

    // Open a IVF file and start reading using our IVFReader
    let file = File::open(&video_file_name)?;
    let reader = BufReader::new(file);
    let (mut ivf, header) = IVFReader::new(reader)?;

    // It is important to use a time.Ticker instead of time.Sleep because
    // * avoids accumulating skew, just calling time.Sleep didn't compensate for the time spent parsing the data
    // * works around latency issues with Sleep
    // Send our video file frame at a time. Pace our sending so we send it at the same speed it should be played back as.
    // This isn't required since the video is timestamped, but we will such much higher loss if we send all at once.
    let sleep_time = Duration::from_millis(
        ((1000 * header.timebase_numerator) / header.timebase_denominator) as u64,
    );
    let mut ticker = tokio::time::interval(sleep_time);

    loop {
        // Check for cancellation
        if cancel_rx.try_recv().is_ok() {
            println!(
                "Video streaming cancelled for sender: {:?}",
                video_sender_id
            );
            break;
        }

        let frame = match ivf.parse_next_frame() {
            Ok((frame, _)) => frame,
            Err(err) => {
                println!("All video frames parsed and sent: {err}");
                break;
            }
        };

        let sample_duration = Duration::from_millis(40);
        let samples = (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
        let packets = packetizer.packetize(&frame.freeze(), samples)?;
        for packet in packets {
            if video_message_tx
                .send((video_sender_id, packet))
                .await
                .is_err()
            {
                println!("Failed to send video packet, channel closed");
                break;
            }
        }

        let _ = ticker.tick().await;
    }

    Ok(())
}
