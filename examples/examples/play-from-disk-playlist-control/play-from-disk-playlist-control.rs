//! play-from-disk-playlist-control streams Opus pages from single or multi-track Ogg containers,
//! exposes the playlist over a DataChannel, and lets the browser switch tracks.
//!
//! This example demonstrates:
//! - Loading multi-track OGG files with Opus audio
//! - WHEP-style HTTP signaling
//! - Data channel for playlist control (next/prev/track selection)
//! - Streaming audio with timing control

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{debug, error, trace};
use rtc::data_channel::RTCDataChannelId;
use rtc::interceptor::{Interceptor, Registry};
use rtc::media::io::ogg_reader::{
    OggHeader, OggHeaderType, OggReader, OpusTags, parse_opus_head, parse_opus_tags,
};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::str::FromStr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;

const LABEL_AUDIO: &str = "audio";
const LABEL_TRACK: &str = "webrtc-rs";
const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);
const RTP_OUTBOUND_MTU: usize = 1200;

#[derive(Parser)]
#[command(name = "play-from-disk-playlist-control")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "A playlist control example streaming Opus from multi-track OGG files.")]
struct Cli {
    #[arg(short, long, default_value_t = format!("127.0.0.1:8080"))]
    addr: String,
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(short, long, default_value_t = format!("playlist.ogg"))]
    playlist_file: String,
}

/// A buffered audio page ready for streaming
#[derive(Clone)]
struct BufferedPage {
    payload: Vec<u8>,
    duration: Duration,
    #[allow(dead_code)]
    granule: u64,
}

/// An OGG track with metadata and buffered pages
struct OggTrack {
    serial: u32,
    header: Option<OggHeader>,
    tags: Option<OpusTags>,
    title: String,
    artist: String,
    vendor: String,
    pages: Vec<BufferedPage>,
    runtime: Duration,
}

impl OggTrack {
    fn new(serial: u32) -> Self {
        Self {
            serial,
            header: None,
            tags: None,
            title: format!("serial-{}", serial),
            artist: String::new(),
            vendor: String::new(),
            pages: Vec::new(),
            runtime: Duration::ZERO,
        }
    }
}

/// Request from HTTP server to create a peer connection
struct WhepRequest {
    offer_sdp: String,
    response_tx: oneshot::Sender<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let addr = cli.addr;
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

    // Parse the playlist
    let playlist_file = cli.playlist_file;
    let tracks = parse_playlist(&playlist_file)?;
    if tracks.is_empty() {
        anyhow::bail!("no playable Opus pages were found in {}", playlist_file);
    }

    println!("Loaded {} track(s) from {}", tracks.len(), playlist_file);
    for (i, t) in tracks.iter().enumerate() {
        println!(
            "  [{}] serial={} title={:?} artist={:?} pages={} duration={:?}",
            i + 1,
            t.serial,
            t.title,
            t.artist,
            t.pages.len(),
            t.runtime
        );
    }

    let tracks = Arc::new(tracks);

    let (stop_tx, stop_rx) = channel::<()>(1);
    let (whep_tx, whep_rx) = channel::<WhepRequest>(16);

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

    // Start HTTP server
    let addr_clone = addr.clone();
    let http_handle = tokio::spawn(async move {
        if let Err(err) = run_http_server(&addr_clone, whep_tx).await {
            eprintln!("HTTP server error: {}", err);
        }
    });

    println!("Serving UI at http://{} ...", addr);

    // Run the main WebRTC handler
    if let Err(err) = run_webrtc_handler(stop_rx, whep_rx, tracks).await {
        eprintln!("WebRTC handler error: {}", err);
    }

    http_handle.abort();

    Ok(())
}

/// Parse a multi-track OGG playlist file
fn parse_playlist(path: &str) -> Result<Vec<OggTrack>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut ogg_reader = OggReader::new_with_options(reader, false);

    let mut tracks: HashMap<u32, OggTrack> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();
    let mut last_granule: HashMap<u32, u64> = HashMap::new();

    loop {
        let (payload, page_header) = match ogg_reader.parse_next_page() {
            Ok(result) => result,
            Err(e) => {
                // Check for EOF
                let err_str = e.to_string();
                if err_str.contains("EOF")
                    || err_str.contains("UnexpectedEof")
                    || err_str.contains("failed to fill")
                {
                    break;
                }
                return Err(e.into());
            }
        };

        let serial = page_header.serial;

        // Ensure track exists
        if !tracks.contains_key(&serial) {
            tracks.insert(serial, OggTrack::new(serial));
            order.push(serial);
        }

        let track = tracks.get_mut(&serial).unwrap();

        // Check for header pages
        if let Some(header_type) = page_header.opus_header_type(&payload) {
            match header_type {
                OggHeaderType::OpusHead => {
                    match parse_opus_head(&payload) {
                        Ok(header) => {
                            track.header = Some(header);
                        }
                        Err(err) => {
                            eprintln!("Failed to parse OpusHead: {}", err);
                        }
                    }
                    continue;
                }
                OggHeaderType::OpusTags => {
                    match parse_opus_tags(&payload) {
                        Ok(tags) => {
                            // Extract title and artist
                            for comment in &tags.user_comments {
                                match comment.comment.to_lowercase().as_str() {
                                    "title" => track.title = comment.value.clone(),
                                    "artist" => track.artist = comment.value.clone(),
                                    _ => {}
                                }
                            }
                            if track.vendor.is_empty() {
                                track.vendor = tags.vendor.clone();
                            }
                            track.tags = Some(tags);
                        }
                        Err(err) => {
                            eprintln!("Failed to parse OpusTags: {}", err);
                        }
                    }
                    continue;
                }
            }
        }

        // Skip if we don't have a header yet
        if track.header.is_none() {
            continue;
        }

        // Calculate page duration
        let duration = page_duration(
            track.header.as_ref().unwrap(),
            page_header.granule_position,
            *last_granule.get(&serial).unwrap_or(&0),
        );
        last_granule.insert(serial, page_header.granule_position);

        track.pages.push(BufferedPage {
            payload: payload.to_vec(),
            duration,
            granule: page_header.granule_position,
        });
        track.runtime += duration;
    }

    // Build ordered result
    let mut ordered = Vec::new();
    for serial in order {
        if let Some(mut track) = tracks.remove(&serial) {
            if track.pages.is_empty() {
                continue;
            }
            if track.title.is_empty() || track.title.starts_with("serial-") {
                track.title = format!("Track {}", ordered.len() + 1);
            }
            ordered.push(track);
        }
    }

    Ok(ordered)
}

/// Calculate the duration of a page based on granule positions
fn page_duration(header: &OggHeader, granule: u64, last: u64) -> Duration {
    let sample_rate = if header.sample_rate == 0 {
        48000
    } else {
        header.sample_rate
    };

    if granule <= last {
        return Duration::from_millis(20);
    }

    let sample_count = granule - last;
    if sample_count == 0 {
        return Duration::from_millis(20);
    }

    Duration::from_nanos((sample_count as f64 / sample_rate as f64 * 1_000_000_000.0) as u64)
}

/// Run the HTTP server for static files and WHEP signaling
async fn run_http_server(addr: &str, whep_tx: Sender<WhepRequest>) -> Result<()> {
    let addr: SocketAddr = addr.parse()?;

    let make_svc = make_service_fn(move |_conn| {
        let whep_tx = whep_tx.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let whep_tx = whep_tx.clone();
                async move { handle_request(req, whep_tx).await }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    server.await?;

    Ok(())
}

/// Handle HTTP requests
async fn handle_request(
    req: Request<Body>,
    whep_tx: Sender<WhepRequest>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/whep") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            let offer_sdp = String::from_utf8_lossy(&body).to_string();

            if offer_sdp.trim().is_empty() {
                let mut response = Response::new(Body::from("empty SDP"));
                *response.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(response);
            }

            let (response_tx, response_rx) = oneshot::channel();

            if whep_tx
                .send(WhepRequest {
                    offer_sdp,
                    response_tx,
                })
                .await
                .is_err()
            {
                let mut response = Response::new(Body::from("server error"));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            }

            match response_rx.await {
                Ok(answer_sdp) => {
                    let mut response = Response::new(Body::from(answer_sdp));
                    response
                        .headers_mut()
                        .insert("Content-Type", "application/sdp".parse().unwrap());
                    Ok(response)
                }
                Err(_) => {
                    let mut response = Response::new(Body::from("failed to create answer"));
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(response)
                }
            }
        }
        (&Method::GET, path) => {
            // Serve static files from web directory
            const WEB_DIR: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/play-from-disk-playlist-control/web"
            );
            let file_path = if path == "/" {
                format!("{}/index.html", WEB_DIR)
            } else {
                format!("{}{}", WEB_DIR, path)
            };

            match std::fs::read(&file_path) {
                Ok(content) => {
                    let content_type = if file_path.ends_with(".html") {
                        "text/html"
                    } else if file_path.ends_with(".css") {
                        "text/css"
                    } else if file_path.ends_with(".js") {
                        "application/javascript"
                    } else {
                        "application/octet-stream"
                    };

                    let mut response = Response::new(Body::from(content));
                    response
                        .headers_mut()
                        .insert("Content-Type", content_type.parse().unwrap());
                    Ok(response)
                }
                Err(_) => {
                    let mut response = Response::new(Body::from("not found"));
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    Ok(response)
                }
            }
        }
        _ => {
            let mut response = Response::new(Body::from("not found"));
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

/// Run the WebRTC handler for incoming connections
async fn run_webrtc_handler(
    mut stop_rx: Receiver<()>,
    mut whep_rx: Receiver<WhepRequest>,
    tracks: Arc<Vec<OggTrack>>,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                println!("Stopping WebRTC handler...");
                break;
            }

            Some(whep_request) = whep_rx.recv() => {
                let tracks = tracks.clone();
                // Handle connection - sends answer via response_tx, then runs peer connection loop
                if let Err(err) = handle_whep_connection(
                    whep_request.offer_sdp,
                    whep_request.response_tx,
                    tracks,
                ).await {
                    eprintln!("WHEP connection error: {}", err);
                }
            }
        }
    }

    Ok(())
}

/// Handle a single WHEP connection
async fn handle_whep_connection(
    offer_sdp: String,
    response_tx: oneshot::Sender<String>,
    tracks: Arc<Vec<OggTrack>>,
) -> Result<()> {
    println!("Received offer ({} bytes)", offer_sdp.len());

    // Create UDP socket - bind to localhost for local connections
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    // Setup media engine
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    let mut media_engine = MediaEngine::default();

    let opus_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 111,
        ..Default::default()
    };

    media_engine.register_codec(opus_codec.clone(), RtpCodecKind::Audio)?;

    let registry = Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;

    // Create audio track
    let ssrc: SSRC = rand::random();
    let output_track = MediaStreamTrack::new(
        "webrtc-rs-stream-id".to_string(),
        LABEL_AUDIO.to_string(),
        LABEL_TRACK.to_string(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: opus_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    let audio_sender_id = peer_connection.add_track(output_track)?;

    // Create data channel for playlist control
    let playlist_channel_id = peer_connection.create_data_channel("playlist", None)?.id();

    // Set remote description
    let offer = RTCSessionDescription::offer(offer_sdp)?;
    println!("Received Offer {}", offer);
    peer_connection.set_remote_description(offer)?;

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

    // Create answer
    let answer = peer_connection.create_answer(None)?;
    peer_connection.set_local_description(answer)?;

    let answer_sdp = peer_connection
        .local_description()
        .map(|d| d.sdp.clone())
        .unwrap_or_default();

    println!(
        "Created answer {}, starting streaming on {:?}",
        answer_sdp, local_addr
    );

    // Send answer back to HTTP handler IMMEDIATELY (before running the loop)
    let _ = response_tx.send(answer_sdp);

    // Now run the peer connection event loop
    run_peer_connection(
        socket,
        local_addr,
        peer_connection,
        tracks,
        audio_sender_id,
        playlist_channel_id,
        ssrc,
        opus_codec,
    )
    .await
}

/// Run the peer connection event loop
async fn run_peer_connection<I: Interceptor>(
    socket: UdpSocket,
    local_addr: std::net::SocketAddr,
    mut peer_connection: RTCPeerConnection<I>,
    tracks: Arc<Vec<OggTrack>>,
    audio_sender_id: RTCRtpSenderId,
    playlist_channel_id: RTCDataChannelId,
    ssrc: SSRC,
    codec: RTCRtpCodecParameters,
) -> Result<()> {
    let current_track = Arc::new(AtomicI32::new(0));
    let current_page = Arc::new(AtomicUsize::new(0));
    let switch_track = Arc::new(AtomicI32::new(-1)); // -1 means no switch requested
    let mut connected = false;

    // Create packetizer
    let mut packetizer = rtp::packetizer::new_packetizer(
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    let mut buf = vec![0; 2000];
    let mut last_stream_time = Instant::now();

    loop {
        // Send outgoing messages
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!(
                        "socket write to {} with bytes {}",
                        msg.transport.peer_addr, n
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

        // Process events
        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Peer Connection State: {}", state);
                    if state == RTCPeerConnectionState::Connected {
                        connected = true;

                        // Send initial playlist
                        if let Some(mut dc) = peer_connection.data_channel(playlist_channel_id) {
                            let playlist_msg = build_playlist_message(
                                &tracks,
                                current_track.load(Ordering::SeqCst),
                            );
                            let _ = dc.send_text(playlist_msg);
                        }
                    } else if state == RTCPeerConnectionState::Failed
                        || state == RTCPeerConnectionState::Closed
                    {
                        println!("Connection closed/failed, exiting...");
                        peer_connection.close()?;
                        return Ok(());
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(_) => {}
                    RTCDataChannelEvent::OnClose(_) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        // Process data channel messages
        while let Some(message) = peer_connection.poll_read() {
            if let RTCMessage::DataChannelMessage(dc_id, dc_message) = message {
                if dc_id == playlist_channel_id {
                    let command = String::from_utf8_lossy(&dc_message.data)
                        .trim()
                        .to_lowercase();
                    handle_playlist_command(
                        &command,
                        &tracks,
                        &current_track,
                        &switch_track,
                        &mut peer_connection,
                        playlist_channel_id,
                    );
                }
            }
        }

        // Stream audio if connected
        if connected && last_stream_time.elapsed() >= Duration::from_millis(20) {
            let track_idx = current_track.load(Ordering::SeqCst) as usize;
            if track_idx < tracks.len() {
                let track = &tracks[track_idx];
                let page_idx = current_page.load(Ordering::SeqCst);

                if page_idx < track.pages.len() {
                    let page = &track.pages[page_idx];

                    // Packetize and send
                    let sample_duration = page.duration;
                    let samples =
                        (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
                    let packets =
                        packetizer.packetize(&bytes::Bytes::from(page.payload.clone()), samples)?;

                    for mut packet in packets {
                        let mut rtp_sender = peer_connection
                            .rtp_sender(audio_sender_id)
                            .ok_or(Error::ErrRTPSenderNotExisted)?;

                        packet.header.ssrc = rtp_sender
                            .track()
                            .ssrcs()
                            .last()
                            .ok_or(Error::ErrSenderWithNoSSRCs)?;
                        debug!("sending rtp packet with media_ssrc={}", packet.header.ssrc);
                        rtp_sender.write_rtp(packet)?;
                    }

                    last_stream_time = Instant::now();

                    // Check for track switch
                    let switch = switch_track.swap(-1, Ordering::SeqCst);
                    if switch >= 0 && (switch as usize) < tracks.len() {
                        current_track.store(switch, Ordering::SeqCst);
                        current_page.store(0, Ordering::SeqCst);

                        // Send now playing
                        if let Some(mut dc) = peer_connection.data_channel(playlist_channel_id) {
                            let now_msg = build_now_playing_message(&tracks, switch as usize);
                            let _ = dc.send_text(now_msg);
                        }
                    } else {
                        current_page.store(page_idx + 1, Ordering::SeqCst);
                    }
                } else {
                    // Track finished, go to next
                    let next = wrap_next(track_idx as i32, tracks.len() as i32);
                    current_track.store(next, Ordering::SeqCst);
                    current_page.store(0, Ordering::SeqCst);

                    // Send now playing
                    if let Some(mut dc) = peer_connection.data_channel(playlist_channel_id) {
                        let now_msg = build_now_playing_message(&tracks, next as usize);
                        let _ = dc.send_text(now_msg);
                    }
                }
            }
        }

        // Poll timeout
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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = timer.as_mut() => {
                peer_connection.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes from {}", n, peer_addr);
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
                        break;
                    }
                }
            }
        }
    }

    peer_connection.close()?;
    Ok(())
}

/// Handle playlist control commands from data channel
fn handle_playlist_command<I: Interceptor>(
    command: &str,
    tracks: &[OggTrack],
    current_track: &AtomicI32,
    switch_track: &AtomicI32,
    peer_connection: &mut RTCPeerConnection<I>,
    playlist_channel_id: RTCDataChannelId,
) {
    let limit = tracks.len() as i32;
    let current = current_track.load(Ordering::SeqCst);
    let mut next = -1i32;

    match command {
        "next" | "n" | "forward" => {
            next = wrap_next(current, limit);
        }
        "prev" | "previous" | "p" | "back" => {
            next = wrap_prev(current, limit);
        }
        "list" => {
            if let Some(mut dc) = peer_connection.data_channel(playlist_channel_id) {
                let msg = build_playlist_message(tracks, current);
                let _ = dc.send_text(msg);
            }
            return;
        }
        _ => {
            // Try to parse as track number
            if let Ok(idx) = command.parse::<i32>() {
                next = normalize_index(idx - 1, limit);
            }
        }
    }

    if next < 0 || next == current {
        return;
    }

    switch_track.store(next, Ordering::SeqCst);

    if let Some(mut dc) = peer_connection.data_channel(playlist_channel_id) {
        let msg = build_playlist_message(tracks, next);
        let _ = dc.send_text(msg);
    }
}

/// Build playlist message for data channel
fn build_playlist_message(tracks: &[OggTrack], current: i32) -> String {
    let mut msg = format!(
        "playlist|{}\n",
        normalize_index(current, tracks.len() as i32)
    );

    for (i, t) in tracks.iter().enumerate() {
        msg.push_str(&format!(
            "track|{}|{}|{}|{}|{}\n",
            i,
            t.serial,
            t.runtime.as_millis(),
            clean_text(&t.title),
            clean_text(&t.artist),
        ));
    }

    if !tracks.is_empty() {
        let idx = normalize_index(current, tracks.len() as i32) as usize;
        msg.push_str(&build_now_line(&tracks[idx], idx));
    }

    msg
}

/// Build now-playing message
fn build_now_playing_message(tracks: &[OggTrack], index: usize) -> String {
    if index >= tracks.len() {
        return String::new();
    }
    build_now_line(&tracks[index], index)
}

/// Build the now-playing line
fn build_now_line(track: &OggTrack, index: usize) -> String {
    let comments = track
        .tags
        .as_ref()
        .map(|tags| {
            tags.user_comments
                .iter()
                .map(|c| format!("{}={}", clean_text(&c.comment), clean_text(&c.value)))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let channels = track.header.as_ref().map(|h| h.channels).unwrap_or(2);
    let sample_rate = track
        .header
        .as_ref()
        .map(|h| h.sample_rate)
        .unwrap_or(48000);

    format!(
        "now|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
        index,
        track.serial,
        channels,
        sample_rate,
        track.runtime.as_millis(),
        clean_text(&track.title),
        clean_text(&track.artist),
        clean_text(&track.vendor),
        comments,
    )
}

/// Clean text for data channel (remove newlines and pipes)
fn clean_text(v: &str) -> String {
    v.replace('\n', " ").replace('|', "/")
}

fn wrap_next(current: i32, limit: i32) -> i32 {
    if limit == 0 {
        return 0;
    }
    (current + 1) % limit
}

fn wrap_prev(current: i32, limit: i32) -> i32 {
    if limit == 0 {
        return 0;
    }
    if current == 0 {
        return limit - 1;
    }
    current - 1
}

fn normalize_index(i: i32, limit: i32) -> i32 {
    if limit == 0 {
        return 0;
    }
    if i < 0 {
        return 0;
    }
    if i >= limit {
        return limit - 1;
    }
    i
}
