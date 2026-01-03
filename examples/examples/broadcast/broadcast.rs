use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{debug, error, trace};
use rtc::media_stream::track::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::track_event::RTCRtpRtcpPacket;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::session_description::RTCSessionDescription;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::rtp;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use rtc::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, channel};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400);

#[derive(Parser)]
#[command(name = "broadcast")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of broadcast.")]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let output_log_file = cli.output_log_file;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    let port = cli.port;

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

    let mut sdp_chan_rx = signal::http_sdp_server(port).await;

    // Wait for the first offer (from broadcaster)
    println!("Waiting for broadcaster offer on port {}", port);
    let line = sdp_chan_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("SDP channel closed"))?;
    let desc_data = signal::decode(line.as_str())?;
    let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;

    // Channel for broadcasting RTP packets from receiver to all viewers
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<rtp::Packet>(1000);
    let broadcast_tx = Arc::new(broadcast_tx);

    // Channel for sharing codec information from receiver to viewers
    let (codec_tx, _) = tokio::sync::broadcast::channel::<
        rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec,
    >(1);
    let codec_tx = Arc::new(codec_tx);

    let (stop_tx, _stop_rx) = tokio::sync::broadcast::channel::<()>(1);

    println!("Press Ctrl-C to stop");
    let stop_tx_clone = stop_tx.clone();
    std::thread::spawn(move || {
        ctrlc::set_handler(move || {
            let _ = stop_tx_clone.send(());
        })
        .expect("Error setting Ctrl-C handler");
    });

    // Run the broadcast receiver in its own thread with its own event loop
    let broadcast_tx_clone = broadcast_tx.clone();
    let codec_tx_clone = codec_tx.clone();
    let receiver_stop_rx = stop_tx.subscribe();
    let receiver_handle = std::thread::spawn(move || {
        // Create a new tokio runtime for this thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            if let Err(err) =
                run_broadcaster(receiver_stop_rx, offer, broadcast_tx_clone, codec_tx_clone).await
            {
                eprintln!("Broadcast receiver error: {}", err);
            }
        });
    });

    // Handle additional viewer connections in main task
    // Each viewer gets its own thread with its own event loop
    if let Err(err) = handle_viewers(sdp_chan_rx, broadcast_tx, codec_tx, stop_tx.clone()).await {
        eprintln!("Viewers handler error: {}", err);
    }

    // Wait for receiver thread to complete
    if let Err(err) = receiver_handle.join() {
        eprintln!("Receiver thread panicked: {:?}", err);
    }

    println!("Broadcast server shut down successfully");

    Ok(())
}

// Broadcaster runs in its own thread with its own event loop
// Receives video from browser and forwards to broadcast channel
async fn run_broadcaster(
    mut stop_rx: tokio::sync::broadcast::Receiver<()>,
    offer: RTCSessionDescription,
    broadcast_tx: Arc<tokio::sync::broadcast::Sender<rtp::Packet>>,
    codec_tx: Arc<
        tokio::sync::broadcast::Sender<rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec>,
    >,
) -> Result<()> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(DTLSRole::Server)?;

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Add transceiver to receive video
    peer_connection.add_transceiver_from_kind(RtpCodecKind::Video, None)?;

    peer_connection.set_remote_description(offer)?;

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

    let answer = peer_connection.create_answer(None)?;
    peer_connection.set_local_description(answer)?;

    if let Some(local_desc) = peer_connection.local_description() {
        let json_str = serde_json::to_string(local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("Broadcast receiver answer:\n{}", b64);
    }

    println!(
        "Broadcast receiver listening on {}...",
        socket.local_addr()?
    );

    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);

    let mut buf = vec![0; 2000];
    let mut packet_count = 0u64;

    // This PeerConnection has its own event loop
    'EventLoop: loop {
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

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    println!("[Receiver] ICE Connection State: {ice_connection_state}");
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("[Receiver] Peer Connection State: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("[Receiver] Connection failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => {
                    // On first track, get the codec information and broadcast it
                    // TODO: https://github.com/webrtc-rs/rtc/issues/7
                    if packet_count == 0 {
                        if let Some(receiver) =
                            peer_connection.rtp_receiver(track_event.receiver_id)
                        {
                            if let Ok(track) = receiver.track() {
                                let codec = track.codec().clone();
                                println!(
                                    "[Receiver] Received track with codec: {}",
                                    codec.mime_type
                                );
                                let _ = codec_tx.send(codec);
                            }
                        }
                    }

                    trace!(
                        "[Receiver] OnTrack event for receiver {:?}",
                        track_event.receiver_id
                    );

                    // Handle RTP/RTCP packets from the track
                    match track_event.packet {
                        RTCRtpRtcpPacket::Rtp(packet) => {
                            packet_count += 1;
                            if packet_count % 100 == 0 {
                                debug!("[Receiver] Broadcasting RTP packet #{}", packet_count);
                            }
                            // Broadcast the RTP packet directly to all viewers
                            let _ = broadcast_tx.send(packet);
                        }
                        RTCRtpRtcpPacket::Rtcp(_rtcp_packets) => {
                            // Handle RTCP if needed
                            trace!("[Receiver] Received RTCP packets");
                        }
                    }
                }
                _ => {}
            }
        }

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
                trace!("[Receiver] stop signal received");
                break 'EventLoop;
            }
            res = event_rx.recv() => {
                match res {
                    Some(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    None => {
                        eprintln!("[Receiver] event_rx closed");
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
                        trace!("[Receiver] socket read {} bytes", n);
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
                        eprintln!("[Receiver] socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    peer_connection.close()?;
    println!(
        "[Receiver] Event loop exited, broadcasted {} packets",
        packet_count
    );
    Ok(())
}

// Handle viewer connections - each viewer gets its own thread with its own event loop
async fn handle_viewers(
    mut sdp_chan_rx: Receiver<String>,
    broadcast_tx: Arc<tokio::sync::broadcast::Sender<rtp::Packet>>,
    codec_tx: Arc<
        tokio::sync::broadcast::Sender<rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec>,
    >,
    stop_tx: tokio::sync::broadcast::Sender<()>,
) -> Result<()> {
    let mut viewer_count = 0;
    let mut main_stop_rx = stop_tx.subscribe();
    let mut viewer_handles = Vec::new();

    loop {
        tokio::select! {
            line_opt = sdp_chan_rx.recv() => {
                let line = match line_opt {
                    Some(line) => line,
                    None => {
                        println!("SDP channel closed");
                        break;
                    }
                };

                let desc_data = signal::decode(line.as_str())?;
                let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;

                viewer_count += 1;
                let viewer_id = viewer_count;

                println!("\nNew viewer #{} connecting...", viewer_id);

                // Each viewer connection runs in its own thread with its own event loop
                let broadcast_rx = broadcast_tx.subscribe();
                let codec_rx = codec_tx.subscribe();
                let viewer_stop_rx = stop_tx.subscribe();
                let handle = std::thread::spawn(move || {
                    // Create a new tokio runtime for this thread
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    rt.block_on(async move {
                        if let Err(err) = run_viewer(viewer_id, offer, broadcast_rx, codec_rx, viewer_stop_rx).await {
                            eprintln!("[Viewer {}] Error: {}", viewer_id, err);
                        }
                    });
                });

                viewer_handles.push(handle);
                println!("Viewer #{} spawned (total viewers: {})", viewer_id, viewer_count);
            }
            _ = main_stop_rx.recv() => {
                println!("Stop signal received in handle_viewers, shutting down...");
                break;
            }
        }
    }

    // Wait for all viewer threads to complete
    println!(
        "Waiting for {} viewer thread(s) to complete...",
        viewer_handles.len()
    );
    for (idx, handle) in viewer_handles.into_iter().enumerate() {
        if let Err(err) = handle.join() {
            eprintln!("Viewer thread #{} panicked: {:?}", idx + 1, err);
        }
    }
    println!("All viewer threads completed");

    Ok(())
}

// Each viewer runs in its own thread with its own event loop
async fn run_viewer(
    viewer_id: usize,
    offer: RTCSessionDescription,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<rtp::Packet>,
    mut codec_rx: tokio::sync::broadcast::Receiver<
        rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec,
    >,
    mut stop_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(DTLSRole::Server)?;

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Wait for codec information from broadcaster
    println!(
        "[Viewer {}] Waiting for codec information from broadcaster...",
        viewer_id
    );
    let rtp_codec = codec_rx
        .recv()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to receive codec: {}", e))?;

    println!(
        "[Viewer {}] Received codec: {}",
        viewer_id, rtp_codec.mime_type
    );

    // Add a video track with the same codec as the incoming stream
    let _video_codec = RTCRtpCodecParameters {
        rtp_codec: rtp_codec.clone(),
        payload_type: 96,
        ..Default::default()
    };

    let ssrc = rand::random::<u32>();
    let video_track = MediaStreamTrack::new(
        format!("webrtc-rs-stream-{}", viewer_id),
        format!("webrtc-rs-track-{}", viewer_id),
        format!("webrtc-rs-video-{}", viewer_id),
        RtpCodecKind::Video,
        None, // rid
        ssrc,
        rtp_codec,
    );

    let _rtp_sender_id = peer_connection.add_track(video_track)?;

    peer_connection.set_remote_description(offer)?;

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

    let answer = peer_connection.create_answer(None)?;
    peer_connection.set_local_description(answer)?;

    if let Some(local_desc) = peer_connection.local_description() {
        let json_str = serde_json::to_string(local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("[Viewer {}] Answer:\n{}", viewer_id, b64);
    }

    println!(
        "[Viewer {}] Listening on {}...",
        viewer_id,
        socket.local_addr()?
    );

    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);

    let mut buf = vec![0; 2000];
    let mut sent_count = 0u64;

    // This viewer PeerConnection has its own event loop
    'EventLoop: loop {
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!("[Viewer {}] socket write {} bytes", viewer_id, n);
                }
                Err(err) => {
                    error!("[Viewer {}] socket write error {}", viewer_id, err);
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!(
                        "[Viewer {}] Connection State: {}",
                        viewer_id, peer_connection_state
                    );
                    if peer_connection_state == RTCPeerConnectionState::Failed
                        || peer_connection_state == RTCPeerConnectionState::Closed
                    {
                        break 'EventLoop;
                    }
                }
                _ => {}
            }
        }

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
                println!("[Viewer {}] Stop signal received, shutting down...", viewer_id);
                break 'EventLoop;
            }
            res = broadcast_rx.recv() => {
                match res {
                    Ok(packet) => {
                         trace!("[Viewer {}] receive rtp packet from broadcaster", viewer_id);
                        // Get all sender IDs and write packet to each
                        let sender_ids: Vec<RTCRtpSenderId> = peer_connection.get_senders().collect();
                        for sender_id in sender_ids {
                            if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
                                if let Err(err) = sender.write_rtp(packet.clone()) {
                                    if err != Error::ErrClosedPipe {
                                        debug!("[Viewer {}] sender {:?} write error: {}", viewer_id, sender_id, err);
                                    }
                                } else {
                                    sent_count += 1;
                                    if sent_count % 100 == 0 {
                                        debug!("[Viewer {}] Sent {} packets", viewer_id, sent_count);
                                    }
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        debug!("[Viewer {}] Lagged, skipped {} messages", viewer_id, skipped);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        println!("[Viewer {}] Broadcast channel closed", viewer_id);
                        break 'EventLoop;
                    }
                }
            }
            res = event_rx.recv() => {
                match res {
                    Some(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    None => break 'EventLoop,
                }
            }
            _ = timer.as_mut() => {
                peer_connection.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("[Viewer {}] socket read {} bytes", viewer_id, n);
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
                        eprintln!("[Viewer {}] socket read error {}", viewer_id, err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    peer_connection.close()?;
    println!(
        "[Viewer {}] Event loop exited, sent {} packets",
        viewer_id, sent_count
    );
    Ok(())
}
