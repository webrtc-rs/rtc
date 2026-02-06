use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{debug, error, trace};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use signal;
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day

#[derive(Parser)]
#[command(name = "rtp-to-webrtc")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of rtp-to-webrtc")]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    input_sdp_file: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let input_sdp_file = cli.input_sdp_file;
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

    // Wait for the offer to be pasted
    println!("Paste your offer here:");
    let line = if input_sdp_file.is_empty() {
        signal::must_read_stdin()?
    } else {
        std::fs::read_to_string(&input_sdp_file)?
    };
    let desc_data = signal::decode(line.as_str())?;
    let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;
    println!("Offer received: {}", offer);

    // Open a UDP Listener for RTP Packets on port 5004
    let rtp_listener = UdpSocket::bind("127.0.0.1:5004").await?;
    println!("Listening for RTP packets on 127.0.0.1:5004");

    // Run the peer connection with event loop
    run_peer_connection(offer, rtp_listener).await?;

    Ok(())
}

async fn run_peer_connection(offer: RTCSessionDescription, rtp_listener: UdpSocket) -> Result<()> {
    let setting_engine = SettingEngine::default();

    // Create a MediaEngine with VP8 support
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let registry = Registry::new();

    // Use the default set of Interceptors
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    // Create configuration with STUN server
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    // Create PeerConnection
    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;

    // Bind to local UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    println!("RTP forwarder listening on {}", local_addr);

    // Set remote description (offer)
    peer_connection.set_remote_description(offer)?;

    // Add video track
    let video_ssrc = rand::random::<u32>();

    let video_track = MediaStreamTrack::new(
        format!("webrtc-rs-stream-id-{}", rand::random::<u32>()),
        format!("webrtc-rs-track-id-{}", rand::random::<u32>()),
        format!("webrtc-rs-track-label-{}", rand::random::<u32>()),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(video_ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "".to_owned(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    );

    let sender_id = peer_connection.add_track(video_track)?;
    println!("Added video track with sender_id: {:?}", sender_id);

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

    let answer = peer_connection.create_answer(None)?;
    println!("Created Answer={}", answer);
    peer_connection.set_local_description(answer.clone())?;

    // Output the answer
    let json_str = serde_json::to_string(&answer)?;
    let b64 = signal::encode(&json_str);
    println!("\nPaste this answer in your browser:\n{}\n", b64);

    let mut buf = vec![0; 2000];
    let mut inbound_rtp_buffer = vec![0u8; 1600]; // UDP MTU

    println!("Press ctrl-c to stop");

    // Event loop
    'EventLoop: loop {
        // Write outgoing messages
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

        // Handle events
        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    println!("ICE Connection State: {ice_connection_state}");
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Peer Connection State: {state}");
                    if state == RTCPeerConnectionState::Failed {
                        println!("Connection failed, exiting...");
                        break 'EventLoop;
                    } else if state == RTCPeerConnectionState::Connected {
                        println!("Connection established!");
                    }
                }
                _ => {}
            }
        }

        // Poll for outgoing RTCP (we don't need to handle incoming RTP/RTCP here)
        while let Some(message) = peer_connection.poll_read() {
            match message {
                rtc::peer_connection::message::RTCMessage::RtpPacket(_, _) => {
                    // We're only sending, not receiving
                }
                rtc::peer_connection::message::RTCMessage::RtcpPacket(_, _) => {
                    trace!("Received RTCP packets");
                }
                rtc::peer_connection::message::RTCMessage::DataChannelMessage(_, _) => {}
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
            // Handle Ctrl-C
            _ = tokio::signal::ctrl_c() => {
                println!("\nReceived Ctrl-C, shutting down...");
                break 'EventLoop;
            }
            // Handle timeouts
            _ = timer.as_mut() => {
                let now = Instant::now();
                peer_connection.handle_timeout(now)?;
            }
            // Handle socket reads (DTLS/STUN/RTP/RTCP from remote)
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer_addr)) => {
                        trace!("socket read from {} with bytes {}", peer_addr, n);
                        if let Err(err) = peer_connection.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        }) {
                            if err.to_string().contains("AlreadyClosed") {
                                debug!("Connection already closed");
                                break 'EventLoop;
                            } else {
                                error!("handle_read got error: {}", err);
                            }
                        }
                    }
                    Err(err) => {
                        error!("socket read error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
            // Read RTP packets from UDP listener and forward to WebRTC
            result = rtp_listener.recv_from(&mut inbound_rtp_buffer) => {
                match result {
                    Ok((n, _)) => {
                        // Parse the RTP packet
                        let mut buf = BytesMut::from(&inbound_rtp_buffer[..n]);
                        if let Ok(mut rtp_packet) = rtp::packet::Packet::unmarshal(&mut buf) {
                            trace!("Received RTP packet from UDP, {} bytes", n);
                            // Write the RTP packet to the sender
                            if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
                                rtp_packet.header.ssrc = sender
                                    .track()
                                    .ssrcs()
                                    .last()
                                    .ok_or(Error::ErrSenderWithNoSSRCs)?;
                                if let Err(err) = sender.write_rtp(rtp_packet) {
                                    error!("Failed to write RTP packet: {}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("rtp_listener read error: {}", err);
                    }
                }
            }
        }
    }

    peer_connection.close()?;
    println!("Event loop exited");
    Ok(())
}
