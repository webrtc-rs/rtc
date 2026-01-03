use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{debug, error, trace};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::track_event::RTCTrackEvent;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::session_description::RTCSessionDescription;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use rtc::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::marshal::Marshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use signal;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day

#[derive(Parser)]
#[command(name = "rtp-forwarder")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.1.0")]
#[command(about = "An example of RTP forwarder")]
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

    // Prepare UDP forwarder connections
    let audio_socket = UdpSocket::bind("127.0.0.1:0").await?;
    audio_socket.connect("127.0.0.1:4000").await?;
    println!("Audio will be forwarded to 127.0.0.1:4000");

    let video_socket = UdpSocket::bind("127.0.0.1:0").await?;
    video_socket.connect("127.0.0.1:4002").await?;
    println!("Video will be forwarded to 127.0.0.1:4002");

    // Run the peer connection with event loop
    run_peer_connection(offer, audio_socket, video_socket).await?;

    Ok(())
}

async fn run_peer_connection(
    offer: RTCSessionDescription,
    audio_socket: UdpSocket,
    video_socket: UdpSocket,
) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(DTLSRole::Server)?;

    let mut media_engine = MediaEngine::default();

    // Register VP8 codec for video
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_string(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "".to_string(),
                rtcp_feedback: vec![],
            },
            payload_type: 96,
            ..Default::default()
        },
        RtpCodecKind::Video,
    )?;

    // Register Opus codec for audio
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: rtc::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_string(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "".to_string(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
            ..Default::default()
        },
        RtpCodecKind::Audio,
    )?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Add transceivers for receiving audio and video
    peer_connection.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
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
    peer_connection.set_local_description(answer.clone())?;

    println!("RTP forwarder listening on {}...", socket.local_addr()?);

    // Output the answer
    let json_str = serde_json::to_string(&answer)?;
    let b64 = signal::encode(&json_str);
    println!("\nPaste this answer in your browser:\n{}\n", b64);

    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);

    let mut buf = vec![0; 2000];
    let mut pli_last_sent = Instant::now();
    let mut ssrc2kind: HashMap<u32, RtpCodecKind> = HashMap::new(); // track ssrc -> kind
    let audio_payload_type = 111u8;
    let video_payload_type = 96u8;

    println!("Press Ctrl-C to stop");

    // Event loop
    'EventLoop: loop {
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!(
                        "socket write to {} with {} bytes",
                        msg.transport.peer_addr, n
                    );
                }
                Err(err) => {
                    error!("socket write error: {}", err);
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Peer Connection State: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        println!("Connection failed, exiting...");
                        break 'EventLoop;
                    } else if state == RTCPeerConnectionState::Connected {
                        println!("Connection established!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!(
                        "OnTrack::OnOpen - receiver_id: {:?}, track_id: {}",
                        init.receiver_id, init.track_id
                    );

                    if let Some(receiver) = peer_connection.rtp_receiver(init.receiver_id) {
                        if let Some(track) = receiver.track(&init.track_id)? {
                            println!(
                                "Track kind: {}, codec: {}",
                                track.kind(),
                                track.codec().mime_type
                            );
                            ssrc2kind.insert(track.ssrc(), track.kind());
                        }
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(_track_id)) => {}
                _ => {}
            }
        }

        // Poll for incoming RTP/RTCP packets from tracks
        while let Some(message) = peer_connection.poll_read() {
            match message {
                rtc::peer_connection::message::RTCMessage::RtpPacket(_track_id, mut rtp_packet) => {
                    // Determine which socket to forward to based on payload type

                    let kind = ssrc2kind
                        .get(&rtp_packet.header.ssrc)
                        .ok_or(Error::ErrTrackNotExisted)?;

                    // Determine type based on original payload type
                    let target_socket = if kind == &RtpCodecKind::Video {
                        rtp_packet.header.payload_type = video_payload_type;
                        &video_socket
                    } else {
                        rtp_packet.header.payload_type = audio_payload_type;
                        &audio_socket
                    };

                    // Marshal and forward the RTP packet
                    let mut marshal_buf = vec![0u8; 1500];
                    if let Ok(n) = rtp_packet.marshal_to(&mut marshal_buf) {
                        if let Err(err) = target_socket.send(&marshal_buf[..n]).await {
                            if !err.to_string().contains("Connection refused") {
                                error!("Forward {} error: {}", kind, err);
                            }
                        } else {
                            trace!("Forwarded {} packet, {} bytes", kind, n);
                        }
                    }
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
            biased;

            _ = tokio::signal::ctrl_c() => {
                println!("\nCtrl-C received, shutting down...");
                break 'EventLoop;
            }
            res = event_rx.recv() => {
                match res {
                    Some(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    None => {
                        eprintln!("event_rx closed");
                        break 'EventLoop;
                    }
                }
            }
            _ = timer.as_mut() => {
                let now = Instant::now();
                peer_connection.handle_timeout(now)?;

                if now > pli_last_sent + Duration::from_secs(3) {
                    // Send a PLI on an interval so that the publisher is pushing a keyframe every rtcpPLIInterval
                    // This is a temporary fix until we implement incoming RTCP events,
                    // then we would push a PLI only when a viewer requests it
                    for (ssrc, kind) in &ssrc2kind {
                        debug!("Sending PLI for {} track (SSRC: {})", kind, ssrc);
                        let receiver_ids: Vec<_> = peer_connection.get_receivers().collect();
                        for receiver_id in receiver_ids {
                            if let Some(mut rtp_receiver) = peer_connection.rtp_receiver(receiver_id) {
                                let _ = rtp_receiver.write_rtcp(vec![Box::new(PictureLossIndication {
                                    sender_ssrc: 0,
                                    media_ssrc: *ssrc,
                                })]);
                            }
                        }
                    }

                    pli_last_sent = now;
                }
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
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    peer_connection.close()?;
    println!("Event loop exited");
    Ok(())
}
