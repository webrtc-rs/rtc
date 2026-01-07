use std::collections::HashMap;
use std::fs::File;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::media::io::Writer;
use rtc::media::io::h26x_writer::H26xWriter;
use rtc::media::io::ogg_writer::OggWriter;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_HEVC, MIME_TYPE_OPUS, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::{fs, fs::OpenOptions, io::Write, str::FromStr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, channel};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

#[derive(Parser)]
#[command(name = "save-to-disk-h26x")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of save-to-disk-h26x.")]
struct Cli {
    #[arg(short, long)]
    client: bool,
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    input_sdp_file: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(short, long)]
    video: Option<String>,
    #[arg(short, long)]
    audio: Option<String>,
    #[arg(long)]
    hevc: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
    let is_client = cli.client;
    let input_sdp_file = cli.input_sdp_file;
    let output_log_file = cli.output_log_file;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    let is_hevc = cli.hevc;
    let video_file = cli.video;
    let audio_file = cli.audio;
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

    if let Err(err) = run(
        stop_rx,
        host,
        port,
        input_sdp_file,
        is_client,
        video_file,
        audio_file,
        is_hevc,
    )
    .await
    {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: Receiver<()>,
    host: String,
    port: u16,
    input_sdp_file: String,
    is_client: bool,
    video_file: Option<String>,
    audio_file: Option<String>,
    is_hevc: bool,
) -> Result<()> {
    // Everything below is the RTC API! Thanks for using it ❤️.
    let socket = UdpSocket::bind(format!("{host}:{port}")).await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(if is_client {
        RTCDtlsRole::Client
    } else {
        RTCDtlsRole::Server
    })?;

    // Create a MediaEngine object to configure the supported codec
    let mut media_engine = MediaEngine::default();

    let audio_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 111,
        ..Default::default()
    };

    let video_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: if is_hevc {
                MIME_TYPE_HEVC.to_owned()
            } else {
                MIME_TYPE_H264.to_owned()
            },
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: if is_hevc {
                "".to_owned()
            } else {
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f".to_owned()
            },
            rtcp_feedback: vec![],
        },
        payload_type: if is_hevc { 98 } else { 102 },
        ..Default::default()
    };

    // Setup the codecs you want to use.
    if audio_file.is_some() {
        media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;
    }

    // We'll use H26x and Opus but you can also define your own
    if video_file.is_some() {
        media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;
    }

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

    // Allow us to receive 1 audio track, and 1 video track
    if audio_file.is_some() {
        peer_connection.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            }),
        )?;
    }
    if video_file.is_some() {
        peer_connection.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            }),
        )?;
    }

    // Wait for the offer to be pasted
    print!("Paste offer from browser and press Enter: ");

    let line = if input_sdp_file.is_empty() {
        signal::must_read_stdin()?
    } else {
        fs::read_to_string(&input_sdp_file)?
    };
    let desc_data = signal::decode(line.as_str())?;
    let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;
    println!("Offer received: {}", offer);

    // Set the remote SessionDescription
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

    // Create an answer
    let answer = peer_connection.create_answer(None)?;

    // Sets the LocalDescription
    peer_connection.set_local_description(answer)?;

    // Output the answer in base64 so we can paste it in browser
    if let Some(local_desc) = peer_connection.local_description() {
        println!("answer created: {}", local_desc);
        let json_str = serde_json::to_string(local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("{b64}");
    } else {
        println!("generate local_description failed!");
        return Err(Error::ErrPeerConnLocalDescriptionNil.into());
    }

    println!("listening {}...", socket.local_addr()?);

    let mut video_writer: Option<H26xWriter<File>> = if let Some(ref video_file_name) = video_file {
        Some(H26xWriter::new(File::create(video_file_name)?, is_hevc))
    } else {
        None
    };

    let mut audio_writer: Option<OggWriter<File>> = if let Some(ref audio_file_name) = audio_file {
        Some(OggWriter::new(File::create(audio_file_name)?, 48000, 2)?)
    } else {
        None
    };

    // Track which receiver_id maps to which track kind
    let mut receiver_id_to_kind: HashMap<RTCRtpReceiverId, RtpCodecKind> = HashMap::new();
    let mut track_id2_receiver_id = HashMap::new();

    let mut buf = vec![0; 2000];
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
                    println!("ICE Connection State has changed: {ice_connection_state}");
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        println!("Peer Connection has gone to failed! Exiting...");
                        println!("Done writing media files");
                        break 'EventLoop;
                    } else if peer_connection_state == RTCPeerConnectionState::Connected {
                        println!("Ctrl+C the remote client to stop the demo");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        track_id2_receiver_id.insert(init.track_id, init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(_track_id) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, rtp_packet) => {
                    let receiver_id = track_id2_receiver_id
                        .get(&track_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?
                        .clone();
                    let rtp_receiver = peer_connection
                        .rtp_receiver(receiver_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;
                    let track = rtp_receiver.track();

                    // Record the track kind for this receiver on first packet
                    if !receiver_id_to_kind.contains_key(&receiver_id) {
                        let kind = track.kind();
                        receiver_id_to_kind.insert(receiver_id, kind);

                        let codec = track
                            .codec(
                                track
                                    .ssrcs()
                                    .next()
                                    .ok_or(Error::ErrRTPReceiverForSSRCTrackStreamNotFound)?,
                            )
                            .ok_or(Error::ErrCodecNotFound)?;
                        let mime_type = codec.mime_type.to_lowercase();

                        if mime_type == MIME_TYPE_OPUS.to_lowercase() {
                            println!(
                                "Got Opus track, saving to disk as {} (48 kHz, 2 channels)",
                                audio_file.as_ref().ok_or(Error::ErrFileNotOpened)?
                            );
                        } else if mime_type == MIME_TYPE_H264.to_lowercase()
                            || mime_type == MIME_TYPE_HEVC.to_lowercase()
                        {
                            println!(
                                "Got {} track, saving to disk as {}",
                                if is_hevc { "H265" } else { "H264" },
                                video_file.as_ref().ok_or(Error::ErrFileNotOpened)?
                            );
                        }
                    }

                    // Write packet to appropriate file
                    match receiver_id_to_kind.get(&receiver_id) {
                        Some(RtpCodecKind::Audio) => {
                            if let Some(ref mut writer) = audio_writer {
                                writer.write_rtp(&rtp_packet)?;
                            }
                        }
                        Some(RtpCodecKind::Video) => {
                            if let Some(ref mut writer) = video_writer {
                                writer.write_rtp(&rtp_packet)?;
                            }
                        }
                        _ => {}
                    }
                }
                RTCMessage::RtcpPacket(_, _) => {
                    // Read incoming RTCP packets
                    // Before these packets are returned they are processed by interceptors. For things
                    // like NACK this needs to be called.
                }
                RTCMessage::DataChannelMessage(_, _) => {}
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

    // Close writers
    if let Some(mut writer) = video_writer {
        println!("Closing video file");
        if let Err(err) = writer.close() {
            println!("Error closing video file: {err}");
        }
    }
    if let Some(mut writer) = audio_writer {
        println!("Closing audio file");
        if let Err(err) = writer.close() {
            println!("Error closing audio file: {err}");
        }
    }

    peer_connection.close()?;

    Ok(())
}
