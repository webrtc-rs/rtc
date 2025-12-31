use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::media_stream::track::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{
    MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::track_event::RTCRtpRtcpPacket;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::session_description::RTCSessionDescription;
use rtc::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::peer_connection::RTCPeerConnection;
use rtc::rtp_transceiver::rtp_sender::rtp_codec::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use sansio::Protocol;
use shared::error::Error;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::time::{Duration, Instant};
use std::{fs, io::Write, str::FromStr};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

#[derive(Parser)]
#[command(name = "reflect")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.0.0")]
#[command(
    about = "An example of how to send back to the user exactly what it receives using the same PeerConnection."
)]
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
    audio: bool,
    #[arg(short, long)]
    video: bool,
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
    let audio = cli.audio;
    let video = cli.video;
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

    let (stop_tx, stop_rx) = broadcast::channel::<()>(1);
    let (_message_tx, message_rx) = broadcast::channel::<RTCMessage>(8);
    let (_event_tx, event_rx) = broadcast::channel::<RTCEvent>(8);

    println!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });

    if let Err(err) = run(
        stop_rx,
        message_rx,
        event_rx,
        host,
        port,
        input_sdp_file,
        is_client,
        audio,
        video,
    )
    .await
    {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: broadcast::Receiver<()>,
    mut message_rx: broadcast::Receiver<RTCMessage>,
    mut event_rx: broadcast::Receiver<RTCEvent>,
    host: String,
    port: u16,
    input_sdp_file: String,
    is_client: bool,
    audio: bool,
    video: bool,
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

    // Setup the codecs you want to use.
    if audio {
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    ..Default::default()
                },
                payload_type: 120,
                ..Default::default()
            },
            RtpCodecKind::Audio,
        )?;
    }

    // We'll use a VP8 and Opus but you can also define your own
    if video {
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
                ..Default::default()
            },
            RtpCodecKind::Video,
        )?;
    }

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

    // For now, this example only demonstrates the peer connection setup
    let mut rtp_sender_ids = HashMap::new();
    let mut media = vec![];
    if audio {
        media.push("audio");
    }
    if video {
        media.push("video");
    };
    for s in media {
        let output_track = MediaStreamTrack::new(
            format!("webrtc-rs-stream-id-{}", s),
            format!("webrtc-rs-track-id-{}", s),
            None,
            if s == "video" {
                RtpCodecKind::Video
            } else {
                RtpCodecKind::Audio
            },
            format!("track-{s}"),
            false,
        );

        // Add this newly created track to the PeerConnection
        let rtp_sender_id = peer_connection.add_track(output_track)?;
        rtp_sender_ids.insert(s.to_string(), rtp_sender_id);

        /*
        // Read incoming RTCP packets
        // Before these packets are returned they are processed by interceptors. For things
        // like NACK this needs to be called.
        let m = s.to_owned();
        tokio::spawn(async move {
            let mut rtcp_buf = vec![0u8; 1500];
            while let Ok((_, _)) = rtp_sender.read(&mut rtcp_buf).await {}
            println!("{m} rtp_sender.read loop exit");
            Result::<()>::Ok(())
        });*/
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
                    if ice_connection_state == RTCIceConnectionState::Failed {
                        eprintln!("ICE Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(_) => {
                    println!("Peer Connection got onDataChannel event");
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event.packet {
                    RTCRtpRtcpPacket::Rtp(packet) => {
                        let rtp_receiver = peer_connection
                            .rtp_receiver(track_event.receiver_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;
                        let track = rtp_receiver.track().ok_or(Error::ErrTrackNotExisted)?;

                        let rtp_sender_id = rtp_sender_ids
                            .get(&track.kind().to_string())
                            .ok_or(Error::ErrRTPSenderNotExisted)?;

                        let mut rtp_sender = peer_connection
                            .rtp_sender(*rtp_sender_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        rtp_sender.write_rtp(packet)?;
                    }
                    RTCRtpRtcpPacket::Rtcp(_) => {}
                },
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
            res = message_rx.recv() => {
                match res {
                    Ok(message) => {
                        peer_connection.handle_write(message)?;
                    }
                    Err(err) => {
                        eprintln!("write_rx error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
            res = event_rx.recv() => {
                match res {
                    Ok(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    Err(err) => {
                        eprintln!("event_rx error: {}", err);
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
