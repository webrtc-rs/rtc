use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{debug, error, trace};
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{
    Notify,
    mpsc::{Receiver, Sender, channel},
};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const RTP_OUTBOUND_MTU: usize = 1200;
const CIPHER_KEY: u8 = 0xAA;

#[derive(Parser)]
#[command(name = "insertable-streams")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of insertable-streams.")]
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
    video: String,
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

    if !Path::new(&video_file).exists() {
        return Err(anyhow::anyhow!("video file: '{}' not exist", video_file));
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

    if let Err(err) = run(stop_rx, host, port, input_sdp_file, is_client, video_file).await {
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
    video_file: String,
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

    let ssrc = rand::random::<u32>();
    let output_track = MediaStreamTrack::new(
        "webrtc-rs-stream-id".to_string(),
        "webrtc-rs-track-id".to_string(),
        "webrtc-rs-track-label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    // Add this newly created track to the PeerConnection
    let rtp_sender_id = peer_connection.add_track(output_track)?;

    // Wait for the offer to be pasted
    print!("Paste offer from browser and press Enter: ");

    let line = if input_sdp_file.is_empty() {
        signal::must_read_stdin()?
    } else {
        std::fs::read_to_string(&input_sdp_file)?
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

    let (message_tx, mut message_rx) = channel::<(RTCRtpSenderId, rtp::Packet)>(8);
    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);
    let notify_tx = Arc::new(Notify::new());
    let video_notify_rx = notify_tx.clone();

    // Spawn video streaming task
    let (video_done_tx, mut video_done_rx) = channel::<()>(1);
    let video_message_tx = message_tx.clone();
    tokio::spawn(async move {
        if let Err(err) = stream_video(
            (ssrc, video_codec),
            video_file,
            rtp_sender_id,
            video_notify_rx,
            video_done_tx,
            video_message_tx,
        )
        .await
        {
            eprintln!("video streaming error: {}", err);
        }
    });

    let mut connection_established = false;
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
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    } else if peer_connection_state == RTCPeerConnectionState::Connected {
                        println!("Peer Connection State has gone to connected!");
                        connection_established = true;
                        notify_tx.notify_waiters();
                    }
                }
                _ => {}
            }
        }

        // Check if video streaming is done
        if connection_established && video_done_rx.try_recv().is_ok() {
            println!("Video streaming completed");
            break 'EventLoop;
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
                    Some((rtp_sender_id, mut packet)) => {
                        let mut rtp_sender = peer_connection
                            .rtp_sender(rtp_sender_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        packet.header.ssrc = rtp_sender
                            .track()?
                            .ssrcs()
                            .last()
                            .ok_or(Error::ErrSenderWithNoSSRCs)?;
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
    video_done_tx: Sender<()>,
    video_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
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
        let mut frame = match ivf.parse_next_frame() {
            Ok((frame, _)) => frame,
            Err(err) => {
                println!("All video frames parsed and sent: {err}");
                break;
            }
        };

        // Encrypt video using XOR Cipher
        for b in &mut frame[..] {
            *b ^= CIPHER_KEY;
        }

        let sample_duration = Duration::from_millis(40);
        let samples = (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
        let packets = packetizer.packetize(&frame.freeze(), samples)?;
        for packet in packets {
            video_message_tx.send((video_sender_id, packet)).await?;
        }

        let _ = ticker.tick().await;
    }

    let _ = video_done_tx.try_send(());

    Ok(())
}
