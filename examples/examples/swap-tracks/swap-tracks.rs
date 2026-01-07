use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{debug, error, trace};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::RTCRtpReceiverId;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;

use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const TRACK_SWAP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "swap-tracks")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of swapping tracks using sans-I/O architecture.")]
struct Cli {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
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

    let (stop_tx, stop_rx) = broadcast::channel::<()>(1);

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

    if let Err(err) = run(stop_rx, input_sdp_file, host, port).await {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: broadcast::Receiver<()>,
    input_sdp_file: String,
    host: String,
    port: u16,
) -> Result<()> {
    // Everything below is the RTC API! Thanks for using it ❤️.
    let socket = UdpSocket::bind(format!("{host}:{port}")).await?;
    let local_addr = socket.local_addr()?;

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    // Create a MediaEngine object to configure the supported codec
    let mut media_engine = MediaEngine::default();

    // Enable VP8 codec for video
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

    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

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

    // Create output track that we send video back to browser on
    let output_track = MediaStreamTrack::new(
        "webrtc-rs".to_string(),
        "video".to_string(),
        "video".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(rand::random::<u32>()),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    // Add this newly created track to the PeerConnection
    let output_sender_id = peer_connection.add_track(output_track)?;

    // Wait for the offer to be pasted
    println!("Paste offer from browser and press Enter:");
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

    // Track state management
    let mut track_id2_receiver_id = HashMap::new();
    let mut receiver_id2ssrcs = HashMap::new();

    // Track last timestamp per receiver for delta calculation
    let mut receiver_last_timestamp = HashMap::new();

    // Track switching state - store receiver_ids in order of arrival
    let mut receiver_ids_in_order = Vec::new();
    let mut curr_track_index = 0usize;
    let mut last_track_swap = Instant::now();
    let mut connected = false;

    // Output track state
    let mut output_timestamp = 0u32;
    let mut output_sequence = 0u16;
    let mut pli_last_sent = Instant::now();

    // Track when we switch tracks to reset timestamp tracking
    let mut last_switched_receiver: Option<RTCRtpReceiverId> = None;

    let mut buf = vec![0; 2000];

    'EventLoop: loop {
        // Poll write - send outgoing packets
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

        // Poll events - handle state changes
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
                    if peer_connection_state == RTCPeerConnectionState::Connected {
                        connected = true;
                        println!("Connection established, will swap tracks every 5 seconds");
                    } else if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        let track_num = receiver_ids_in_order.len();
                        println!(
                            "Track {} has started (receiver_id: {:?})",
                            track_num, init.receiver_id
                        );

                        track_id2_receiver_id.insert(init.track_id.clone(), init.receiver_id);
                        receiver_ids_in_order.push(init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(track_id) => {
                        if let Some(&receiver_id) = track_id2_receiver_id.get(&track_id) {
                            if let Some(pos) = receiver_ids_in_order
                                .iter()
                                .position(|&id| id == receiver_id)
                            {
                                println!("Track {} closed (receiver_id: {:?})", pos, receiver_id);
                                receiver_ids_in_order.remove(pos);
                                // Adjust current index if needed
                                if curr_track_index >= receiver_ids_in_order.len()
                                    && !receiver_ids_in_order.is_empty()
                                {
                                    curr_track_index = 0;
                                }
                            }
                            receiver_last_timestamp.remove(&receiver_id);
                        }
                        track_id2_receiver_id.remove(&track_id);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Poll read - receive application messages
        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, mut rtp_packet) => {
                    // Get the receiver for this track
                    let receiver_id = *track_id2_receiver_id
                        .get(&track_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;

                    let media_ssrc = {
                        let rtp_receiver = peer_connection
                            .rtp_receiver(receiver_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        let track = rtp_receiver.track();
                        track.ssrcs().next().unwrap_or(0)
                    };

                    receiver_id2ssrcs.insert(receiver_id, media_ssrc);

                    // Get current timestamp for this track
                    let current_timestamp = rtp_packet.header.timestamp;

                    // Calculate timestamp delta from last packet on this receiver
                    let timestamp_delta =
                        if let Some(&last_ts) = receiver_last_timestamp.get(&receiver_id) {
                            current_timestamp.wrapping_sub(last_ts)
                        } else {
                            0 // First packet from this track
                        };

                    // Update last timestamp for this receiver
                    receiver_last_timestamp.insert(receiver_id, current_timestamp);

                    // Forward packets from current track to output
                    let curr_receiver_id = receiver_ids_in_order.get(curr_track_index).copied();
                    if Some(receiver_id) == curr_receiver_id {
                        // Check if we just switched to this track
                        if last_switched_receiver != Some(receiver_id) {
                            // On track switch, reset to use actual timestamp delta
                            debug!(
                                "Switched to receiver {:?}, using timestamp delta {}",
                                receiver_id, timestamp_delta
                            );
                        }

                        // Update output timestamp
                        output_timestamp = output_timestamp.wrapping_add(timestamp_delta);
                        rtp_packet.header.timestamp = output_timestamp;

                        // Update sequence number
                        rtp_packet.header.sequence_number = output_sequence;
                        output_sequence = output_sequence.wrapping_add(1);

                        // Update SSRC to match output sender
                        let output_ssrc = {
                            let output_sender = peer_connection
                                .rtp_sender(output_sender_id)
                                .ok_or(Error::ErrRTPSenderNotExisted)?;

                            output_sender.track().ssrcs().next().unwrap_or(0)
                        };

                        rtp_packet.header.ssrc = output_ssrc;

                        // Send packet
                        let mut output_sender = peer_connection
                            .rtp_sender(output_sender_id)
                            .ok_or(Error::ErrRTPSenderNotExisted)?;

                        debug!("forwarding rtp packet from receiver_id {:?}", receiver_id);
                        output_sender.write_rtp(rtp_packet)?;
                    }
                }
                RTCMessage::RtcpPacket(_, _) => {
                    // RTCP packets are handled internally
                }
                RTCMessage::DataChannelMessage(_, _) => {}
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

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        // Event loop with tokio::select!
        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                trace!("received stop signal, exiting event loop");
                break 'EventLoop;
            }

            _ = timer.as_mut() => {
                let now = Instant::now();
                peer_connection.handle_timeout(now)?;

                // Send PLI periodically for incoming streams
                if now > pli_last_sent + Duration::from_secs(3) {
                    for (&receiver_id, &media_ssrc) in &receiver_id2ssrcs {
                        let mut rtp_receiver = peer_connection
                            .rtp_receiver(receiver_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        debug!("sending PLI rtcp packet with media_ssrc={}", media_ssrc);
                        rtp_receiver.write_rtcp(vec![Box::new(PictureLossIndication{
                            sender_ssrc: 0,
                            media_ssrc,
                        })])?;
                    }
                    pli_last_sent = now;
                }

                // Swap tracks periodically if connected
                if connected && now > last_track_swap + TRACK_SWAP_INTERVAL {
                    if !receiver_ids_in_order.is_empty() {
                        let current_idx = curr_track_index;
                        let next_idx = if current_idx >= receiver_ids_in_order.len() - 1 {
                            0
                        } else {
                            current_idx + 1
                        };
                        curr_track_index = next_idx;

                        let next_receiver_id = receiver_ids_in_order[next_idx];
                        last_switched_receiver = Some(next_receiver_id);
                        println!("Switched from track {} to track {} (receiver_id: {:?})",
                                 current_idx, next_idx, next_receiver_id);

                        // Send PLI for the new track
                        if let (Some(&media_ssrc), Some(mut rtp_receiver)) =
                            (receiver_id2ssrcs.get(&next_receiver_id), peer_connection.rtp_receiver(next_receiver_id)) {
                            let _ = rtp_receiver.write_rtcp(vec![Box::new(PictureLossIndication{
                                sender_ssrc: 0,
                                media_ssrc,
                            })]);
                        }
                    }
                    last_track_swap = now;
                }
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
