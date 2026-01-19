use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::error;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::fs::OpenOptions;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use std::{io::Write, str::FromStr};
use tokio::net::UdpSocket;

use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const BUFFERED_AMOUNT_LOW_THRESHOLD: u32 = 512 * 1024; // 512 KB
const BUFFERED_AMOUNT_HIGH_THRESHOLD: u32 = 1024 * 1024; // 1 MB

#[derive(Parser)]
#[command(name = "data-channels-flow-control")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.0.0")]
#[command(about = "An example of Data-Channels-Flow-Control", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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

    let (stop_tx, _stop_rx) = tokio::sync::broadcast::channel::<()>(1);
    let (offer_tx, offer_rx) = tokio::sync::mpsc::channel::<RTCSessionDescription>(8);
    let (answer_tx, answer_rx) = tokio::sync::mpsc::channel::<RTCSessionDescription>(8);

    println!("Press Ctrl-C to stop");
    let stop_tx_clone = stop_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        let _ = stop_tx_clone.send(());
    });

    let stop_tx_clone = stop_tx.clone();
    let requester_handle = std::thread::spawn(move || {
        // Create a new tokio runtime for this thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            if let Err(err) = run_requester(stop_tx_clone, offer_tx, answer_rx).await {
                eprintln!("run got error: {}", err);
            }
        });
    });

    let stop_tx_clone = stop_tx.clone();
    let responder_handle = std::thread::spawn(move || {
        // Create a new tokio runtime for this thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            if let Err(err) = run_responder(stop_tx_clone, offer_rx, answer_tx).await {
                eprintln!("run got error: {}", err);
            }
        });
    });

    if let Err(err) = requester_handle.join() {
        eprintln!("requester thread exited with error: {:?}", err);
    }
    if let Err(err) = responder_handle.join() {
        eprintln!("responder thread exited with error: {:?}", err);
    }

    Ok(())
}

async fn run_requester(
    stop_tx: tokio::sync::broadcast::Sender<()>,
    offer_tx: tokio::sync::mpsc::Sender<RTCSessionDescription>,
    mut answer_rx: tokio::sync::mpsc::Receiver<RTCSessionDescription>,
) -> Result<()> {
    let requester_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            ..Default::default()
        }])
        .build();

    // Create requester (sender) peer connection
    let mut requester = RTCPeerConnection::new(requester_config)?;
    let options = Some(RTCDataChannelInit {
        ordered: false,
        max_retransmits: Some(0u16),
        ..Default::default()
    });
    let mut dc = requester.create_data_channel("data", options)?;
    dc.set_buffered_amount_low_threshold(BUFFERED_AMOUNT_LOW_THRESHOLD);
    dc.set_buffered_amount_high_threshold(BUFFERED_AMOUNT_HIGH_THRESHOLD);

    // Create sockets first
    let req_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let req_local_addr = req_socket.local_addr()?;

    println!("Requester listening on {}", req_local_addr);

    // Add ICE candidates
    let req_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: req_local_addr.ip().to_string(),
            port: req_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    // Add local candidates
    requester.add_local_candidate(RTCIceCandidate::from(&req_candidate).to_json()?)?;

    // Create offer
    let offer = requester.create_offer(None)?;
    requester.set_local_description(offer.clone())?;
    offer_tx.send(offer).await?;

    let answer = answer_rx.recv().await.unwrap();
    // set answer
    requester.set_remote_description(answer)?;

    // Track state for requester (sender)
    let mut req_data_channel_opened = None;
    let mut req_can_send_more = true;
    let send_buf = vec![0u8; 1024];

    let mut req_buf = vec![0; 2000];
    let mut stop_rx = stop_tx.subscribe();

    'EventLoop: loop {
        // Poll requester writes
        while let Some(msg) = requester.poll_write() {
            if let Err(err) = req_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                error!("requester socket write error: {}", err);
            }
        }

        // Poll requester events
        while let Some(event) = requester.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        eprintln!("Requester peer connection failed");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(data_channel_event) => {
                    match data_channel_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            println!("Requester: Data channel opened");
                            req_data_channel_opened = Some(channel_id);
                        }
                        RTCDataChannelEvent::OnBufferedAmountLow(_channel_id) => {
                            println!("Requester: OnBufferedAmountLow");
                            req_can_send_more = true;
                        }
                        RTCDataChannelEvent::OnBufferedAmountHigh(_channel_id) => {
                            println!("Requester: OnBufferedAmountHigh");
                            req_can_send_more = false;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Requester: send data when channel is open and can send
        if req_data_channel_opened.is_some() && req_can_send_more {
            let channel_id = req_data_channel_opened.unwrap();
            if let Some(mut dc) = requester.data_channel(channel_id) {
                let _ = dc.send(BytesMut::from(&send_buf[..]));
            }
        }

        // Get next timeout
        let req_timeout = requester
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let delay_from_now = req_timeout
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        if delay_from_now.is_zero() {
            requester.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                break 'EventLoop;
            }
            _ = timer.as_mut() => {
                requester.handle_timeout(Instant::now())?;
            }
            res = req_socket.recv_from(&mut req_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        requester.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: req_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&req_buf[..n]),
                        })?;
                    }
                    Err(err) => {
                        eprintln!("requester socket read error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    requester.close()?;

    Ok(())
}

async fn run_responder(
    stop_tx: tokio::sync::broadcast::Sender<()>,
    mut offer_rx: tokio::sync::mpsc::Receiver<RTCSessionDescription>,
    answer_tx: tokio::sync::mpsc::Sender<RTCSessionDescription>,
) -> Result<()> {
    let responder_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            ..Default::default()
        }])
        .build();

    // Create responder (receiver) peer connection
    let mut responder = RTCPeerConnection::new(responder_config)?;

    // Create sockets first
    let resp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let resp_local_addr = resp_socket.local_addr()?;

    println!("Responder listening on {}", resp_local_addr);

    // Add ICE candidates
    let resp_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: resp_local_addr.ip().to_string(),
            port: resp_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    // Add local candidates
    responder.add_local_candidate(RTCIceCandidate::from(&resp_candidate).to_json()?)?;

    let offer = offer_rx.recv().await.unwrap();
    // set offer
    responder.set_remote_description(offer)?;

    // Create answer
    let answer = responder.create_answer(None)?;
    responder.set_local_description(answer.clone())?;
    answer_tx.send(answer).await?;

    // Track state for responder (receiver)
    let mut resp_data_channel_opened = false;
    let total_bytes_received = Arc::new(AtomicUsize::new(0));
    let mut last_total_bytes_received: usize = 0;
    let mut throughput_start = SystemTime::now();
    let mut throughput_timer = Instant::now();

    let mut resp_buf = vec![0; 2000];
    let mut stop_rx = stop_tx.subscribe();

    'EventLoop: loop {
        // Poll responder writes
        while let Some(msg) = responder.poll_write() {
            if let Err(err) = resp_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                error!("responder socket write error: {}", err);
            }
        }

        // Poll responder events
        while let Some(event) = responder.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        eprintln!("Responder peer connection failed");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(data_channel_event) => {
                    match data_channel_event {
                        RTCDataChannelEvent::OnOpen(_channel_id) => {
                            println!("Responder: Data channel opened");
                            resp_data_channel_opened = true;
                            throughput_start = SystemTime::now();
                            throughput_timer = Instant::now();
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        while let Some(message) = responder.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(_channel_id, data_channel_message) => {
                    total_bytes_received
                        .fetch_add(data_channel_message.data.len(), Ordering::Relaxed);
                }
            }
        }

        // Responder: print throughput every second
        if resp_data_channel_opened {
            let now = Instant::now();
            if now.duration_since(throughput_timer) >= Duration::from_secs(1) {
                let current_total = total_bytes_received.load(Ordering::Relaxed);
                let epoch_bytes_received = current_total - last_total_bytes_received;
                last_total_bytes_received = current_total;

                let elapsed = SystemTime::now().duration_since(throughput_start);
                let bps = (epoch_bytes_received * 8) as f64 / elapsed.unwrap().as_secs_f64();

                println!(
                    "Throughput is about {:.03} Mbps",
                    bps / (1024 * 1024) as f64
                );
                throughput_start = SystemTime::now();
                throughput_timer = now;
            }
        }

        // Get next timeout
        let resp_timeout = responder
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let delay_from_now = resp_timeout
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        if delay_from_now.is_zero() {
            responder.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                break 'EventLoop;
            }
            _ = timer.as_mut() => {
                responder.handle_timeout(Instant::now())?;
            }
            res = resp_socket.recv_from(&mut resp_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        responder.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: resp_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&resp_buf[..n]),
                        })?;
                    }
                    Err(err) => {
                        eprintln!("responder socket read error: {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    responder.close()?;

    Ok(())
}
