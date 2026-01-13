// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//! rtcp-processing demonstrates the Public API for processing RTCP packets in sansio RTC.
//!
//! This example shows:
//! - How to create a custom RTCP forwarder interceptor
//! - How to receive and process incoming RTCP packets
//! - Displaying RTCP packet information (Sender Reports, Receiver Reports, etc.)
//! - Handling track events and connection state changes
//!
//! Note: By default, RTCP packets are consumed by the interceptor chain and not forwarded
//! to the application. This example demonstrates how to create a custom interceptor that
//! forwards RTCP packets to the application via `poll_read()`.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::interceptor::{Interceptor, Packet, Registry, StreamInfo, TaggedPacket, interceptor};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::event::{RTCEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::sansio::{self, Protocol}; // Required for #[interceptor] macro and Protocol trait methods
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day

// ============================================================================
// RTCP Forwarder Interceptor
// ============================================================================
//
// This interceptor forwards RTCP packets to the application via poll_read().
// By default, RTCP packets are consumed by the interceptor chain (for generating
// statistics, NACK, etc.) and not forwarded to the application.

/// Builder for the RtcpForwarderInterceptor.
pub struct RtcpForwarderBuilder<P> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P> Default for RtcpForwarderBuilder<P> {
    fn default() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P> RtcpForwarderBuilder<P> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the interceptor.
    pub fn build(self) -> impl FnOnce(P) -> RtcpForwarderInterceptor<P> {
        move |inner| RtcpForwarderInterceptor::new(inner)
    }
}

/// Interceptor that forwards RTCP packets to the application.
///
/// This interceptor intercepts incoming RTCP packets and queues them for
/// `poll_read()`, allowing the application to receive and process RTCP packets.
#[derive(Interceptor)]
pub struct RtcpForwarderInterceptor<P> {
    #[next]
    next: P,
    read_queue: VecDeque<TaggedPacket>,
}

impl<P> RtcpForwarderInterceptor<P> {
    /// Create a new RtcpForwarderInterceptor.
    fn new(next: P) -> Self {
        Self {
            next,
            read_queue: VecDeque::new(),
        }
    }
}

#[interceptor]
impl<P: Interceptor> RtcpForwarderInterceptor<P> {
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // If this is an RTCP packet, queue a copy for the application
        if let Packet::Rtcp(rtcp_packets) = &msg.message {
            self.read_queue.push_back(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: Packet::Rtcp(rtcp_packets.clone()),
            });
        }
        // Always pass to next interceptor for normal processing
        self.next.handle_read(msg)
    }

    #[overrides]
    fn poll_read(&mut self) -> Option<Self::Rout> {
        // First return any queued RTCP packets
        if let Some(pkt) = self.read_queue.pop_front() {
            return Some(pkt);
        }
        // Then check next interceptor
        self.next.poll_read()
    }

    #[overrides]
    fn close(&mut self) -> Result<(), Self::Error> {
        self.read_queue.clear();
        self.next.close()
    }
}

// ============================================================================
// Main Application
// ============================================================================

#[derive(Parser)]
#[command(name = "rtcp-processing")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.1.0")]
#[command(about = "An example of RTCP packet processing")]
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

    // Run the peer connection with event loop
    run(input_sdp_file).await?;

    Ok(())
}

async fn run(input_sdp_file: String) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let mut media_engine = MediaEngine::default();

    // Register VP8 codec for video
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: rtc::rtp_transceiver::rtp_sender::RTCRtpCodec {
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
            rtp_codec: rtc::rtp_transceiver::rtp_sender::RTCRtpCodec {
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

    // Create interceptor registry with RTCP forwarder
    let registry = Registry::new();

    // Register default interceptors (NACK, reports, etc.)
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    // Add our RTCP forwarder interceptor as the outermost layer
    // This ensures RTCP packets are captured before being consumed
    let registry = registry.with(RtcpForwarderBuilder::new().build());

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let mut peer_connection = RTCPeerConnection::new(config)?;

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

    println!("RTCP Processing listening on {}...", socket.local_addr()?);

    // Output the answer
    let json_str = serde_json::to_string(&answer)?;
    let b64 = signal::encode(&json_str);
    println!("\nPaste this answer in your browser:\n{}\n", b64);

    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);

    let mut buf = vec![0; 2000];
    let mut ssrc2kind: HashMap<u32, RtpCodecKind> = HashMap::new();
    let mut rtcp_count: u64 = 0;

    println!("Waiting for RTCP packets...");
    println!("Press Ctrl-C to stop\n");

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
                    println!("Connection State has changed: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        println!("Connection failed, exiting...");
                        break 'EventLoop;
                    } else if state == RTCPeerConnectionState::Connected {
                        println!("Connection established! Waiting for RTCP packets...\n");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!(
                        "Track has started - track_id: {}, receiver_id: {:?}",
                        init.track_id, init.receiver_id
                    );

                    if let Some(receiver) = peer_connection.rtp_receiver(init.receiver_id) {
                        let track = receiver.track();
                        let ssrc = track
                            .ssrcs()
                            .next()
                            .ok_or(Error::ErrRTPReceiverForSSRCTrackStreamNotFound)?;

                        let codec = track.codec(ssrc).ok_or(Error::ErrCodecNotFound)?;

                        println!(
                            "  Stream ID: {}, Track ID: {}, Kind: {}, Codec: {}",
                            track.stream_id(),
                            track.track_id(),
                            track.kind(),
                            codec.mime_type
                        );

                        ssrc2kind.insert(ssrc, track.kind());
                    }
                    println!();
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(track_id)) => {
                    println!("Track closed: {}", track_id);
                }
                _ => {}
            }
        }

        // Poll for incoming RTP/RTCP packets
        while let Some(message) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, _rtp_packet) => {
                    // We're not processing RTP packets in this example
                    trace!("Received RTP packet");
                }
                RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
                    rtcp_count += 1;
                    println!("=== RTCP Packet #{} (Track: {}) ===", rtcp_count, track_id);

                    for (i, packet) in rtcp_packets.iter().enumerate() {
                        // Print header info
                        let header = packet.header();
                        println!(
                            "  [{}] Type: {:?}, Length: {} words",
                            i + 1,
                            header.packet_type,
                            header.length
                        );

                        // Print the packet details using Display trait
                        // The RTCP packets implement Display for human-readable output
                        let packet_str = format!("{}", packet);
                        for line in packet_str.lines() {
                            println!("      {}", line);
                        }
                    }
                    println!();
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

            _ = tokio::signal::ctrl_c() => {
                println!("\nCtrl-C received, shutting down...");
                println!("Total RTCP packets received: {}", rtcp_count);
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
