//! rtcp-processing-boxed is the type-erased counterpart of the `rtcp-processing` example.
//!
//! It does exactly the same thing — installs a custom `RtcpForwarderInterceptor` so RTCP
//! packets surface through `poll_read()`, then prints them — but it holds the peer
//! connection as `RTCPeerConnection<BoxedInterceptor>` instead of letting the interceptor
//! chain's type leak into the application.
//!
//! # Why erase the chain?
//!
//! An interceptor chain is a nest of generic types: `register_default_interceptors`
//! followed by `.with(RtcpForwarderBuilder::new().build())` produces something like
//!
//! ```text
//! RtcpForwarderInterceptor<TwccReceiverInterceptor<SenderReportInterceptor<
//!     ReceiverReportInterceptor<NackResponderInterceptor<NackGeneratorInterceptor<
//!         NoopInterceptor>>>>>>
//! ```
//!
//! `RTCPeerConnection<I>` is generic over that type. As long as the chain flows straight
//! into a local variable, `impl Interceptor` hides it (that is what `rtcp-processing`
//! does). But the moment an application wants to *store* the peer connection, the type
//! parameter propagates: every struct that owns one, and every function that touches
//! those structs, has to carry `<I: Interceptor>`. And an opaque `impl Interceptor` type
//! still cannot be produced by two different branches of an `if`, nor put in a collection
//! next to a peer built with a different chain.
//!
//! [`Registry::boxed`] erases the chain to [`BoxedInterceptor`] (`Box<dyn Interceptor>`),
//! so every peer connection has the same concrete type no matter how its chain was
//! assembled at runtime. Two consequences are visible below:
//!
//! * [`build_peer_connection`] picks its chain from a **command-line flag** — the two
//!   branches build different chain types and unify only after `.boxed()`.
//! * [`RtcpSession`] is a plain struct with **no type parameter**, and its methods are
//!   ordinary non-generic methods.
//!
//! The cost is one virtual call per chain entry point; the chain's interior stays
//! statically dispatched.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::interceptor::{
    BoxedInterceptor, Interceptor, Packet, Registry, StreamInfo, TaggedPacket, interceptor,
};
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
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters};
use rtc::sansio::{self, Protocol}; // Required for #[interceptor] macro and Protocol trait methods
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day

// ============================================================================
// RTCP Forwarder Interceptor
// ============================================================================
//
// Identical to the one in the `rtcp-processing` example: it forwards RTCP packets to the
// application via poll_read(). By default RTCP is consumed by the interceptor chain (for
// statistics, NACK, congestion control) and never reaches the application.

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
// Building the peer connection: the chain is chosen at runtime
// ============================================================================

/// Build a peer connection whose interceptor chain depends on `forward_rtcp`.
///
/// This is the shape that the `impl Interceptor` return type cannot express. The two
/// branches produce chains of different Rust types, and `if`/`else` arms must agree on a
/// type — so without erasure this function would have to be split in two, and its two
/// return types would then infect everything downstream. `Registry::boxed()` collapses
/// both to [`BoxedInterceptor`], leaving one ordinary return type.
fn build_peer_connection(
    forward_rtcp: bool,
    mut media_engine: MediaEngine,
) -> Result<RTCPeerConnection<BoxedInterceptor>> {
    // Default interceptors (NACK, RTCP reports, TWCC receiver) in both cases.
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    // The RTCP forwarder must be the *outermost* layer, so it sees RTCP before the rest
    // of the chain consumes it.
    let registry = if forward_rtcp {
        registry.with(RtcpForwarderBuilder::new().build()).boxed()
    } else {
        registry.boxed()
    };

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    let peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;

    Ok(peer_connection)
}

// ============================================================================
// The session: a plain struct that owns the peer connection
// ============================================================================

/// Everything the example needs to run one session.
///
/// The point of this struct is what is *missing* from it: a type parameter. Holding an
/// `RTCPeerConnection<I>` would have made this `struct RtcpSession<I: Interceptor>`, and
/// then every `impl` block, every helper function, and any collection of sessions would
/// have had to carry `I` too. With the chain erased, this is an ordinary struct with
/// ordinary methods — and a server could keep a `Vec<RtcpSession>` or
/// `HashMap<SessionId, RtcpSession>` even if each session were configured with a
/// different chain.
struct RtcpSession {
    peer_connection: RTCPeerConnection<BoxedInterceptor>,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    ssrc2kind: HashMap<u32, RtpCodecKind>,
    rtcp_count: u64,
}

impl RtcpSession {
    /// Bind a socket and build the peer connection with the requested chain.
    async fn new(forward_rtcp: bool) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;

        let mut media_engine = MediaEngine::default();

        // Register VP8 codec for video
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_string(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_string(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )?;

        // Register Opus codec for audio
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_string(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "".to_string(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            },
            RtpCodecKind::Audio,
        )?;

        let peer_connection = build_peer_connection(forward_rtcp, media_engine)?;

        Ok(Self {
            peer_connection,
            socket: Arc::new(socket),
            local_addr,
            ssrc2kind: HashMap::new(),
            rtcp_count: 0,
        })
    }

    /// Apply the browser's offer and produce our answer.
    fn answer(&mut self, offer: RTCSessionDescription) -> Result<RTCSessionDescription> {
        self.peer_connection.set_remote_description(offer)?;

        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.local_addr.ip().to_string(),
                port: self.local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        self.peer_connection
            .add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        let answer = self.peer_connection.create_answer(None)?;
        self.peer_connection.set_local_description(answer.clone())?;
        Ok(answer)
    }

    /// Send everything the peer connection wants to put on the wire.
    async fn flush_writes(&mut self) {
        while let Some(msg) = self.peer_connection.poll_write() {
            match self
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => trace!(
                    "socket write to {} with {} bytes",
                    msg.transport.peer_addr, n
                ),
                Err(err) => error!("socket write error: {}", err),
            }
        }
    }

    /// Drain connection/track events. Returns `false` when the session should stop.
    fn drain_events(&mut self) -> Result<bool> {
        while let Some(event) = self.peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Connection State has changed: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        println!("Connection failed, exiting...");
                        return Ok(false);
                    } else if state == RTCPeerConnectionState::Connected {
                        println!("Connection established! Waiting for RTCP packets...\n");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!(
                        "Track has started - track_id: {}, receiver_id: {:?}",
                        init.track_id, init.receiver_id
                    );

                    if let Some(receiver) = self.peer_connection.rtp_receiver(init.receiver_id) {
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

                        self.ssrc2kind.insert(ssrc, track.kind());
                    }
                    println!();
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(track_id)) => {
                    println!("Track closed: {}", track_id);
                }
                _ => {}
            }
        }
        Ok(true)
    }

    /// Print every RTCP packet the forwarder surfaced.
    ///
    /// Nothing arrives here when the session was built without the forwarder — that is
    /// what `--no-rtcp-forwarding` demonstrates.
    fn drain_reads(&mut self) {
        while let Some(message) = self.peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, _rtp_packet) => {
                    // We're not processing RTP packets in this example
                    trace!("Received RTP packet");
                }
                RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
                    self.rtcp_count += 1;
                    println!(
                        "=== RTCP Packet #{} (Track: {}) ===",
                        self.rtcp_count, track_id
                    );

                    for (i, packet) in rtcp_packets.iter().enumerate() {
                        let header = packet.header();
                        println!(
                            "  [{}] Type: {:?}, Length: {} words",
                            i + 1,
                            header.packet_type,
                            header.length
                        );

                        // The RTCP packets implement Display for human-readable output
                        for line in format!("{}", packet).lines() {
                            println!("      {}", line);
                        }
                    }
                    println!();
                }
                RTCMessage::DataChannelMessage(_, _) => {}
            }
        }
    }

    /// Feed a datagram read off the socket into the peer connection.
    fn handle_datagram(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        self.peer_connection.handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(data),
        })?;
        Ok(())
    }
}

// ============================================================================
// Main Application
// ============================================================================

#[derive(Parser)]
#[command(name = "rtcp-processing-boxed")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.1.0")]
#[command(about = "RTCP packet processing with a type-erased interceptor chain")]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    input_sdp_file: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    /// Build the chain *without* the RTCP forwarder. The peer connection still has type
    /// `RTCPeerConnection<BoxedInterceptor>`; it simply never surfaces RTCP to the
    /// application, so no RTCP packets are printed.
    #[arg(long)]
    no_rtcp_forwarding: bool,
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

    run(input_sdp_file, !cli.no_rtcp_forwarding).await?;

    Ok(())
}

async fn run(input_sdp_file: String, forward_rtcp: bool) -> Result<()> {
    // The chain is decided here, at runtime — and the session type does not change.
    let mut session = RtcpSession::new(forward_rtcp).await?;
    if forward_rtcp {
        println!("Interceptor chain: defaults + RTCP forwarder (boxed)");
    } else {
        println!("Interceptor chain: defaults only (boxed) — no RTCP will be printed");
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

    let answer = session.answer(offer)?;

    println!(
        "RTCP Processing (boxed) listening on {}...",
        session.local_addr
    );

    // Output the answer
    let json_str = serde_json::to_string(&answer)?;
    let b64 = signal::encode(&json_str);
    println!("\nPaste this answer in your browser:\n{}\n", b64);

    let (_event_tx, mut event_rx) = channel::<RTCEvent>(8);
    let mut buf = vec![0; 2000];

    println!("Waiting for RTCP packets...");
    println!("Press Ctrl-C to stop\n");

    // Event loop — all of it non-generic, because `RtcpSession` is.
    'EventLoop: loop {
        session.flush_writes().await;
        if !session.drain_events()? {
            break 'EventLoop;
        }
        session.drain_reads();

        // Poll peer_connection to get next timeout
        let eto = session
            .peer_connection
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            session.peer_connection.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);
        // Clone the socket handle out so the recv future does not borrow `session` while
        // the other arms mutate it.
        let socket = Arc::clone(&session.socket);

        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                println!("\nCtrl-C received, shutting down...");
                println!("Total RTCP packets received: {}", session.rtcp_count);
                break 'EventLoop;
            }
            res = event_rx.recv() => {
                match res {
                    Some(event) => {
                        session.peer_connection.handle_event(event)?;
                    }
                    None => {
                        eprintln!("event_rx closed");
                        break 'EventLoop;
                    }
                }
            }
            _ = timer.as_mut() => {
                session.peer_connection.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes from {}", n, peer_addr);
                        session.handle_datagram(&buf[..n], peer_addr)?;
                    }
                    Err(err) => {
                        eprintln!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    session.peer_connection.close()?;
    println!("Event loop exited");
    Ok(())
}
