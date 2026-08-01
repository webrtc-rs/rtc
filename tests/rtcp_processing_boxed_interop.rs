//! Integration tests for RTCP packet processing with a **type-erased** interceptor chain.
//!
//! This is the `RTCPeerConnection<BoxedInterceptor>` counterpart of
//! `rtcp_processing_interop.rs`. Both files install the same custom
//! `RtcpForwarderInterceptor`; the difference is how the resulting peer connection is
//! *typed*, and therefore what the application can do with it.
//!
//! `rtcp_processing_interop.rs` returns `RTCPeerConnection<impl Interceptor>`. That works
//! as long as the chain flows straight into a local variable, but the opaque type is
//! chosen once per return site, so it cannot:
//!
//! - be stored in a plain (non-generic) application struct,
//! - be put in a `Vec`/`HashMap` alongside peers built with a *different* chain,
//! - be produced by two different branches of an `if` in the same function.
//!
//! Erasing the chain to [`BoxedInterceptor`] removes all three limits: every peer
//! connection has the one concrete type `RTCPeerConnection<BoxedInterceptor>` regardless
//! of how its chain was assembled at runtime. That is what lets [`RtcpPeer`] below — an
//! ordinary struct with no type parameters — own a peer connection, and what lets
//! `test_boxed_rtc_to_rtc_heterogeneous_chains` drive two peers with *different* chains
//! out of a single `Vec`.
//!
//! Test scenarios:
//! 1. webrtc (offerer sending video) + boxed-chain RTC (answerer receiving RTCP)
//! 2. boxed-chain RTC (sender) receives RTCP feedback about its own stream from webrtc
//! 3. two boxed-chain RTC peers with *different* chains, driven from one `Vec<RtcpPeer>`

use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtc::interceptor::{
    BoxedInterceptor, Interceptor, Packet, Registry, StreamInfo, TaggedPacket, interceptor,
};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::shared::error::Error;

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors as webrtc_register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry as WebrtcRegistry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};

mod common;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

// ============================================================================
// RTCP Forwarder Interceptor
// ============================================================================

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> impl FnOnce(P) -> RtcpForwarderInterceptor<P> {
        move |inner| RtcpForwarderInterceptor::new(inner)
    }
}

/// Interceptor that forwards RTCP packets to the application via poll_read().
#[derive(Interceptor)]
pub struct RtcpForwarderInterceptor<P> {
    #[next]
    next: P,
    read_queue: VecDeque<TaggedPacket>,
}

impl<P> RtcpForwarderInterceptor<P> {
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
// Building a peer connection whose interceptor chain is chosen at runtime
// ============================================================================

/// Build a peer connection whose chain is decided at *runtime* by `forward_rtcp`.
///
/// This is the function the `impl Interceptor` form cannot express. The two branches
/// build chains of different Rust types —
/// `RtcpForwarderInterceptor<TwccReceiver<SenderReport<...>>>` versus
/// `TwccReceiver<SenderReport<...>>` — so there is no single `impl Interceptor` they can
/// both satisfy, and `if`/`else` arms must agree on a type. [`Registry::boxed`] erases
/// both to [`BoxedInterceptor`], after which the branches unify and the function has one
/// ordinary return type.
fn build_boxed_rtc_peer(
    forward_rtcp: bool,
    is_answerer: bool,
) -> Result<RTCPeerConnection<BoxedInterceptor>> {
    let mut setting_engine = SettingEngine::default();
    if is_answerer {
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
    }

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
    };
    media_engine.register_codec(video_codec, RtpCodecKind::Video)?;

    // Default interceptors (NACK, RTCP reports, TWCC receiver) in both cases.
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    // The RTCP forwarder is layered on only for peers that want to see RTCP in
    // `poll_read`. Both arms are erased to the same `Registry<BoxedInterceptor>`.
    let registry = if forward_rtcp {
        registry.with(RtcpForwarderBuilder::new().build()).boxed()
    } else {
        registry.boxed()
    };

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;
    Ok(pc)
}

// ============================================================================
// A non-generic peer holder
// ============================================================================

/// An application-level peer: socket, peer connection, and the counters the tests assert
/// on.
///
/// Note that this struct has **no type parameter**. With `RTCPeerConnection<I>` it would
/// have needed one (`RtcpPeer<I: Interceptor>`), and that parameter would then infect
/// every function, collection, and struct that touches an `RtcpPeer` — which is exactly
/// the boilerplate erasure removes.
struct RtcpPeer {
    name: &'static str,
    pc: RTCPeerConnection<BoxedInterceptor>,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    connected: bool,
    rtp_received: u32,
    rtcp_received: u32,
}

impl RtcpPeer {
    /// Bind a socket, build the peer connection, and advertise the socket as a host
    /// candidate.
    async fn new(name: &'static str, forward_rtcp: bool, is_answerer: bool) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;
        log::info!("{} bound to {}", name, local_addr);

        let mut pc = build_boxed_rtc_peer(forward_rtcp, is_answerer)?;

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
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        Ok(Self {
            name,
            pc,
            socket: Arc::new(socket),
            local_addr,
            connected: false,
            rtp_received: 0,
            rtcp_received: 0,
        })
    }

    /// Send everything the peer connection wants to put on the wire.
    async fn flush_writes(&mut self) {
        while let Some(msg) = self.pc.poll_write() {
            // Ignore send errors - some candidate addresses may be unreachable.
            let _ = self
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await;
        }
    }

    /// Drain connection/track events, tracking the connected state.
    fn drain_events(&mut self) -> Result<()> {
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("{} ICE state: {}", self.name, state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("{} ICE connection failed", self.name));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("{} connection state: {}", self.name, state);
                    if state == RTCPeerConnectionState::Connected {
                        self.connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    log::info!("{} track opened: {}", self.name, init.track_id);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Drain RTP/RTCP surfaced to the application, counting both.
    ///
    /// RTCP only ever appears here for peers built with `forward_rtcp: true` — the
    /// default chain consumes it. That asymmetry is what test 3 asserts on.
    fn drain_reads(&mut self) {
        while let Some(message) = self.pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                    self.rtp_received += 1;
                    if self.rtp_received.is_multiple_of(10) {
                        log::info!(
                            "{} received RTP packet #{} (seq: {})",
                            self.name,
                            self.rtp_received,
                            rtp_packet.header.sequence_number
                        );
                    }
                }
                RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
                    self.rtcp_received += 1;
                    log::info!(
                        "{} received RTCP packet #{} (track: {}, {} sub-packets)",
                        self.name,
                        self.rtcp_received,
                        track_id,
                        rtcp_packets.len()
                    );
                    for (i, packet) in rtcp_packets.iter().enumerate() {
                        let header = packet.header();
                        log::info!(
                            "  [{}] Type: {:?}, Length: {} words",
                            i + 1,
                            header.packet_type,
                            header.length
                        );
                    }
                }
                RTCMessage::DataChannelMessage(_, _) => {}
                _ => {}
            }
        }
    }

    /// The peer connection's next deadline, or a far-future default.
    fn next_timeout(&mut self) -> Instant {
        self.pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION)
    }

    /// Feed a datagram read off this peer's socket into the peer connection.
    fn handle_datagram(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        self.pc.handle_read(TaggedBytesMut {
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
// Helper Functions
// ============================================================================

/// Create a webrtc peer connection
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = WebrtcRegistry::new();
    registry = webrtc_register_default_interceptors(registry, &mut media_engine)?;

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let config = WebrtcRTCConfiguration {
        ice_servers: vec![WebrtcIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }],
        ..Default::default()
    };

    Ok(Arc::new(api.new_peer_connection(config).await?))
}

/// A VP8 track carrying a single known SSRC.
fn video_track(stream_id: &str, track_id: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        stream_id.to_owned(),
        track_id.to_owned(),
        format!("{track_id}-label"),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
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
    )
}

/// A dummy VP8 RTP packet for `ssrc` with the given sequence number.
fn dummy_rtp(ssrc: u32, seq: u32, payload_type: u8) -> rtc::rtp::packet::Packet {
    rtc::rtp::packet::Packet {
        header: rtc::rtp::header::Header {
            version: 2,
            payload_type,
            sequence_number: seq as u16,
            timestamp: seq.wrapping_mul(3000),
            ssrc,
            ..Default::default()
        },
        payload: bytes::Bytes::from(vec![0xAAu8; 100]),
    }
}

// ============================================================================
// Test 1: webrtc offerer sends video, boxed-chain RTC answerer receives RTCP
// ============================================================================

/// The boxed counterpart of `test_rtcp_processing_webrtc_offerer_rtc_answerer`.
///
/// Verifies that erasing the chain changes nothing observable: the custom forwarder still
/// surfaces RTCP via `poll_read()`, and the default interceptors still process RTP.
#[tokio::test]
async fn test_boxed_rtcp_processing_webrtc_offerer_rtc_answerer() -> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting boxed RTCP processing test: webrtc (offerer) -> boxed RTC (answerer)");

    // Create webrtc peer (offerer) with video track
    let webrtc_pc = create_webrtc_peer().await?;

    let track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "boxed-rtcp-test-stream".to_owned(),
    ));
    webrtc_pc
        .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    let offer = webrtc_pc.create_offer(None).await?;
    webrtc_pc.set_local_description(offer).await?;
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;
    let offer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");

    // The RTC answerer: one concrete type, held by an ordinary non-generic struct.
    let mut peer = RtcpPeer::new("boxed-answerer", true, true).await?;

    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;
    peer.pc.set_remote_description(rtc_offer)?;

    let answer = peer.pc.create_answer(None)?;
    peer.pc.set_local_description(answer.clone())?;

    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    // Event loop
    let mut buf = vec![0u8; 2000];
    let mut webrtc_connected = false;
    let mut rtp_sending_started = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Start sending RTP once webrtc is connected
        if webrtc_connected && !rtp_sending_started {
            rtp_sending_started = true;
            log::info!("WebRTC connected, starting to send RTP packets");
            let track = Arc::clone(&track);
            tokio::spawn(async move {
                for seq in 0u16..50 {
                    let rtp = webrtc::rtp::packet::Packet {
                        header: webrtc::rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number: seq,
                            timestamp: seq as u32 * 3000,
                            ssrc: 12345,
                            ..Default::default()
                        },
                        payload: bytes::Bytes::from(vec![0xAAu8; 100]),
                    };
                    let _ = track.write_rtp(&rtp).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
        }

        peer.flush_writes().await;
        peer.drain_events()?;
        peer.drain_reads();

        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("WebRTC peer connected!");
        }

        // Success: the boxed chain surfaced RTCP and passed RTP through.
        if peer.rtcp_received >= 2 && peer.rtp_received >= 10 {
            log::info!(
                "Test passed! RTP received: {}, RTCP received: {}",
                peer.rtp_received,
                peer.rtcp_received
            );
            peer.pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
        }

        let delay_from_now = peer
            .next_timeout()
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            peer.pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);
        let socket = Arc::clone(&peer.socket);

        tokio::select! {
            _ = timer.as_mut() => {
                peer.pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, peer_addr)) = res {
                    peer.handle_datagram(&buf[..n], peer_addr)?;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - RTP: {}, RTCP: {}",
        peer.rtp_received,
        peer.rtcp_received
    ))
}

// ============================================================================
// Test 2: boxed-chain RTC sender receives RTCP feedback about its OWN stream
// ============================================================================

/// The boxed counterpart of `test_rtcp_processing_rtc_sender_receives_feedback`.
///
/// The RTC peer *sends* video; webrtc receives it and reports back. The feedback's media
/// SSRC is the RTC peer's sender SSRC, so it surfaces tagged with the sender's track id —
/// exactly what an SFU needs in order to relay PLI/FIR upstream to a publisher.
#[tokio::test]
async fn test_boxed_rtcp_processing_rtc_sender_receives_feedback() -> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    const SENDER_SSRC: u32 = 0x00DE_CAFE;
    const SENDER_TRACK_ID: &str = "boxed-rtcp-sender-test-track";

    log::info!("Starting boxed RTCP processing test: boxed RTC (sender) <- webrtc feedback");

    let mut peer = RtcpPeer::new("boxed-sender", true, false).await?;

    let sender_id = peer.pc.add_track(video_track(
        "boxed-rtcp-sender-test-stream",
        SENDER_TRACK_ID,
        SENDER_SSRC,
    ))?;

    let offer = peer.pc.create_offer(None)?;
    peer.pc.set_local_description(offer.clone())?;

    let webrtc_pc = create_webrtc_peer().await?;
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer).await?;
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;
    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    let rtc_answer = rtc::peer_connection::sdp::RTCSessionDescription::answer(
        answer_with_candidates.sdp.clone(),
    )?;
    peer.pc.set_remote_description(rtc_answer)?;

    let mut buf = vec![0u8; 2000];
    let mut rtp_packets_sent = 0u32;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Keep the webrtc receiver reporting by streaming RTP.
        if peer.connected
            && rtp_packets_sent < 300
            && let Some(mut sender) = peer.pc.rtp_sender(sender_id)
        {
            let _ = sender.write_rtp(dummy_rtp(SENDER_SSRC, rtp_packets_sent, 96));
            rtp_packets_sent += 1;
        }

        peer.flush_writes().await;
        peer.drain_events()?;
        peer.drain_reads();

        // Success: feedback about our SENT stream surfaced through the boxed chain.
        if peer.rtcp_received >= 2 {
            log::info!(
                "Test passed! RTP sent: {}, RTCP received about sent stream: {}",
                rtp_packets_sent,
                peer.rtcp_received
            );
            peer.pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
        }

        let delay_from_now = peer
            .next_timeout()
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            peer.pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);
        let socket = Arc::clone(&peer.socket);

        tokio::select! {
            _ = timer.as_mut() => {
                peer.pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, peer_addr)) = res {
                    peer.handle_datagram(&buf[..n], peer_addr)?;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - RTP sent: {}, RTCP received about sent stream: {}",
        rtp_packets_sent,
        peer.rtcp_received
    ))
}

// ============================================================================
// Test 3: two RTC peers with DIFFERENT chains, driven from one Vec
// ============================================================================

/// The test the non-erased form cannot express.
///
/// Two peer connections are built with genuinely different interceptor chains — the
/// answerer has the RTCP forwarder layered on, the offerer does not — and both are stored
/// in a single `Vec<RtcpPeer>` and driven by the same non-generic code. With
/// `RTCPeerConnection<impl Interceptor>` the two would have incompatible types and could
/// not share a collection.
///
/// The chains' *behaviour* differs accordingly, and that is the assertion. The offerer
/// streams RTP, so its `SenderReportInterceptor` emits periodic Sender Reports; the
/// answerer receives both. The answerer, having the forwarder, surfaces those SRs to the
/// application through `poll_read()`, while the offerer — same peer connection type,
/// different chain — never surfaces a single RTCP packet, because without the forwarder
/// the default chain consumes RTCP internally.
#[tokio::test]
async fn test_boxed_rtc_to_rtc_heterogeneous_chains() -> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    const SENDER_SSRC: u32 = 0x00B0_0DED;

    log::info!("Starting boxed rtc-to-rtc test with heterogeneous interceptor chains");

    // Same type, different chains — so they can live in one Vec.
    let mut offerer = RtcpPeer::new("without-forwarder", false, false).await?;
    let answerer = RtcpPeer::new("with-forwarder", true, true).await?;

    let sender_id = offerer.pc.add_track(video_track(
        "boxed-heterogeneous-stream",
        "boxed-heterogeneous-track",
        SENDER_SSRC,
    ))?;

    let mut peers: Vec<RtcpPeer> = vec![offerer, answerer];

    // Offer/answer between the two.
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(offer.clone())?;
    peers[1].pc.set_remote_description(offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(answer.clone())?;
    peers[0].pc.set_remote_description(answer)?;

    let mut bufs = [vec![0u8; 2000], vec![0u8; 2000]];
    let mut rtp_packets_sent = 0u32;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Stream RTP from the offerer once both transports are up.
        if peers[0].connected
            && peers[1].connected
            && rtp_packets_sent < 600
            && let Some(mut sender) = peers[0].pc.rtp_sender(sender_id)
        {
            let _ = sender.write_rtp(dummy_rtp(SENDER_SSRC, rtp_packets_sent, 96));
            rtp_packets_sent += 1;
        }

        // One non-generic loop body drives both peers, whatever chain each was built with.
        for peer in &mut peers {
            peer.flush_writes().await;
            peer.drain_events()?;
            peer.drain_reads();
        }

        // Success: RTP arrived at the answerer, whose forwarder also surfaced the
        // offerer's Sender Reports about that stream.
        if peers[1].rtp_received >= 10 && peers[1].rtcp_received >= 2 {
            log::info!(
                "Test passed! RTP sent: {}, RTP received: {}, RTCP surfaced (with-forwarder): {}, \
                 RTCP surfaced (without-forwarder): {}",
                rtp_packets_sent,
                peers[1].rtp_received,
                peers[1].rtcp_received,
                peers[0].rtcp_received
            );
            assert_eq!(
                peers[0].rtcp_received, 0,
                "a peer built without the forwarder must never surface RTCP to the application"
            );
            for peer in &mut peers {
                peer.pc.close()?;
            }
            return Ok(());
        }

        let next_timeout = peers[0].next_timeout().min(peers[1].next_timeout());
        let delay_from_now = next_timeout
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            let now = Instant::now();
            for peer in &mut peers {
                peer.pc.handle_timeout(now)?;
            }
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);
        let socket0 = Arc::clone(&peers[0].socket);
        let socket1 = Arc::clone(&peers[1].socket);
        let (buf0, buf1) = bufs.split_at_mut(1);

        tokio::select! {
            _ = timer.as_mut() => {
                let now = Instant::now();
                for peer in &mut peers {
                    peer.pc.handle_timeout(now)?;
                }
            }
            res = socket0.recv_from(&mut buf0[0]) => {
                if let Ok((n, peer_addr)) = res {
                    peers[0].handle_datagram(&buf0[0][..n], peer_addr)?;
                }
            }
            res = socket1.recv_from(&mut buf1[0]) => {
                if let Ok((n, peer_addr)) = res {
                    peers[1].handle_datagram(&buf1[0][..n], peer_addr)?;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - RTP sent: {}, RTP received: {}, RTCP surfaced: {}",
        rtp_packets_sent,
        peers[1].rtp_received,
        peers[1].rtcp_received
    ))
}
