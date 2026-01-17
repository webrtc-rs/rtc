//! Integration tests for RTCP packet processing with custom interceptor.
//!
//! These tests verify that sansio RTC correctly receives and processes RTCP packets
//! using a custom RtcpForwarderInterceptor that forwards RTCP to poll_read().
//!
//! Test scenarios:
//! 1. webrtc (offerer sending video) + sansio RTC (answerer receiving RTCP)
//! 2. sansio RTC (offerer receiving video) + webrtc (answerer sending video)

use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtc::interceptor::{Interceptor, Packet, Registry, StreamInfo, TaggedPacket, interceptor};
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
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
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
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

/// Create sansio RTC peer with RTCP forwarder interceptor
fn create_rtc_peer_config_with_rtcp_forwarder(
    is_answerer: bool,
) -> Result<rtc::peer_connection::configuration::RTCConfiguration<impl Interceptor>> {
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

    // Create registry with default interceptors
    let registry = Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    // Add RTCP forwarder as outermost layer to capture RTCP before consumption
    let registry = registry.with(RtcpForwarderBuilder::new().build());

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    Ok(config)
}

// ============================================================================
// Test 1: webrtc offerer sends video, sansio RTC answerer receives RTCP
// ============================================================================

/// Test RTCP processing: webrtc (offerer) sends video, sansio RTC (answerer) receives RTCP
///
/// This test verifies:
/// - Custom RtcpForwarderInterceptor correctly forwards RTCP to poll_read()
/// - RTCP Sender Reports are received from webrtc
/// - RTCP packets can be parsed and inspected
#[tokio::test]
async fn test_rtcp_processing_webrtc_offerer_rtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting RTCP processing test: webrtc (offerer) -> sansio RTC (answerer)");

    // Create webrtc peer (offerer) with video track
    let webrtc_pc = create_webrtc_peer().await?;

    // Create video track to send
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "rtcp-test-stream".to_owned(),
    ));

    webrtc_pc
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    // Create offer
    let offer = webrtc_pc.create_offer(None).await?;
    webrtc_pc.set_local_description(offer.clone()).await?;

    // Wait for ICE gathering
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let offer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");

    // Create sansio RTC peer (answerer) with RTCP forwarder
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let config = create_rtc_peer_config_with_rtcp_forwarder(true)?;
    let mut rtc_pc = RtcPeerConnection::new(config)?;

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
    rtc_pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    // Set remote description (offer)
    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;
    rtc_pc.set_remote_description(rtc_offer)?;

    // Create and set answer
    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(answer.clone())?;

    // Set answer on webrtc
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    // Run event loop
    let mut buf = vec![0u8; 2000];
    let mut _rtc_connected = false;
    let mut webrtc_connected = false;
    let mut _track_opened = false;
    let mut rtcp_packets_received = 0u32;
    let mut rtp_packets_received = 0u32;
    let mut rtp_sending_started = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    // Clone track for sending
    let video_track_clone = Arc::clone(&video_track);

    while start_time.elapsed() < test_timeout {
        // Start sending RTP once webrtc is connected
        if webrtc_connected && !rtp_sending_started {
            rtp_sending_started = true;
            log::info!("WebRTC connected, starting to send RTP packets");
            let track = Arc::clone(&video_track_clone);
            tokio::spawn(async move {
                for seq in 0u16..50 {
                    let rtp = webrtc::rtp::packet::Packet {
                        header: webrtc::rtp::header::Header {
                            version: 2,
                            padding: false,
                            extension: false,
                            marker: false,
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

        // Process writes
        while let Some(msg) = rtc_pc.poll_write() {
            // Ignore send errors - some addresses may be unreachable (e.g., external STUN candidates)
            let _ = socket.send_to(&msg.message, msg.transport.peer_addr).await;
        }

        // Process events
        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("RTC ICE state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("RTC ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("RTC connection state: {}", state);
                    if state == RTCPeerConnectionState::Connected {
                        _rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    log::info!("RTC track opened: {}", init.track_id);
                    _track_opened = true;
                }
                _ => {}
            }
        }

        // Process reads - check for RTCP packets
        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                    rtp_packets_received += 1;
                    if rtp_packets_received.is_multiple_of(10) {
                        log::info!(
                            "RTC received RTP packet #{} (seq: {})",
                            rtp_packets_received,
                            rtp_packet.header.sequence_number
                        );
                    }
                }
                RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
                    rtcp_packets_received += 1;
                    log::info!(
                        "RTC received RTCP packet #{} (track: {}, {} sub-packets)",
                        rtcp_packets_received,
                        track_id,
                        rtcp_packets.len()
                    );

                    // Log details of each RTCP packet
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
                _ => {}
            }
        }

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("WebRTC peer connected!");
        }

        // Check success - we should receive RTCP packets
        if rtcp_packets_received >= 2 && rtp_packets_received >= 10 {
            log::info!("Test passed!");
            log::info!(
                "  RTP packets received: {}, RTCP packets received: {}",
                rtp_packets_received,
                rtcp_packets_received
            );
            rtc_pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
        }

        // Handle timeouts
        let eto = rtc_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        if delay_from_now.is_zero() {
            rtc_pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, peer_addr)) = res {
                    rtc_pc.handle_read(TaggedBytesMut {
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
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - RTP: {}, RTCP: {}",
        rtp_packets_received,
        rtcp_packets_received
    ))
}

// ============================================================================
// Test 2: sansio RTC offerer receives video, webrtc answerer sends video
// ============================================================================

/// Test RTCP processing: sansio RTC (offerer) receives video from webrtc (answerer)
///
/// This test verifies RTCP processing when roles are reversed.
#[tokio::test]
async fn test_rtcp_processing_rtc_offerer_webrtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting RTCP processing test: sansio RTC (offerer) <- webrtc (answerer)");

    // Create sansio RTC peer (offerer) with RTCP forwarder
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let config = create_rtc_peer_config_with_rtcp_forwarder(false)?;
    let mut rtc_pc = RtcPeerConnection::new(config)?;

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
    rtc_pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    // Add recv-only transceiver to receive video
    rtc_pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: rtc::rtp_transceiver::RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )?;

    // Create offer
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;

    // Create webrtc peer (answerer)
    let webrtc_pc = create_webrtc_peer().await?;

    // Create video track on webrtc
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "rtcp-test-stream".to_owned(),
    ));

    webrtc_pc
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    // Set offer on webrtc
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;

    // Create answer
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer.clone()).await?;

    // Wait for ICE gathering
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");

    // Set answer on RTC
    let rtc_answer = rtc::peer_connection::sdp::RTCSessionDescription::answer(
        answer_with_candidates.sdp.clone(),
    )?;
    rtc_pc.set_remote_description(rtc_answer)?;

    // Run event loop
    let mut buf = vec![0u8; 2000];
    let mut _rtc_connected = false;
    let mut webrtc_connected = false;
    let mut rtcp_packets_received = 0u32;
    let mut rtp_packets_received = 0u32;
    let mut rtp_sending_started = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    // Clone track for sending
    let video_track_clone = Arc::clone(&video_track);

    while start_time.elapsed() < test_timeout {
        // Start sending RTP once webrtc is connected
        if webrtc_connected && !rtp_sending_started {
            rtp_sending_started = true;
            log::info!("WebRTC connected, starting to send RTP packets");
            let track = Arc::clone(&video_track_clone);
            tokio::spawn(async move {
                for seq in 0u16..50 {
                    let rtp = webrtc::rtp::packet::Packet {
                        header: webrtc::rtp::header::Header {
                            version: 2,
                            padding: false,
                            extension: false,
                            marker: false,
                            payload_type: 96,
                            sequence_number: seq,
                            timestamp: seq as u32 * 3000,
                            ssrc: 54321,
                            ..Default::default()
                        },
                        payload: bytes::Bytes::from(vec![0xBBu8; 100]),
                    };

                    let _ = track.write_rtp(&rtp).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
        }

        // Process writes
        while let Some(msg) = rtc_pc.poll_write() {
            // Ignore send errors - some addresses may be unreachable (e.g., external STUN candidates)
            let _ = socket.send_to(&msg.message, msg.transport.peer_addr).await;
        }

        // Process events
        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("RTC ICE state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("RTC ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("RTC connection state: {}", state);
                    if state == RTCPeerConnectionState::Connected {
                        _rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    log::info!("RTC track opened: {}", init.track_id);
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                    rtp_packets_received += 1;
                    if rtp_packets_received.is_multiple_of(10) {
                        log::info!(
                            "RTC received RTP packet #{} (seq: {})",
                            rtp_packets_received,
                            rtp_packet.header.sequence_number
                        );
                    }
                }
                RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
                    rtcp_packets_received += 1;
                    log::info!(
                        "RTC received RTCP packet #{} (track: {}, {} sub-packets)",
                        rtcp_packets_received,
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
                _ => {}
            }
        }

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("WebRTC peer connected!");
        }

        // Check success
        if rtcp_packets_received >= 2 && rtp_packets_received >= 10 {
            log::info!("Test passed!");
            log::info!(
                "  RTP packets received: {}, RTCP packets received: {}",
                rtp_packets_received,
                rtcp_packets_received
            );
            rtc_pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
        }

        // Handle timeouts
        let eto = rtc_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        if delay_from_now.is_zero() {
            rtc_pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((n, peer_addr)) = res {
                    rtc_pc.handle_read(TaggedBytesMut {
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
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - RTP: {}, RTCP: {}",
        rtp_packets_received,
        rtcp_packets_received
    ))
}
