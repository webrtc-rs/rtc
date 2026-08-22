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

use rtc::interceptor::Registry as RtcRegistry;
use rtc::interceptor::{Attribute, Interceptor, Packet, Slot, StreamInfo, TaggedPacket};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::shared::error::Error;

use webrtc::api::APIBuilder;
// webrtc links its own `rtcp`, so the type it is handed is not the one this crate parses with.
use webrtc::api::interceptor_registry::register_default_interceptors as webrtc_register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry as WebrtcRegistry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication as WebrtcPictureLossIndication;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};

mod common;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

// ============================================================================
// RTCP Forwarder Interceptor
// ============================================================================

/// Builder for the [`RtcpForwarderInterceptor`].
pub struct RtcpForwarderBuilder;

impl Default for RtcpForwarderBuilder {
    fn default() -> Self {
        Self
    }
}

impl RtcpForwarderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> RtcpForwarderInterceptor {
        RtcpForwarderInterceptor {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Passes inbound keyframe requests — PLI and FIR — on to the application, and drops every other
/// inbound RTCP packet.
///
/// # Why an SFU wants exactly this
///
/// The rest of the inbound RTCP is for the interceptors: a receiver report feeds the sender
/// statistics, a NACK is answered by the responder, transport-wide feedback drives the bandwidth
/// estimate. A keyframe request is the exception — it is about a stream this endpoint is only
/// relaying, so the only thing that can act on it is the application, which knows where the
/// publisher is.
///
/// # Where it belongs
///
/// **Last**, so every interceptor that reads RTCP has already seen the whole of it before this one
/// narrows it down.
///
/// What it keeps, it marks with [`Attribute::DeliverToApplication`]; inbound RTCP stops at the
/// terminus otherwise. Re-emitting a copy would not help — on the belt, a packet an interceptor
/// emits rejoins *behind* itself, so no position exists from which to forward past the end of the
/// chain. Marking works because it does not try to: the packet finishes the walk and the terminus
/// reads the mark.
pub struct RtcpForwarderInterceptor {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

/// Hands every inbound RTCP packet to the application, for the arm of this test that wants the lot.
///
/// The counterpart to [`RtcpForwarderInterceptor`]: same mechanism, no predicate. Together they are
/// what replaced a chain-wide "deliver inbound RTCP" switch — the choice is per-packet now, made by
/// an interceptor that knows which packets the application can act on.
#[derive(Default)]
struct DeliverAllRtcp {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for DeliverAllRtcp {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if matches!(msg.message.packet, Packet::Rtcp(_)) {
            msg.message.add(Attribute::DeliverToApplication);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for DeliverAllRtcp {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// Whether an RTCP packet is a request for a keyframe.
fn is_keyframe_request(packet: &Box<dyn rtcp::Packet>) -> bool {
    let payload = packet.as_any();
    payload.is::<rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication>()
        || payload.is::<rtcp::payload_feedbacks::full_intra_request::FullIntraRequest>()
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RtcpForwarderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &msg.message.packet {
            let requests: Vec<Box<dyn rtcp::Packet>> = packets
                .iter()
                .filter(|packet| is_keyframe_request(packet))
                .cloned()
                .collect();
            if requests.is_empty() {
                // Not the application's business, and it has already been acted on.
                return Ok(());
            }
            msg.message.packet = Packet::Rtcp(requests);
            msg.message.add(Attribute::DeliverToApplication);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for RtcpForwarderInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
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

/// Create a sansio RTC peer whose application can read inbound RTCP.
///
/// `keyframe_requests_only` adds the [`RtcpForwarderInterceptor`], which narrows what the
/// application sees to PLI and FIR. Only a peer that is *sending* can be asked for a keyframe, so
/// the receive-only tests leave it off and read the reports they are about.
fn create_rtc_peer_config_with_rtcp_forwarder(
    is_answerer: bool,
    keyframe_requests_only: bool,
) -> Result<RTCPeerConnection> {
    let mut builder = SettingEngineBuilder::new();
    if is_answerer {
        builder = builder.with_answering_dtls_role(RTCDtlsRole::Client);
    }
    let setting_engine = builder.build();

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

    let registry = RtcRegistry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    // Inbound RTCP reaches the application only if something marks it. Both arms mark; they differ
    // in what they are willing to vouch for. Application-most either way, so every interceptor has
    // already seen the whole of the inbound RTCP before it is narrowed.
    let registry = if keyframe_requests_only {
        registry.with(Slot::from(14_000), RtcpForwarderBuilder::new().build())
    } else {
        registry.with(Slot::from(14_000), DeliverAllRtcp::default())
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
        .build(Instant::now())?;
    Ok(pc)
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
    common::install_crypto_provider();
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

    let mut rtc_pc = create_rtc_peer_config_with_rtcp_forwarder(true, false)?;

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
    rtc_pc.set_remote_description(Instant::now(), rtc_offer)?;

    // Create and set answer
    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(Instant::now(), answer.clone())?;

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
        while let Some(TaggedRTCMessage { message, .. }) = rtc_pc.poll_read() {
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
    common::install_crypto_provider();
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

    let mut rtc_pc = create_rtc_peer_config_with_rtcp_forwarder(false, false)?;

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
    rtc_pc.set_local_description(Instant::now(), offer.clone())?;

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
    rtc_pc.set_remote_description(Instant::now(), rtc_answer)?;

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
        while let Some(TaggedRTCMessage { message, .. }) = rtc_pc.poll_read() {
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

// ============================================================================
// Test 3: sansio RTC sender receives RTCP feedback about its OWN sent stream
// ============================================================================

/// Regression test for the sender-side RTCP surfacing fix.
///
/// The sansio RTC peer (offerer) *sends* a video track; the webrtc peer receives it and its
/// interceptors send RTCP feedback (Receiver Reports / transport-cc / keyframe requests)
/// back — feedback whose media SSRC is the RTC peer's *sender* SSRC. Before the fix,
/// `find_track_id_by_ssrc` searched only receivers, so this inbound RTCP could not be tagged
/// with a track and was dropped in the endpoint handler; the application never saw it. The
/// fix adds a sender fallback so such feedback surfaces via `poll_read`, tagged with the
/// sender's track id — exactly what an SFU needs to relay PLI/FIR upstream to a publisher.
///
/// The chain here carries [`RtcpForwarderInterceptor`], so what reaches the application is
/// narrowed to keyframe requests; the webrtc peer sends them explicitly, since nothing in the
/// default interceptor set asks for a keyframe on its own.
///
/// Asserts the RTC peer receives those requests, tagged with the sender's track id.
#[tokio::test]
async fn test_rtcp_processing_rtc_sender_receives_feedback() -> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    const SENDER_SSRC: u32 = 0x00DE_CAFE;
    const SENDER_TRACK_ID: &str = "rtcp-sender-test-track";

    log::info!("Starting RTCP processing test: sansio RTC (sender) <- webrtc feedback");

    // sansio RTC peer (offerer) that SENDS video, with the RTCP forwarder installed.
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut rtc_pc = create_rtc_peer_config_with_rtcp_forwarder(false, true)?;

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

    // Add a sendonly video track with a known SSRC.
    let output_track = MediaStreamTrack::new(
        "rtcp-sender-test-stream".to_owned(),
        SENDER_TRACK_ID.to_owned(),
        "rtcp-sender-test-label".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SENDER_SSRC),
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
    );
    let sender_id = rtc_pc.add_track(output_track)?;

    // Offer/answer with the webrtc peer (answerer, which receives the video).
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(Instant::now(), offer.clone())?;

    let webrtc_pc = create_webrtc_peer().await?;
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;
    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    let rtc_answer = rtc::peer_connection::sdp::RTCSessionDescription::answer(
        answer_with_candidates.sdp.clone(),
    )?;
    rtc_pc.set_remote_description(Instant::now(), rtc_answer)?;

    // Event loop: stream RTP once connected, watch for inbound RTCP about our sent stream.
    let mut buf = vec![0u8; 2000];
    let mut connected = false;
    let mut rtcp_packets_received = 0u32;
    let mut rtp_packets_sent = 0u32;
    let mut keyframe_requests_sent = 0u32;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // The receiver asks for a keyframe. Nothing in the default interceptor set generates one,
        // so the test drives it: this is the packet the forwarder is there to surface, and the
        // one an SFU would relay to the publisher.
        if connected && keyframe_requests_sent < 8 && rtp_packets_sent % 25 == 0 {
            let pli = WebrtcPictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: SENDER_SSRC,
            };
            let _ = webrtc_pc.write_rtcp(&[Box::new(pli)]).await;
            keyframe_requests_sent += 1;
        }

        // Keep the webrtc receiver active (so it keeps reporting) by streaming RTP.
        if connected && rtp_packets_sent < 300 {
            if let Some(mut sender) = rtc_pc.rtp_sender(sender_id) {
                let packet = rtc::rtp::packet::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number: rtp_packets_sent as u16,
                        timestamp: rtp_packets_sent.wrapping_mul(3000),
                        ssrc: SENDER_SSRC,
                        ..Default::default()
                    },
                    payload: bytes::Bytes::from(vec![0xAAu8; 100]),
                };
                let _ = sender.write_rtp(Instant::now(), packet);
                rtp_packets_sent += 1;
            }
        }

        while let Some(msg) = rtc_pc.poll_write() {
            let _ = socket.send_to(&msg.message, msg.transport.peer_addr).await;
        }

        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state)
                    if state == RTCIceConnectionState::Failed =>
                {
                    return Err(anyhow::anyhow!("RTC ICE connection failed"));
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("RTC connection state: {}", state);
                    if state == RTCPeerConnectionState::Connected {
                        connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                _ => {}
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = rtc_pc.poll_read() {
            if let RTCMessage::RtcpPacket(track_id, rtcp_packets) = message {
                // The fix: feedback about our SENT stream surfaces, tagged with the
                // sender's track id (the RTC peer has no receiver, so all inbound RTCP
                // here is sender-side and would have been dropped before the fix).
                assert_eq!(
                    track_id, SENDER_TRACK_ID,
                    "sender-side RTCP should be tagged with the sender's track id"
                );
                // And the forwarder narrowed it: reports were dropped, keyframe requests kept.
                assert!(
                    rtcp_packets
                        .iter()
                        .all(|packet| is_keyframe_request(packet)),
                    "the forwarder passes PLI and FIR only, but let something else through"
                );
                rtcp_packets_received += 1;
                log::info!(
                    "RTC sender received RTCP #{} about its stream (track {}, {} sub-packets)",
                    rtcp_packets_received,
                    track_id,
                    rtcp_packets.len()
                );
            }
        }

        // Success: the sender saw RTCP feedback about its own stream — impossible before
        // the fix, when it was dropped for lack of a receiver owning the ssrc.
        if rtcp_packets_received >= 2 {
            log::info!(
                "Test passed! RTP sent: {}, RTCP received about sent stream: {}",
                rtp_packets_sent,
                rtcp_packets_received
            );
            rtc_pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
        }

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
        "Test timeout - RTP sent: {}, RTCP received about sent stream: {}",
        rtp_packets_sent,
        rtcp_packets_received
    ))
}
