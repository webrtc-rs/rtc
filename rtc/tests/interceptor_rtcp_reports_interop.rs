/// Integration tests for RTCP Sender/Receiver Report interceptors at the peer connection level.
///
/// These tests verify that the rtc interceptor chain correctly generates RTCP Sender Reports
/// and Receiver Reports when integrated with a full peer connection, using webrtc v0.14.0 as peer.
///
/// Test scenarios:
/// 1. Custom interceptor registry with configurable report intervals
/// 2. Sender Reports generated when sending RTP
/// 3. Receiver Reports generated when receiving RTP
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtc::interceptor::{ReceiverReportBuilder, Registry, SenderReportBuilder};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_VP8};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
};
use rtc::shared::error::Error;

use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry as WebrtcRegistry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};
use webrtc::track::track_remote::TrackRemote;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test that custom interceptor registry with SenderReportBuilder and ReceiverReportBuilder
/// can be used with RTCConfigurationBuilder.
#[tokio::test]
async fn test_custom_interceptor_registry_with_rtcp_reports() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting custom interceptor registry test");

    // Create rtc peer with custom interceptor registry
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let setting_engine = SettingEngine::default();
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

    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    // Create custom interceptor registry with configurable intervals
    // Using shorter intervals to ensure reports are generated during the test
    let registry = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        );

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection with custom interceptor registry");

    // Create output track
    let output_track = MediaStreamTrack::new(
        "test-stream".to_string(),
        "test-track".to_string(),
        "test-label".to_string(),
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

    let output_sender_id = rtc_pc.add_track(output_track)?;
    log::info!("Added output track to RTC peer");

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

    // Create offer
    let offer = rtc_pc.create_offer(None)?;
    log::info!("RTC created offer");

    rtc_pc.set_local_description(offer.clone())?;
    log::info!("RTC set local description");

    // Create webrtc peer
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Create reflect track on webrtc
    let reflect_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-reflect".to_owned(),
    ));

    let _rtp_sender = webrtc_pc
        .add_track(Arc::clone(&reflect_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    // Set up reflect handler
    let reflect_track_clone = Arc::clone(&reflect_track);
    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let reflect_track = Arc::clone(&reflect_track_clone);
            Box::pin(async move {
                log::info!("WebRTC got track: {}", track.stream_id());
                tokio::spawn(async move {
                    while let Ok((rtp_packet, _)) = track.read_rtp().await {
                        let _ = reflect_track.write_rtp(&rtp_packet).await;
                    }
                });
            })
        },
    ));

    // Exchange SDP
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

    let rtc_answer =
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer_with_candidates.sdp)?;
    rtc_pc.set_remote_description(rtc_answer)?;

    // Run event loop and verify behavior
    let rtc_socket = Arc::new(socket);
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sent = 0u32;
    let received_packets = Arc::new(AtomicU32::new(0));
    let received_packets_clone = Arc::clone(&received_packets);
    let mut track_id2_receiver_id = HashMap::new();

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(15);
    let dummy_frame = vec![0xAA; 500];

    while start_time.elapsed() < test_timeout {
        // Process writes
        while let Some(msg) = rtc_pc.poll_write() {
            let _ = rtc_socket.send_to(&msg.message, msg.transport.peer_addr).await;
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
                        rtc_connected = true;
                        log::info!("✅ RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => {
                    if let RTCTrackEvent::OnOpen(init) = track_event {
                        log::info!("RTC got track opened: {}", init.track_id);
                        track_id2_receiver_id.insert(init.track_id, init.receiver_id);
                    }
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = rtc_pc.poll_read() {
            if let RTCMessage::RtpPacket(_track_id, rtp_packet) = message {
                let count = received_packets_clone.fetch_add(1, Ordering::SeqCst) + 1;
                log::info!(
                    "RTC received reflected RTP packet #{} (seq: {})",
                    count,
                    rtp_packet.header.sequence_number
                );
            }
        }

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("✅ WebRTC peer connected!");
        }

        // Send RTP packets once connected
        if rtc_connected && webrtc_connected && packets_sent < 10 {
            if packets_sent == 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let mut rtp_sender = rtc_pc
                .rtp_sender(output_sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?;

            let ssrc = rtp_sender
                .track()
                .ssrcs()
                .last()
                .ok_or(Error::ErrSenderWithNoSSRCs)?;

            let packet = rtc::rtp::packet::Packet {
                header: rtc::rtp::header::Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: packets_sent == 0,
                    payload_type: 96,
                    sequence_number: packets_sent as u16,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(dummy_frame.clone()),
            };

            if rtp_sender.write_rtp(packet).is_ok() {
                packets_sent += 1;
                log::info!("RTC sent RTP packet #{}", packets_sent);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check success
        let count = received_packets.load(Ordering::SeqCst);
        if count >= 5 {
            log::info!("✅ Test completed successfully!");
            log::info!(
                "   Sent {} packets, received {} reflected packets",
                packets_sent,
                count
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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(50)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = rtc_socket.recv_from(&mut buf) => {
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

    Err(anyhow::anyhow!("Test timeout"))
}

/// Test that Sender Reports are generated when RTC peer sends RTP packets.
/// This test monitors the outgoing packets to verify SR generation.
#[tokio::test]
async fn test_sender_report_generation_on_rtp_send() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting Sender Report generation test");

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let setting_engine = SettingEngine::default();
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

    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    // Use short interval to ensure SR is generated during test
    let registry = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        );

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;

    let output_track = MediaStreamTrack::new(
        "test-stream".to_string(),
        "test-track".to_string(),
        "test-label".to_string(),
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

    let output_sender_id = rtc_pc.add_track(output_track)?;

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

    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;

    let webrtc_pc = create_webrtc_peer().await?;

    let reflect_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-reflect".to_owned(),
    ));

    let _ = webrtc_pc
        .add_track(Arc::clone(&reflect_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

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

    let rtc_answer =
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer_with_candidates.sdp)?;
    rtc_pc.set_remote_description(rtc_answer)?;

    let rtc_socket = Arc::new(socket);
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sent = 0u32;
    let mut rtcp_packets_sent = 0u32;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(15);
    let dummy_frame = vec![0xAA; 500];

    while start_time.elapsed() < test_timeout {
        // Process writes and count RTCP packets (potential Sender Reports)
        while let Some(msg) = rtc_pc.poll_write() {
            // Check if this looks like RTCP (first byte indicates version and type)
            if !msg.message.is_empty() && msg.message.len() > 1 {
                let pt = msg.message[1];
                if pt == 200 {
                    // Sender Report
                    rtcp_packets_sent += 1;
                    log::info!("📤 Detected RTCP Sender Report #{}", rtcp_packets_sent);
                }
            }
            let _ = rtc_socket.send_to(&msg.message, msg.transport.peer_addr).await;
        }

        // Process events
        while let Some(event) = rtc_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                if state == RTCPeerConnectionState::Connected {
                    rtc_connected = true;
                    log::info!("✅ RTC peer connected!");
                }
            }
        }

        // Drain reads
        while rtc_pc.poll_read().is_some() {}

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("✅ WebRTC peer connected!");
        }

        // Send RTP packets
        if rtc_connected && webrtc_connected && packets_sent < 20 {
            if packets_sent == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            let mut rtp_sender = rtc_pc
                .rtp_sender(output_sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?;

            let ssrc = rtp_sender
                .track()
                .ssrcs()
                .last()
                .ok_or(Error::ErrSenderWithNoSSRCs)?;

            let packet = rtc::rtp::packet::Packet {
                header: rtc::rtp::header::Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: packets_sent == 0,
                    payload_type: 96,
                    sequence_number: packets_sent as u16,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(dummy_frame.clone()),
            };

            if rtp_sender.write_rtp(packet).is_ok() {
                packets_sent += 1;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Check success - we should have seen at least one Sender Report
        if packets_sent >= 10 && rtcp_packets_sent >= 1 {
            log::info!("✅ Test completed successfully!");
            log::info!(
                "   Sent {} RTP packets, generated {} RTCP Sender Reports",
                packets_sent,
                rtcp_packets_sent
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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(30)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = rtc_socket.recv_from(&mut buf) => {
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

    // If we sent RTP but no RTCP SR was detected, that's a failure
    if packets_sent > 0 && rtcp_packets_sent == 0 {
        return Err(anyhow::anyhow!(
            "Sent {} RTP packets but no Sender Reports were generated",
            packets_sent
        ));
    }

    Err(anyhow::anyhow!("Test timeout"))
}

/// Test that using register_default_interceptors helper function works correctly.
#[tokio::test]
async fn test_register_default_interceptors_helper() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting register_default_interceptors helper test");

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    let setting_engine = SettingEngine::default();
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

    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    // Use the helper function to register default interceptors
    let registry = Registry::new();
    let registry = rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
        registry,
        &mut media_engine,
    )?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection with default interceptors");

    let output_track = MediaStreamTrack::new(
        "test-stream".to_string(),
        "test-track".to_string(),
        "test-label".to_string(),
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

    let output_sender_id = rtc_pc.add_track(output_track)?;

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

    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;

    let webrtc_pc = create_webrtc_peer().await?;

    let reflect_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-reflect".to_owned(),
    ));

    let reflect_track_clone = Arc::clone(&reflect_track);
    let _ = webrtc_pc
        .add_track(Arc::clone(&reflect_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let reflect_track = Arc::clone(&reflect_track_clone);
            Box::pin(async move {
                tokio::spawn(async move {
                    while let Ok((rtp_packet, _)) = track.read_rtp().await {
                        let _ = reflect_track.write_rtp(&rtp_packet).await;
                    }
                });
            })
        },
    ));

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

    let rtc_answer =
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer_with_candidates.sdp)?;
    rtc_pc.set_remote_description(rtc_answer)?;

    let rtc_socket = Arc::new(socket);
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sent = 0u32;
    let received_packets = Arc::new(AtomicU32::new(0));
    let received_packets_clone = Arc::clone(&received_packets);

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(15);
    let dummy_frame = vec![0xAA; 500];

    while start_time.elapsed() < test_timeout {
        while let Some(msg) = rtc_pc.poll_write() {
            let _ = rtc_socket.send_to(&msg.message, msg.transport.peer_addr).await;
        }

        while let Some(event) = rtc_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                if state == RTCPeerConnectionState::Connected {
                    rtc_connected = true;
                    log::info!("✅ RTC peer connected!");
                }
            }
        }

        while let Some(message) = rtc_pc.poll_read() {
            if let RTCMessage::RtpPacket(_, _) = message {
                received_packets_clone.fetch_add(1, Ordering::SeqCst);
            }
        }

        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("✅ WebRTC peer connected!");
        }

        if rtc_connected && webrtc_connected && packets_sent < 10 {
            if packets_sent == 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let mut rtp_sender = rtc_pc
                .rtp_sender(output_sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?;

            let ssrc = rtp_sender
                .track()
                .ssrcs()
                .last()
                .ok_or(Error::ErrSenderWithNoSSRCs)?;

            let packet = rtc::rtp::packet::Packet {
                header: rtc::rtp::header::Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: packets_sent == 0,
                    payload_type: 96,
                    sequence_number: packets_sent as u16,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(dummy_frame.clone()),
            };

            if rtp_sender.write_rtp(packet).is_ok() {
                packets_sent += 1;
                log::info!("RTC sent RTP packet #{}", packets_sent);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let count = received_packets.load(Ordering::SeqCst);
        if count >= 5 {
            log::info!("✅ Test completed successfully!");
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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(50)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = rtc_socket.recv_from(&mut buf) => {
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

    Err(anyhow::anyhow!("Test timeout"))
}

/// Helper function to create a webrtc peer connection
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = WebrtcRegistry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

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
