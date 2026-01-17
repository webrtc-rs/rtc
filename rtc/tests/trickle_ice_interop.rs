//! Integration tests for Trickle ICE interop between sansio RTC and webrtc.
//!
//! Trickle ICE is the process of sharing ICE candidates as soon as they are gathered,
//! rather than waiting for all candidates before sending the SDP. This parallelizes
//! connection establishment with TURN server sessions.
//!
//! These tests verify:
//! 1. ICE candidates can be added after SDP exchange (trickle)
//! 2. Connection is established with candidates added post-SDP
//! 3. Data channel communication works with trickle ICE
//!
//! Test scenarios:
//! 1. webrtc (offerer) + sansio RTC (answerer) with trickle ICE
//! 2. sansio RTC (offerer) + webrtc (answerer) with trickle ICE

use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit as WebrtcIceCandidateInit;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Helper function to create a webrtc peer connection (no STUN - local only)
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    // No ICE servers - local only (STUN can't be reached in sandbox)
    let config = WebrtcRTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };

    Ok(Arc::new(api.new_peer_connection(config).await?))
}

/// Create sansio RTC peer configuration (no STUN - local only)
fn create_rtc_peer_config(
    is_answerer: bool,
) -> Result<rtc::peer_connection::configuration::RTCConfiguration> {
    let mut setting_engine = SettingEngine::default();
    if is_answerer {
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
    }

    // No ICE servers - local only
    let config = RTCConfigurationBuilder::new()
        .with_setting_engine(setting_engine)
        .build();

    Ok(config)
}

// ============================================================================
// Test 1: webrtc offerer + sansio RTC answerer with trickle ICE
// ============================================================================

/// Test Trickle ICE: webrtc (offerer) + sansio RTC (answerer)
///
/// This test verifies:
/// - webrtc creates offer WITHOUT waiting for ICE gathering
/// - sansio RTC receives offer and creates answer
/// - ICE candidates are added AFTER SDP exchange (trickle)
/// - Data channel communication works with trickle ICE
#[tokio::test]
async fn test_trickle_ice_webrtc_offerer_rtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting Trickle ICE test: webrtc (offerer) -> sansio RTC (answerer)");

    // Create webrtc peer (offerer)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Track received messages
    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Create data channel on webrtc side
    let dc_label = "trickle-ice-test";
    let webrtc_dc = webrtc_pc
        .create_data_channel(
            dc_label,
            Some(RTCDataChannelInit {
                ordered: Some(true),
                ..Default::default()
            }),
        )
        .await?;
    log::info!("Created webrtc data channel: {}", dc_label);

    webrtc_dc.on_open(Box::new(move || {
        log::info!("WebRTC data channel opened");
        Box::pin(async {})
    }));

    webrtc_dc.on_message(Box::new(move |msg| {
        let messages = Arc::clone(&webrtc_received_messages_clone);
        Box::pin(async move {
            let data = String::from_utf8(msg.data.to_vec()).unwrap_or_default();
            log::info!("WebRTC received echoed message: '{}'", data);
            let mut msgs = messages.lock().await;
            msgs.push(data);
        })
    }));

    // Create offer from webrtc WITHOUT waiting for ICE gathering (trickle ICE)
    let offer = webrtc_pc.create_offer(None).await?;
    log::info!("WebRTC created offer (without waiting for ICE gathering)");

    // Set local description on webrtc BEFORE ICE gathering completes
    webrtc_pc.set_local_description(offer.clone()).await?;
    log::info!("WebRTC set local description");

    // Get offer immediately (may not have all candidates yet - that's the point of trickle ICE)
    let offer_sdp = offer.sdp.clone();
    log::info!("WebRTC offer SDP ready (trickle ICE - candidates may be added later)");

    // Create sansio RTC peer (answerer) - bind to localhost
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let config = create_rtc_peer_config(true)?;
    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Set remote description (offer) on RTC - no candidates in SDP yet (trickle ICE demo)
    let rtc_offer = rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_sdp)?;
    rtc_pc.set_remote_description(rtc_offer)?;
    log::info!("RTC set remote description (offer without candidates)");

    // Create answer on RTC
    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(answer.clone())?;
    log::info!("RTC created and set answer");

    // Set answer on webrtc
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;
    log::info!("WebRTC set remote description (answer)");

    // === TRICKLE ICE: Add candidates AFTER SDP exchange ===

    // Add local candidate for RTC peer (trickle) - use localhost
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
    rtc_pc.add_local_candidate(local_candidate_init.clone())?;
    log::info!(
        "RTC added local candidate (trickle): {}",
        local_candidate_init.candidate
    );

    // Add RTC's local candidate to webrtc as remote candidate (trickle)
    // This must happen BEFORE we wait for gathering so webrtc can form pairs
    let webrtc_remote_candidate = WebrtcIceCandidateInit {
        candidate: local_candidate_init.candidate.clone(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    };
    webrtc_pc
        .add_ice_candidate(webrtc_remote_candidate)
        .await?;
    log::info!("WebRTC added remote candidate (trickle from RTC)");

    // Wait for webrtc ICE gathering to complete
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), gathering_done.recv()).await;

    // Get webrtc's gathered candidates and add them to RTC
    if let Some(local_desc) = webrtc_pc.local_description().await {
        log::info!("WebRTC ICE gathering complete, adding candidates to RTC");

        for line in local_desc.sdp.lines() {
            if line.starts_with("a=candidate:") && line.contains("typ host") && line.contains(" udp ") {
                let candidate_str = line.strip_prefix("a=").unwrap_or(line);
                let remote_candidate = rtc::peer_connection::transport::RTCIceCandidateInit {
                    candidate: candidate_str.to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: None,
                };
                if let Err(e) = rtc_pc.add_remote_candidate(remote_candidate.clone()) {
                    log::warn!("Failed to add remote candidate: {}", e);
                } else {
                    log::info!("RTC added remote candidate (trickle): {}", candidate_str);
                }
            }
        }
    }

    // Run event loop
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut message_sent = false;
    let mut data_channel_opened = false;
    let test_message = "Hello via Trickle ICE!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process writes
        while let Some(msg) = rtc_pc.poll_write() {
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
                        rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    let dc = rtc_pc
                        .data_channel(channel_id)
                        .expect("data channel should exist");
                    log::info!("RTC data channel opened: {}", dc.label());
                    data_channel_opened = true;
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = rtc_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(channel_id, data_channel_message) = message {
                let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                log::info!("RTC received message: '{}'", msg_str);

                {
                    let mut rtc_msgs = rtc_received_messages.lock().await;
                    rtc_msgs.push(msg_str.clone());
                }

                // Echo back
                if let Some(mut dc) = rtc_pc.data_channel(channel_id) {
                    log::info!("RTC echoing message back");
                    dc.send_text(msg_str)?;
                }
            }
        }

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("WebRTC peer connected!");
        }

        // Send message once connected
        if rtc_connected && webrtc_connected && data_channel_opened && !message_sent {
            tokio::time::sleep(Duration::from_millis(500)).await;
            log::info!("Sending message from WebRTC: '{}'", test_message);
            webrtc_dc.send_text(test_message).await?;
            message_sent = true;
        }

        // Check for success
        if message_sent {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message)
                && webrtc_msgs.iter().any(|m| m == test_message)
            {
                log::info!("Test passed: Trickle ICE working correctly!");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
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

    Err(anyhow::anyhow!("Test timeout"))
}

// ============================================================================
// Test 2: sansio RTC offerer + webrtc answerer with trickle ICE
// ============================================================================

/// Test Trickle ICE: sansio RTC (offerer) + webrtc (answerer)
///
/// This test verifies:
/// - sansio RTC creates offer
/// - webrtc receives offer and creates answer
/// - ICE candidates are added AFTER SDP exchange (trickle)
/// - Data channel communication works with trickle ICE
#[tokio::test]
async fn test_trickle_ice_rtc_offerer_webrtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting Trickle ICE test: sansio RTC (offerer) -> webrtc (answerer)");

    // Create sansio RTC peer (offerer) - bind to localhost
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let config = create_rtc_peer_config(false)?;
    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection (offerer)");

    // Track received messages
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Create data channel on RTC side
    let dc_label = "trickle-ice-rtc-offerer";
    rtc_pc.create_data_channel(dc_label, None)?;
    log::info!("Created RTC data channel: {}", dc_label);

    // Create offer on RTC (without adding candidates yet - trickle ICE)
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;
    log::info!("RTC created and set offer (without candidates)");

    // Create webrtc peer (answerer)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection (answerer)");

    // Track received messages for webrtc
    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);

    // Set up webrtc data channel handler
    webrtc_pc.on_data_channel(Box::new(move |dc| {
        let messages = Arc::clone(&webrtc_received_messages_clone);

        Box::pin(async move {
            log::info!("WebRTC received data channel: {}", dc.label());

            let dc_clone = Arc::clone(&dc);
            dc.on_open(Box::new(move || {
                log::info!("WebRTC data channel opened");
                let dc_inner = Arc::clone(&dc_clone);
                Box::pin(async move {
                    // Send test message once open
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let msg = "Hello from WebRTC answerer via Trickle ICE!";
                    log::info!("WebRTC sending: '{}'", msg);
                    dc_inner.send_text(msg).await.ok();
                })
            }));

            dc.on_message(Box::new(move |msg| {
                let msgs = Arc::clone(&messages);
                Box::pin(async move {
                    let data = String::from_utf8(msg.data.to_vec()).unwrap_or_default();
                    log::info!("WebRTC received: '{}'", data);
                    let mut m = msgs.lock().await;
                    m.push(data);
                })
            }));
        })
    }));

    // Set offer on webrtc (no candidates in SDP - trickle ICE)
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    log::info!("WebRTC set remote description (offer without candidates)");

    // Create answer on webrtc (without waiting for ICE gathering)
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer.clone()).await?;
    log::info!("WebRTC created and set answer");

    // Set answer on RTC
    let rtc_answer = rtc::peer_connection::sdp::RTCSessionDescription::answer(answer.sdp.clone())?;
    rtc_pc.set_remote_description(rtc_answer)?;
    log::info!("RTC set remote description (answer)");

    // === TRICKLE ICE: Add candidates AFTER SDP exchange ===

    // Add local candidate for RTC peer (trickle) - use localhost
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
    rtc_pc.add_local_candidate(local_candidate_init.clone())?;
    log::info!(
        "RTC added local candidate (trickle): {}",
        local_candidate_init.candidate
    );

    // Add RTC's local candidate to webrtc as remote candidate (trickle)
    let webrtc_remote_candidate = WebrtcIceCandidateInit {
        candidate: local_candidate_init.candidate.clone(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    };
    webrtc_pc
        .add_ice_candidate(webrtc_remote_candidate)
        .await?;
    log::info!("WebRTC added remote candidate (trickle from RTC)");

    // Wait for webrtc ICE gathering and add candidates to RTC
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), gathering_done.recv()).await;

    // Get webrtc's local candidates and add them to RTC as remote candidates
    if let Some(local_desc) = webrtc_pc.local_description().await {
        log::info!("WebRTC ICE gathering complete, adding candidates to RTC");

        for line in local_desc.sdp.lines() {
            if line.starts_with("a=candidate:") && line.contains("typ host") && line.contains(" udp ") {
                let candidate_str = line.strip_prefix("a=").unwrap_or(line);
                let remote_candidate = rtc::peer_connection::transport::RTCIceCandidateInit {
                    candidate: candidate_str.to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: None,
                };
                if let Err(e) = rtc_pc.add_remote_candidate(remote_candidate.clone()) {
                    log::warn!("Failed to add remote candidate: {}", e);
                } else {
                    log::info!("RTC added remote candidate (trickle): {}", candidate_str);
                }
            }
        }
    }

    // Run event loop
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut data_channel_opened = false;
    let test_message = "Hello from WebRTC answerer via Trickle ICE!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process writes
        while let Some(msg) = rtc_pc.poll_write() {
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
                        rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    let dc = rtc_pc
                        .data_channel(channel_id)
                        .expect("data channel should exist");
                    log::info!("RTC data channel opened: {}", dc.label());
                    data_channel_opened = true;
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = rtc_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_channel_id, data_channel_message) = message {
                let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                log::info!("RTC received message: '{}'", msg_str);

                {
                    let mut rtc_msgs = rtc_received_messages.lock().await;
                    rtc_msgs.push(msg_str.clone());
                }
            }
        }

        // Check webrtc connection
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("WebRTC peer connected!");
        }

        // Check for success
        if rtc_connected && webrtc_connected && data_channel_opened {
            let rtc_msgs = rtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message) {
                log::info!("Test passed: Trickle ICE (RTC offerer) working correctly!");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
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

    Err(anyhow::anyhow!("Test timeout"))
}
