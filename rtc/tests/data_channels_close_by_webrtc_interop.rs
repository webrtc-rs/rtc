/// Integration test for data channel close behavior where WebRTC closes the channel
///
/// This test verifies that:
/// - RTC can create a data channel (as offerer)
/// - WebRTC can send periodic messages to RTC
/// - WebRTC can close the data channel after sending N messages
/// - RTC properly detects the data channel close event
///
/// This is the inverse of the data_channels_close_interop test where RTC closes the channel.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use rtc::configuration::setting_engine::SettingEngine;
use rtc::configuration::RTCConfigurationBuilder;
use rtc::data_channel::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{CandidateConfig, CandidateHostConfig};
use rtc::peer_connection::transport::ice::server::RTCIceServer as RtcIceServer;
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;

use interceptor::registry::Registry;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel as WebrtcRTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test data channel close behavior with WebRTC sending periodic messages and closing
#[tokio::test]
async fn test_data_channel_close_by_webrtc_interop() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        //.is_test(true)
        .try_init()
        .ok();

    log::info!("Starting data channel close interop test: WebRTC sends and closes");

    // Track received messages and close events on RTC side
    let mut rtc_received_messages = Vec::<String>::new();
    let mut rtc_channel_closed = false;

    // Number of messages to send before closing
    let messages_to_send = Arc::new(Mutex::new(3));

    // Create rtc peer (will be the offerer and create the data channel)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(DTLSRole::Server)?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RtcIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Create a data channel from RTC side
    let dc_label = "test-channel";
    let _rtc_dc = rtc_pc.create_data_channel(dc_label, None)?;
    log::info!("RTC created data channel: {}", dc_label);

    // Add local candidate for rtc peer
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
    let local_candidate_init =
        rtc::peer_connection::transport::ice::candidate::RTCIceCandidate::from(&candidate)
            .to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create offer from rtc peer
    let offer = rtc_pc.create_offer(None)?;
    log::info!("RTC created offer");

    // Set local description on rtc peer
    rtc_pc.set_local_description(offer.clone())?;
    log::info!("RTC set local description");

    // Convert rtc offer to webrtc SDP
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;

    // Create webrtc peer (will be the answerer)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Set up data channel handler on webrtc side
    let webrtc_dc = Arc::new(Mutex::new(None::<Arc<WebrtcRTCDataChannel>>));
    let webrtc_dc_clone = Arc::clone(&webrtc_dc);

    webrtc_pc.on_data_channel(Box::new(move |dc| {
        let webrtc_dc = Arc::clone(&webrtc_dc_clone);
        let webrtc_dc2 = Arc::clone(&webrtc_dc_clone);
        let dc_clone = Arc::clone(&dc);
        Box::pin(async move {
            let label = dc.label();
            log::info!("WebRTC received data channel: {}", label);

            dc.on_open(Box::new(move || {
                let webrtc_dc = Arc::clone(&webrtc_dc);
                let dc_clone = Arc::clone(&dc_clone);
                Box::pin(async move {
                    log::info!("WebRTC data channel opened");
                    let mut dc_guard = webrtc_dc.lock().await;
                    *dc_guard = Some(dc_clone);
                })
            }));

            dc.on_message(Box::new(move |msg| {
                Box::pin(async move {
                    let data = String::from_utf8(msg.data.to_vec()).unwrap_or_default();
                    log::info!("WebRTC received message: '{}'", data);
                })
            }));

            dc.on_close(Box::new(move || {
                let webrtc_dc = Arc::clone(&webrtc_dc2);
                Box::pin(async move {
                    log::info!("WebRTC data channel closed");
                    let mut dc_guard = webrtc_dc.lock().await;
                    *dc_guard = None;
                })
            }));
        })
    }));

    // Set remote description on webrtc (the offer from rtc)
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    log::info!("WebRTC set remote description");

    // Create answer from webrtc
    let answer = webrtc_pc.create_answer(None).await?;
    log::info!("WebRTC created answer");

    // Set local description on webrtc
    webrtc_pc.set_local_description(answer.clone()).await?;
    log::info!("WebRTC set local description");

    // Wait for ICE gathering to complete on webrtc
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    // Get the complete answer with ICE candidates
    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    log::info!("WebRTC answer with candidates ready");

    // Convert webrtc answer to rtc SDP
    let rtc_answer = rtc::peer_connection::sdp::session_description::RTCSessionDescription::answer(
        answer_with_candidates.sdp.clone(),
    )?;

    // Set remote description on rtc (the answer from webrtc)
    rtc_pc.set_remote_description(rtc_answer)?;
    log::info!("RTC set remote description");

    // Run event loops for both peers
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut rtc_data_channel_opened = false;
    let mut last_message_time = Instant::now();
    let message_interval = Duration::from_millis(500); // Send every 500ms for testing

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process rtc events
        while let Some(msg) = rtc_pc.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    log::trace!("RTC sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("RTC socket write error: {}", err);
                }
            }
        }

        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("RTC ICE connection state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("RTC ICE connection failed"));
                    }
                    if state == RTCIceConnectionState::Connected {
                        log::info!("RTC ICE connected!");
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("RTC peer connection state: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("RTC peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        log::info!("RTC peer connection connected!");
                        rtc_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
                    log::info!("RTC data channel event: {:?}", dc_event);
                    match dc_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            let dc = rtc_pc
                                .data_channel(channel_id)
                                .expect("data channel should exist");
                            log::info!(
                                "RTC data channel opened: {} (id: {})",
                                dc.label()?,
                                channel_id
                            );
                            rtc_data_channel_opened = true;
                            last_message_time = Instant::now();
                        }
                        RTCDataChannelEvent::OnMessage(channel_id, msg) => {
                            let data = String::from_utf8(msg.data.to_vec()).unwrap_or_default();
                            log::info!(
                                "RTC received message on channel {}: '{}'",
                                channel_id,
                                data
                            );
                            rtc_received_messages.push(data);
                        }
                        RTCDataChannelEvent::OnClose(channel_id) => {
                            log::info!("RTC data channel {} closed", channel_id);
                            rtc_data_channel_opened = false;
                            rtc_channel_closed = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            log::info!("WebRTC peer connection connected!");
            webrtc_connected = true;
        }

        // Send periodic messages from WebRTC side
        if rtc_connected && webrtc_connected && rtc_data_channel_opened {
            let elapsed = Instant::now().duration_since(last_message_time);
            if elapsed >= message_interval {
                let webrtc_dc_guard = webrtc_dc.lock().await;
                if let Some(dc) = webrtc_dc_guard.as_ref() {
                    let mut messages = messages_to_send.lock().await;
                    if *messages > 0 {
                        let message = format!("Message #{}", 4 - *messages);
                        log::info!("WebRTC sending: '{}'", message);
                        dc.send_text(message).await?;
                        last_message_time = Instant::now();
                        *messages -= 1;
                    } else {
                        log::info!("WebRTC finished sending messages, closing data channel");
                        dc.close().await?;
                        drop(webrtc_dc_guard); // Release lock before sleep
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } else {
                    log::info!("WebRTC data channel is closed, waiting RTC data channel closing");
                }
            }
        }

        // Check if test is complete - RTC side should see the close
        if rtc_channel_closed {
            log::info!("✅ Test completed successfully!");
            log::info!("   Data channel closed (detected by RTC)");

            log::info!(
                "   RTC received {} messages: {:?}",
                rtc_received_messages.len(),
                rtc_received_messages
            );

            // Verify RTC received all messages before close
            assert!(
                rtc_received_messages.len() >= 3,
                "RTC should have received at least 3 messages before close"
            );

            webrtc_pc.close().await?;
            rtc_pc.close()?;
            return Ok(());
        }

        // Poll timeout
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

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        log::trace!("RTC received {} bytes from {}", n, peer_addr);
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
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, continue
                    }
                    Err(err) => {
                        log::error!("RTC socket read error: {}", err);
                        return Err(err.into());
                    }
                }
            }
        }
    }

    // If we get here, close the connections anyway
    webrtc_pc.close().await?;
    rtc_pc.close()?;

    Err(anyhow::anyhow!(
        "Test timeout - data channel close not detected by RTC in time"
    ))
}

/// Helper function to create a webrtc peer connection
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = Registry::new();
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

    let peer_connection = Arc::new(api.new_peer_connection(config).await?);
    Ok(peer_connection)
}
