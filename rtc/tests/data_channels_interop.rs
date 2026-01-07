/// Integration test for data channels interop between rtc and webrtc
///
/// This test verifies that the rtc library can successfully establish a peer connection
/// and exchange data with the webrtc library, ensuring interoperability between the two.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig};

use rtc::peer_connection::message::RTCMessage;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test data channel communication between rtc (sansio) and webrtc (async) implementations
#[tokio::test]
async fn test_data_channel_rtc_to_webrtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting data channel interop test: rtc -> webrtc");

    // Create webrtc peer (will be the offerer)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Track received messages on both sides
    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Set up data channel on webrtc side
    let dc_label = "test-channel";
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

    // Set up webrtc data channel handlers
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

    // Create offer from webrtc side
    let offer = webrtc_pc.create_offer(None).await?;
    log::info!("WebRTC created offer");

    // Set local description on webrtc
    webrtc_pc.set_local_description(offer.clone()).await?;
    log::info!("WebRTC set local description");

    // Wait for ICE gathering to complete
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    // Get the complete offer with ICE candidates
    let offer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    log::info!("WebRTC offer with candidates ready");

    // Convert webrtc SDP to rtc SDP
    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;

    // Create rtc peer (will be the answerer)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Set remote description (the offer from webrtc)
    log::info!("RTC set remote description {}", rtc_offer);
    rtc_pc.set_remote_description(rtc_offer)?;

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
        rtc::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create answer from rtc peer
    let answer = rtc_pc.create_answer(None)?;
    log::info!("RTC created answer");

    // Set local description on rtc peer
    rtc_pc.set_local_description(answer.clone())?;
    log::info!("RTC set local description {}", answer);

    // Convert rtc answer to webrtc SDP
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;

    // Set remote description on webrtc (the answer from rtc)
    webrtc_pc.set_remote_description(webrtc_answer).await?;
    log::info!("WebRTC set remote description");

    // Run event loops for both peers
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut message_sent = false;
    let mut data_channel_opened = false;

    let test_message = "Hello from WebRTC!";

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
                                dc.label(),
                                channel_id
                            );
                            data_channel_opened = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(channel_id, data_channel_message) => {
                    let mut dc = rtc_pc
                        .data_channel(channel_id)
                        .expect("data channel should exist");
                    let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                    log::info!(
                        "RTC received message on channel {}: '{}'",
                        channel_id,
                        msg_str
                    );

                    // Verify the message matches what we expect
                    {
                        let mut rtc_msgs = rtc_received_messages.lock().await;
                        rtc_msgs.push(msg_str.clone());
                    }

                    // Echo back
                    log::info!("RTC echoing message back: '{}'", msg_str);
                    dc.send_text(msg_str)?;
                }
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            log::info!("WebRTC peer connection connected!");
            webrtc_connected = true;
        }

        // Send message once both are connected and data channel is open
        // Use ICE connected state for RTC since peer connection state may not fire in sansio model
        if rtc_connected && webrtc_connected && data_channel_opened && !message_sent {
            log::info!("Both peers connected and data channel open, sending test message");
            tokio::time::sleep(Duration::from_millis(500)).await;
            log::info!("Sending message from WebRTC: '{}'", test_message);
            webrtc_dc.send_text(test_message).await?;
            message_sent = true;
        }

        // Check if we received the echo back and verify the messages
        if message_sent {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            // Check if RTC received the original message
            let rtc_received_correct = rtc_msgs.iter().any(|msg| msg == test_message);

            // Check if WebRTC received the echoed message back
            let webrtc_received_echo = webrtc_msgs.iter().any(|msg| msg == test_message);

            if rtc_received_correct && webrtc_received_echo {
                log::info!("✅ Test completed successfully!");
                log::info!("   RTC received: {:?}", rtc_msgs.as_slice());
                log::info!("   WebRTC received echo: {:?}", webrtc_msgs.as_slice());

                // Verify the messages match
                assert_eq!(
                    rtc_msgs.first(),
                    Some(&test_message.to_string()),
                    "RTC should have received the test message"
                );
                assert_eq!(
                    webrtc_msgs.first(),
                    Some(&test_message.to_string()),
                    "WebRTC should have received the echoed message"
                );

                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
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

    Err(anyhow::anyhow!(
        "Test timeout - message was not echoed back in time"
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
