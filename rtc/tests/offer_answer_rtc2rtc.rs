/// Integration test for offer/answer between two rtc (sansio) peers (rtc-to-rtc)
///
/// This test simulates the offer-answer example but with both peers using the sansio API.
/// It verifies that two rtc peers can establish a connection, create data channels,
/// and exchange messages without requiring the webrtc library.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use rtc::configuration::setting_engine::SettingEngine;
use rtc::configuration::RTCConfigurationBuilder;
use rtc::data_channel::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::RTCIceCandidateInit;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer;
use rtc::peer_connection::RTCPeerConnection;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const TEST_MESSAGE: &str = "Hello from offer!";
const ECHO_MESSAGE: &str = "Echo from answer!";

/// Test data channel communication between two rtc (sansio) peers
#[tokio::test]
async fn test_offer_answer_rtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting offer-answer test: rtc offer -> rtc answer");

    // Track received messages
    let offer_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let answer_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Create offer peer
    let offer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let offer_local_addr = offer_socket.local_addr()?;
    log::info!("Offer peer bound to {}", offer_local_addr);

    let mut offer_setting_engine = SettingEngine::default();
    offer_setting_engine.set_answering_dtls_role(DTLSRole::Server)?;

    let offer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(offer_setting_engine)
        .build();

    let mut offer_pc = RTCPeerConnection::new(offer_config)?;
    log::info!("Created offer peer connection");

    // Create data channel on offer side
    let dc_label = "test-channel";
    let _ = offer_pc.create_data_channel(dc_label, None)?;
    log::info!("Created data channel: {}", dc_label);

    // Add local candidate for offer peer
    let offer_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: offer_local_addr.ip().to_string(),
            port: offer_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let offer_candidate_init = RTCIceCandidate::from(&offer_candidate).to_json()?;
    offer_pc.add_local_candidate(offer_candidate_init)?;

    // Create offer
    let offer = offer_pc.create_offer(None)?;
    log::info!("Offer peer created offer");

    // Set local description on offer
    offer_pc.set_local_description(offer.clone())?;
    log::info!("Offer peer set local description");

    // Create answer peer
    let answer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let answer_local_addr = answer_socket.local_addr()?;
    log::info!("Answer peer bound to {}", answer_local_addr);

    let mut answer_setting_engine = SettingEngine::default();
    answer_setting_engine.set_answering_dtls_role(DTLSRole::Client)?;

    let answer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(answer_setting_engine)
        .build();

    let mut answer_pc = RTCPeerConnection::new(answer_config)?;
    log::info!("Created answer peer connection");

    // Set remote description on answer (the offer)
    answer_pc.set_remote_description(offer)?;
    log::info!("Answer peer set remote description");

    // Add local candidate for answer peer
    let answer_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: answer_local_addr.ip().to_string(),
            port: answer_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let answer_candidate_init = RTCIceCandidate::from(&answer_candidate).to_json()?;
    answer_pc.add_local_candidate(answer_candidate_init)?;

    // Create answer
    let answer = answer_pc.create_answer(None)?;
    log::info!("Answer peer created answer");

    // Set local description on answer
    answer_pc.set_local_description(answer.clone())?;
    log::info!("Answer peer set local description");

    // Set remote description on offer (the answer)
    offer_pc.set_remote_description(answer)?;
    log::info!("Offer peer set remote description");

    // Add remote candidates (these are actually local candidates for the remote peer)
    // In sansio API, we add the remote peer's local candidate as our remote candidate
    let offer_remote_candidate_init = RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            answer_local_addr.ip(),
            answer_local_addr.port()
        ),
        ..Default::default()
    };
    offer_pc.add_local_candidate(offer_remote_candidate_init)?;
    log::info!("Offer peer added remote peer's candidate");

    let answer_remote_candidate_init = RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            offer_local_addr.ip(),
            offer_local_addr.port()
        ),
        ..Default::default()
    };
    answer_pc.add_local_candidate(answer_remote_candidate_init)?;
    log::info!("Answer peer added remote peer's candidate");

    // Run event loops for both peers
    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];
    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_dc_id = None;
    let mut message_sent = false;
    let mut echo_sent = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process offer peer
        while let Some(msg) = offer_pc.poll_write() {
            match offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("Offer sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("Offer socket write error: {}", err);
                }
            }
        }

        while let Some(event) = offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("Offer ICE connection state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("Offer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("Offer peer connection state: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Offer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        log::info!("Offer peer connection connected!");
                        offer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(channel_id) => {
                        log::info!("Offer data channel {} opened", channel_id);
                        offer_dc_id = Some(channel_id);
                    }
                    RTCDataChannelEvent::OnMessage(channel_id, message) => {
                        let msg_str = String::from_utf8(message.data.to_vec())?;
                        log::info!("Offer received message: '{}' from {}", msg_str, channel_id);
                        let mut msgs = offer_received_messages.lock().await;
                        msgs.push(msg_str);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Process answer peer
        while let Some(msg) = answer_pc.poll_write() {
            match answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("Answer sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("Answer socket write error: {}", err);
                }
            }
        }

        while let Some(event) = answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("Answer ICE connection state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("Answer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("Answer peer connection state: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Answer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        log::info!("Answer peer connection connected!");
                        answer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
                    match dc_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            log::info!("Answer data channel {} opened", channel_id);
                        }
                        RTCDataChannelEvent::OnMessage(channel_id, message) => {
                            let msg_str = String::from_utf8(message.data.to_vec())?;
                            log::info!("Answer received message: '{}'", msg_str);
                            let mut msgs = answer_received_messages.lock().await;
                            msgs.push(msg_str.clone());

                            // Echo back
                            if !echo_sent {
                                if let Some(mut dc) = answer_pc.data_channel(channel_id) {
                                    log::info!("Answer echoing: '{}'", ECHO_MESSAGE);
                                    dc.send_text(ECHO_MESSAGE.to_string())?;
                                    echo_sent = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Send test message from offer once connected
        if offer_connected && offer_dc_id.is_some() && !message_sent {
            if let Some(mut dc) = offer_pc.data_channel(offer_dc_id.unwrap()) {
                log::info!("Offer sending message: '{}'", TEST_MESSAGE);
                dc.send_text(TEST_MESSAGE.to_string())?;
                message_sent = true;
            }
        }

        // Check if test is complete
        let offer_msgs = offer_received_messages.lock().await;
        let answer_msgs = answer_received_messages.lock().await;
        if offer_msgs.len() >= 1 && answer_msgs.len() >= 1 {
            log::info!("Test complete - both peers received messages");
            break;
        }
        drop(offer_msgs);
        drop(answer_msgs);

        // Handle timeouts
        let offer_timeout = offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_timeout = answer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offer_timeout.min(answer_timeout);
        let delay = next_timeout.saturating_duration_since(Instant::now());

        if delay.is_zero() {
            offer_pc.handle_timeout(Instant::now()).ok();
            answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        // Wait for data or timeout
        let sleep = tokio::time::sleep(delay.min(Duration::from_millis(10)));
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                offer_pc.handle_timeout(Instant::now()).ok();
                answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = offer_socket.recv_from(&mut offer_buf) => {
                offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = answer_socket.recv_from(&mut answer_buf) => {
                answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    // Verify test results
    let offer_msgs = offer_received_messages.lock().await;
    let answer_msgs = answer_received_messages.lock().await;

    log::info!("Offer received {} messages", offer_msgs.len());
    log::info!("Answer received {} messages", answer_msgs.len());

    assert!(offer_connected, "Offer peer should have connected");
    assert!(answer_connected, "Answer peer should have connected");
    assert!(
        !offer_msgs.is_empty(),
        "Offer peer should have received messages"
    );
    assert!(
        !answer_msgs.is_empty(),
        "Answer peer should have received messages"
    );
    assert_eq!(
        answer_msgs[0], TEST_MESSAGE,
        "Answer should have received the test message"
    );
    assert_eq!(
        offer_msgs[0], ECHO_MESSAGE,
        "Offer should have received the echo message"
    );

    log::info!("Offer-answer test completed successfully!");

    // Clean up
    offer_pc.close()?;
    answer_pc.close()?;

    Ok(())
}
