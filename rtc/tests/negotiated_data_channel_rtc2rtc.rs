/// Integration test for negotiated DataChannels between two rtc (sansio) peers
///
/// This test verifies that two rtc peers can create negotiated DataChannels
/// (out-of-band negotiation with matching channel IDs) and exchange messages.
/// Unlike in-band channels, negotiated channels must be created on BOTH peers
/// with the same channel ID before the connection is established.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const NEGOTIATED_CHANNEL_ID: u16 = 5;
const TEST_MESSAGE_FROM_OFFERER: &str = "Hello from offerer (negotiated)!";
const TEST_MESSAGE_FROM_ANSWERER: &str = "Hello from answerer (negotiated)!";

/// Test negotiated DataChannel communication between two rtc (sansio) peers.
///
/// Both peers create a DataChannel with `negotiated: Some(5)` (same channel ID).
/// After connecting, both sides send a message and verify the other received it.
#[tokio::test]
async fn test_negotiated_data_channel_rtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting negotiated DataChannel test: rtc offer <-> rtc answer");

    // Track received messages
    let offerer_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let answerer_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // --- Create offerer peer ---
    let offerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let offerer_local_addr = offerer_socket.local_addr()?;
    log::info!("Offerer peer bound to {}", offerer_local_addr);

    let mut offerer_setting_engine = SettingEngine::default();
    offerer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    let offerer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut offerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(offerer_config)
        .with_setting_engine(offerer_setting_engine)
        .build()?;
    log::info!("Created offerer peer connection");

    // Create negotiated DataChannel on offerer side
    let dc_label = "negotiated-channel";
    let _offerer_dc = offerer_pc.create_data_channel(
        dc_label,
        Some(RTCDataChannelInit {
            negotiated: Some(NEGOTIATED_CHANNEL_ID),
            ..Default::default()
        }),
    )?;
    log::info!(
        "Offerer created negotiated DataChannel '{}' with id={}",
        dc_label,
        NEGOTIATED_CHANNEL_ID
    );

    // Add local candidate for offerer
    let offerer_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: offerer_local_addr.ip().to_string(),
            port: offerer_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let offerer_candidate_init = RTCIceCandidate::from(&offerer_candidate).to_json()?;
    offerer_pc.add_local_candidate(offerer_candidate_init)?;

    // Create offer
    let offer = offerer_pc.create_offer(None)?;
    log::info!("Offerer created offer");
    offerer_pc.set_local_description(offer.clone())?;
    log::info!("Offerer set local description");

    // --- Create answerer peer ---
    let answerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let answerer_local_addr = answerer_socket.local_addr()?;
    log::info!("Answerer peer bound to {}", answerer_local_addr);

    let mut answerer_setting_engine = SettingEngine::default();
    answerer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

    let answerer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut answerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(answerer_config)
        .with_setting_engine(answerer_setting_engine)
        .build()?;
    log::info!("Created answerer peer connection");

    // Create negotiated DataChannel on answerer side (same label and ID)
    let _answerer_dc = answerer_pc.create_data_channel(
        dc_label,
        Some(RTCDataChannelInit {
            negotiated: Some(NEGOTIATED_CHANNEL_ID),
            ..Default::default()
        }),
    )?;
    log::info!(
        "Answerer created negotiated DataChannel '{}' with id={}",
        dc_label,
        NEGOTIATED_CHANNEL_ID
    );

    // Set remote description on answerer (the offer)
    answerer_pc.set_remote_description(offer)?;
    log::info!("Answerer set remote description");

    // Add local candidate for answerer
    let answerer_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: answerer_local_addr.ip().to_string(),
            port: answerer_local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let answerer_candidate_init = RTCIceCandidate::from(&answerer_candidate).to_json()?;
    answerer_pc.add_local_candidate(answerer_candidate_init)?;

    // Create and set answer
    let answer = answerer_pc.create_answer(None)?;
    log::info!("Answerer created answer");
    answerer_pc.set_local_description(answer.clone())?;
    log::info!("Answerer set local description");

    // Set remote description on offerer (the answer)
    offerer_pc.set_remote_description(answer)?;
    log::info!("Offerer set remote description");

    // Exchange ICE candidates between peers
    let offerer_remote_candidate = RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            answerer_local_addr.ip(),
            answerer_local_addr.port()
        ),
        ..Default::default()
    };
    offerer_pc.add_local_candidate(offerer_remote_candidate)?;
    log::info!("Offerer added answerer's candidate");

    let answerer_remote_candidate = RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            offerer_local_addr.ip(),
            offerer_local_addr.port()
        ),
        ..Default::default()
    };
    answerer_pc.add_local_candidate(answerer_remote_candidate)?;
    log::info!("Answerer added offerer's candidate");

    // --- Run event loops ---
    let mut offerer_buf = vec![0u8; 2000];
    let mut answerer_buf = vec![0u8; 2000];
    let mut offerer_connected = false;
    let mut answerer_connected = false;
    let mut offerer_dc_opened = false;
    let mut answerer_dc_opened = false;
    let mut offerer_message_sent = false;
    let mut answerer_message_sent = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // --- Process offerer ---
        while let Some(msg) = offerer_pc.poll_write() {
            match offerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("Offerer sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("Offerer socket write error: {}", err);
                }
            }
        }

        while let Some(event) = offerer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("Offerer ICE connection state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("Offerer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("Offerer peer connection state: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Offerer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        log::info!("Offerer peer connection connected!");
                        offerer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(channel_id) => {
                        log::info!("Offerer data channel {} opened", channel_id);
                        if channel_id == NEGOTIATED_CHANNEL_ID {
                            offerer_dc_opened = true;
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = offerer_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(channel_id, data_channel_message) => {
                    let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                    log::info!(
                        "Offerer received message on channel {}: '{}'",
                        channel_id,
                        msg_str
                    );
                    let mut msgs = offerer_received_messages.lock().await;
                    msgs.push(msg_str);
                }
            }
        }

        // --- Process answerer ---
        while let Some(msg) = answerer_pc.poll_write() {
            match answerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("Answerer sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("Answerer socket write error: {}", err);
                }
            }
        }

        while let Some(event) = answerer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    log::info!("Answerer ICE connection state: {}", state);
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("Answerer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("Answerer peer connection state: {}", state);
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Answerer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        log::info!("Answerer peer connection connected!");
                        answerer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                    RTCDataChannelEvent::OnOpen(channel_id) => {
                        log::info!("Answerer data channel {} opened", channel_id);
                        if channel_id == NEGOTIATED_CHANNEL_ID {
                            answerer_dc_opened = true;
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = answerer_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {}
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(channel_id, data_channel_message) => {
                    let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
                    log::info!(
                        "Answerer received message on channel {}: '{}'",
                        channel_id,
                        msg_str
                    );
                    let mut msgs = answerer_received_messages.lock().await;
                    msgs.push(msg_str);
                }
            }
        }

        // Send messages once both are connected and both channels are open
        if offerer_connected
            && answerer_connected
            && offerer_dc_opened
            && answerer_dc_opened
            && !offerer_message_sent
        {
            if let Some(mut dc) = offerer_pc.data_channel(NEGOTIATED_CHANNEL_ID) {
                log::info!("Offerer sending message: '{}'", TEST_MESSAGE_FROM_OFFERER);
                dc.send_text(TEST_MESSAGE_FROM_OFFERER.to_string())?;
                offerer_message_sent = true;
            }
        }

        if offerer_connected
            && answerer_connected
            && offerer_dc_opened
            && answerer_dc_opened
            && !answerer_message_sent
        {
            if let Some(mut dc) = answerer_pc.data_channel(NEGOTIATED_CHANNEL_ID) {
                log::info!("Answerer sending message: '{}'", TEST_MESSAGE_FROM_ANSWERER);
                dc.send_text(TEST_MESSAGE_FROM_ANSWERER.to_string())?;
                answerer_message_sent = true;
            }
        }

        // Check if both sides received the expected messages
        if offerer_message_sent && answerer_message_sent {
            let offerer_msgs = offerer_received_messages.lock().await;
            let answerer_msgs = answerer_received_messages.lock().await;

            let offerer_got_msg = offerer_msgs.iter().any(|m| m == TEST_MESSAGE_FROM_ANSWERER);
            let answerer_got_msg = answerer_msgs.iter().any(|m| m == TEST_MESSAGE_FROM_OFFERER);

            if offerer_got_msg && answerer_got_msg {
                log::info!(
                    "Test complete - both peers received messages via negotiated DataChannel"
                );
                log::info!("  Offerer received: {:?}", offerer_msgs.as_slice());
                log::info!("  Answerer received: {:?}", answerer_msgs.as_slice());

                assert!(
                    answerer_msgs.iter().any(|m| m == TEST_MESSAGE_FROM_OFFERER),
                    "Answerer should have received offerer's message"
                );
                assert!(
                    offerer_msgs.iter().any(|m| m == TEST_MESSAGE_FROM_ANSWERER),
                    "Offerer should have received answerer's message"
                );

                offerer_pc.close()?;
                answerer_pc.close()?;
                return Ok(());
            }
        }

        // Handle timeouts
        let offerer_timeout = offerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answerer_timeout = answerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offerer_timeout.min(answerer_timeout);
        let delay = next_timeout.saturating_duration_since(Instant::now());

        if delay.is_zero() {
            offerer_pc.handle_timeout(Instant::now()).ok();
            answerer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay.min(Duration::from_millis(10)));
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                offerer_pc.handle_timeout(Instant::now()).ok();
                answerer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = offerer_socket.recv_from(&mut offerer_buf) => {
                offerer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: offerer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offerer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = answerer_socket.recv_from(&mut answerer_buf) => {
                answerer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: answerer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answerer_buf[..n]),
                }).ok();
            }
        }
    }

    Err(anyhow::anyhow!(
        "Test timeout - negotiated DataChannel bidirectional message exchange did not complete in time"
    ))
}
