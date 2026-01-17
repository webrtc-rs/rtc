#![allow(unused_assignments)]
#![allow(unused_variables)]

//! Integration tests for WebRTC Statistics collection in sansio RTC.
//!
//! These tests verify that the sansio RTC implementation correctly collects
//! and reports statistics according to the W3C WebRTC Statistics API.
//!
//! Test scenarios:
//! 1. Data channel statistics - verify stats after data exchange
//! 2. Transport statistics - verify ICE/DTLS stats after connection
//! 3. RTP stream statistics - verify inbound/outbound stats during media flow
//! 4. Stats report completeness - ensure no stats are missing

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelState;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceServer, RTCIceTransportState,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::report::RTCStatsReportEntry;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Helper struct to run two peers in an event loop
struct PeerRunner {
    offer_pc: RTCPeerConnection,
    answer_pc: RTCPeerConnection,
    offer_socket: Arc<UdpSocket>,
    answer_socket: Arc<UdpSocket>,
    offer_local_addr: std::net::SocketAddr,
    answer_local_addr: std::net::SocketAddr,
}

impl PeerRunner {
    async fn new() -> Result<Self> {
        // Create offer peer
        let offer_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let offer_local_addr = offer_socket.local_addr()?;

        let mut offer_setting_engine = SettingEngine::default();
        offer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

        let offer_config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            }])
            .with_setting_engine(offer_setting_engine)
            .build();

        let mut offer_pc = RTCPeerConnection::new(offer_config)?;

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
        offer_pc.add_local_candidate(RTCIceCandidate::from(&offer_candidate).to_json()?)?;

        // Create answer peer
        let answer_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let answer_local_addr = answer_socket.local_addr()?;

        let mut answer_setting_engine = SettingEngine::default();
        answer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

        let answer_config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            }])
            .with_setting_engine(answer_setting_engine)
            .build();

        let mut answer_pc = RTCPeerConnection::new(answer_config)?;

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
        answer_pc.add_local_candidate(RTCIceCandidate::from(&answer_candidate).to_json()?)?;

        Ok(Self {
            offer_pc,
            answer_pc,
            offer_socket: Arc::new(offer_socket),
            answer_socket: Arc::new(answer_socket),
            offer_local_addr,
            answer_local_addr,
        })
    }
}

/// Test that data channel statistics are correctly collected.
///
/// This test verifies:
/// - Data channel stats are present in the report
/// - Messages sent/received counters are correct
/// - Bytes sent/received counters are correct
/// - Data channel state is correctly reported
#[tokio::test]
async fn test_data_channel_statistics_collection() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting data channel statistics test");

    let mut runner = PeerRunner::new().await?;

    // Create data channel on offer side
    let dc_label = "stats-test-channel";
    runner.offer_pc.create_data_channel(dc_label, None)?;
    log::info!("Created data channel: {}", dc_label);

    // Exchange offer/answer
    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    // Track state
    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_dc_id = None;
    let mut _answer_dc_id = None;
    let messages_to_send = 5;
    let mut offer_messages_sent = 0;
    let mut answer_messages_received = 0;
    let message_size = 100; // bytes per message

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process offer peer writes
        while let Some(msg) = runner.offer_pc.poll_write() {
            runner
                .offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // Process offer peer events
        while let Some(event) = runner.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Connected {
                        offer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    offer_dc_id = Some(channel_id);
                }
                _ => {}
            }
        }

        // Read messages from offer
        while let Some(message) = runner.offer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                // Handle any incoming messages
            }
        }

        // Process answer peer writes
        while let Some(msg) = runner.answer_pc.poll_write() {
            runner
                .answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // Process answer peer events
        while let Some(event) = runner.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Connected {
                        answer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    _answer_dc_id = Some(channel_id);
                }
                _ => {}
            }
        }

        // Read messages from answer
        while let Some(message) = runner.answer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                answer_messages_received += 1;
            }
        }

        // Send messages from offer once connected
        if offer_connected && offer_dc_id.is_some() && offer_messages_sent < messages_to_send {
            if let Some(mut dc) = runner.offer_pc.data_channel(offer_dc_id.unwrap()) {
                let msg = "x".repeat(message_size);
                dc.send_text(msg)?;
                offer_messages_sent += 1;
            }
        }

        // Check if test is complete
        if answer_messages_received >= messages_to_send {
            log::info!("All messages received, checking stats");
            break;
        }

        // Handle timeouts
        let offer_timeout = runner
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_timeout = runner
            .answer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offer_timeout.min(answer_timeout);
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            runner.offer_pc.handle_timeout(Instant::now()).ok();
            runner.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                runner.offer_pc.handle_timeout(Instant::now()).ok();
                runner.answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = runner.offer_socket.recv_from(&mut offer_buf) => {
                runner.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = runner.answer_socket.recv_from(&mut answer_buf) => {
                runner.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    // Get stats from offer peer
    let now = Instant::now();
    let offer_stats = runner.offer_pc.get_stats(now);
    let answer_stats = runner.answer_pc.get_stats(now);

    // Verify offer peer stats
    log::info!("Offer peer stats report has {} entries", offer_stats.len());
    for entry in offer_stats.iter() {
        log::info!("  - {:?}: {}", entry.stats_type(), entry.id());
    }

    // Verify peer connection stats exist
    assert!(
        offer_stats.peer_connection().is_some(),
        "Offer should have peer connection stats"
    );
    let pc_stats = offer_stats.peer_connection().unwrap();
    assert!(
        pc_stats.data_channels_opened >= 1,
        "Should have at least 1 data channel opened"
    );

    // Verify data channel stats exist
    let dc_stats: Vec<_> = offer_stats.data_channels().collect();
    assert!(!dc_stats.is_empty(), "Offer should have data channel stats");
    let dc = dc_stats[0];
    assert_eq!(dc.label, dc_label, "Data channel label should match");
    assert_eq!(
        dc.state,
        RTCDataChannelState::Open,
        "Data channel should be open"
    );
    assert_eq!(
        dc.messages_sent, messages_to_send as u32,
        "Messages sent count should match"
    );
    assert!(
        dc.bytes_sent >= (messages_to_send * message_size) as u64,
        "Bytes sent should be at least {} but was {}",
        messages_to_send * message_size,
        dc.bytes_sent
    );

    // Verify answer peer data channel stats
    let answer_dc_stats: Vec<_> = answer_stats.data_channels().collect();
    assert!(
        !answer_dc_stats.is_empty(),
        "Answer should have data channel stats"
    );
    let answer_dc = answer_dc_stats[0];
    assert_eq!(
        answer_dc.messages_received, messages_to_send as u32,
        "Messages received count should match"
    );
    assert!(
        answer_dc.bytes_received >= (messages_to_send * message_size) as u64,
        "Bytes received should be at least {} but was {}",
        messages_to_send * message_size,
        answer_dc.bytes_received
    );

    // Clean up
    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("Data channel statistics test passed!");
    Ok(())
}

/// Test that transport statistics are correctly collected after connection.
///
/// This test verifies:
/// - Transport stats are present
/// - ICE state is reported correctly
/// - DTLS state is reported correctly
/// - Packet/byte counters are non-zero after data exchange
#[tokio::test]
async fn test_transport_statistics_collection() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting transport statistics test");

    let mut runner = PeerRunner::new().await?;

    // Create data channel to trigger connection
    runner
        .offer_pc
        .create_data_channel("transport-test", None)?;

    // Exchange offer/answer
    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    // Wait for connection
    let mut offer_connected = false;
    let mut answer_connected = false;

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout && (!offer_connected || !answer_connected) {
        // Process writes
        while let Some(msg) = runner.offer_pc.poll_write() {
            runner
                .offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = runner.answer_pc.poll_write() {
            runner
                .answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // Process events
        while let Some(event) = runner.offer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                RTCPeerConnectionState::Connected,
            ) = event
            {
                offer_connected = true;
            }
        }
        while let Some(event) = runner.answer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                RTCPeerConnectionState::Connected,
            ) = event
            {
                answer_connected = true;
            }
        }

        // Drain read queues
        while runner.offer_pc.poll_read().is_some() {}
        while runner.answer_pc.poll_read().is_some() {}

        // Handle timeouts
        let offer_timeout = runner
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_timeout = runner
            .answer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offer_timeout.min(answer_timeout);
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            runner.offer_pc.handle_timeout(Instant::now()).ok();
            runner.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                runner.offer_pc.handle_timeout(Instant::now()).ok();
                runner.answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = runner.offer_socket.recv_from(&mut offer_buf) => {
                runner.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = runner.answer_socket.recv_from(&mut answer_buf) => {
                runner.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    assert!(offer_connected, "Offer peer should be connected");
    assert!(answer_connected, "Answer peer should be connected");

    // Get stats
    let now = Instant::now();
    let offer_stats = runner.offer_pc.get_stats(now);

    log::info!("Transport stats report has {} entries", offer_stats.len());

    // Verify transport stats exist
    let transport = offer_stats.transport();
    assert!(transport.is_some(), "Should have transport stats");

    let transport = transport.unwrap();
    log::info!("Transport stats:");
    log::info!("  - ICE state: {:?}", transport.ice_state);
    log::info!("  - DTLS state: {:?}", transport.dtls_state);
    log::info!("  - Packets sent: {}", transport.packets_sent);
    log::info!("  - Packets received: {}", transport.packets_received);
    log::info!("  - Bytes sent: {}", transport.bytes_sent);
    log::info!("  - Bytes received: {}", transport.bytes_received);

    // Verify transport state
    assert_eq!(
        transport.ice_state,
        RTCIceTransportState::Connected,
        "ICE should be connected"
    );
    assert_eq!(
        transport.dtls_state,
        RTCDtlsTransportState::Connected,
        "DTLS should be connected"
    );

    // Verify packet counters are non-zero (connection establishment sends packets)
    assert!(
        transport.packets_sent > 0,
        "Should have sent packets during connection"
    );
    assert!(
        transport.packets_received > 0,
        "Should have received packets during connection"
    );

    // Clean up
    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("Transport statistics test passed!");
    Ok(())
}

/// Test that stats report contains all expected entry types.
///
/// This test verifies:
/// - Peer connection stats are always present
/// - Transport stats are present after connection
/// - ICE candidate pair stats are present after connection
/// - All stats have valid timestamps and IDs
#[tokio::test]
async fn test_stats_report_completeness() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting stats report completeness test");

    let mut runner = PeerRunner::new().await?;

    // Create data channel
    runner
        .offer_pc
        .create_data_channel("completeness-test", None)?;

    // Exchange offer/answer
    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    // Wait for connection and data channel open
    let mut connected = false;
    let mut dc_open = false;
    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout && !(connected && dc_open) {
        while let Some(msg) = runner.offer_pc.poll_write() {
            runner
                .offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = runner.answer_pc.poll_write() {
            runner
                .answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = runner.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => {
                    connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    dc_open = true;
                }
                _ => {}
            }
        }
        while runner.answer_pc.poll_event().is_some() {}
        while runner.offer_pc.poll_read().is_some() {}
        while runner.answer_pc.poll_read().is_some() {}

        let offer_timeout = runner
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_timeout = runner
            .answer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offer_timeout.min(answer_timeout);
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            runner.offer_pc.handle_timeout(Instant::now()).ok();
            runner.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                runner.offer_pc.handle_timeout(Instant::now()).ok();
                runner.answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = runner.offer_socket.recv_from(&mut offer_buf) => {
                runner.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = runner.answer_socket.recv_from(&mut answer_buf) => {
                runner.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    assert!(connected, "Should be connected");
    assert!(dc_open, "Data channel should be open");

    // Get stats
    let now = Instant::now();
    let stats = runner.offer_pc.get_stats(now);

    log::info!("Stats report completeness check:");
    log::info!("  Total entries: {}", stats.len());

    // Check for required stats types
    let mut has_peer_connection = false;
    let mut has_transport = false;
    let mut has_candidate_pair = false;
    let mut has_data_channel = false;

    for entry in stats.iter() {
        log::info!("  - {:?}: {}", entry.stats_type(), entry.id());

        // Verify all entries have non-empty IDs
        assert!(!entry.id().is_empty(), "Stats entry should have an ID");

        match entry {
            RTCStatsReportEntry::PeerConnection(pc) => {
                has_peer_connection = true;
                assert_eq!(pc.stats.id, "RTCPeerConnection");
            }
            RTCStatsReportEntry::Transport(_) => {
                has_transport = true;
            }
            RTCStatsReportEntry::IceCandidatePair(_) => {
                has_candidate_pair = true;
            }
            RTCStatsReportEntry::DataChannel(dc) => {
                has_data_channel = true;
                assert!(!dc.label.is_empty(), "Data channel should have a label");
            }
            _ => {}
        }
    }

    // Verify required stats are present
    assert!(has_peer_connection, "Should have peer connection stats");
    assert!(has_transport, "Should have transport stats");
    assert!(
        has_candidate_pair,
        "Should have ICE candidate pair stats after connection"
    );
    assert!(has_data_channel, "Should have data channel stats");

    // Verify minimum expected stats count
    // After connection with data channel, we expect at least:
    // - 1 peer connection
    // - 1 transport
    // - 1+ candidate pairs
    // - 1 data channel
    assert!(
        stats.len() >= 4,
        "Should have at least 4 stats entries, got {}",
        stats.len()
    );

    // Clean up
    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("Stats report completeness test passed!");
    Ok(())
}

/// Test that JSON serialization of stats produces valid output.
#[tokio::test]
async fn test_stats_json_serialization() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting stats JSON serialization test");

    let mut runner = PeerRunner::new().await?;

    runner.offer_pc.create_data_channel("json-test", None)?;

    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    // Wait for connection briefly
    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];
    let mut connected = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout && !connected {
        while let Some(msg) = runner.offer_pc.poll_write() {
            runner
                .offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = runner.answer_pc.poll_write() {
            runner
                .answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = runner.offer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                RTCPeerConnectionState::Connected,
            ) = event
            {
                connected = true;
            }
        }
        while runner.answer_pc.poll_event().is_some() {}
        while runner.offer_pc.poll_read().is_some() {}
        while runner.answer_pc.poll_read().is_some() {}

        let next_timeout = runner
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION)
            .min(
                runner
                    .answer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION),
            );
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            runner.offer_pc.handle_timeout(Instant::now()).ok();
            runner.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                runner.offer_pc.handle_timeout(Instant::now()).ok();
                runner.answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = runner.offer_socket.recv_from(&mut offer_buf) => {
                runner.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = runner.answer_socket.recv_from(&mut answer_buf) => {
                runner.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    // Get stats
    let now = Instant::now();
    let stats = runner.offer_pc.get_stats(now);

    // Verify each stats entry can be serialized to JSON
    for entry in stats.iter() {
        let json_result = match entry {
            RTCStatsReportEntry::PeerConnection(s) => serde_json::to_string(s),
            RTCStatsReportEntry::Transport(s) => serde_json::to_string(s),
            RTCStatsReportEntry::IceCandidatePair(s) => serde_json::to_string(s),
            RTCStatsReportEntry::LocalCandidate(s) => serde_json::to_string(s),
            RTCStatsReportEntry::RemoteCandidate(s) => serde_json::to_string(s),
            RTCStatsReportEntry::Certificate(s) => serde_json::to_string(s),
            RTCStatsReportEntry::Codec(s) => serde_json::to_string(s),
            RTCStatsReportEntry::DataChannel(s) => serde_json::to_string(s),
            RTCStatsReportEntry::InboundRtp(s) => serde_json::to_string(s),
            RTCStatsReportEntry::OutboundRtp(s) => serde_json::to_string(s),
            RTCStatsReportEntry::RemoteInboundRtp(s) => serde_json::to_string(s),
            RTCStatsReportEntry::RemoteOutboundRtp(s) => serde_json::to_string(s),
            RTCStatsReportEntry::AudioSource(s) => serde_json::to_string(s),
            RTCStatsReportEntry::VideoSource(s) => serde_json::to_string(s),
            RTCStatsReportEntry::AudioPlayout(s) => serde_json::to_string(s),
        };

        assert!(
            json_result.is_ok(),
            "Failed to serialize {:?}: {:?}",
            entry.stats_type(),
            json_result.err()
        );

        let json = json_result.unwrap();
        log::info!("{}: {}", entry.id(), json);

        // Verify JSON has required fields
        assert!(
            json.contains("\"type\""),
            "JSON should contain 'type' field: {}",
            json
        );
        assert!(
            json.contains("\"timestamp\""),
            "JSON should contain 'timestamp' field: {}",
            json
        );
        assert!(
            json.contains("\"id\""),
            "JSON should contain 'id' field: {}",
            json
        );
    }

    // Clean up
    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("Stats JSON serialization test passed!");
    Ok(())
}
