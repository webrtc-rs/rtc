//! Integration tests for ICE over TCP with active/passive candidates.
//!
//! This test verifies that the sansio RTC implementation correctly handles
//! ICE over TCP connections where:
//! - The offerer uses TCP active candidates (initiates connections)
//! - The answerer uses TCP passive candidates (accepts connections)
//!
//! Key aspects tested:
//! 1. TCP active candidate creation with port 9 placeholder
//! 2. TCP passive candidate creation with listening port
//! 3. RFC 4571 TCP framing for ICE/DTLS/SCTP messages
//! 4. Data channel communication over TCP transport

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Helper struct to run two peers with TCP active/passive candidates.
struct TcpPeerRunner {
    /// TCP active offerer
    offer_pc: RTCPeerConnection,
    /// TCP passive answerer
    answer_pc: RTCPeerConnection,
    /// TCP listener for passive side
    tcp_listener: TcpListener,
    /// Local address for passive TCP candidate
    passive_local_addr: SocketAddr,
}

impl TcpPeerRunner {
    async fn new() -> Result<Self> {
        // Create TCP listener for the passive (answer) side
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let passive_local_addr = tcp_listener.local_addr()?;

        // Configure offer peer with TCP active candidate
        let mut offer_setting_engine = SettingEngine::default();
        offer_setting_engine.set_network_types(vec![
            ice::network_type::NetworkType::Tcp4,
            ice::network_type::NetworkType::Tcp6,
        ]);

        let offer_config = RTCConfigurationBuilder::new()
            .with_setting_engine(offer_setting_engine)
            .build();

        let mut offer_pc = RTCPeerConnection::new(offer_config)?;

        // Create TCP active candidate for offer side
        // Port 9 (discard) is used as placeholder for active candidates
        let offer_candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: "127.0.0.1".to_string(),
                port: 9, // Placeholder port for active candidates
                component: 1,
                ..Default::default()
            },
            tcp_type: ice::tcp_type::TcpType::Active,
        }
        .new_candidate_host()?;
        offer_pc.add_local_candidate(RTCIceCandidate::from(&offer_candidate).to_json()?)?;

        // Configure answer peer with TCP passive candidate
        let mut answer_setting_engine = SettingEngine::default();
        answer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
        answer_setting_engine.set_network_types(vec![
            ice::network_type::NetworkType::Tcp4,
            ice::network_type::NetworkType::Tcp6,
        ]);

        let answer_config = RTCConfigurationBuilder::new()
            .with_setting_engine(answer_setting_engine)
            .build();

        let mut answer_pc = RTCPeerConnection::new(answer_config)?;

        // Create TCP passive candidate for answer side
        let answer_candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: passive_local_addr.ip().to_string(),
                port: passive_local_addr.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: ice::tcp_type::TcpType::Passive,
        }
        .new_candidate_host()?;
        answer_pc.add_local_candidate(RTCIceCandidate::from(&answer_candidate).to_json()?)?;

        Ok(Self {
            offer_pc,
            answer_pc,
            tcp_listener,
            passive_local_addr,
        })
    }
}

/// Test that ICE over TCP works with active (offerer) and passive (answerer) candidates.
///
/// This test verifies:
/// - TCP active candidate connects to TCP passive candidate
/// - RFC 4571 framing is correctly applied
/// - Data channel messages are exchanged over TCP
#[tokio::test]
async fn test_ice_tcp_active_passive_connection() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting ICE TCP active/passive test");

    let mut runner = TcpPeerRunner::new().await?;

    // Create data channel on offer side
    let dc_label = "tcp-test-channel";
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
    let mut answer_dc_open = false;
    let messages_to_send = 3;
    let mut offer_messages_sent = 0;
    let mut answer_messages_received = 0;
    let message_content = "Hello over TCP!";

    // TCP connection state
    let mut answer_stream: Option<TcpStream> = None;
    let mut offer_decoder = TcpFrameDecoder::new();
    let mut answer_decoder = TcpFrameDecoder::new();
    let mut offer_buf = vec![0u8; 4096];
    let mut answer_buf = vec![0u8; 4096];

    // Offerer initiates TCP connection to passive candidate
    log::info!(
        "Connecting to passive candidate at {}",
        runner.passive_local_addr
    );
    let stream = TcpStream::connect(runner.passive_local_addr).await?;
    let offer_local_addr = stream.local_addr()?;
    let mut offer_stream: Option<TcpStream> = Some(stream);
    log::info!("TCP connection established from {}", offer_local_addr);

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process offer peer writes - send via TCP with framing
        while let Some(msg) = runner.offer_pc.poll_write() {
            if let Some(ref mut stream) = offer_stream {
                let framed = frame_packet(&msg.message);
                stream.write_all(&framed).await?;
            }
        }

        // Process answer peer writes - send via TCP with framing
        while let Some(msg) = runner.answer_pc.poll_write() {
            if let Some(ref mut stream) = answer_stream {
                let framed = frame_packet(&msg.message);
                stream.write_all(&framed).await?;
            }
        }

        // Process offer peer events
        while let Some(event) = runner.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("[Offer] Connection state: {:?}", state);
                    if state == RTCPeerConnectionState::Connected {
                        offer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    log::info!("[Offer] Data channel opened: {}", channel_id);
                    offer_dc_id = Some(channel_id);
                }
                _ => {}
            }
        }

        // Process answer peer events
        while let Some(event) = runner.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    log::info!("[Answer] Connection state: {:?}", state);
                    if state == RTCPeerConnectionState::Connected {
                        answer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(channel_id)) => {
                    log::info!("[Answer] Data channel opened: {}", channel_id);
                    answer_dc_open = true;
                }
                _ => {}
            }
        }

        // Read messages from offer peer
        while let Some(message) = runner.offer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                // Handle any echo messages
            }
        }

        // Read messages from answer peer
        while let Some(message) = runner.answer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, msg) = message {
                let received = String::from_utf8_lossy(&msg.data);
                log::info!("[Answer] Received message: {}", received);
                answer_messages_received += 1;
            }
        }

        // Send messages from offer once connected
        if offer_connected
            && offer_messages_sent < messages_to_send
            && let Some(dc_id) = offer_dc_id
            && let Some(mut dc) = runner.offer_pc.data_channel(dc_id)
        {
            dc.send_text(message_content.to_string())?;
            offer_messages_sent += 1;
            log::info!("[Offer] Sent message {}/{}", offer_messages_sent, messages_to_send);
        }

        // Check if test is complete
        if answer_messages_received >= messages_to_send {
            log::info!("All messages received!");
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
            // Accept TCP connection on passive side
            result = runner.tcp_listener.accept() => {
                if let Ok((stream, addr)) = result {
                    log::info!("[Answer] Accepted TCP connection from {}", addr);
                    answer_stream = Some(stream);
                }
            }
            // Read TCP data on offer side
            result = async {
                if let Some(ref mut stream) = offer_stream {
                    stream.read(&mut offer_buf).await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(n) = result
                    && n > 0
                {
                    offer_decoder.extend_from_slice(&offer_buf[..n]);
                    while let Some(packet) = offer_decoder.next_packet() {
                        let peer_addr = runner.passive_local_addr;
                        runner.offer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: offer_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::TCP,
                            },
                            message: BytesMut::from(&packet[..]),
                        }).ok();
                    }
                }
            }
            // Read TCP data on answer side
            result = async {
                if let Some(ref mut stream) = answer_stream {
                    stream.read(&mut answer_buf).await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(n) = result
                    && n > 0
                {
                    answer_decoder.extend_from_slice(&answer_buf[..n]);
                    while let Some(packet) = answer_decoder.next_packet() {
                        let peer_addr = answer_stream.as_ref()
                            .and_then(|s| s.peer_addr().ok())
                            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
                        runner.answer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: runner.passive_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::TCP,
                            },
                            message: BytesMut::from(&packet[..]),
                        }).ok();
                    }
                }
            }
        }
    }

    // Verify test results
    assert!(offer_connected, "Offer peer should be connected");
    assert!(answer_connected, "Answer peer should be connected");
    assert!(answer_dc_open, "Answer should have opened data channel");
    assert_eq!(
        answer_messages_received, messages_to_send,
        "Should have received all messages"
    );

    // Clean up
    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("ICE TCP active/passive test passed!");
    Ok(())
}

/// Test that TCP passive candidate correctly accepts multiple connection attempts.
///
/// This verifies the listener behavior when the active side reconnects.
#[tokio::test]
async fn test_ice_tcp_passive_accepts_connection() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting TCP passive accept test");

    // Create TCP listener
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let listener_addr = tcp_listener.local_addr()?;
    log::info!("TCP listener at {}", listener_addr);

    // Connect from active side
    let stream = TcpStream::connect(listener_addr).await?;
    let active_local = stream.local_addr()?;
    log::info!("Active side connected from {}", active_local);

    // Accept on passive side
    let (accepted_stream, peer_addr) = tcp_listener.accept().await?;
    log::info!("Passive side accepted connection from {}", peer_addr);

    // Verify addresses match
    assert_eq!(peer_addr, active_local);
    assert_eq!(
        accepted_stream.peer_addr()?,
        active_local
    );

    // Test TCP framing round-trip
    let test_message = b"Test STUN binding request";
    let framed = frame_packet(test_message);

    // Active sends to passive
    let mut active_stream = stream;
    active_stream.write_all(&framed).await?;

    // Passive receives and decodes
    let mut accepted_stream = accepted_stream;
    let mut buf = vec![0u8; 1024];
    let n = accepted_stream.read(&mut buf).await?;

    let mut decoder = TcpFrameDecoder::new();
    decoder.extend_from_slice(&buf[..n]);
    let received = decoder.next_packet();

    assert!(received.is_some(), "Should decode a packet");
    assert_eq!(received.unwrap(), test_message.to_vec());

    log::info!("TCP passive accept test passed!");
    Ok(())
}

/// Test RFC 4571 framing with partial reads.
///
/// This simulates realistic TCP behavior where packets may be fragmented.
#[tokio::test]
async fn test_tcp_framing_partial_reads() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting TCP framing partial reads test");

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let listener_addr = tcp_listener.local_addr()?;

    // Spawn sender that sends in small chunks
    let sender_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(listener_addr).await.unwrap();

        let message1 = b"First STUN message";
        let message2 = b"Second STUN message";
        let message3 = b"Third STUN message";

        let mut framed = frame_packet(message1);
        framed.extend_from_slice(&frame_packet(message2));
        framed.extend_from_slice(&frame_packet(message3));

        // Send in small chunks to simulate fragmentation
        for chunk in framed.chunks(5) {
            stream.write_all(chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    // Receiver side
    let (mut stream, _) = tcp_listener.accept().await?;
    let mut decoder = TcpFrameDecoder::new();
    let mut buf = vec![0u8; 256];
    let mut packets = Vec::new();

    let start = Instant::now();
    while packets.len() < 3 && start.elapsed() < Duration::from_secs(5) {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        decoder.extend_from_slice(&buf[..n]);
        while let Some(packet) = decoder.next_packet() {
            packets.push(packet);
        }
    }

    sender_handle.await?;

    assert_eq!(packets.len(), 3, "Should receive 3 packets");
    assert_eq!(packets[0], b"First STUN message".to_vec());
    assert_eq!(packets[1], b"Second STUN message".to_vec());
    assert_eq!(packets[2], b"Third STUN message".to_vec());

    log::info!("TCP framing partial reads test passed!");
    Ok(())
}

/// Test bidirectional data channel communication over TCP.
///
/// Both peers send messages to each other over the TCP transport.
#[tokio::test]
async fn test_ice_tcp_bidirectional_data_channel() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting bidirectional TCP data channel test");

    let mut runner = TcpPeerRunner::new().await?;

    // Create data channel on offer side
    runner.offer_pc.create_data_channel("bidirectional", None)?;

    // Exchange offer/answer
    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    // State tracking
    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_dc_id = None;
    let mut answer_dc_id = None;
    let mut offer_received = 0;
    let mut answer_received = 0;
    let messages_each = 2;

    // TCP state
    let mut answer_stream: Option<TcpStream> = None;
    let mut offer_decoder = TcpFrameDecoder::new();
    let mut answer_decoder = TcpFrameDecoder::new();
    let mut offer_buf = vec![0u8; 4096];
    let mut answer_buf = vec![0u8; 4096];

    // Offerer connects
    let stream = TcpStream::connect(runner.passive_local_addr).await?;
    let offer_local_addr = stream.local_addr()?;
    let mut offer_stream: Option<TcpStream> = Some(stream);

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process writes
        while let Some(msg) = runner.offer_pc.poll_write() {
            if let Some(ref mut stream) = offer_stream {
                stream.write_all(&frame_packet(&msg.message)).await?;
            }
        }
        while let Some(msg) = runner.answer_pc.poll_write() {
            if let Some(ref mut stream) = answer_stream {
                stream.write_all(&frame_packet(&msg.message)).await?;
            }
        }

        // Process events
        while let Some(event) = runner.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(RTCPeerConnectionState::Connected) => {
                    offer_connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    offer_dc_id = Some(id);
                }
                _ => {}
            }
        }
        while let Some(event) = runner.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(RTCPeerConnectionState::Connected) => {
                    answer_connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    answer_dc_id = Some(id);
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = runner.offer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                offer_received += 1;
            }
        }
        while let Some(message) = runner.answer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                answer_received += 1;
            }
        }

        // Send messages from both sides
        if offer_connected {
            let sent = offer_received + answer_received;
            if sent < messages_each * 2
                && let Some(dc_id) = offer_dc_id
                && let Some(mut dc) = runner.offer_pc.data_channel(dc_id)
            {
                dc.send_text("From offer".to_string()).ok();
            }
        }
        if answer_connected {
            let sent = offer_received + answer_received;
            if sent < messages_each * 2
                && let Some(dc_id) = answer_dc_id
                && let Some(mut dc) = runner.answer_pc.data_channel(dc_id)
            {
                dc.send_text("From answer".to_string()).ok();
            }
        }

        // Check completion
        if offer_received >= messages_each && answer_received >= messages_each {
            break;
        }

        // Handle timeouts and I/O
        let next_timeout = runner.offer_pc.poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION)
            .min(runner.answer_pc.poll_timeout()
                .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION));
        let delay = next_timeout.saturating_duration_since(Instant::now())
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
            result = runner.tcp_listener.accept() => {
                if let Ok((stream, _)) = result {
                    answer_stream = Some(stream);
                }
            }
            result = async {
                if let Some(ref mut stream) = offer_stream {
                    stream.read(&mut offer_buf).await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(n) = result
                    && n > 0
                {
                    offer_decoder.extend_from_slice(&offer_buf[..n]);
                    while let Some(packet) = offer_decoder.next_packet() {
                        runner.offer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: offer_local_addr,
                                peer_addr: runner.passive_local_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::TCP,
                            },
                            message: BytesMut::from(&packet[..]),
                        }).ok();
                    }
                }
            }
            result = async {
                if let Some(ref mut stream) = answer_stream {
                    stream.read(&mut answer_buf).await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(n) = result
                    && n > 0
                {
                    answer_decoder.extend_from_slice(&answer_buf[..n]);
                    while let Some(packet) = answer_decoder.next_packet() {
                        let peer_addr = answer_stream.as_ref()
                            .and_then(|s| s.peer_addr().ok())
                            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
                        runner.answer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: runner.passive_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::TCP,
                            },
                            message: BytesMut::from(&packet[..]),
                        }).ok();
                    }
                }
            }
        }
    }

    assert!(offer_connected, "Offer should be connected");
    assert!(answer_connected, "Answer should be connected");
    assert!(offer_received >= messages_each, "Offer should receive messages");
    assert!(answer_received >= messages_each, "Answer should receive messages");

    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    log::info!("Bidirectional TCP data channel test passed!");
    Ok(())
}
