//! Integration tests for mDNS query and gather interop between sansio RTC and webrtc.
//!
//! These tests verify that the sansio RTC implementation correctly handles mDNS
//! (Multicast DNS) for ICE candidate resolution in both QueryOnly and QueryAndGather modes.
//!
//! Test matrix (webrtc always uses QueryAndGather mode):
//! 1. webrtc (offerer, QueryAndGather) + sansio RTC (answerer, QueryOnly)
//! 2. webrtc (offerer, QueryAndGather) + sansio RTC (answerer, QueryAndGather)
//! 3. sansio RTC (offerer, QueryOnly) + webrtc (answerer, QueryAndGather)
//! 4. sansio RTC (offerer, QueryAndGather) + webrtc (answerer, QueryAndGather)

use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use rtc::ice::mdns::MulticastDnsMode;
use rtc::mdns::{MDNS_PORT, MulticastSocket};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig};
use rtc::peer_connection::{RTCPeerConnection as RtcPeerConnection, RTCPeerConnectionBuilder};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine as WebrtcSettingEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice::mdns::MulticastDnsMode as WebrtcMulticastDnsMode;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const MDNS_LOCAL_NAME: &str = "webrtc-rs-test-mdns.local";
const WEBRTC_MDNS_LOCAL_NAME: &str = "webrtc-peer-mdns.local";

/// Helper function to create a webrtc peer connection with QueryAndGather mDNS mode
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    // Configure mDNS QueryAndGather mode
    let mut setting_engine = WebrtcSettingEngine::default();
    setting_engine.set_ice_multicast_dns_mode(WebrtcMulticastDnsMode::QueryAndGather);
    setting_engine.set_multicast_dns_host_name(WEBRTC_MDNS_LOCAL_NAME.to_string());

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting_engine)
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

/// Helper to create sansio RTC peer with mDNS configuration
fn create_rtc_peer_with_mdns(
    local_addr: std::net::SocketAddr,
    mdns_mode: MulticastDnsMode,
    is_answerer: bool,
) -> Result<RtcPeerConnection> {
    let mut setting_engine = SettingEngine::default();

    if is_answerer {
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;
    } else {
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;
    }

    // Configure mDNS
    setting_engine.set_multicast_dns_timeout(Some(Duration::from_secs(10)));
    setting_engine.set_multicast_dns_mode(mdns_mode);

    if mdns_mode == MulticastDnsMode::QueryAndGather {
        // In QueryAndGather mode, hide the local IP behind mDNS name
        setting_engine.set_multicast_dns_local_name(MDNS_LOCAL_NAME.to_string());
        setting_engine.set_multicast_dns_local_ip(Some(local_addr.ip()));
    }

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .build()?)
}

/// Run the RTC event loop with mDNS support
async fn run_rtc_event_loop(
    rtc_pc: &mut RtcPeerConnection,
    pc_socket: &UdpSocket,
    mdns_socket: &UdpSocket,
    local_addr: std::net::SocketAddr,
    rtc_received_messages: &Arc<Mutex<Vec<String>>>,
    echo_messages: bool,
) -> Result<(bool, bool, Option<u16>)> {
    let mut pc_buf = vec![0u8; 2000];
    let mut mdns_buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut data_channel_opened = false;
    let mut data_channel_id: Option<u16> = None;

    // Process writes - route to appropriate socket based on port
    while let Some(msg) = rtc_pc.poll_write() {
        if msg.transport.peer_addr.port() == MDNS_PORT {
            match mdns_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("mDNS sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("mDNS socket write error: {}", err);
                }
            }
        } else {
            match pc_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(n) => {
                    log::trace!("RTC sent {} bytes to {}", n, msg.transport.peer_addr);
                }
                Err(err) => {
                    log::error!("RTC socket write error: {}", err);
                }
            }
        }
    }

    // Process events
    while let Some(event) = rtc_pc.poll_event() {
        match event {
            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                log::info!("RTC ICE connection state: {}", state);
                if state == RTCIceConnectionState::Failed {
                    return Err(anyhow::anyhow!("RTC ICE connection failed"));
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
                if let RTCDataChannelEvent::OnOpen(channel_id) = dc_event {
                    let dc = rtc_pc
                        .data_channel(channel_id)
                        .expect("data channel should exist");
                    log::info!(
                        "RTC data channel opened: {} (id: {})",
                        dc.label(),
                        channel_id
                    );
                    data_channel_opened = true;
                    data_channel_id = Some(channel_id);
                }
            }
            _ => {}
        }
    }

    // Process reads
    while let Some(message) = rtc_pc.poll_read() {
        if let RTCMessage::DataChannelMessage(channel_id, data_channel_message) = message {
            let msg_str = String::from_utf8(data_channel_message.data.to_vec())?;
            log::info!(
                "RTC received message on channel {}: '{}'",
                channel_id,
                msg_str
            );

            {
                let mut rtc_msgs = rtc_received_messages.lock().await;
                rtc_msgs.push(msg_str.clone());
            }

            if echo_messages && let Some(mut dc) = rtc_pc.data_channel(channel_id) {
                log::info!("RTC echoing message back: '{}'", msg_str);
                dc.send_text(msg_str)?;
            }
        }
    }

    // Handle timeout
    let eto = rtc_pc
        .poll_timeout()
        .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

    let delay_from_now = eto
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::from_secs(0));

    if delay_from_now.is_zero() {
        rtc_pc.handle_timeout(Instant::now())?;
    } else {
        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = pc_socket.recv_from(&mut pc_buf) => {
                if let Ok((n, peer_addr)) = res {
                    log::trace!("RTC received {} bytes from {}", n, peer_addr);
                    rtc_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&pc_buf[..n]),
                    })?;
                }
            }
            res = mdns_socket.recv_from(&mut mdns_buf) => {
                if let Ok((n, peer_addr)) = res {
                    log::trace!("mDNS received {} bytes from {}", n, peer_addr);
                    rtc_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: mdns_socket.local_addr()?,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&mdns_buf[..n]),
                    })?;
                }
            }
        }
    }

    Ok((rtc_connected, data_channel_opened, data_channel_id))
}

// =============================================================================
// Test 1: webrtc (offerer) + sansio RTC (answerer) with QueryOnly mode
// =============================================================================

/// Test mDNS QueryOnly mode: webrtc as offerer, sansio RTC as answerer
///
/// In QueryOnly mode, the RTC peer only queries for mDNS names but doesn't
/// advertise its own IP via mDNS.
#[tokio::test]
async fn test_mdns_query_only_webrtc_offerer_rtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting mDNS QueryOnly test: webrtc (offerer) -> sansio RTC (answerer)");

    // Create webrtc peer (offerer)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Track received messages
    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Create data channel on webrtc side
    let dc_label = "mdns-query-only-test";
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

    // Create offer from webrtc
    let offer = webrtc_pc.create_offer(None).await?;
    webrtc_pc.set_local_description(offer.clone()).await?;

    // Wait for ICE gathering
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let offer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");

    // Convert to RTC SDP
    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;

    // Create RTC peer (answerer) with QueryOnly mode
    let pc_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = pc_socket.local_addr()?;
    let mdns_socket = UdpSocket::from_std(MulticastSocket::new().into_std()?)?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut rtc_pc = create_rtc_peer_with_mdns(local_addr, MulticastDnsMode::QueryOnly, true)?;
    log::info!("Created RTC peer with QueryOnly mDNS mode");

    // Set remote description
    rtc_pc.set_remote_description(rtc_offer)?;

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
    let local_candidate_init =
        rtc::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create answer
    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(answer.clone())?;

    // Set answer on webrtc
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    // Run event loops
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut message_sent = false;
    let mut data_channel_opened = false;
    let test_message = "Hello via mDNS QueryOnly!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        let (connected, dc_open, _) = run_rtc_event_loop(
            &mut rtc_pc,
            &pc_socket,
            &mdns_socket,
            local_addr,
            &rtc_received_messages,
            true, // echo messages
        )
        .await?;

        if connected {
            rtc_connected = true;
        }
        if dc_open {
            data_channel_opened = true;
        }

        if webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected {
            webrtc_connected = true;
        }

        if rtc_connected && webrtc_connected && data_channel_opened && !message_sent {
            tokio::time::sleep(Duration::from_millis(500)).await;
            log::info!("Sending message from WebRTC: '{}'", test_message);
            webrtc_dc.send_text(test_message).await?;
            message_sent = true;
        }

        if message_sent {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message)
                && webrtc_msgs.iter().any(|m| m == test_message)
            {
                log::info!("Test passed: mDNS QueryOnly mode working correctly");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!("Test timeout"))
}

// =============================================================================
// Test 2: webrtc (offerer) + sansio RTC (answerer) with QueryAndGather mode
// =============================================================================

/// Test mDNS QueryAndGather mode: webrtc as offerer, sansio RTC as answerer
///
/// In QueryAndGather mode, the RTC peer both queries for mDNS names AND
/// advertises its own IP via an mDNS name.
#[tokio::test]
async fn test_mdns_query_and_gather_webrtc_offerer_rtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting mDNS QueryAndGather test: webrtc (offerer) -> sansio RTC (answerer)");

    // Create webrtc peer (offerer)
    let webrtc_pc = create_webrtc_peer().await?;

    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    let dc_label = "mdns-query-gather-test";
    let webrtc_dc = webrtc_pc
        .create_data_channel(
            dc_label,
            Some(RTCDataChannelInit {
                ordered: Some(true),
                ..Default::default()
            }),
        )
        .await?;

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

    let offer = webrtc_pc.create_offer(None).await?;
    webrtc_pc.set_local_description(offer.clone()).await?;

    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let offer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");

    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;

    // Create RTC peer with QueryAndGather mode
    let pc_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = pc_socket.local_addr()?;
    let mdns_socket = UdpSocket::from_std(MulticastSocket::new().into_std()?)?;

    let mut rtc_pc = create_rtc_peer_with_mdns(local_addr, MulticastDnsMode::QueryAndGather, true)?;
    log::info!(
        "Created RTC peer with QueryAndGather mDNS mode, local name: {}",
        MDNS_LOCAL_NAME
    );

    rtc_pc.set_remote_description(rtc_offer)?;

    // Add local candidate (in QueryAndGather mode, the IP will be hidden behind mDNS name)
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

    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(answer.clone())?;

    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut message_sent = false;
    let mut data_channel_opened = false;
    let test_message = "Hello via mDNS QueryAndGather!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        let (connected, dc_open, _) = run_rtc_event_loop(
            &mut rtc_pc,
            &pc_socket,
            &mdns_socket,
            local_addr,
            &rtc_received_messages,
            true,
        )
        .await?;

        if connected {
            rtc_connected = true;
        }
        if dc_open {
            data_channel_opened = true;
        }

        if webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected {
            webrtc_connected = true;
        }

        if rtc_connected && webrtc_connected && data_channel_opened && !message_sent {
            tokio::time::sleep(Duration::from_millis(500)).await;
            log::info!("Sending message from WebRTC: '{}'", test_message);
            webrtc_dc.send_text(test_message).await?;
            message_sent = true;
        }

        if message_sent {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message)
                && webrtc_msgs.iter().any(|m| m == test_message)
            {
                log::info!("Test passed: mDNS QueryAndGather mode working correctly");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!("Test timeout"))
}

// =============================================================================
// Test 3: sansio RTC (offerer) with QueryOnly mode + webrtc (answerer)
// =============================================================================

/// Test mDNS QueryOnly mode: sansio RTC as offerer, webrtc as answerer
#[tokio::test]
async fn test_mdns_query_only_rtc_offerer_webrtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting mDNS QueryOnly test: sansio RTC (offerer) -> webrtc (answerer)");

    // Create RTC peer (offerer) with QueryOnly mode
    let pc_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = pc_socket.local_addr()?;
    let mdns_socket = UdpSocket::from_std(MulticastSocket::new().into_std()?)?;

    let mut rtc_pc = create_rtc_peer_with_mdns(local_addr, MulticastDnsMode::QueryOnly, false)?;
    log::info!("Created RTC peer (offerer) with QueryOnly mDNS mode");

    // Create data channel on RTC side
    let dc_label = "rtc-offerer-query-only";
    rtc_pc.create_data_channel(dc_label, None)?;
    log::info!("Created RTC data channel: {}", dc_label);

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
    let local_candidate_init =
        rtc::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create offer
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;

    // Create webrtc peer (answerer)
    let webrtc_pc = create_webrtc_peer().await?;

    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    // Set up webrtc to handle incoming data channel
    let webrtc_dc_handle = Arc::new(Mutex::new(None));
    let webrtc_dc_handle_clone = Arc::clone(&webrtc_dc_handle);

    webrtc_pc.on_data_channel(Box::new(move |dc| {
        let handle = Arc::clone(&webrtc_dc_handle_clone);
        let messages = Arc::clone(&webrtc_received_messages_clone);

        Box::pin(async move {
            log::info!("WebRTC received data channel: {}", dc.label());

            let dc_clone = Arc::clone(&dc);
            dc.on_open(Box::new(move || {
                log::info!("WebRTC data channel opened");
                let dc_inner = Arc::clone(&dc_clone);
                Box::pin(async move {
                    // Send a message once open
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let msg = "Hello from WebRTC answerer!";
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

            let mut h = handle.lock().await;
            *h = Some(dc);
        })
    }));

    // Convert and set offer on webrtc
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;

    // Create answer from webrtc
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

    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut data_channel_opened = false;
    let test_message = "Hello from WebRTC answerer!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        let (connected, dc_open, dc_id) = run_rtc_event_loop(
            &mut rtc_pc,
            &pc_socket,
            &mdns_socket,
            local_addr,
            &rtc_received_messages,
            false, // don't echo, we're checking for message from webrtc
        )
        .await?;

        if connected {
            rtc_connected = true;
        }
        if dc_open {
            data_channel_opened = true;

            // Send message from RTC once data channel is open
            if let Some(id) = dc_id
                && let Some(mut dc) = rtc_pc.data_channel(id)
            {
                let msg = "Hello from RTC offerer!";
                log::info!("RTC sending: '{}'", msg);
                dc.send_text(msg.to_string()).ok();
            }
        }

        if webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected {
            webrtc_connected = true;
        }

        if rtc_connected && webrtc_connected && data_channel_opened {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message)
                && webrtc_msgs.iter().any(|m| m == "Hello from RTC offerer!")
            {
                log::info!("Test passed: RTC offerer with QueryOnly mode working correctly");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!("Test timeout"))
}

// =============================================================================
// Test 4: sansio RTC (offerer) with QueryAndGather mode + webrtc (answerer)
// =============================================================================

/// Test mDNS QueryAndGather mode: sansio RTC as offerer, webrtc as answerer
#[tokio::test]
async fn test_mdns_query_and_gather_rtc_offerer_webrtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting mDNS QueryAndGather test: sansio RTC (offerer) -> webrtc (answerer)");

    // Create RTC peer (offerer) with QueryAndGather mode
    let pc_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = pc_socket.local_addr()?;
    let mdns_socket = UdpSocket::from_std(MulticastSocket::new().into_std()?)?;

    let mut rtc_pc =
        create_rtc_peer_with_mdns(local_addr, MulticastDnsMode::QueryAndGather, false)?;
    log::info!(
        "Created RTC peer (offerer) with QueryAndGather mDNS mode, local name: {}",
        MDNS_LOCAL_NAME
    );

    // Create data channel
    let dc_label = "rtc-offerer-query-gather";
    rtc_pc.create_data_channel(dc_label, None)?;

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
    let local_candidate_init =
        rtc::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create offer
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(offer.clone())?;

    // Create webrtc peer (answerer)
    let webrtc_pc = create_webrtc_peer().await?;

    let webrtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let webrtc_received_messages_clone = Arc::clone(&webrtc_received_messages);
    let rtc_received_messages = Arc::new(Mutex::new(Vec::<String>::new()));

    let webrtc_dc_handle = Arc::new(Mutex::new(None));
    let webrtc_dc_handle_clone = Arc::clone(&webrtc_dc_handle);

    webrtc_pc.on_data_channel(Box::new(move |dc| {
        let handle = Arc::clone(&webrtc_dc_handle_clone);
        let messages = Arc::clone(&webrtc_received_messages_clone);

        Box::pin(async move {
            log::info!("WebRTC received data channel: {}", dc.label());

            let dc_clone = Arc::clone(&dc);
            dc.on_open(Box::new(move || {
                log::info!("WebRTC data channel opened");
                let dc_inner = Arc::clone(&dc_clone);
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let msg = "Hello from WebRTC answerer (QueryAndGather)!";
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

            let mut h = handle.lock().await;
            *h = Some(dc);
        })
    }));

    // Set offer on webrtc
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;

    // Create answer
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
    rtc_pc.set_remote_description(rtc_answer)?;

    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut data_channel_opened = false;
    let test_message = "Hello from WebRTC answerer (QueryAndGather)!";

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        let (connected, dc_open, dc_id) = run_rtc_event_loop(
            &mut rtc_pc,
            &pc_socket,
            &mdns_socket,
            local_addr,
            &rtc_received_messages,
            false,
        )
        .await?;

        if connected {
            rtc_connected = true;
        }
        if dc_open {
            data_channel_opened = true;

            if let Some(id) = dc_id
                && let Some(mut dc) = rtc_pc.data_channel(id)
            {
                let msg = "Hello from RTC offerer (QueryAndGather)!";
                log::info!("RTC sending: '{}'", msg);
                dc.send_text(msg.to_string()).ok();
            }
        }

        if webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected {
            webrtc_connected = true;
        }

        if rtc_connected && webrtc_connected && data_channel_opened {
            let rtc_msgs = rtc_received_messages.lock().await;
            let webrtc_msgs = webrtc_received_messages.lock().await;

            if rtc_msgs.iter().any(|m| m == test_message)
                && webrtc_msgs
                    .iter()
                    .any(|m| m == "Hello from RTC offerer (QueryAndGather)!")
            {
                log::info!("Test passed: RTC offerer with QueryAndGather mode working correctly");
                webrtc_pc.close().await?;
                rtc_pc.close()?;
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!("Test timeout"))
}
