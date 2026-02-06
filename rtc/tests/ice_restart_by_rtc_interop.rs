/// Integration test for ICE restart initiated by rtc (sansio) when communicating with webrtc
///
/// This test verifies that the rtc library can successfully initiate ICE restart
/// when communicating with the webrtc library.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const TEST_MESSAGE: &str = "Hello before restart!";
const TEST_MESSAGE_AFTER_RESTART: &str = "Hello after restart!";

#[tokio::test]
async fn test_ice_restart_by_rtc_interop() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Starting ICE Restart Test (initiated by RTC) ===");

    // Create WebRTC peer
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let registry = Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let webrtc_pc = Arc::new(
        api.new_peer_connection(WebrtcRTCConfiguration {
            ice_servers: vec![WebrtcIceServer {
                ..Default::default()
            }],
            ..Default::default()
        })
        .await?,
    );

    let webrtc_connected = Arc::new(AtomicBool::new(false));
    let webrtc_message_received = Arc::new(Mutex::new(None::<String>));
    let webrtc_dc = Arc::new(Mutex::new(None));

    // Set up WebRTC connection state handler
    {
        let connected = Arc::clone(&webrtc_connected);
        webrtc_pc.on_peer_connection_state_change(Box::new(move |state| {
            log::info!("WebRTC peer connection state changed: {:?}", state);
            if state == WebrtcRTCPeerConnectionState::Connected {
                connected.store(true, Ordering::SeqCst);
            }
            Box::pin(async {})
        }));
    }

    // Set up WebRTC data channel handler
    {
        let dc = Arc::clone(&webrtc_dc);
        let msg = Arc::clone(&webrtc_message_received);

        webrtc_pc.on_data_channel(Box::new(move |d| {
            log::info!("WebRTC: Data channel opened: {}", d.label());
            let dc = Arc::clone(&dc);
            let msg = Arc::clone(&msg);

            tokio::spawn(async move {
                *dc.lock().await = Some(Arc::clone(&d));

                d.on_message(Box::new(move |data| {
                    let msg_text = String::from_utf8_lossy(&data.data).to_string();
                    log::info!("WebRTC: Received message: {}", msg_text);
                    let msg = Arc::clone(&msg);
                    tokio::spawn(async move {
                        *msg.lock().await = Some(msg_text);
                    });
                    Box::pin(async {})
                }));
            });

            Box::pin(async {})
        }));
    }

    // Create RTC peer in a separate thread with its own runtime
    enum Command {
        CreateOffer,
        SetRemoteDescription(String),
        SendMessage(String),
        RestartIce,
        Shutdown,
    }

    enum Response {
        Offer(String),
        Connected,
        DataChannelOpen,
        Error(String),
    }

    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<Command>(10);
    let (resp_tx, resp_rx) = mpsc::sync_channel::<Response>(10);

    let rtc_thread = std::thread::spawn(move || -> Result<()> {
        let rt = Runtime::new()?;
        let _guard = rt.enter();

        // Bind UDP socket
        let socket = rt.block_on(async {
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind socket")
        });
        let local_addr = socket.local_addr()?;
        log::info!("RTC bound to {}", local_addr);

        // Create RTC peer connection
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

        let config = RTCConfigurationBuilder::default()
            .with_ice_servers(vec![RTCIceServer {
                ..Default::default()
            }])
            .build();

        let mut rtc_pc = RTCPeerConnectionBuilder::new()
            .with_configuration(config)
            .with_setting_engine(setting_engine)
            .build()?;

        // Create data channel
        let _ = rtc_pc.create_data_channel("test", None)?;
        log::info!("RTC: Created data channel");

        let mut dc_id: Option<u16> = None;
        let mut buf = vec![0u8; 8192];
        let mut write_buf = BytesMut::new();

        loop {
            // Check for commands (non-blocking)
            match cmd_rx.try_recv() {
                Ok(Command::CreateOffer) => {
                    log::info!("RTC: Creating offer");
                    match rtc_pc.create_offer(None) {
                        Ok(offer) => {
                            if let Err(e) = rtc_pc.set_local_description(offer.clone()) {
                                resp_tx
                                    .send(Response::Error(format!(
                                        "Failed to set local description: {}",
                                        e
                                    )))
                                    .ok();
                                continue;
                            }

                            // Add local candidate
                            let candidate_config = CandidateHostConfig {
                                base_config: CandidateConfig {
                                    network: "udp".to_owned(),
                                    address: local_addr.ip().to_string(),
                                    port: local_addr.port(),
                                    component: 1,
                                    ..Default::default()
                                },
                                ..Default::default()
                            };

                            match candidate_config.new_candidate_host() {
                                Ok(candidate) => {
                                    let candidate_init =
                                        rtc::peer_connection::transport::RTCIceCandidate::from(
                                            &candidate,
                                        )
                                        .to_json()?;
                                    if let Err(e) = rtc_pc.add_local_candidate(candidate_init) {
                                        resp_tx
                                            .send(Response::Error(format!(
                                                "Failed to add local candidate: {}",
                                                e
                                            )))
                                            .ok();
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    resp_tx
                                        .send(Response::Error(format!(
                                            "Failed to create candidate: {}",
                                            e
                                        )))
                                        .ok();
                                    continue;
                                }
                            }

                            let offer_with_candidate = rtc_pc
                                .local_description()
                                .expect("local description should be set");
                            resp_tx
                                .send(Response::Offer(offer_with_candidate.sdp.clone()))
                                .ok();
                        }
                        Err(e) => {
                            resp_tx
                                .send(Response::Error(format!("Failed to create offer: {}", e)))
                                .ok();
                        }
                    }
                }
                Ok(Command::SetRemoteDescription(sdp)) => {
                    log::info!("RTC: Setting remote description");
                    let answer = rtc::peer_connection::sdp::RTCSessionDescription::answer(sdp)?;
                    if let Err(e) = rtc_pc.set_remote_description(answer) {
                        resp_tx
                            .send(Response::Error(format!(
                                "Failed to set remote description: {}",
                                e
                            )))
                            .ok();
                    }
                }
                Ok(Command::SendMessage(msg)) => {
                    log::info!("RTC: Sending message: {}", msg);
                    if let Some(channel_id) = dc_id {
                        if let Some(mut dc) = rtc_pc.data_channel(channel_id) {
                            if let Err(e) = dc.send_text(msg) {
                                resp_tx
                                    .send(Response::Error(format!("Failed to send message: {}", e)))
                                    .ok();
                            }
                        }
                    }
                }
                Ok(Command::RestartIce) => {
                    log::info!("RTC: Restarting ICE");

                    // Get ICE credentials from current local description before restart
                    let (old_ufrag, old_pwd): (Option<String>, Option<String>) =
                        if let Some(desc) = rtc_pc.local_description() {
                            match desc.unmarshal() {
                                Ok(parsed) => {
                                    let ufrag: Option<String> = parsed
                                        .media_descriptions
                                        .first()
                                        .and_then(|m| m.attribute("ice-ufrag"))
                                        .flatten()
                                        .map(|s| s.to_string());
                                    let pwd: Option<String> = parsed
                                        .media_descriptions
                                        .first()
                                        .and_then(|m| m.attribute("ice-pwd"))
                                        .flatten()
                                        .map(|s| s.to_string());
                                    (ufrag, pwd)
                                }
                                Err(e) => {
                                    log::warn!("Failed to parse local description: {}", e);
                                    (None, None)
                                }
                            }
                        } else {
                            (None, None)
                        };

                    // The restart_ice method tells the RTCPeerConnection that ICE should be restarted.
                    // Subsequent calls to create_offer will create descriptions that will restart ICE,
                    // event create_offer doesn't have option to pass
                    rtc_pc.restart_ice();

                    // Create new offer after restart
                    match rtc_pc.create_offer(None) {
                        Ok(offer) => {
                            // Verify ICE credentials changed in the new offer
                            let parsed = match offer.unmarshal() {
                                Ok(sd) => sd,
                                Err(e) => {
                                    resp_tx
                                        .send(Response::Error(format!(
                                            "Failed to parse offer: {}",
                                            e
                                        )))
                                        .ok();
                                    continue;
                                }
                            };
                            let new_ufrag = parsed
                                .media_descriptions
                                .first()
                                .and_then(|m| m.attribute("ice-ufrag"))
                                .flatten()
                                .map(|s| s.to_string());
                            let new_pwd = parsed
                                .media_descriptions
                                .first()
                                .and_then(|m| m.attribute("ice-pwd"))
                                .flatten()
                                .map(|s| s.to_string());

                            if old_ufrag.is_some() && new_ufrag.is_some() && old_ufrag == new_ufrag
                            {
                                resp_tx
                                    .send(Response::Error(
                                        "ICE ufrag did not change after restart_ice".to_string(),
                                    ))
                                    .ok();
                                continue;
                            }
                            if old_pwd.is_some() && new_pwd.is_some() && old_pwd == new_pwd {
                                resp_tx
                                    .send(Response::Error(
                                        "ICE pwd did not change after restart_ice".to_string(),
                                    ))
                                    .ok();
                                continue;
                            }

                            log::info!(
                                "RTC: ICE credentials changed: ufrag {:?} -> {:?}, pwd {:?} -> {:?}",
                                old_ufrag,
                                new_ufrag,
                                old_pwd,
                                new_pwd
                            );

                            if let Err(e) = rtc_pc.set_local_description(offer.clone()) {
                                resp_tx
                                    .send(Response::Error(format!(
                                        "Failed to set local description: {}",
                                        e
                                    )))
                                    .ok();
                                continue;
                            }

                            // Add local candidate
                            let candidate_config = CandidateHostConfig {
                                base_config: CandidateConfig {
                                    network: "udp".to_owned(),
                                    address: local_addr.ip().to_string(),
                                    port: local_addr.port(),
                                    component: 1,
                                    ..Default::default()
                                },
                                ..Default::default()
                            };

                            match candidate_config.new_candidate_host() {
                                Ok(candidate) => {
                                    let candidate_init =
                                        rtc::peer_connection::transport::RTCIceCandidate::from(
                                            &candidate,
                                        )
                                        .to_json()?;
                                    if let Err(e) = rtc_pc.add_local_candidate(candidate_init) {
                                        resp_tx
                                            .send(Response::Error(format!(
                                                "Failed to add local candidate: {}",
                                                e
                                            )))
                                            .ok();
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    resp_tx
                                        .send(Response::Error(format!(
                                            "Failed to create candidate: {}",
                                            e
                                        )))
                                        .ok();
                                    continue;
                                }
                            }

                            let offer_with_candidate = rtc_pc
                                .local_description()
                                .expect("local description should be set");
                            resp_tx
                                .send(Response::Offer(offer_with_candidate.sdp.clone()))
                                .ok();
                        }
                        Err(e) => {
                            resp_tx
                                .send(Response::Error(format!(
                                    "Failed to create offer after restart: {}",
                                    e
                                )))
                                .ok();
                        }
                    }
                }
                Ok(Command::Shutdown) => {
                    log::info!("RTC: Shutting down");
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => break,
            }

            // Poll for writes
            while let Some(transmit) = rtc_pc.poll_write() {
                write_buf.clear();
                write_buf.extend_from_slice(&transmit.message);

                rt.block_on(async {
                    if let Err(e) = socket
                        .send_to(&write_buf, transmit.transport.peer_addr)
                        .await
                    {
                        log::info!("Socket write error: {}", e);
                    }
                });
            }

            // Poll for events
            while let Some(event) = rtc_pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        log::info!("RTC peer connection state changed: {:?}", state);
                        if state == RTCPeerConnectionState::Connected {
                            resp_tx.send(Response::Connected).ok();
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(dc_event) => match dc_event {
                        RTCDataChannelEvent::OnOpen(data_channel_id) => {
                            log::info!("RTC: Data channel {} opened", data_channel_id);
                            dc_id = Some(data_channel_id);
                            resp_tx.send(Response::DataChannelOpen).ok();
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            // Try to receive data with timeout
            let recv_result = rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(10), socket.recv_from(&mut buf)).await
            });

            match recv_result {
                Ok(Ok((n, peer_addr))) => {
                    rtc_pc
                        .handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        })
                        .ok();
                }
                Ok(Err(e)) => {
                    log::info!("Socket read error: {}", e);
                }
                Err(_) => {
                    // Timeout - handle timeout
                    rtc_pc.handle_timeout(Instant::now()).ok();
                }
            }
        }

        Ok(())
    });

    // Create initial offer from RTC
    cmd_tx.send(Command::CreateOffer)?;
    let offer_sdp = match resp_rx.recv_timeout(Duration::from_secs(5))? {
        Response::Offer(sdp) => sdp,
        Response::Error(e) => anyhow::bail!("Failed to create offer: {}", e),
        _ => anyhow::bail!("Unexpected response"),
    };
    log::info!("RTC: Offer created");

    // Set offer on WebRTC peer
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer_sdp)?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    log::info!("WebRTC: Set remote description (offer)");

    // Create answer
    let webrtc_answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc
        .set_local_description(webrtc_answer.clone())
        .await?;
    log::info!("WebRTC: Created and set answer");

    // Wait for ICE gathering to complete
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    log::info!("WebRTC: Answer with candidates ready");

    // Set answer on RTC peer
    cmd_tx.send(Command::SetRemoteDescription(
        answer_with_candidates.sdp.clone(),
    ))?;

    // Wait for initial connection and data channels
    log::info!("Waiting for initial connection...");
    let deadline = Instant::now() + DEFAULT_TIMEOUT_DURATION;
    let mut rtc_connected = false;
    let mut rtc_dc_open = false;
    loop {
        // Check for RTC connection events
        while let Ok(resp) = resp_rx.try_recv() {
            match resp {
                Response::Connected => rtc_connected = true,
                Response::DataChannelOpen => rtc_dc_open = true,
                Response::Error(e) => log::warn!("RTC error: {}", e),
                _ => {}
            }
        }

        if rtc_connected
            && webrtc_connected.load(Ordering::SeqCst)
            && rtc_dc_open
            && webrtc_dc.lock().await.is_some()
        {
            log::info!("Initial connection and data channels established!");
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("Timeout waiting for initial connection and data channels");
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Send initial message
    log::info!("Sending initial message...");
    cmd_tx.send(Command::SendMessage(TEST_MESSAGE.to_string()))?;

    // Wait for message to be received
    let deadline = Instant::now() + DEFAULT_TIMEOUT_DURATION;
    loop {
        if let Some(msg) = webrtc_message_received.lock().await.as_ref() {
            if msg == TEST_MESSAGE {
                log::info!("Initial message received: {}", msg);
                break;
            }
        }
        if Instant::now() > deadline {
            anyhow::bail!("Timeout waiting for initial message");
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Now initiate ICE restart from RTC peer
    log::info!("=== Initiating ICE restart from RTC peer ===");

    // Reset flags
    webrtc_connected.store(false, Ordering::SeqCst);
    *webrtc_message_received.lock().await = None;

    // Send restart command
    cmd_tx.send(Command::RestartIce)?;

    // Wait for new offer
    let restart_offer_sdp = match resp_rx.recv_timeout(Duration::from_secs(5))? {
        Response::Offer(sdp) => sdp,
        Response::Error(e) => anyhow::bail!("Failed to create restart offer: {}", e),
        _ => anyhow::bail!("Unexpected response"),
    };
    log::info!("RTC: Restart offer created");

    // Set the new offer on WebRTC peer
    let webrtc_restart_offer = WebrtcRTCSessionDescription::offer(restart_offer_sdp)?;
    webrtc_pc
        .set_remote_description(webrtc_restart_offer)
        .await?;
    log::info!("WebRTC: Set remote description (restart offer)");

    // Create new answer
    let webrtc_restart_answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc
        .set_local_description(webrtc_restart_answer.clone())
        .await?;
    log::info!("WebRTC: Created and set answer for ICE restart");

    // Wait for ICE gathering to complete
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let restart_answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    log::info!("WebRTC: Restart answer with candidates ready");

    // Set the new answer on RTC peer
    cmd_tx.send(Command::SetRemoteDescription(
        restart_answer_with_candidates.sdp.clone(),
    ))?;

    // Wait for reconnection
    log::info!("Waiting for reconnection after ICE restart...");
    let deadline = Instant::now() + DEFAULT_TIMEOUT_DURATION;
    let mut rtc_reconnected = false;
    loop {
        while let Ok(resp) = resp_rx.try_recv() {
            match resp {
                Response::Connected => rtc_reconnected = true,
                Response::Error(e) => log::warn!("RTC error: {}", e),
                _ => {}
            }
        }

        if rtc_reconnected && webrtc_connected.load(Ordering::SeqCst) {
            log::info!("Reconnection established after ICE restart!");
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("Timeout waiting for reconnection after ICE restart");
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Send message after restart
    log::info!("Sending message after ICE restart...");
    cmd_tx.send(Command::SendMessage(TEST_MESSAGE_AFTER_RESTART.to_string()))?;

    // Wait for message to be received
    let deadline = Instant::now() + DEFAULT_TIMEOUT_DURATION;
    loop {
        if let Some(msg) = webrtc_message_received.lock().await.as_ref() {
            if msg == TEST_MESSAGE_AFTER_RESTART {
                log::info!("Message received after ICE restart: {}", msg);
                break;
            }
        }
        if Instant::now() > deadline {
            anyhow::bail!("Timeout waiting for message after ICE restart");
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Cleanup
    cmd_tx.send(Command::Shutdown)?;
    rtc_thread.join().expect("RTC thread panicked")?;
    webrtc_pc.close().await?;

    log::info!("=== ICE Restart Test (initiated by RTC) Completed Successfully ===");
    Ok(())
}
