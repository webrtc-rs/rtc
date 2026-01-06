/// Integration test for webrtc-to-rtc interop (RTP packet reception)
///
/// This test verifies that the rtc library (sans-I/O) can receive RTP packets
/// from webrtc v0.14.0 and properly handle them through the event loop pattern.
///
/// Test flow:
/// 1. webrtc peer creates offer with video track
/// 2. rtc peer creates answer and adds local ICE candidate
/// 3. Both peers exchange SDP and establish ICE/DTLS connection
/// 4. After 3-second stabilization delay, webrtc sends 50 RTP packets
/// 5. rtc receives all packets via poll_read() and tracks them by SSRC
/// 6. Test verifies at least 10 packets received (expects 50)
///
/// This demonstrates the core interop capability but does not test true
/// simulcast with multiple RID-based encodings, which requires additional
/// SDP manipulation and RTP header extension configuration in webrtc v0.14.0.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc::channel};
use tokio::time::timeout;

use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpHeaderExtensionCapability, RtpCodecKind,
};
use rtc::shared::error::Error;

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::{
    RTCRtpCodecCapability, RTCRtpCodecParameters as WebrtcRtpCodecParameters, RTPCodecType,
};
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Integration test for multi-track video streaming (webrtc → rtc)
///
/// This test demonstrates rtc (sans-I/O) receiving RTP packets from multiple
/// concurrent webrtc v0.14.0 video tracks, which simulates simulcast infrastructure.
///
/// **What this test demonstrates:**
/// - ✅ 3 concurrent video tracks with unique SSRCs
/// - ✅ rtc receiving and demultiplexing multiple RTP streams simultaneously
/// - ✅ RTP header extension negotiation infrastructure
/// - ✅ Each track tracked independently by SSRC
///
/// **Note on TRUE simulcast with RID:**
/// This test creates 3 SEPARATE tracks (3 m-lines in SDP), not true simulcast  
/// (1 m-line with `a=simulcast` and `a=rid` attributes). webrtc v0.14.0's  
/// `add_track()` API doesn't support creating true simulcast SDP. True RID-based
/// simulcast requires either:
/// - Manual SDP manipulation to add `a=simulcast:send low;mid;high` and `a=rid` lines
/// - Using a real browser as sender (browsers handle simulcast SDP correctly)
/// - The `/examples/simulcast/` example shows rtc receiving from browser with RIDs
///
/// This test validates the **infrastructure** needed for simulcast (multiple streams,
/// header extensions, concurrent reception) even though RIDs aren't signaled in SDP.
///
/// Test flow:
/// 1. webrtc creates 3 TrackLocalStaticSample with RID metadata ("low"/"mid"/"high")
/// 2. Each track added separately, creating 3 m-lines in SDP (not true simulcast)
/// 3. Each track sends 30 media samples with unique SSRC
/// 4. rtc receives all 90 packets and tracks by SSRC (no RID in SDP)
/// 5. Test verifies 3 distinct SSRCs received with expected packet counts

//TODO: make it TRUE simulcast with RID
#[tokio::test]
#[ignore]
async fn test_simulcast_webrtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting simulcast interop test: webrtc (sender) -> rtc (receiver)");

    // Track received packets by RID for true simulcast
    let packets_received = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let packets_received_clone = Arc::clone(&packets_received);

    // Create webrtc peer (will be the offerer and sender)
    let webrtc_pc = create_webrtc_peer_with_simulcast().await?;
    log::info!("Created webrtc peer connection with simulcast support");

    // Create 3 video tracks with different RIDs for simulcast layers
    let track_low = Arc::new(TrackLocalStaticSample::new_with_rid(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video_low".to_owned(),
        "low".to_owned(),
        "webrtc_stream".to_owned(),
    ));

    let track_mid = Arc::new(TrackLocalStaticSample::new_with_rid(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video_mid".to_owned(),
        "mid".to_owned(),
        "webrtc_stream".to_owned(),
    ));

    let track_high = Arc::new(TrackLocalStaticSample::new_with_rid(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video_high".to_owned(),
        "high".to_owned(),
        "webrtc_stream".to_owned(),
    ));

    // Add all 3 tracks to webrtc peer for simulcast
    let _rtp_sender_low = webrtc_pc
        .add_track(track_low.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added track with RID: low");

    let _rtp_sender_mid = webrtc_pc
        .add_track(track_mid.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added track with RID: mid");

    let _rtp_sender_high = webrtc_pc
        .add_track(track_high.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added track with RID: high");

    // Note: webrtc will automatically add RID header extensions to packets
    log::info!("Configured webrtc sender with 3 simulcast layers (low/mid/high)");

    // Create offer from webrtc side
    let offer = webrtc_pc.create_offer(None).await?;
    log::info!("WebRTC created offer with simulcast");

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
    log::debug!("Offer SDP:\n{}", offer_with_candidates.sdp);

    // Convert webrtc SDP to rtc SDP
    let rtc_offer =
        rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_with_candidates.sdp.clone())?;

    // Create rtc peer (will be the answerer and receiver)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

    // Create a MediaEngine object to configure the supported codec
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

    // Enable Extension Headers needed for Simulcast
    for extension in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: extension.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Set the remote description (offer from webrtc)
    log::info!("RTC set remote description offer {}", rtc_offer);
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
    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;
    log::info!("RTC added local candidate");

    // Create an answer
    let answer = rtc_pc.create_answer(None)?;
    log::info!("RTC created answer {}", answer);

    // Set the local description
    rtc_pc.set_local_description(answer)?;

    // Get the answer to send back to webrtc
    let rtc_answer = rtc_pc
        .local_description()
        .expect("local description should be set");
    log::info!("RTC set local description");
    log::debug!("Answer SDP:\n{}", rtc_answer.sdp);

    // Convert rtc answer to webrtc answer
    let webrtc_answer = WebrtcRTCSessionDescription::answer(rtc_answer.sdp.clone())?;

    // Set remote description on webrtc
    webrtc_pc.set_remote_description(webrtc_answer).await?;
    log::info!("WebRTC set remote description");

    // Wait for connection establishment with timeout
    let (webrtc_connected_tx, _webrtc_connected_rx) = channel(1);
    let webrtc_connected_tx = Arc::new(Mutex::new(Some(webrtc_connected_tx)));

    webrtc_pc.on_peer_connection_state_change(Box::new(move |state| {
        log::info!("WebRTC peer connection state changed: {}", state);
        if state == WebrtcRTCPeerConnectionState::Connected {
            let tx = webrtc_connected_tx.clone();
            Box::pin(async move {
                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send(()).await;
                }
            })
        } else {
            Box::pin(async {})
        }
    }));

    // Track incoming simulcast layers on rtc side
    let mut track_id2_receiver_id = HashMap::new();

    // Start event loop for rtc peer
    let rtc_socket = Arc::new(socket);
    let rtc_socket_clone = Arc::clone(&rtc_socket);
    let mut buf = vec![0; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sending_started = false;

    // Spawn task to send dummy samples from webrtc on all 3 simulcast layers
    let track_low_clone = Arc::clone(&track_low);
    let track_mid_clone = Arc::clone(&track_mid);
    let track_high_clone = Arc::clone(&track_high);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await; // Wait longer for DTLS handshake
        log::info!(
            "Starting to send samples on all simulcast layers (webrtc will add RID extensions)"
        );

        let start_time = std::time::SystemTime::now();

        for i in 0..30u32 {
            let timestamp = start_time + Duration::from_millis(i as u64 * 33); // ~30fps

            // Send sample on LOW layer
            let sample_low = Sample {
                data: bytes::Bytes::from(vec![0xAA; 100]),
                duration: Duration::from_millis(33),
                timestamp,
                ..Default::default()
            };

            if let Err(e) = track_low_clone.write_sample(&sample_low).await {
                log::warn!("Failed to send sample on low layer: {}", e);
            }

            // Send sample on MID layer
            let sample_mid = Sample {
                data: bytes::Bytes::from(vec![0xBB; 150]),
                duration: Duration::from_millis(33),
                timestamp,
                ..Default::default()
            };

            if let Err(e) = track_mid_clone.write_sample(&sample_mid).await {
                log::warn!("Failed to send sample on mid layer: {}", e);
            }

            // Send sample on HIGH layer
            let sample_high = Sample {
                data: bytes::Bytes::from(vec![0xCC; 200]),
                duration: Duration::from_millis(33),
                timestamp,
                ..Default::default()
            };

            if let Err(e) = track_high_clone.write_sample(&sample_high).await {
                log::warn!("Failed to send sample on high layer: {}", e);
            }

            if i % 10 == 0 {
                log::info!("Sent {} samples on each simulcast layer", i + 1);
            }

            tokio::time::sleep(Duration::from_millis(33)).await; // ~30fps
        }
        log::info!("Finished sending samples");
    });

    // Run rtc event loop
    let start_time = Instant::now();
    let test_duration = Duration::from_secs(15);

    'EventLoop: loop {
        // Check timeout
        if start_time.elapsed() > test_duration {
            log::info!("Test duration reached, exiting event loop");
            break 'EventLoop;
        }

        // Poll write - send outgoing packets
        while let Some(msg) = rtc_pc.poll_write() {
            match rtc_socket_clone
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(_n) => {}
                Err(err) => {
                    log::error!(
                        "socket write to {} with error {}",
                        msg.transport.peer_addr,
                        err
                    );
                }
            }
        }

        // Poll events - handle state changes
        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    log::info!(
                        "RTC ICE Connection State has changed: {}",
                        ice_connection_state
                    );
                    if ice_connection_state == RTCIceConnectionState::Failed {
                        log::error!("RTC ICE Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    log::info!(
                        "RTC Peer Connection State has changed: {}",
                        peer_connection_state
                    );
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        log::error!("RTC Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    }
                    if peer_connection_state == RTCPeerConnectionState::Connected {
                        rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        track_id2_receiver_id.insert(init.track_id.clone(), init.receiver_id);

                        if let Some(rid) = init.rid.as_ref() {
                            log::info!("RTC Track Open with RID: {}", rid);
                        } else {
                            log::info!("RTC Track Open without RID (track_id: {})", init.track_id);
                        }
                    }
                    RTCTrackEvent::OnClose(track_id) => {
                        log::info!("RTC Track closed: {}", track_id);
                        track_id2_receiver_id.remove(&track_id);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Poll read - receive application messages
        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, rtp_packet) => {
                    // Get the receiver for this track
                    let receiver_id = track_id2_receiver_id
                        .get(&track_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?
                        .clone();

                    let rtp_receiver = rtc_pc
                        .rtp_receiver(receiver_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;

                    // Get RID from the track (webrtc automatically adds RID header extensions)
                    let rid = rtp_receiver
                        .track()?
                        .rid(rtp_packet.header.ssrc)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("ssrc_{}", rtp_packet.header.ssrc));

                    let mut counts = packets_received_clone.lock().await;
                    let count = counts.entry(rid.clone()).or_insert(0);
                    *count += 1;

                    if *count % 10 == 0 {
                        log::info!(
                            "RTC received RTP packet #{} for RID: {} (SSRC: {}, seq: {})",
                            *count,
                            rid,
                            rtp_packet.header.ssrc,
                            rtp_packet.header.sequence_number
                        );
                    }
                }
                RTCMessage::RtcpPacket(_, _) => {
                    // RTCP packets are handled internally
                }
                RTCMessage::DataChannelMessage(_, _) => {}
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            log::info!("WebRTC peer connected!");
            webrtc_connected = true;
        }

        // Log connection status periodically
        if rtc_connected && webrtc_connected && !packets_sending_started {
            log::info!("Both peers connected, waiting for DTLS handshake to complete...");
            packets_sending_started = true;
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

        // Event loop with tokio::select!
        tokio::select! {
            _ = timer.as_mut() => {
                rtc_pc.handle_timeout(Instant::now())?;
            }

            res = rtc_socket_clone.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
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
                    Err(err) => {
                        log::error!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    // Check results
    let final_counts = packets_received.lock().await;
    log::info!("Final packet counts by SSRC:");
    for (ssrc_key, count) in final_counts.iter() {
        log::info!("  {}: {} packets", ssrc_key, count);
    }

    // Verify we received packets from 3 different SSRCs (3 separate tracks)
    assert_eq!(
        final_counts.len(),
        3,
        "Should have received packets from 3 different SSRCs (3 tracks), got {}",
        final_counts.len()
    );

    // Verify each track sent approximately the expected number of packets
    for (ssrc_key, count) in final_counts.iter() {
        assert!(
            *count >= 25,
            "Each track should send ~30 packets, {} sent {}",
            ssrc_key,
            count
        );
    }

    // Verify total packets
    let total_packets: u32 = final_counts.values().sum();
    assert!(
        total_packets >= 75,
        "Should have received at least 75 packets total (3 tracks × ~30), got {}",
        total_packets
    );

    log::info!(
        "✅ Received {} total RTP packets across {} concurrent video tracks",
        total_packets,
        final_counts.len()
    );

    // Close connections
    rtc_pc.close()?;
    webrtc_pc.close().await?;

    log::info!("Test completed successfully!");
    Ok(())
}

/// Create a webrtc peer connection with simulcast support
async fn create_webrtc_peer_with_simulcast() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();

    // Register VP8 codec
    media_engine.register_codec(
        WebrtcRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: "video/VP8".to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 96,
            ..Default::default()
        },
        RTPCodecType::Video,
    )?;

    // Enable simulcast extension headers
    for extension in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        media_engine.register_header_extension(
            webrtc::rtp_transceiver::rtp_codec::RTCRtpHeaderExtensionCapability {
                uri: extension.to_owned(),
            },
            RTPCodecType::Video,
            None,
        )?;
    }

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

    Ok(Arc::new(api.new_peer_connection(config).await?))
}
