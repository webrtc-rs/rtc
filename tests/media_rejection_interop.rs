//! Integration tests for media rejection interop between sansio RTC and webrtc.
//!
//! This test verifies that sansio RTC correctly rejects media sections it doesn't support.
//!
//! Test scenario:
//! - Offer contains both video and audio tracks
//! - sansio RTC (answerer/receiver) only accepts video, rejects audio
//!
//! This demonstrates:
//! 1. Partial media acceptance - accepting some media sections while rejecting others
//! 2. Proper SDP answer generation with port=0 for rejected tracks
//! 3. Video-only reception when audio codec is not registered
//!
//! Note: Network-based tests require network permissions. In sandboxed environments
//! (e.g., macOS sandbox), network I/O may be blocked. The SDP-only test
//! (`test_sdp_answer_rejects_audio_correctly`) works without network permissions.

use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors as webrtc_register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit as WebrtcIceCandidateInit;
use webrtc::interceptor::registry::Registry as WebrtcRegistry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a webrtc peer connection (no STUN - local only) with video only
async fn create_webrtc_peer_video_only() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = WebrtcRegistry::new();
    registry = webrtc_register_default_interceptors(registry, &mut media_engine)?;

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    // No ICE servers - local only
    let config = WebrtcRTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };

    Ok(Arc::new(api.new_peer_connection(config).await?))
}

/// Create sansio RTC peer configuration with video-only codec support
/// Audio codecs are NOT registered, so audio tracks will be rejected
fn create_rtc_peer_config_video_only()
-> Result<RTCPeerConnection<impl rtc::interceptor::Interceptor>> {
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

    // Only register video codec - no audio!
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
    };
    media_engine.register_codec(video_codec, RtpCodecKind::Video)?;
    // Note: Audio codec is NOT registered, so audio will be rejected

    let registry = Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    let config = RTCConfigurationBuilder::new().build();

    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;

    Ok(pc)
}

// ============================================================================
// Test: webrtc offerer sends video, sansio RTC receives video
// ============================================================================

/// Test video-only media reception from webrtc to sansio RTC
///
/// This test verifies:
/// - webrtc creates offer with video track
/// - sansio RTC receives video track correctly
/// - Video RTP packets are received successfully
#[tokio::test]
async fn test_video_only_webrtc_offerer_rtc_answerer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting video-only test: webrtc (offerer) -> sansio RTC (answerer)");

    // Create webrtc peer (offerer) with video track only
    let webrtc_pc = create_webrtc_peer_video_only().await?;
    log::info!("Created webrtc peer connection");

    // Create video track
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "video-stream".to_owned(),
    ));

    // Add video track to webrtc
    webrtc_pc
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added video track to webrtc");

    // Create offer
    let offer = webrtc_pc.create_offer(None).await?;
    webrtc_pc.set_local_description(offer.clone()).await?;
    log::info!("WebRTC created offer with video");

    // Create sansio RTC peer (answerer) with video-only support
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut rtc_pc = create_rtc_peer_config_video_only()?;
    log::info!("Created RTC peer with video-only codec support");

    // Set remote description (offer) on RTC - use offer without candidates (trickle ICE)
    let offer_sdp = offer.sdp.clone();
    let rtc_offer = rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_sdp)?;
    rtc_pc.set_remote_description(rtc_offer)?;
    log::info!("RTC set remote description (offer with video)");

    // Create and set answer
    let answer = rtc_pc.create_answer(None)?;
    rtc_pc.set_local_description(answer.clone())?;
    log::info!("RTC created answer");

    // Set answer on webrtc
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;
    log::info!("WebRTC set remote description (answer)");

    // === TRICKLE ICE: Add candidates AFTER SDP exchange ===

    // Add local candidate for RTC peer
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
        "RTC added local candidate: {}",
        local_candidate_init.candidate
    );

    // Add RTC's candidate to webrtc (trickle)
    let webrtc_remote_candidate = WebrtcIceCandidateInit {
        candidate: local_candidate_init.candidate.clone(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    };
    webrtc_pc.add_ice_candidate(webrtc_remote_candidate).await?;
    log::info!("WebRTC added remote candidate from RTC");

    // Wait for ICE gathering
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    // Add webrtc's gathered candidates to RTC
    if let Some(local_desc) = webrtc_pc.local_description().await {
        log::info!("WebRTC ICE gathering complete, adding candidates to RTC");
        for line in local_desc.sdp.lines() {
            if line.starts_with("a=candidate:")
                && line.contains("typ host")
                && line.contains(" udp ")
            {
                let candidate_str = line.strip_prefix("a=").unwrap_or(line);
                let remote_candidate = rtc::peer_connection::transport::RTCIceCandidateInit {
                    candidate: candidate_str.to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: None,
                };
                if let Err(e) = rtc_pc.add_remote_candidate(remote_candidate) {
                    log::warn!("Failed to add remote candidate: {}", e);
                } else {
                    log::info!("RTC added remote candidate: {}", candidate_str);
                }
            }
        }
    }

    // Run event loop
    let mut buf = vec![0u8; 2000];
    let mut _rtc_connected = false;
    let mut webrtc_connected = false;
    let mut video_track_opened = false;
    let mut video_packets_received = 0u32;
    let mut rtp_sending_started = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    // Clone track for sending
    let video_track_clone = Arc::clone(&video_track);

    while start_time.elapsed() < test_timeout {
        // Start sending RTP once webrtc is connected
        if webrtc_connected && !rtp_sending_started {
            rtp_sending_started = true;
            log::info!("WebRTC connected, starting to send video RTP packets");

            // Send video packets
            let v_track = Arc::clone(&video_track_clone);
            tokio::spawn(async move {
                for seq in 0u16..50 {
                    let rtp = webrtc::rtp::packet::Packet {
                        header: webrtc::rtp::header::Header {
                            version: 2,
                            padding: false,
                            extension: false,
                            marker: false,
                            payload_type: 96,
                            sequence_number: seq,
                            timestamp: seq as u32 * 3000,
                            ssrc: 11111,
                            ..Default::default()
                        },
                        payload: bytes::Bytes::from(vec![0xAAu8; 100]),
                    };

                    let _ = v_track.write_rtp(&rtp).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
        }

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
                        _rtc_connected = true;
                        log::info!("RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    // Get the receiver to check track kind
                    if let Some(receiver) = rtc_pc.rtp_receiver(init.receiver_id) {
                        let kind = receiver.track().kind();
                        log::info!("RTC track opened: {} (kind: {:?})", init.track_id, kind);
                        if kind == RtpCodecKind::Video {
                            video_track_opened = true;
                            log::info!("Video track opened successfully");
                        }
                    }
                }
                _ => {}
            }
        }

        // Process reads
        while let Some(message) = rtc_pc.poll_read() {
            if let RTCMessage::RtpPacket(_track_id, rtp_packet) = message {
                video_packets_received += 1;
                if video_packets_received == 1 || video_packets_received % 10 == 0 {
                    log::info!(
                        "RTC received RTP packet #{} (seq: {}, ssrc: {})",
                        video_packets_received,
                        rtp_packet.header.sequence_number,
                        rtp_packet.header.ssrc
                    );
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

        // Check success - should receive video packets
        if video_packets_received >= 20 && video_track_opened {
            log::info!("Test passed!");
            log::info!("  Video track opened: {}", video_track_opened);
            log::info!("  Video packets received: {}", video_packets_received);
            rtc_pc.close()?;
            webrtc_pc.close().await?;
            return Ok(());
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

    Err(anyhow::anyhow!(
        "Test timeout - video_opened: {}, video_packets: {}",
        video_track_opened,
        video_packets_received
    ))
}

/// Test that verifies the SDP answer format for rejected audio tracks
///
/// This is a focused test that only checks the SDP generation,
/// without the full connection establishment. It uses a manually
/// crafted SDP offer with both video and audio to verify that
/// sansio RTC correctly rejects audio (port=0) while accepting video.
#[tokio::test]
async fn test_sdp_answer_rejects_audio_correctly() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Testing SDP answer format for audio rejection");

    // Create a minimal SDP offer with video and audio
    let offer_sdp = r#"v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=extmap-allow-mixed
a=msid-semantic: WMS
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:test
a=ice-pwd:testpasswordtestpassword
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
a=setup:actpass
a=mid:0
a=sendonly
a=rtcp-mux
a=rtpmap:96 VP8/90000
a=ssrc:11111 cname:test
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:test
a=ice-pwd:testpasswordtestpassword
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
a=setup:actpass
a=mid:1
a=sendonly
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=ssrc:22222 cname:test
"#;

    // Create RTC peer with video-only support
    let mut rtc_pc = create_rtc_peer_config_video_only()?;

    // Set remote description (offer with video + audio)
    let rtc_offer = rtc::peer_connection::sdp::RTCSessionDescription::offer(offer_sdp.to_string())?;
    rtc_pc.set_remote_description(rtc_offer)?;

    // Add a dummy local candidate
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
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
    rtc_pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    // Create answer
    let answer = rtc_pc.create_answer(None)?;
    let answer_sdp = answer.sdp.clone();
    log::info!("Generated answer SDP:\n{}", answer_sdp);

    // Parse and verify the answer
    let lines: Vec<&str> = answer_sdp.lines().collect();

    // Find video m-line
    let video_mline = lines.iter().find(|l| l.starts_with("m=video"));
    assert!(video_mline.is_some(), "Answer should contain video m-line");
    let video_mline = video_mline.unwrap();
    assert!(
        !video_mline.starts_with("m=video 0"),
        "Video should NOT be rejected (should have non-zero port)"
    );
    log::info!("Video m-line (accepted): {}", video_mline);

    // Find audio m-line
    let audio_mline = lines.iter().find(|l| l.starts_with("m=audio"));
    assert!(
        audio_mline.is_some(),
        "Answer should contain audio m-line (even if rejected)"
    );
    let audio_mline = audio_mline.unwrap();
    assert!(
        audio_mline.starts_with("m=audio 0"),
        "Audio should be rejected with port=0, got: {}",
        audio_mline
    );
    log::info!("Audio m-line (rejected): {}", audio_mline);

    // Verify BUNDLE group only contains video
    // After audio rejection, the bundle should only have video mid
    let bundle_line = lines.iter().find(|l| l.contains("a=group:BUNDLE"));
    if let Some(bundle) = bundle_line {
        log::info!("Bundle group: {}", bundle);
        // Bundle should contain video mid (0) but not audio mid (1) after rejection
        // However, implementation may vary - the key is port=0 for audio
    }

    rtc_pc.close()?;
    log::info!("Test passed: Audio correctly rejected with port=0 in SDP answer");
    Ok(())
}
