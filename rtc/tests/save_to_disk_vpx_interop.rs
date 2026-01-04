/// Integration test for save-to-disk-vpx example with webrtc interop
///
/// This test verifies that webrtc can stream media and the rtc library
/// can successfully receive the RTP packets.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::track_event::RTCTrackEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::transport::dtls::role::DTLSRole;
use rtc::peer_connection::transport::ice::candidate::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate,
};
use rtc::peer_connection::transport::ice::server::RTCIceServer as RtcIceServer;
use rtc::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::rtp_codec::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverInit};

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
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test streaming media to disk: webrtc streams -> rtc receives
#[tokio::test]
async fn test_save_to_disk_vpx_webrtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting save-to-disk-vpx interop test: webrtc -> rtc");

    // Track received packets
    let video_packets_received = Arc::new(Mutex::new(0u32));
    let video_packets_received_clone = Arc::clone(&video_packets_received);
    let audio_packets_received = Arc::new(Mutex::new(0u32));
    let audio_packets_received_clone = Arc::clone(&audio_packets_received);

    // Create webrtc peer (will be the offerer and sender)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Create video track
    let video_track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: "video/vp8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-rs".to_owned(),
    ));

    // Add video track to webrtc peer
    webrtc_pc
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added video track");

    // Create audio track
    let audio_track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: "audio/opus".to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "audio".to_owned(),
        "webrtc-rs".to_owned(),
    ));

    // Add audio track to webrtc peer
    webrtc_pc
        .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added audio track");

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
    let rtc_offer = rtc::peer_connection::sdp::session_description::RTCSessionDescription::offer(
        offer_with_candidates.sdp.clone(),
    )?;

    // Create rtc peer (will be the answerer and receiver)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(DTLSRole::Client)?;

    // Create a MediaEngine object to configure the supported codec
    let mut media_engine = MediaEngine::default();

    let audio_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 111,
        ..Default::default()
    };

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

    media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;
    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RtcIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Add transceivers to receive video and audio
    rtc_pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )?;
    log::info!("Added audio transceiver");

    rtc_pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )?;
    log::info!("Added video transceiver");

    // Set remote description (the offer from webrtc)
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
    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    rtc_pc.add_local_candidate(local_candidate_init)?;

    // Create answer from rtc peer
    let answer = rtc_pc.create_answer(None)?;
    log::info!("RTC created answer");

    // Set local description on rtc peer
    rtc_pc.set_local_description(answer.clone())?;
    log::info!("RTC set local description");

    // Convert rtc answer to webrtc SDP
    let webrtc_answer = WebrtcRTCSessionDescription::answer(answer.sdp.clone())?;

    // Set remote description on webrtc (the answer from rtc)
    webrtc_pc.set_remote_description(webrtc_answer).await?;
    log::info!("WebRTC set remote description");

    // Track which receiver_id maps to which track kind
    let receiver_id_to_kind =
        Arc::new(Mutex::new(HashMap::<RTCRtpReceiverId, RtpCodecKind>::new()));
    let track_id2_receiver_id = Arc::new(Mutex::new(HashMap::new()));

    // Spawn media streaming tasks
    let video_track_clone = Arc::clone(&video_track);
    let video_count_clone = Arc::clone(&video_packets_received_clone);
    tokio::spawn(async move {
        // Send some dummy video frames
        for i in 0..30 {
            let sample = Sample {
                data: vec![0u8; 100].into(), // Dummy VP8 data
                duration: Duration::from_millis(33),
                ..Default::default()
            };
            if let Err(err) = video_track_clone.write_sample(&sample).await {
                log::error!("Error writing video sample: {}", err);
                break;
            }
            *video_count_clone.lock().await += 1;
            if i % 10 == 0 {
                log::info!("WebRTC sent video sample #{}", i + 1);
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
        log::info!("WebRTC finished sending video samples");
    });

    let audio_track_clone = Arc::clone(&audio_track);
    let audio_count_clone = Arc::clone(&audio_packets_received_clone);
    tokio::spawn(async move {
        // Send some dummy audio frames
        for i in 0..30 {
            let sample = Sample {
                data: vec![0u8; 100].into(), // Dummy Opus data
                duration: Duration::from_millis(20),
                ..Default::default()
            };
            if let Err(err) = audio_track_clone.write_sample(&sample).await {
                log::error!("Error writing audio sample: {}", err);
                break;
            }
            *audio_count_clone.lock().await += 1;
            if i % 10 == 0 {
                log::info!("WebRTC sent audio sample #{}", i + 1);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        log::info!("WebRTC finished sending audio samples");
    });

    // Run event loops for both peers
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut video_received = 0u32;
    let mut audio_received = 0u32;

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
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        log::info!("RTC got track: {:?}", init.track_id);
                        track_id2_receiver_id
                            .lock()
                            .await
                            .insert(init.track_id, init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(_track_id) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        // Process RTP packets received by rtc
        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, _rtp_packet) => {
                    let receiver_id = {
                        let map = track_id2_receiver_id.lock().await;
                        map.get(&track_id).copied()
                    };

                    if let Some(receiver_id) = receiver_id {
                        let rtp_receiver = rtc_pc
                            .rtp_receiver(receiver_id)
                            .ok_or_else(|| anyhow::anyhow!("RTP receiver not found"))?;
                        let track = rtp_receiver
                            .track(&track_id)?
                            .ok_or_else(|| anyhow::anyhow!("Track not found"))?;

                        // Record the track kind for this receiver on first packet
                        let mut kind_map = receiver_id_to_kind.lock().await;
                        if !kind_map.contains_key(&receiver_id) {
                            let kind = track.kind();
                            kind_map.insert(receiver_id, kind);

                            let codec = track.codec();
                            let mime_type = codec.mime_type.to_lowercase();

                            if mime_type == MIME_TYPE_OPUS.to_lowercase() {
                                log::info!("Got Opus track");
                            } else if mime_type == MIME_TYPE_VP8.to_lowercase() {
                                log::info!("Got VP8 track");
                            }
                        }

                        // Count received packets
                        match kind_map.get(&receiver_id) {
                            Some(RtpCodecKind::Audio) => {
                                audio_received += 1;
                                if audio_received % 10 == 0 {
                                    log::info!("RTC received audio RTP packet #{}", audio_received);
                                }
                            }
                            Some(RtpCodecKind::Video) => {
                                video_received += 1;
                                if video_received % 10 == 0 {
                                    log::info!("RTC received video RTP packet #{}", video_received);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                RTCMessage::RtcpPacket(_, _) => {
                    // Process RTCP packets
                }
                RTCMessage::DataChannelMessage(_, _) => {}
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            log::info!("WebRTC peer connection connected!");
            webrtc_connected = true;
        }

        // Check if we've received enough packets
        if rtc_connected && webrtc_connected && video_received >= 20 && audio_received >= 20 {
            log::info!("✅ Test completed successfully!");
            log::info!(
                "   Received {} video packets and {} audio packets",
                video_received,
                audio_received
            );

            webrtc_pc.close().await?;
            rtc_pc.close()?;

            assert!(
                video_received >= 20,
                "Should have received at least 20 video packets"
            );
            assert!(
                audio_received >= 20,
                "Should have received at least 20 audio packets"
            );

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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
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
        "Test timeout - did not receive enough media packets in time"
    ))
}

/// Helper function to create a webrtc peer connection
async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
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
