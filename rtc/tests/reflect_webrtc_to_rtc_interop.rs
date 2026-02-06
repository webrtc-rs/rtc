/// Integration test for reflect example with webrtc interop
///
/// This test verifies that the rtc library can receive RTP packets from webrtc,
/// reflect them back on the same connection, and webrtc receives the reflected packets.
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

use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
};
use rtc::shared::error::Error;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};
use webrtc::track::track_remote::TrackRemote;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test reflect functionality: webrtc sends RTP -> rtc reflects -> webrtc receives
#[tokio::test]
async fn test_reflect_webrtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting reflect interop test: webrtc -> rtc -> webrtc");

    // Track received packets
    let received_packets = Arc::new(Mutex::new(0u32));
    let received_packets_clone = Arc::clone(&received_packets);

    // Create webrtc peer (will be the offerer and sender)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Create a video track to send
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-rs-video".to_owned(),
    ));

    // Add track to webrtc peer
    let _rtp_sender = webrtc_pc
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added video track to webrtc peer");

    // Set up handler for receiving reflected packets
    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let received_packets = Arc::clone(&received_packets_clone);
            Box::pin(async move {
                log::info!(
                    "WebRTC got track: {} (codec: {})",
                    track.stream_id(),
                    track.codec().capability.mime_type
                );

                tokio::spawn(async move {
                    while let Ok((rtp_packet, _)) = track.read_rtp().await {
                        let count = {
                            let mut count = received_packets.lock().await;
                            *count += 1;
                            *count
                        };
                        log::info!(
                            "WebRTC received reflected RTP packet #{} (seq: {})",
                            count,
                            rtp_packet.header.sequence_number
                        );
                    }
                });
            })
        },
    ));

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

    // Create rtc peer (will be the answerer and reflector)
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

    let registry = rtc::interceptor::Registry::new();

    // Use the default set of Interceptors
    let registry =
        rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
            registry,
            &mut media_engine,
        )?;

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut rtc_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?;
    log::info!("Created RTC peer connection");

    // Create output track for reflecting
    let mut rtp_sender_ids = HashMap::new();
    let output_track = MediaStreamTrack::new(
        format!("webrtc-rs-stream-id-{}", RtpCodecKind::Video),
        format!("webrtc-rs-track-id-{}", RtpCodecKind::Video),
        format!("webrtc-rs-track-label-{}", RtpCodecKind::Video),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(rand::random::<u32>()),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    let rtp_sender_id = rtc_pc.add_track(output_track)?;
    rtp_sender_ids.insert(RtpCodecKind::Video, rtp_sender_id);
    log::info!("Added output track to RTC peer for reflecting");

    // Set remote description (the offer from webrtc)
    log::info!("RTC set remote description");
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

    // Run event loops for both peers
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sent = 0u32;
    let mut rtp_receiver_id2ssrcs = HashMap::new();
    let mut track_id2_receiver_id = HashMap::new();

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
                        track_id2_receiver_id.insert(init.track_id, init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(_track_id) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, mut rtp_packet) => {
                    let receiver_id = track_id2_receiver_id
                        .get(&track_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?
                        .clone();
                    let rtp_receiver = rtc_pc
                        .rtp_receiver(receiver_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;
                    let track = rtp_receiver.track();
                    let media_ssrc = track
                        .ssrcs()
                        .last()
                        .ok_or(Error::ErrRTPReceiverForSSRCTrackStreamNotFound)?;
                    rtp_receiver_id2ssrcs.insert(receiver_id, media_ssrc);

                    let rtp_sender_id = rtp_sender_ids
                        .get(&track.kind())
                        .ok_or(Error::ErrRTPSenderNotExisted)?;

                    let mut rtp_sender = rtc_pc
                        .rtp_sender(*rtp_sender_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;

                    rtp_packet.header.ssrc = rtp_sender
                        .track()
                        .ssrcs()
                        .last()
                        .ok_or(Error::ErrSenderWithNoSSRCs)?;
                    log::debug!(
                        "RTC reflecting rtp packet (seq: {}, ssrc: {})",
                        rtp_packet.header.sequence_number,
                        media_ssrc
                    );
                    rtp_sender.write_rtp(rtp_packet)?;
                }
                RTCMessage::RtcpPacket(_, _) => {
                    // Read incoming RTCP packets
                    // Before these packets are returned they are processed by interceptors. For things
                    // like NACK this needs to be called.
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

        // Send RTP packets from webrtc once connected
        if rtc_connected && webrtc_connected && packets_sent < 10 {
            // Give some time for the connection to stabilize
            if packets_sent == 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            // Create a simple RTP packet with a random SSRC
            let rtp_packet = webrtc::rtp::packet::Packet {
                header: webrtc::rtp::header::Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: packets_sent == 0,
                    payload_type: 96,
                    sequence_number: packets_sent as u16,
                    timestamp: packets_sent * 3000,
                    ssrc: rand::random::<u32>(),
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(), // Dummy payload
            };

            video_track.write_rtp(&rtp_packet).await?;
            packets_sent += 1;
            log::info!("WebRTC sent RTP packet #{}", packets_sent);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check if we received reflected packets
        let count = *received_packets.lock().await;
        if count >= 5 {
            log::info!("✅ Test completed successfully!");
            log::info!(
                "   Sent {} packets, received {} reflected packets",
                packets_sent,
                count
            );

            assert!(
                count >= 5,
                "Should have received at least 5 reflected packets"
            );

            webrtc_pc.close().await?;
            rtc_pc.close()?;
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

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(50)));
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
        "Test timeout - did not receive enough reflected packets in time"
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
