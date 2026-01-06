/// Integration test for reflect: rtc sends RTP -> webrtc reflects -> rtc receives
///
/// This test verifies that the rtc library can send RTP packets to webrtc,
/// webrtc reflects them back on the same connection, and rtc receives the reflected packets.
///
/// Test flow:
/// 1. rtc peer creates offer with video track
/// 2. webrtc peer creates answer with video track
/// 3. Both peers exchange SDP and establish ICE/DTLS connection
/// 4. rtc sends RTP packets to webrtc
/// 5. webrtc reflects packets back to rtc
/// 6. Test verifies rtc received reflected packets
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
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
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

/// Test reflect functionality: rtc sends RTP -> webrtc reflects -> rtc receives
#[tokio::test]
async fn test_reflect_rtc_to_webrtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting reflect interop test: rtc -> webrtc -> rtc");

    // Track received packets on rtc side
    let received_packets = Arc::new(Mutex::new(0u32));
    let received_packets_clone = Arc::clone(&received_packets);

    // Create rtc peer (will be the offerer and sender)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let setting_engine = SettingEngine::default();
    // RTC is creating the offer, so it will be the DTLS client
    // No need to set answering_dtls_role since we're not answering

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

    // Create output track on rtc for sending
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

    let output_sender_id = rtc_pc.add_track(output_track)?;
    log::info!("Added output track to RTC peer for sending");

    // Add local candidate for rtc
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
    log::info!("RTC added local candidate");

    // Create offer from rtc
    let offer = rtc_pc.create_offer(None)?;
    log::info!("RTC created offer {}", offer);

    // Set local description on rtc
    rtc_pc.set_local_description(offer.clone())?;
    log::info!("RTC set local description");

    // Create webrtc peer (will be the answerer and reflector)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Create a video track on webrtc for reflecting
    let reflect_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        "video".to_owned(),
        "webrtc-reflect".to_owned(),
    ));

    // Add track to webrtc peer
    let _rtp_sender = webrtc_pc
        .add_track(Arc::clone(&reflect_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;
    log::info!("Added reflect track to webrtc peer");

    // Set up handler on webrtc to reflect incoming packets
    let reflect_track_clone = Arc::clone(&reflect_track);
    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let reflect_track = Arc::clone(&reflect_track_clone);
            Box::pin(async move {
                log::info!(
                    "WebRTC got track: {} (codec: {})",
                    track.stream_id(),
                    track.codec().capability.mime_type
                );

                tokio::spawn(async move {
                    while let Ok((rtp_packet, _)) = track.read_rtp().await {
                        log::debug!(
                            "WebRTC reflecting RTP packet (seq: {})",
                            rtp_packet.header.sequence_number
                        );
                        if let Err(e) = reflect_track.write_rtp(&rtp_packet).await {
                            log::warn!("Failed to reflect packet: {}", e);
                        }
                    }
                });
            })
        },
    ));

    // Convert rtc offer to webrtc offer
    let webrtc_offer = WebrtcRTCSessionDescription::offer(offer.sdp.clone())?;

    // Set remote description on webrtc
    webrtc_pc.set_remote_description(webrtc_offer).await?;
    log::info!("WebRTC set remote description");

    // Create answer from webrtc
    let answer = webrtc_pc.create_answer(None).await?;
    log::info!("WebRTC created answer");

    // Set local description on webrtc
    webrtc_pc.set_local_description(answer.clone()).await?;
    log::info!("WebRTC set local description");

    // Wait for ICE gathering on webrtc
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;

    let answer_with_candidates = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    log::info!("WebRTC answer with candidates ready");
    log::info!("Answer SDP:\n{}", answer_with_candidates.sdp);

    // Convert webrtc answer to rtc answer
    let rtc_answer =
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer_with_candidates.sdp)?;

    // Set remote description on rtc
    log::info!("RTC set remote description {}", rtc_answer);
    rtc_pc.set_remote_description(rtc_answer)?;

    // Run event loops
    let rtc_socket = Arc::new(socket);
    let rtc_socket_clone = Arc::clone(&rtc_socket);
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut packets_sent = 0u32;
    let mut track_id2_receiver_id = HashMap::new();

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    // Create dummy video data to send
    let dummy_frame = vec![0xAA; 500];

    while start_time.elapsed() < test_timeout {
        // Process rtc writes
        while let Some(msg) = rtc_pc.poll_write() {
            match rtc_socket_clone
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                Ok(_n) => {}
                Err(err) => {
                    log::error!("RTC socket write error: {}", err);
                }
            }
        }

        // Process rtc events
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
                        rtc_connected = true;
                        log::info!("✅ RTC peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        log::info!("RTC got track opened: {}", init.track_id);
                        track_id2_receiver_id.insert(init.track_id, init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(_track_id) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        // Process rtc reads (reflected packets from webrtc)
        while let Some(message) = rtc_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                    let mut count = received_packets_clone.lock().await;
                    *count += 1;
                    log::info!(
                        "RTC received reflected RTP packet #{} (seq: {})",
                        *count,
                        rtp_packet.header.sequence_number
                    );
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
            webrtc_connected = true;
            log::info!("✅ WebRTC peer connected!");
        }

        // Send RTP packets from rtc once both are connected
        if rtc_connected && webrtc_connected && packets_sent < 10 {
            // Give some time for the connection to stabilize
            if packets_sent == 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let mut rtp_sender = rtc_pc
                .rtp_sender(output_sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?;

            // Debug: check sender parameters
            let params = rtp_sender.get_parameters()?;
            if packets_sent == 0 {
                log::info!(
                    "Sender parameters: {} codecs, {} encodings",
                    params.rtp_parameters.codecs.len(),
                    params.encodings.len()
                );
                for (i, codec) in params.rtp_parameters.codecs.iter().enumerate() {
                    log::info!(
                        "  Codec {}: {} (PT: {})",
                        i,
                        codec.rtp_codec.mime_type,
                        codec.payload_type
                    );
                }
                for (i, enc) in params.encodings.iter().enumerate() {
                    log::info!(
                        "  Encoding {}: ssrc={:?}, codec={}",
                        i,
                        enc.rtp_coding_parameters.ssrc,
                        enc.codec.mime_type
                    );
                }
            }

            let ssrc = rtp_sender
                .track()?
                .ssrcs()
                .last()
                .ok_or(Error::ErrSenderWithNoSSRCs)?;

            // Create RTP packet
            let packet = rtc::rtp::packet::Packet {
                header: rtc::rtp::header::Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: packets_sent == 0,
                    payload_type: 96,
                    sequence_number: packets_sent as u16,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(dummy_frame.clone()),
            };

            if let Err(e) = rtp_sender.write_rtp(packet) {
                log::warn!("Failed to send RTP packet: {}", e);
            } else {
                packets_sent += 1;
                log::info!("RTC sent RTP packet #{}", packets_sent);
            }

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

            rtc_pc.close()?;
            webrtc_pc.close().await?;
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
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available
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

    Ok(Arc::new(api.new_peer_connection(config).await?))
}
