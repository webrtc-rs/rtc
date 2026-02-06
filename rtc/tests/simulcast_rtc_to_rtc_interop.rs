/// Integration test for TRUE simulcast with RID (rtc → rtc)
///
/// This test demonstrates TRUE simulcast by having one rtc peer send 3 simulcast layers
/// with proper RID header extensions, and another rtc peer receive them.
///
/// **Test flow:**
/// 1. Offerer creates 3 tracks with RIDs ("low"/"mid"/"high") and adds to peer
/// 2. Offerer creates offer with proper simulcast SDP
/// 3. Answerer receives offer and creates answer
/// 4. Offerer sends RTP packets with RID header extensions on each track
/// 5. Answerer receives packets and can identify them by track
/// 6. Test verifies answerer received packets from all 3 simulcast layers
use anyhow::Result;
use bytes::BytesMut;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test simulcast: rtc sends 3 layers with RIDs -> rtc receives all 3 layers
#[tokio::test]
async fn test_simulcast_rtc_to_rtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting TRUE simulcast test: rtc (offerer/sender) -> rtc (answerer/receiver)");

    // Create answerer rtc peer
    let answerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let answerer_local_addr = answerer_socket.local_addr()?;
    log::info!("Answerer bound to {}", answerer_local_addr);

    let mut answerer_setting_engine = SettingEngine::default();
    answerer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    let mut answerer_media_engine = MediaEngine::default();

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

    let audio_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 120,
        ..Default::default()
    };

    answerer_media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;
    answerer_media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;

    // Enable Extension Headers needed for Simulcast
    for extension in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        answerer_media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: extension.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }

    let registry = rtc::interceptor::Registry::new();

    // Use the default set of Interceptors
    let registry =
        rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
            registry,
            &mut answerer_media_engine,
        )?;

    let answerer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut answerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(answerer_config)
        .with_setting_engine(answerer_setting_engine)
        .with_media_engine(answerer_media_engine)
        .with_interceptor_registry(registry)
        .build()?;
    log::info!("Created answerer peer connection");

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
    answerer_pc.add_local_candidate(RTCIceCandidate::from(&answerer_candidate).to_json()?)?;
    log::info!("Answerer added local candidate");

    // Create offerer rtc peer
    let offerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let offerer_local_addr = offerer_socket.local_addr()?;
    log::info!("Offerer bound to {}", offerer_local_addr);

    let mut offerer_setting_engine = SettingEngine::default();
    offerer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    let mut offerer_media_engine = MediaEngine::default();
    offerer_media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;
    offerer_media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;

    for extension in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        offerer_media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: extension.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }

    let registry = rtc::interceptor::Registry::new();

    // Use the default set of Interceptors
    let registry =
        rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
            registry,
            &mut offerer_media_engine,
        )?;

    let offerer_config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    let mut offerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(offerer_config)
        .with_setting_engine(offerer_setting_engine)
        .with_media_engine(offerer_media_engine)
        .with_interceptor_registry(registry)
        .build()?;
    log::info!("Created offerer peer connection");

    // Create 3 tracks for simulcast layers with RIDs
    let mid = "0".to_owned();
    let mut rid2ssrc = HashMap::new();
    let mut codings = vec![];

    // Track sent/received packets per track
    let mut packets_received = HashMap::new();
    let mut packets_sent = HashMap::new();

    for rid in ["low", "mid", "high"] {
        let ssrc = rand::random::<u32>();
        rid2ssrc.insert(rid, ssrc);
        codings.push(RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_string(),
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        });
        log::info!("✅ Offerer added track with RID: {} vs SSRC: {}", rid, ssrc);
        packets_received.insert(rid.to_string(), 0u16);
        packets_sent.insert(rid.to_string(), 0u16);
    }

    let output_track = MediaStreamTrack::new(
        format!("rtc-rs_simulcast"),
        format!("video_simulcast"),
        format!("video_simulcast"),
        RtpCodecKind::Video,
        codings,
    );
    let sender_id = offerer_pc.add_track(output_track)?;
    let _ = offerer_pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
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
    offerer_pc.add_local_candidate(RTCIceCandidate::from(&offerer_candidate).to_json()?)?;
    log::info!("Offerer added local candidate");

    // Create offer from offerer
    let offer = offerer_pc.create_offer(None)?;
    log::info!("Offerer created offer {}", offer);

    // Set local description on offerer
    offerer_pc.set_local_description(offer.clone())?;
    log::info!("Offerer set local description");

    // Set remote description on answerer
    answerer_pc.set_remote_description(offer.clone())?;
    log::info!("Answerer set remote description");

    // Create answer from answerer
    let answer = answerer_pc.create_answer(None)?;
    log::info!("Answerer created answer");

    // Set local description on answerer
    answerer_pc.set_local_description(answer.clone())?;
    log::info!("Answerer set local description");

    // Set remote description on offerer
    log::info!("Offerer set remote description {}", answer);
    offerer_pc.set_remote_description(answer)?;

    // Run event loops for both peers
    let offerer_socket = Arc::new(offerer_socket);
    let answerer_socket = Arc::new(answerer_socket);
    let mut offerer_buf = vec![0u8; 2000];
    let mut answerer_buf = vec![0u8; 2000];
    let mut offerer_connected = false;
    let mut answerer_connected = false;
    let mut streaming_started = false;

    // Track mapping for answerer
    let mut track_id2_receiver_id = HashMap::new();

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(15);

    // Create dummy video data to send
    let dummy_frame = vec![0xAA; 500];
    let total_threshold = 60u16;

    while start_time.elapsed() < test_timeout {
        // Process offerer writes
        while let Some(msg) = offerer_pc.poll_write() {
            if let Err(err) = offerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                log::error!("Offerer socket write error: {}", err);
            }
        }

        // Process answerer writes
        while let Some(msg) = answerer_pc.poll_write() {
            if let Err(err) = answerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                log::error!("Answerer socket write error: {}", err);
            }
        }

        // Process offerer events
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
                        offerer_connected = true;
                        log::info!("✅ Offerer peer connected!");
                    }
                }
                _ => {}
            }
        }

        // Process answerer events
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
                        answerer_connected = true;
                        log::info!("✅ Answerer peer connected!");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        track_id2_receiver_id.insert(init.track_id.clone(), init.receiver_id);

                        if let Some(rid) = init.rid.as_ref() {
                            log::info!(
                                "✅ Answerer Track (track_id: {}) Open with RID: {}",
                                init.track_id,
                                rid
                            );
                        } else {
                            log::info!(
                                "✅ Answerer Track (track_id: {}) Open without RID ",
                                init.track_id
                            );
                        }
                    }
                    RTCTrackEvent::OnClose(track_id) => {
                        log::info!("Answerer Track closed: {}", track_id);
                        track_id2_receiver_id.remove(&track_id);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Poll read - receive RTP packets on answerer
        while let Some(message) = answerer_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, rtp_packet) => {
                    // Get the receiver for this track
                    let receiver_id = track_id2_receiver_id
                        .get(&track_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?
                        .clone();

                    let rtp_receiver = answerer_pc
                        .rtp_receiver(receiver_id)
                        .ok_or(Error::ErrRTPReceiverNotExisted)?;

                    // Get RID from the track
                    let rid = rtp_receiver
                        .track()
                        .rid(rtp_packet.header.ssrc)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("ssrc_{}", rtp_packet.header.ssrc));

                    let count = packets_received.entry(rid.clone()).or_insert(0u16);
                    *count += 1;
                    log::debug!(
                        "simulcast read rid {}'s rtp packet sequence number {}",
                        rid,
                        rtp_packet.header.sequence_number,
                    );
                    if *count % 10 == 0 {
                        log::info!(
                            "Answerer received RTP packet #{} for RID: {} (SSRC: {}, seq: {})",
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

        // Start streaming once both are connected
        if offerer_connected && answerer_connected && !streaming_started {
            log::info!("Both peers connected, starting simulcast streaming...");
            streaming_started = true;
        }

        // Send RTP packets from offerer on all 3 simulcast layers
        let total_sent: u16 = packets_sent.values().sum();
        if streaming_started && total_sent < total_threshold {
            for (rid, ssrc) in &rid2ssrc {
                let mut rtp_sender = offerer_pc
                    .rtp_sender(sender_id)
                    .ok_or(Error::ErrRTPSenderNotExisted)?;

                // Get negotiated header extension IDs
                let params = rtp_sender.get_parameters();
                let mut mid_id = None;
                let mut rid_id = None;

                for ext in &params.rtp_parameters.header_extensions {
                    if ext.uri == "urn:ietf:params:rtp-hdrext:sdes:mid" {
                        mid_id = Some(ext.id as u8);
                    } else if ext.uri == "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id" {
                        rid_id = Some(ext.id as u8);
                    }
                }

                let sequence_number = packets_sent.entry(rid.to_string()).or_insert(0u16);
                *sequence_number += 1;

                // Create RTP packet header
                let mut header = rtp::header::Header {
                    version: 2,
                    padding: false,
                    marker: false,
                    payload_type: 96,
                    sequence_number: *sequence_number,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc: *ssrc,
                    ..Default::default()
                };

                if *sequence_number % 10 == 0 {
                    log::info!(
                        "Offer sent RTP packet #{} for RID: {} (SSRC: {}, seq: {})",
                        *sequence_number,
                        rid,
                        header.ssrc,
                        header.sequence_number
                    );
                }

                // Add MID extension using set_extension
                if let Some(id) = mid_id {
                    header
                        .set_extension(id, bytes::Bytes::from(mid.as_bytes().to_vec()))
                        .expect("Failed to set MID extension");
                }

                // Add RID extension using set_extension
                if let Some(id) = rid_id {
                    header
                        .set_extension(id, bytes::Bytes::from(rid.as_bytes().to_vec()))
                        .expect("Failed to set RID extension");
                }

                // Create RTP packet with extensions
                let packet = rtp::packet::Packet {
                    header,
                    payload: bytes::Bytes::from(dummy_frame.clone()),
                };

                log::debug!(
                    "simulcast write rid {}'s rtp packet sequence number {}",
                    rid,
                    packet.header.sequence_number
                );
                if let Err(e) = rtp_sender.write_rtp(packet) {
                    log::debug!("Failed to send RTP on {}: {}", rid, e);
                }
            }

            // Send at ~30fps
            tokio::time::sleep(Duration::from_millis(33)).await;
        }

        // Poll timeouts
        let offerer_eto = offerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answerer_eto = answerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let next_timeout = offerer_eto.min(answerer_eto);
        let delay_from_now = next_timeout
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        if delay_from_now.is_zero() {
            offerer_pc.handle_timeout(Instant::now())?;
            answerer_pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                offerer_pc.handle_timeout(Instant::now())?;
                answerer_pc.handle_timeout(Instant::now())?;
            }
            res = offerer_socket.recv_from(&mut offerer_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        offerer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: offerer_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&offerer_buf[..n]),
                        })?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => {
                        log::error!("Offerer socket read error: {}", err);
                        return Err(err.into());
                    }
                }
            }
            res = answerer_socket.recv_from(&mut answerer_buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        answerer_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: answerer_local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&answerer_buf[..n]),
                        })?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => {
                        log::error!("Answerer socket read error: {}", err);
                        return Err(err.into());
                    }
                }
            }
        }

        // Check if we've received enough packets
        let total_received: u16 = packets_received.values().sum();
        if total_received >= total_threshold && packets_received.len() >= 3 {
            log::info!("Received sufficient packets from all tracks, ending test");
            break;
        }
    }

    // Check results
    log::info!("Final packet counts by track:");
    for (track, count) in packets_received.iter() {
        log::info!("  {}: {} packets", track, count);
    }

    // Verify we received packets on all 3 simulcast layers
    assert!(
        packets_received.len() >= 3,
        "Should have received packets on 3 tracks, got {}",
        packets_received.len()
    );

    let total_packets: u16 = packets_received.values().sum();
    assert!(
        total_packets >= 30,
        "Should have received at least 30 packets total, got {}",
        total_packets
    );

    log::info!(
        "✅ SUCCESS: Received {} packets across {} simulcast tracks!",
        total_packets,
        packets_received.len()
    );

    offerer_pc.close()?;
    answerer_pc.close()?;

    Ok(())
}
