/// Integration test for TRUE simulcast with RID (rtc → webrtc)
///
/// This test demonstrates TRUE simulcast by having rtc send 3 simulcast layers
/// with proper RID header extensions, and webrtc receive them.
///
/// **Why this direction works:**
/// - rtc (sansio) has full simulcast support with RID as the SENDER
/// - rtc automatically adds RID header extensions to outgoing RTP packets
/// - webrtc v0.14.0 can properly RECEIVE simulcast streams with RIDs
/// - The `/examples/simulcast/` example proves rtc→browser simulcast works
///
/// **Test flow:**
/// 1. rtc creates 3 tracks with RIDs ("low"/"mid"/"high") and adds to peer
/// 2. rtc creates offer with proper simulcast SDP
/// 3. webrtc receives offer and creates answer
/// 4. rtc sends RTP packets with RID header extensions on each track
/// 5. webrtc receives packets and can identify them by track
/// 6. Test verifies webrtc received packets from all 3 simulcast layers
use anyhow::Result;
use bytes::BytesMut;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::track::track_remote::TrackRemote;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// Test simulcast: rtc sends 3 layers with RIDs -> webrtc receives all 3 layers
#[tokio::test]
async fn test_simulcast_rtc_to_webrtc() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("Starting TRUE simulcast test: rtc (sender) -> webrtc (receiver)");

    // Track received packets per track on webrtc side
    let packets_received = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let packets_received_clone = Arc::clone(&packets_received);

    // Create webrtc peer (will be the answerer and receiver)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Add transceiver to receive video
    /*webrtc_pc
        .add_transceiver_from_kind(
            RTPCodecType::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                send_encodings: vec![],
            }),
        )
        .await?;
    log::info!("Added video transceiver to webrtc");*/

    // Set up handler for receiving media on all tracks
    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let packets_count = Arc::clone(&packets_received_clone);
            Box::pin(async move {
                let track_id = track.stream_id();
                let track_rid = track.rid();
                let codec = track.codec();
                log::info!(
                    "✅ WebRTC got track: {} (codec: {}, rid: {:?})",
                    track_id,
                    codec.capability.mime_type,
                    track_rid
                );

                let track_key = format!("{}_{}", track_id, track_rid);

                tokio::spawn(async move {
                    while let Ok((rtp_packet, _)) = track.read_rtp().await {
                        let mut count = packets_count.lock().await;
                        let counter = count.entry(track_key.clone()).or_insert(0);
                        *counter += 1;
                        if *counter % 10 == 0 {
                            log::info!(
                                "WebRTC received packet #{} on track {} (seq: {})",
                                *counter,
                                track_key,
                                rtp_packet.header.sequence_number
                            );
                        }
                    }
                });
            })
        },
    ));

    // Create rtc peer (will be the offerer and sender)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

    // Create MediaEngine with simulcast support
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

    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;
    media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;

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
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Create 3 tracks for simulcast layers with RIDs
    let mid = "0".to_owned();
    let mut rid2ssrc = HashMap::new();
    let mut codings = vec![];
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
        log::info!("✅ RTC added track with RID: {} vs SSRC: {}", rid, ssrc);
    }

    let output_track = MediaStreamTrack::new(
        format!("webrtc-rs_simulcast"),
        format!("video_simulcast"),
        format!("video_simulcast"),
        RtpCodecKind::Video,
        codings,
    );
    let sender_id = rtc_pc.add_track(output_track)?;
    let _ = rtc_pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    );

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
    let mut streaming_started = false;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(15);

    // Create dummy video data to send
    let dummy_frame = vec![0xAA; 500];
    let mut sequence_number = 0;

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
                _ => {}
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            webrtc_connected = true;
            log::info!("✅ WebRTC peer connected!");
        }

        // Start streaming once both are connected
        if rtc_connected && webrtc_connected && !streaming_started {
            log::info!("Both peers connected, starting simulcast streaming...");
            streaming_started = true;
        }

        // Send RTP packets from rtc on all 3 simulcast layers
        if streaming_started {
            for (rid, ssrc) in &rid2ssrc {
                let mut rtp_sender = rtc_pc
                    .rtp_sender(sender_id)
                    .ok_or(Error::ErrRTPSenderNotExisted)?;

                // Get negotiated header extension IDs
                let params = rtp_sender.get_parameters();
                let mut mid_id = None;
                let mut rid_id = None;

                for ext in &params.rtp_parameters.header_extensions {
                    if ext.uri == "urn:ietf:params:rtp-hdrext:sdes:mid" {
                        mid_id = Some(ext.id as u8);
                        log::debug!("Found MID extension with ID: {}", ext.id);
                    } else if ext.uri == "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id" {
                        rid_id = Some(ext.id as u8);
                        log::debug!("Found RID extension with ID: {}", ext.id);
                    }
                }

                if mid_id.is_none() {
                    log::warn!("MID extension ID not found in negotiated parameters!");
                }
                if rid_id.is_none() {
                    log::warn!("RID extension ID not found in negotiated parameters!");
                }

                // Create RTP packet header
                let mut header = rtp::header::Header {
                    version: 2,
                    padding: false,
                    marker: false,
                    payload_type: 96,
                    sequence_number,
                    timestamp: (Instant::now().duration_since(start_time).as_millis() * 90) as u32,
                    ssrc: *ssrc,
                    ..Default::default()
                };

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

                if let Err(e) = rtp_sender.write_rtp(packet) {
                    log::debug!("Failed to send RTP on {}: {}", rid, e);
                }
                sequence_number += 1;
            }

            // Send at ~30fps
            tokio::time::sleep(Duration::from_millis(33)).await;
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

        // Check if we've received enough packets
        let received_count = packets_received.lock().await;
        let total: u32 = received_count.values().sum();
        if total >= 30 && received_count.len() >= 3 {
            log::info!("Received sufficient packets from all tracks, ending test");
            break;
        }
    }

    // Check results
    let final_counts = packets_received.lock().await;
    log::info!("Final packet counts by track:");
    for (track, count) in final_counts.iter() {
        log::info!("  {}: {} packets", track, count);
    }

    // Verify we received packets on all 3 simulcast layers
    assert!(
        final_counts.len() >= 3,
        "Should have received packets on 3 tracks, got {}",
        final_counts.len()
    );

    let total_packets: u32 = final_counts.values().sum();
    assert!(
        total_packets >= 30,
        "Should have received at least 30 packets total, got {}",
        total_packets
    );

    log::info!(
        "✅ SUCCESS: Received {} packets across {} simulcast tracks from RTC!",
        total_packets,
        final_counts.len()
    );

    rtc_pc.close()?;
    webrtc_pc.close().await?;

    Ok(())
}

async fn create_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
    media_engine.register_default_codecs()?;

    // Register header extensions for simulcast support
    // These must match the extensions registered on the RTC (sender) side
    use webrtc::rtp_transceiver::rtp_codec::RTCRtpHeaderExtensionCapability as WebrtcHeaderExtCap;

    for extension_uri in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        media_engine.register_header_extension(
            WebrtcHeaderExtCap {
                uri: extension_uri.to_owned(),
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
