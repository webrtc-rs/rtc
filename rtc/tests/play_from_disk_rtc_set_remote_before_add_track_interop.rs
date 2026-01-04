/// Integration test for play-from-disk with RecvOnly offerer
///
/// This test verifies that webrtc v0.14.0 as offerer with RecvOnly transceivers
/// can receive media from rtc answerer that streams from disk files.
use anyhow::Result;
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Sender, channel};
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

use rtc::media::io::ivf_reader::IVFReader;
use rtc::media::io::ogg_reader::OggReader;
use rtc::media_stream::track::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection as RtcPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer as WebrtcIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as WebrtcRTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::track::track_remote::TrackRemote;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const OGG_PAGE_DURATION: Duration = Duration::from_millis(20);
const RTP_OUTBOUND_MTU: usize = 1200;

/// Test webrtc as RecvOnly offerer, rtc as answerer streaming from disk
#[tokio::test]
async fn test_play_from_disk_rtc_set_remote_before_add_track() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!(
        "Starting play-from-disk RecvOnly offerer interop test: webrtc (receiver) <- rtc (disk)"
    );

    // Determine test data paths
    let video_file = "../examples/examples/test-data/output_vp8.ivf";
    let audio_file = "../examples/examples/test-data/output.ogg";

    // Check if test files exist
    if !Path::new(video_file).exists() {
        log::warn!("Video file not found: {}", video_file);
        return Ok(()); // Skip test if files don't exist
    }
    if !Path::new(audio_file).exists() {
        log::warn!("Audio file not found: {}", audio_file);
        return Ok(()); // Skip test if files don't exist
    }

    // Track received packets
    let video_packets_received = Arc::new(Mutex::new(0u32));
    let video_packets_received_clone = Arc::clone(&video_packets_received);
    let audio_packets_received = Arc::new(Mutex::new(0u32));
    let audio_packets_received_clone = Arc::clone(&audio_packets_received);

    // Create webrtc peer (will be the offerer with RecvOnly transceivers)
    let webrtc_pc = create_webrtc_peer().await?;
    log::info!("Created webrtc peer connection");

    // Add RecvOnly transceivers for video and audio
    webrtc_pc
        .add_transceiver_from_kind(
            RTPCodecType::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                send_encodings: vec![],
            }),
        )
        .await?;
    log::info!("Added RecvOnly video transceiver");

    webrtc_pc
        .add_transceiver_from_kind(
            RTPCodecType::Audio,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                send_encodings: vec![],
            }),
        )
        .await?;
    log::info!("Added RecvOnly audio transceiver");

    // Set up handlers for receiving media
    webrtc_pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver, _transceiver| {
            let video_count = Arc::clone(&video_packets_received_clone);
            let audio_count = Arc::clone(&audio_packets_received_clone);

            Box::pin(async move {
                let codec = track.codec();
                log::info!(
                    "WebRTC got track: {} (codec: {})",
                    track.stream_id(),
                    codec.capability.mime_type
                );

                let is_video = codec.capability.mime_type.contains("video");

                tokio::spawn(async move {
                    while let Ok((_rtp_packet, _)) = track.read_rtp().await {
                        if is_video {
                            let mut count = video_count.lock().await;
                            *count += 1;
                            if *count % 10 == 0 {
                                log::info!("WebRTC received video RTP packet #{}", *count);
                            }
                        } else {
                            let mut count = audio_count.lock().await;
                            *count += 1;
                            if *count % 10 == 0 {
                                log::info!("WebRTC received audio RTP packet #{}", *count);
                            }
                        }
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

    // Create rtc peer (will be the answerer and sender)
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    log::info!("RTC peer bound to {}", local_addr);

    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

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
        payload_type: 120,
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
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build();

    let mut rtc_pc = RtcPeerConnection::new(config)?;
    log::info!("Created RTC peer connection");

    // Set remote description first (the offer from webrtc)
    rtc_pc.set_remote_description(rtc_offer)?;
    log::info!("RTC set remote description");

    // Now add tracks for streaming
    let mut rtp_sender_ids = HashMap::new();
    let mut kind_codecs = HashMap::new();
    kind_codecs.insert(
        RtpCodecKind::Audio,
        (rand::random::<u32>(), audio_codec.clone()),
    );
    kind_codecs.insert(
        RtpCodecKind::Video,
        (rand::random::<u32>(), video_codec.clone()),
    );

    for (&kind, (ssrc, codec)) in &kind_codecs {
        let output_track = MediaStreamTrack::new(
            format!("webrtc-rs-stream-id-{}", kind),
            format!("webrtc-rs-track-id-{}", kind),
            format!("webrtc-rs-track-label-{}", kind),
            kind,
            None,
            *ssrc,
            codec.rtp_codec.clone(),
        );

        let rtp_sender_id = rtc_pc.add_track(output_track)?;
        rtp_sender_ids.insert(kind, rtp_sender_id);
    }
    log::info!("Added tracks to RTC peer");

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

    // Set up media streaming
    let (message_tx, mut message_rx) = channel::<(RTCRtpSenderId, rtp::Packet)>(8);
    let notify_tx = Arc::new(Notify::new());
    let video_notify_rx = notify_tx.clone();
    let audio_notify_rx = notify_tx.clone();

    // Spawn video streaming task
    let (video_done_tx, _video_done_rx) = channel::<()>(1);
    let video_sender_id = *rtp_sender_ids
        .get(&RtpCodecKind::Video)
        .ok_or_else(|| anyhow::anyhow!("Video sender not found"))?;
    let video_message_tx = message_tx.clone();
    let (ssrc, codec) = kind_codecs.get(&RtpCodecKind::Video).cloned().unwrap();
    let video_file_clone = video_file.to_owned();
    tokio::spawn(async move {
        if let Err(err) = stream_video(
            (ssrc, codec),
            video_file_clone,
            video_sender_id,
            video_notify_rx,
            video_done_tx,
            video_message_tx,
        )
        .await
        {
            log::error!("video streaming error: {}", err);
        }
    });

    // Spawn audio streaming task
    let (audio_done_tx, _audio_done_rx) = channel::<()>(1);
    let audio_sender_id = *rtp_sender_ids
        .get(&RtpCodecKind::Audio)
        .ok_or_else(|| anyhow::anyhow!("Audio sender not found"))?;
    let audio_message_tx = message_tx.clone();
    let (ssrc, codec) = kind_codecs.get(&RtpCodecKind::Audio).cloned().unwrap();
    let audio_file_clone = audio_file.to_owned();
    tokio::spawn(async move {
        if let Err(err) = stream_audio(
            (ssrc, codec),
            audio_file_clone,
            audio_sender_id,
            audio_notify_rx,
            audio_done_tx,
            audio_message_tx,
        )
        .await
        {
            log::error!("audio streaming error: {}", err);
        }
    });

    // Run event loops for both peers
    let mut buf = vec![0u8; 2000];
    let mut rtc_connected = false;
    let mut webrtc_connected = false;
    let mut streaming_started = false;

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
                _ => {}
            }
        }

        // Check webrtc connection state
        if !webrtc_connected
            && webrtc_pc.connection_state() == WebrtcRTCPeerConnectionState::Connected
        {
            log::info!("WebRTC peer connection connected!");
            webrtc_connected = true;
        }

        // Start streaming once both are connected
        if rtc_connected && webrtc_connected && !streaming_started {
            log::info!("Both peers connected, starting media streaming");
            notify_tx.notify_waiters();
            streaming_started = true;
        }

        // Handle media messages from streaming tasks
        while let Ok((rtp_sender_id, packet)) = message_rx.try_recv() {
            let mut rtp_sender = rtc_pc
                .rtp_sender(rtp_sender_id)
                .ok_or_else(|| anyhow::anyhow!("RTP sender not found"))?;

            log::trace!("sending rtp packet with ssrc={}", packet.header.ssrc);
            rtp_sender.write_rtp(packet)?;
        }

        // Check if we've received enough packets
        let video_count = *video_packets_received.lock().await;
        let audio_count = *audio_packets_received.lock().await;

        if streaming_started && video_count >= 20 && audio_count >= 20 {
            log::info!("✅ Test completed successfully!");
            log::info!(
                "   Received {} video packets and {} audio packets",
                video_count,
                audio_count
            );

            assert!(
                video_count >= 20,
                "Should have received at least 20 video packets"
            );
            assert!(
                audio_count >= 20,
                "Should have received at least 20 audio packets"
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

async fn stream_video(
    (ssrc, codec): (SSRC, RTCRtpCodecParameters),
    video_file_name: String,
    video_sender_id: RTCRtpSenderId,
    video_notify_rx: Arc<Notify>,
    video_done_tx: Sender<()>,
    video_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
) -> Result<()> {
    use std::fs::File;
    use std::io::BufReader;

    // Open a IVF file and start reading using our IVFReader
    let file = File::open(&video_file_name)?;
    let reader = BufReader::new(file);
    let (mut ivf, header) = IVFReader::new(reader)?;

    // Wait for connection established
    video_notify_rx.notified().await;

    log::info!("play video from disk file {video_file_name}");

    let mut packetizer = rtp::packetizer::new_packetizer(
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    let sleep_time = Duration::from_millis(
        ((1000 * header.timebase_numerator) / header.timebase_denominator) as u64,
    );
    let mut ticker = tokio::time::interval(sleep_time);

    // Stream only a limited number of frames for the test
    let max_frames = 30;
    let mut frame_count = 0;

    loop {
        let frame = match ivf.parse_next_frame() {
            Ok((frame, _)) => frame,
            Err(err) => {
                log::info!("All video frames parsed and sent: {err}");
                break;
            }
        };

        let sample_duration = Duration::from_millis(40);
        let samples = (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
        let packets = packetizer.packetize(&frame.freeze(), samples)?;
        for packet in packets {
            video_message_tx.send((video_sender_id, packet)).await?;
        }

        frame_count += 1;
        if frame_count >= max_frames {
            log::info!("Streamed {} video frames", frame_count);
            break;
        }

        let _ = ticker.tick().await;
    }

    let _ = video_done_tx.try_send(());

    Ok(())
}

async fn stream_audio(
    (ssrc, codec): (SSRC, RTCRtpCodecParameters),
    audio_file_name: String,
    audio_sender_id: RTCRtpSenderId,
    audio_notify_rx: Arc<Notify>,
    audio_done_tx: Sender<()>,
    audio_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
) -> Result<()> {
    use std::fs::File;
    use std::io::BufReader;

    // Open a OGG file and start reading using our OGGReader
    let file = File::open(&audio_file_name)?;
    let reader = BufReader::new(file);
    let (mut ogg, _) = match OggReader::new(reader, true) {
        Ok(tup) => tup,
        Err(err) => {
            log::error!("error while opening audio file {audio_file_name}: {err}");
            return Err(err.into());
        }
    };

    // Wait for connection established
    audio_notify_rx.notified().await;

    log::info!("play audio from disk file {audio_file_name}");

    let mut packetizer = rtp::packetizer::new_packetizer(
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    let mut ticker = tokio::time::interval(OGG_PAGE_DURATION);

    // Keep track of last granule
    let mut last_granule: u64 = 0;

    // Stream only a limited number of pages for the test
    let max_pages = 30;
    let mut page_count = 0;

    while let Ok((page_data, page_header)) = ogg.parse_next_page() {
        let sample_count = page_header.granule_position - last_granule;
        last_granule = page_header.granule_position;
        let sample_duration = Duration::from_millis(sample_count * 1000 / 48000);

        let samples = (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
        let packets = packetizer.packetize(&page_data.freeze(), samples)?;
        for packet in packets {
            audio_message_tx.send((audio_sender_id, packet)).await?;
        }

        page_count += 1;
        if page_count >= max_pages {
            log::info!("Streamed {} audio pages", page_count);
            break;
        }

        let _ = ticker.tick().await;
    }

    let _ = audio_done_tx.try_send(());

    Ok(())
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
