//! Integration test for media-only rtc-to-rtc negotiation without SCTP.
//!
//! This is a regression test for commit 897422b8:
//! "Only start SCTP transport if application media has been negotiated".
//!
//! Test scenario:
//! - Offerer negotiates a single video track only
//! - Neither SDP contains an `m=application` section
//! - RTP flows successfully between the peers
//! - No data-channel events or data-channel messages are observed

use anyhow::Result;
use bytes::BytesMut;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

fn build_video_only_peer(
    role: RTCDtlsRole,
) -> Result<rtc::peer_connection::RTCPeerConnection<impl rtc::interceptor::Interceptor>> {
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_answering_dtls_role(role)?;

    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            payload_type: 96,
            ..Default::default()
        },
        RtpCodecKind::Video,
    )?;

    RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .build()
        .map_err(Into::into)
}

#[tokio::test]
async fn test_media_only_negotiation_does_not_start_sctp() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let answerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let answerer_local_addr = answerer_socket.local_addr()?;
    let mut answerer_pc = build_video_only_peer(RTCDtlsRole::Client)?;

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

    let offerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let offerer_local_addr = offerer_socket.local_addr()?;
    let mut offerer_pc = build_video_only_peer(RTCDtlsRole::Server)?;

    let ssrc = rand::random::<u32>();
    let video_track = MediaStreamTrack::new(
        "media-only-stream".to_owned(),
        "video-track".to_owned(),
        "video-track".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    );
    let sender_id = offerer_pc.add_track(video_track)?;

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

    let offer = offerer_pc.create_offer(None)?;
    assert!(
        !offer
            .sdp
            .lines()
            .any(|line| line.starts_with("m=application ")),
        "media-only offer should not contain an application m-line:\n{}",
        offer.sdp
    );
    offerer_pc.set_local_description(offer.clone())?;
    answerer_pc.set_remote_description(offer)?;

    let answer = answerer_pc.create_answer(None)?;
    assert!(
        !answer
            .sdp
            .lines()
            .any(|line| line.starts_with("m=application ")),
        "media-only answer should not contain an application m-line:\n{}",
        answer.sdp
    );
    answerer_pc.set_local_description(answer.clone())?;
    offerer_pc.set_remote_description(answer)?;

    let mut offerer_buf = vec![0u8; 2000];
    let mut answerer_buf = vec![0u8; 2000];
    let mut offerer_connected = false;
    let mut answerer_connected = false;
    let mut track_opened = false;
    let mut rtp_packets_received = 0u16;
    let mut rtp_packets_sent = 0u16;
    let mut unexpected_data_channel_events = 0u16;
    let mut unexpected_data_channel_messages = 0u16;
    let total_threshold = 15u16;
    let dummy_frame = vec![0xAA; 500];

    let start_time = Instant::now();
    while start_time.elapsed() < Duration::from_secs(15) {
        while let Some(msg) = offerer_pc.poll_write() {
            offerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(msg) = answerer_pc.poll_write() {
            answerer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = offerer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("offerer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("offerer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        offerer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(_) => {
                    unexpected_data_channel_events += 1;
                }
                _ => {}
            }
        }

        while let Some(event) = answerer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    if state == RTCIceConnectionState::Failed {
                        return Err(anyhow::anyhow!("answerer ICE connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("answerer peer connection failed"));
                    }
                    if state == RTCPeerConnectionState::Connected {
                        answerer_connected = true;
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_)) => {
                    track_opened = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(_) => {
                    unexpected_data_channel_events += 1;
                }
                _ => {}
            }
        }

        while let Some(message) = offerer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, _) = message {
                unexpected_data_channel_messages += 1;
            }
        }

        while let Some(message) = answerer_pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(_, _) => {
                    rtp_packets_received += 1;
                }
                RTCMessage::DataChannelMessage(_, _) => {
                    unexpected_data_channel_messages += 1;
                }
                RTCMessage::RtcpPacket(_, _) => {}
            }
        }

        if offerer_connected && answerer_connected && rtp_packets_sent < total_threshold {
            let mut rtp_sender = offerer_pc
                .rtp_sender(sender_id)
                .ok_or_else(|| anyhow::anyhow!("rtp sender not found"))?;
            rtp_packets_sent += 1;
            // write_rtp requires the packet's PT to match a negotiated codec; derive it
            // from the sender's parameters instead of hardcoding (single video codec).
            let payload_type = rtp_sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .first()
                .map(|codec| codec.payload_type)
                .unwrap_or(96);
            rtp_sender.write_rtp(rtp::packet::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type,
                    sequence_number: rtp_packets_sent,
                    timestamp: rtp_packets_sent as u32 * 3000,
                    ssrc,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(dummy_frame.clone()),
            })?;
        }

        if rtp_packets_received >= total_threshold {
            break;
        }

        let offerer_eto = offerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answerer_eto = answerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offerer_eto.min(answerer_eto);
        let delay = next_timeout
            .checked_duration_since(Instant::now())
            .unwrap_or_default();

        if delay.is_zero() {
            offerer_pc.handle_timeout(Instant::now())?;
            answerer_pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay.min(Duration::from_millis(10)));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() => {
                offerer_pc.handle_timeout(Instant::now())?;
                answerer_pc.handle_timeout(Instant::now())?;
            }
            res = offerer_socket.recv_from(&mut offerer_buf) => {
                let (n, peer_addr) = res?;
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
            res = answerer_socket.recv_from(&mut answerer_buf) => {
                let (n, peer_addr) = res?;
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
        }
    }

    assert!(offerer_connected, "offerer should connect");
    assert!(answerer_connected, "answerer should connect");
    assert!(
        track_opened,
        "answerer should open the negotiated video track"
    );
    assert!(
        rtp_packets_received >= total_threshold,
        "answerer should receive RTP packets, got {}",
        rtp_packets_received
    );
    assert_eq!(
        unexpected_data_channel_events, 0,
        "media-only negotiation should not emit data-channel events"
    );
    assert_eq!(
        unexpected_data_channel_messages, 0,
        "media-only negotiation should not produce data-channel messages"
    );

    offerer_pc.close()?;
    answerer_pc.close()?;

    Ok(())
}
