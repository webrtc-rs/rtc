//! A rid simulcast publisher names its repair flows on the wire, and the receiver must read them.
//!
//! A non-simulcast publisher names its repair flow in the SDP with
//! `a=ssrc-group:FID <primary> <rtx>` (RFC 5576). A simulcast publisher cannot: the offer names
//! rids, not SSRCs, so the only statement of which repair stream belongs to which layer is the
//! `repaired-rtp-stream-id` header extension on the wire (RFC 8852 section 4).
//!
//! Three layers publish, one packet of each is never sent, and the answerer's NACK generator asks
//! for all three back. Each is answered with a retransmission carrying an rrid — the only thing
//! that says which layer it repairs — and the test holds that every one of them is de-encapsulated
//! and delivered under the SSRC and sequence number of the layer it belongs to.
//!
//! The failure this guards against is silent and internal: without the pairing the retransmission
//! is discarded in `EndpointHandler::find_track_id`, because no track owns a repair SSRC the SDP
//! never mentioned. The application never sees the packet and never learns it was dropped — it
//! sees only a gap that its own NACK was answered for.
//!
//! The retransmissions are built by the test rather than by the offerer's NACK responder, which
//! sends no header extensions and so cannot name the layer it is repairing. Building them here is
//! what lets the answerer be tested against a publisher that does.

use anyhow::Result;
use bytes::BytesMut;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

mod common;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

const MID: &str = "0";
const RIDS: [&str; 3] = ["low", "mid", "high"];

const VP8_PT: u8 = 96;
const VP8_RTX_PT: u8 = 97;

const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const SDES_RID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
const SDES_RRID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

/// The sequence number each layer skips. Chosen well inside the run so that packets arrive on
/// either side of it — a gap is only a gap once something after it has been seen.
const LOST_SEQUENCE_NUMBER: u16 = 5;

/// Marks the payload of a retransmission, so a repaired packet cannot be mistaken for an original
/// that simply arrived late.
const REPAIR_MARKER: &[u8] = b"repaired-by-rrid";

fn video_codec(mime_type: &str, payload_type: u8, sdp_fmtp_line: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: sdp_fmtp_line.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
        ..Default::default()
    }
}

/// VP8 and its RTX pairing, plus the three simulcast header extensions.
///
/// Registering the RTX codec is what decides whether a repair flow can exist at all: the receiver
/// resolves a retransmission's original payload type from the negotiated RTX codec's `apt=`, so
/// without it the pairing has nowhere to land even once the rrid names the layer.
fn simulcast_media_engine() -> Result<MediaEngine> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(video_codec(MIME_TYPE_VP8, VP8_PT, ""), RtpCodecKind::Video)?;
    media_engine.register_codec(
        video_codec(MIME_TYPE_RTX, VP8_RTX_PT, &format!("apt={VP8_PT}")),
        RtpCodecKind::Video,
    )?;

    for uri in [SDES_MID_URI, SDES_RID_URI, SDES_RRID_URI] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }

    Ok(media_engine)
}

/// RFC 4588 section 4: the retransmission payload is `[OSN: u16 big-endian][original payload]`,
/// and the header names the repair flow's own SSRC, payload type and sequence-number space.
///
/// The rrid is the whole point: it is the only place the packet says which of the three layers it
/// repairs, and it is set here because the offerer's NACK responder does not set it.
fn repair_packet(
    ssrc_rtx: u32,
    sequence_number_rtx: u16,
    original_sequence_number: u16,
    rrid: &str,
    extension_ids: &HashMap<String, u8>,
) -> Result<rtp::packet::Packet> {
    let mut header = rtp::header::Header {
        version: 2,
        payload_type: VP8_RTX_PT,
        sequence_number: sequence_number_rtx,
        ssrc: ssrc_rtx,
        ..Default::default()
    };

    for (uri, value) in [(SDES_MID_URI, MID), (SDES_RRID_URI, rrid)] {
        let id = *extension_ids
            .get(uri)
            .ok_or_else(|| anyhow::anyhow!("{uri} was not negotiated"))?;
        header.set_extension(id, bytes::Bytes::from(value.as_bytes().to_vec()))?;
    }

    let mut payload = original_sequence_number.to_be_bytes().to_vec();
    payload.extend_from_slice(REPAIR_MARKER);

    Ok(rtp::packet::Packet {
        header,
        payload: payload.into(),
    })
}

/// A 3-layer rid simulcast publisher, one lost packet per layer, each repaired over RTX with an
/// rrid naming its layer.
#[tokio::test]
async fn test_simulcast_rrid_rtx_rtc_to_rtc() -> Result<()> {
    common::install_crypto_provider();

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    // Answerer — the peer under test. It receives three rid layers and must pair each repair flow
    // with the layer its rrid names.
    let answerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let answerer_local_addr = answerer_socket.local_addr()?;

    let answerer_setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Server)
        .build();
    let mut answerer_media_engine = simulcast_media_engine()?;
    let answerer_registry =
        rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
            Registry::new(),
            &mut answerer_media_engine,
        )?;

    let mut answerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(answerer_setting_engine)
        .with_media_engine(answerer_media_engine)
        .with_interceptor_registry(answerer_registry)
        .build(Instant::now())?;

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

    // Offerer — the publisher.
    let offerer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let offerer_local_addr = offerer_socket.local_addr()?;

    let offerer_setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Server)
        .build();
    let mut offerer_media_engine = simulcast_media_engine()?;
    let offerer_registry =
        rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
            Registry::new(),
            &mut offerer_media_engine,
        )?;

    let mut offerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(offerer_setting_engine)
        .with_media_engine(offerer_media_engine)
        .with_interceptor_registry(offerer_registry)
        .build(Instant::now())?;

    // Three layers, each with a media SSRC and a repair SSRC. Only the media SSRCs reach the SDP:
    // a rid offer describes its encodings with `a=rid`/`a=simulcast` and names no SSRC at all, so
    // the repair SSRCs below exist purely on the wire.
    let mut layers: Vec<(&str, u32, u32)> = vec![];
    let mut codings = vec![];
    for (index, rid) in RIDS.iter().enumerate() {
        let ssrc = 0x1000_0000 + index as u32;
        let ssrc_rtx = 0x2000_0000 + index as u32;
        layers.push((rid, ssrc, ssrc_rtx));
        codings.push(RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_string(),
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: video_codec(MIME_TYPE_VP8, VP8_PT, "").rtp_codec,
            ..Default::default()
        });
    }

    let output_track = MediaStreamTrack::new(
        "rtc-rs_simulcast".to_owned(),
        "video_simulcast".to_owned(),
        "video_simulcast".to_owned(),
        RtpCodecKind::Video,
        codings,
    );
    let sender_id = offerer_pc.add_track(output_track)?;

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
        offer.sdp.contains(SDES_RRID_URI),
        "a simulcast offer must offer rrid, or the answer never negotiates the only extension \
         that can name a repair flow's layer:\n{}",
        offer.sdp
    );
    assert!(
        !offer.sdp.contains("a=ssrc-group:FID"),
        "a rid offer names no SSRCs, so it cannot declare a repair flow the way RFC 5576 does — \
         which is the whole reason rrid exists:\n{}",
        offer.sdp
    );

    offerer_pc.set_local_description(Instant::now(), offer.clone())?;
    answerer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answerer_pc.create_answer(None)?;
    answerer_pc.set_local_description(Instant::now(), answer.clone())?;
    offerer_pc.set_remote_description(Instant::now(), answer)?;

    let offerer_socket = Arc::new(offerer_socket);
    let answerer_socket = Arc::new(answerer_socket);
    let mut offerer_buf = vec![0u8; 2000];
    let mut answerer_buf = vec![0u8; 2000];
    let mut offerer_connected = false;
    let mut answerer_connected = false;

    let mut track_id2_receiver_id = HashMap::new();

    // Per layer: how many originals have been sent, and how many the answerer has delivered.
    let mut packets_sent: HashMap<&str, u16> = RIDS.iter().map(|rid| (*rid, 0u16)).collect();
    let mut packets_received: HashMap<&str, u16> = RIDS.iter().map(|rid| (*rid, 0u16)).collect();
    // Layers whose loss the answerer has asked back, and layers whose repair it has delivered.
    let mut nacked: HashSet<&str> = HashSet::new();
    let mut repaired: HashSet<&str> = HashSet::new();

    let dummy_frame = vec![0xAA; 500];
    let originals_per_layer = 20u16;

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(20);

    while start_time.elapsed() < test_timeout && repaired.len() < RIDS.len() {
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
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                    RTCIceConnectionState::Failed,
                ) => return Err(anyhow::anyhow!("Offerer ICE connection failed")),
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Offerer peer connection failed"));
                    }
                    offerer_connected |= state == RTCPeerConnectionState::Connected;
                }
                _ => {}
            }
        }

        while let Some(event) = answerer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                    RTCIceConnectionState::Failed,
                ) => return Err(anyhow::anyhow!("Answerer ICE connection failed")),
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("Answerer peer connection failed"));
                    }
                    answerer_connected |= state == RTCPeerConnectionState::Connected;
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    log::info!(
                        "Answerer track {} open, rid {:?}, ssrc {}",
                        init.track_id,
                        init.rid,
                        init.ssrc
                    );
                    track_id2_receiver_id.insert(init.track_id.clone(), init.receiver_id);
                }
                _ => {}
            }
        }

        // Repair each layer once the answerer has asked for it.
        //
        // The asking is read from the answerer's own stats rather than off the offerer's wire.
        // Inbound RTCP is chain business: the chain's terminus drops a report no interceptor
        // marked for delivery, so a NACK that the offerer's NACK responder has already handled
        // never reaches its application — and handle it is all the responder can do, which for a
        // packet that was never sent is nothing. The answerer's `nackCount` is the same event
        // seen from the end that generated it, and it is per layer, which is what matters here.
        if nacked.len() < RIDS.len() {
            let stats = answerer_pc.get_stats(Instant::now(), StatsSelector::None);
            let asking: Vec<u32> = stats
                .inbound_rtp_streams()
                .filter(|stream| stream.nack_count > 0)
                .map(|stream| stream.received_rtp_stream_stats.rtp_stream_stats.ssrc)
                .collect();

            for (rid, ssrc, ssrc_rtx) in &layers {
                if !asking.contains(ssrc) || nacked.contains(rid) {
                    continue;
                }
                nacked.insert(rid);

                log::info!(
                    "Answerer asked {rid} back; repairing seq {LOST_SEQUENCE_NUMBER} over rtx ssrc {ssrc_rtx}"
                );
                let extension_ids = negotiated_extension_ids(&mut offerer_pc, sender_id)?;
                // A repair flow numbers its own packets, so this is its first: only the OSN in
                // the payload refers to the layer's sequence space.
                let packet =
                    repair_packet(*ssrc_rtx, 1, LOST_SEQUENCE_NUMBER, rid, &extension_ids)?;
                // Not `RTCRtpSender::write_rtp`: that accepts only the SSRCs of the sender's own
                // encodings, and a repair flow is not one of them.
                offerer_pc.handle_write(TaggedRTCMessage {
                    now: Instant::now(),
                    message: RTCMessage::RtpPacket("video_simulcast".to_owned(), packet),
                })?;
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = answerer_pc.poll_read() {
            let RTCMessage::RtpPacket(track_id, rtp_packet) = message else {
                continue;
            };

            let receiver_id = *track_id2_receiver_id
                .get(&track_id)
                .ok_or(Error::ErrRTPReceiverNotExisted)?;
            let rid = answerer_pc
                .rtp_receiver(receiver_id)
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .track()
                .rid(rtp_packet.header.ssrc)
                .map(|rid| rid.to_string())
                .unwrap_or_else(|| format!("ssrc_{}", rtp_packet.header.ssrc));
            let Some(&(rid, ssrc, _)) = layers.iter().find(|(layer, _, _)| *layer == rid) else {
                panic!("answerer delivered a packet under an unknown rid {rid}");
            };

            *packets_received.entry(rid).or_insert(0) += 1;

            if rtp_packet.header.sequence_number == LOST_SEQUENCE_NUMBER {
                assert_eq!(
                    ssrc, rtp_packet.header.ssrc,
                    "a repaired packet must arrive under the SSRC of the layer it repairs, not \
                     the repair flow's own"
                );
                assert_eq!(
                    VP8_PT, rtp_packet.header.payload_type,
                    "de-encapsulation must restore the original payload type from the RTX \
                     codec's apt"
                );
                assert_eq!(
                    REPAIR_MARKER,
                    &rtp_packet.payload[..],
                    "the OSN header must be stripped, leaving the original payload"
                );
                repaired.insert(rid);
            }
        }

        // Publish, skipping one sequence number per layer so there is something to repair.
        if offerer_connected && answerer_connected {
            for (rid, ssrc, _) in &layers {
                let sent = packets_sent.entry(rid).or_insert(0);
                if *sent >= originals_per_layer {
                    continue;
                }
                *sent += 1;
                if *sent == LOST_SEQUENCE_NUMBER {
                    // Never sent, so the offerer's NACK responder has nothing to retransmit and
                    // only the rrid path can fill the gap.
                    *sent += 1;
                }

                let extension_ids = negotiated_extension_ids(&mut offerer_pc, sender_id)?;
                let mut header = rtp::header::Header {
                    version: 2,
                    payload_type: VP8_PT,
                    sequence_number: *sent,
                    timestamp: (start_time.elapsed().as_millis() * 90) as u32,
                    ssrc: *ssrc,
                    ..Default::default()
                };
                for (uri, value) in [(SDES_MID_URI, MID), (SDES_RID_URI, rid)] {
                    let id = *extension_ids
                        .get(uri)
                        .ok_or_else(|| anyhow::anyhow!("{uri} was not negotiated"))?;
                    header.set_extension(id, bytes::Bytes::from(value.as_bytes().to_vec()))?;
                }

                let mut rtp_sender = offerer_pc
                    .rtp_sender(sender_id)
                    .ok_or(Error::ErrRTPSenderNotExisted)?;
                rtp_sender.write_rtp(
                    Instant::now(),
                    rtp::packet::Packet {
                        header,
                        payload: bytes::Bytes::from(dummy_frame.clone()),
                    },
                )?;
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let next_timeout = offerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION)
            .min(
                answerer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION),
            );
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

    for rid in RIDS {
        assert!(
            packets_received[rid] > 0,
            "the {rid} layer delivered nothing, so the repair it is asked about below would \
             prove nothing"
        );
        assert!(
            nacked.contains(rid),
            "the {rid} layer's loss was never asked back — without a NACK there is no \
             retransmission to pair"
        );
        assert!(
            repaired.contains(rid),
            "the {rid} layer's retransmission never reached the application: its rrid named the \
             layer, and nothing else could have"
        );
    }

    // The pairing is what lets a repair flow's bytes be attributed at all: `on_rtx_packet_received`
    // resolves the arriving SSRC through the map the pairing fills, and for rid simulcast nothing
    // else ever fills it.
    let stats = answerer_pc.get_stats(Instant::now(), StatsSelector::None);
    let repaired_layers = stats
        .inbound_rtp_streams()
        .filter(|stream| stream.retransmitted_packets_received > 0)
        .count();
    assert_eq!(
        RIDS.len(),
        repaired_layers,
        "every layer's retransmission must be counted against that layer"
    );

    offerer_pc.close()?;
    answerer_pc.close()?;

    Ok(())
}

/// The ids the peers agreed on for the simulcast extensions.
///
/// Read back from the sender rather than assumed: the answer decides them, and a guess that
/// disagreed would put the rid and rrid where the receiver does not look for them.
fn negotiated_extension_ids(
    offerer_pc: &mut rtc::peer_connection::RTCPeerConnection,
    sender_id: rtc::rtp_transceiver::RTCRtpSenderId,
) -> Result<HashMap<String, u8>> {
    let mut rtp_sender = offerer_pc
        .rtp_sender(sender_id)
        .ok_or(Error::ErrRTPSenderNotExisted)?;
    Ok(rtp_sender
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .map(|extension| (extension.uri.clone(), extension.id as u8))
        .collect())
}
