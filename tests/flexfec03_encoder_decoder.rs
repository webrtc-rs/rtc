//! FlexFEC-03 end to end: the encoder protects, the path loses, the decoder rebuilds.
//!
//! The two halves of [`play-from-disk-fec`](../examples/play-from-disk-fec) and
//! [`save-to-disk-fec`](../examples/save-to-disk-fec) in one process, with the assertion those
//! examples can only gesture at: **every media packet the sender discarded arrives at the
//! receiver, and arrives marked as rebuilt.**
//!
//! # Why sequence numbers rather than counts
//!
//! A recovered packet is re-injected where the decoder finishes rebuilding it, not where it would
//! have arrived, so the inbound stream is not in sequence order. Counting is therefore not enough —
//! "we dropped 10 and received 200" holds just as well if FEC rebuilt the wrong ten. Both sides
//! report the sequence numbers they acted on and the test compares the two *sets*, which is order
//! independent and says exactly which packets were involved.
//!
//! # Why the chain is this small
//!
//! Neither side calls `register_default_interceptors`. With the NACK pair in the chain the receiver
//! would ask for the missing packets and the sender would retransmit them, so the packets would
//! come back and the test would pass with the FEC decoder doing nothing at all. Retransmission is a
//! perfectly good recovery mechanism; it is just not the one under test.

use anyhow::Result;
use bytes::BytesMut;
use rtc::interceptor::{
    Attribute, FlexFec03ReceiveBuilder, FlexFec03SendBuilder, Interceptor, Packet, Registry, Slot,
    StreamInfo, TaggedPacket,
};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpFecParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

mod common;

const VP8_PT: u8 = 96;
const FLEX_FEC_PT: u8 = 49;

const MEDIA_SSRC: SSRC = 0x1111_1111;
const FEC_SSRC: SSRC = 0x2222_2222;

/// One repair packet per ten media packets recovers a single loss anywhere in the block.
const NUM_MEDIA_PACKETS: u32 = 10;
const NUM_FEC_PACKETS: u32 = 1;

/// Drop one media packet in twenty.
///
/// Chosen against the repair rate above, not for realism: at most one loss lands in any block of
/// ten, so every loss is recoverable and the test can demand *all* of them back. At one in five —
/// what `play-from-disk-fec` defaults to — most blocks lose two and the correct expectation would
/// be a fraction, which is a much weaker thing to assert.
const DROP_ONE_IN: u64 = 20;

/// Enough to exercise twenty FEC blocks, so a systematic failure cannot hide behind one lucky one.
const MEDIA_PACKETS_TO_SEND: u16 = 200;

/// The drop filter stands in for the network: below every built-in slot, so the packet is gone only
/// after everything on the sending side has already accounted for it.
const DROP_FILTER_SLOT: usize = 500;

/// The recorder sits immediately application-ward of `Slot::FecDecoder` (6_000) — the earliest
/// point at which [`Attribute::RecoveredByFec`] exists to be read.
const RECOVERY_RECORDER_SLOT: usize = 6_500;

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Discards one media packet in `drop_one_in` and reports the sequence number it discarded.
///
/// Repair packets are exempt: dropping those would be testing something else. They are identified
/// by the FEC SSRC the stream negotiated, learned at bind.
struct DropFilter {
    fec_ssrcs: Vec<SSRC>,
    media_packets: u64,
    dropped_tx: UnboundedSender<u16>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl DropFilter {
    fn new(dropped_tx: UnboundedSender<u16>) -> Self {
        Self {
            fec_ssrcs: Vec::new(),
            media_packets: 0,
            dropped_tx,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for DropFilter {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(ref rtp_packet) = msg.message.packet else {
            self.write_queue.push_back(msg);
            return Ok(());
        };

        if self.fec_ssrcs.contains(&rtp_packet.header.ssrc) {
            self.write_queue.push_back(msg);
            return Ok(());
        }

        self.media_packets += 1;
        if self.media_packets.is_multiple_of(DROP_ONE_IN) {
            let _ = self.dropped_tx.send(rtp_packet.header.sequence_number);
            // Not queued: nothing below this point ever sees it, exactly as if the path had lost it.
            return Ok(());
        }

        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for DropFilter {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.push(ssrc_fec);
        }
    }
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.retain(|ssrc| *ssrc != ssrc_fec);
        }
    }
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// Reports every inbound media packet's sequence number, and whether the decoder rebuilt it.
struct RecoveryRecorder {
    fec_ssrcs: Vec<SSRC>,
    arrivals_tx: UnboundedSender<(u16, bool)>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl RecoveryRecorder {
    fn new(arrivals_tx: UnboundedSender<(u16, bool)>) -> Self {
        Self {
            fec_ssrcs: Vec::new(),
            arrivals_tx,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RecoveryRecorder {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && !self.fec_ssrcs.contains(&rtp_packet.header.ssrc)
        {
            let _ = self.arrivals_tx.send((
                rtp_packet.header.sequence_number,
                msg.message.has(&Attribute::RecoveredByFec),
            ));
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for RecoveryRecorder {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.push(ssrc_fec);
        }
    }
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.retain(|ssrc| *ssrc != ssrc_fec);
        }
    }
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

fn video_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: VP8_PT,
    }
}

fn fec_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_FLEX_FEC03.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "repair-window=10000000".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: FLEX_FEC_PT,
    }
}

fn media_engine() -> Result<MediaEngine> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(video_codec(), RtpCodecKind::Video)?;
    media_engine.register_codec(fec_codec(), RtpCodecKind::Video)?;
    Ok(media_engine)
}

#[tokio::test]
async fn flexfec03_recovers_every_dropped_packet() -> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let (dropped_tx, mut dropped_rx) = unbounded_channel::<u16>();
    let (arrivals_tx, mut arrivals_rx) = unbounded_channel::<(u16, bool)>();

    // ---- receiver (answerer) ----
    let answerer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let answerer_local_addr = answerer_socket.local_addr()?;

    let mut answerer_media_engine = media_engine()?;
    let answerer_registry = Registry::new()
        .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
        .with(
            Slot::from(RECOVERY_RECORDER_SLOT),
            RecoveryRecorder::new(arrivals_tx),
        );

    let mut answerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Server)
                .build(),
        )
        .with_media_engine(std::mem::take(&mut answerer_media_engine))
        .with_interceptor_registry(answerer_registry)
        .build(Instant::now())?;

    answerer_pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )?;
    answerer_pc.add_local_candidate(
        RTCIceCandidate::from(&host_candidate(&answerer_local_addr)?).to_json()?,
    )?;

    // ---- sender (offerer) ----
    let offerer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let offerer_local_addr = offerer_socket.local_addr()?;

    let mut offerer_media_engine = media_engine()?;
    let offerer_registry = Registry::new()
        .with(
            Slot::FecEncoder,
            FlexFec03SendBuilder::new()
                .with_num_media_packets(NUM_MEDIA_PACKETS)
                .with_num_fec_packets(NUM_FEC_PACKETS)
                .build(),
        )
        .with(Slot::from(DROP_FILTER_SLOT), DropFilter::new(dropped_tx));

    let mut offerer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Server)
                .build(),
        )
        .with_media_engine(std::mem::take(&mut offerer_media_engine))
        .with_interceptor_registry(offerer_registry)
        .build(Instant::now())?;

    let sender_id = offerer_pc.add_track(MediaStreamTrack::new(
        "stream".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(MEDIA_SSRC),
                fec: Some(RTCRtpFecParameters { ssrc: FEC_SSRC }),
                ..Default::default()
            },
            codec: video_codec().rtp_codec,
            ..Default::default()
        }],
    ))?;
    offerer_pc.add_local_candidate(
        RTCIceCandidate::from(&host_candidate(&offerer_local_addr)?).to_json()?,
    )?;

    // ---- negotiate ----
    let offer = offerer_pc.create_offer(None)?;
    assert!(
        offer
            .sdp
            .contains(&format!("a=rtpmap:{FLEX_FEC_PT} flexfec-03/90000")),
        "the offer must carry the repair codec, or nothing below tests FEC:\n{}",
        offer.sdp
    );
    assert!(
        offer
            .sdp
            .contains(&format!("a=ssrc-group:FEC-FR {MEDIA_SSRC} {FEC_SSRC}")),
        "the offer must group the repair flow with the media it repairs:\n{}",
        offer.sdp
    );

    offerer_pc.set_local_description(Instant::now(), offer.clone())?;
    answerer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answerer_pc.create_answer(None)?;
    assert!(
        answer
            .sdp
            .contains(&format!("a=rtpmap:{FLEX_FEC_PT} flexfec-03/90000")),
        "the answerer must select the repair codec, or its decoder never binds:\n{}",
        answer.sdp
    );
    answerer_pc.set_local_description(Instant::now(), answer.clone())?;
    offerer_pc.set_remote_description(Instant::now(), answer)?;

    // ---- run ----
    let mut offerer_buf = vec![0u8; 2000];
    let mut answerer_buf = vec![0u8; 2000];
    let mut offerer_connected = false;
    let mut answerer_connected = false;
    let mut packets_sent: u16 = 0;
    let mut last_send = Instant::now();
    let mut finished_sending_at: Option<Instant> = None;

    let payload = bytes::Bytes::from(vec![0xAB; 200]);
    let start = Instant::now();
    let deadline = Duration::from_secs(30);

    while start.elapsed() < deadline {
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
                ) => return Err(anyhow::anyhow!("offerer ICE failed")),
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("offerer peer connection failed"));
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
                ) => return Err(anyhow::anyhow!("answerer ICE failed")),
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("answerer peer connection failed"));
                    }
                    answerer_connected |= state == RTCPeerConnectionState::Connected;
                }
                _ => {}
            }
        }

        // The application-facing stream is drained but not asserted on: `RTCMessage::RtpPacket`
        // carries no attributes, which is exactly why `RecoveryRecorder` exists.
        while let Some(TaggedRTCMessage { message, .. }) = answerer_pc.poll_read() {
            if let RTCMessage::RtpPacket(_, _) = message {}
        }

        if offerer_connected
            && answerer_connected
            && packets_sent < MEDIA_PACKETS_TO_SEND
            && last_send.elapsed() >= Duration::from_millis(2)
        {
            packets_sent += 1;
            last_send = Instant::now();

            let mut rtp_sender = offerer_pc
                .rtp_sender(sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?;
            rtp_sender.write_rtp(
                Instant::now(),
                rtp::packet::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: VP8_PT,
                        // The identity under test. One per packet, from 1, so a reported
                        // sequence number names exactly one send.
                        sequence_number: packets_sent,
                        timestamp: u32::from(packets_sent) * 3000,
                        ssrc: MEDIA_SSRC,
                        ..Default::default()
                    },
                    payload: payload.clone(),
                },
            )?;

            if packets_sent == MEDIA_PACKETS_TO_SEND {
                finished_sending_at = Some(Instant::now());
            }
        }

        // Give the tail of the stream time to land: the last block's repair packet is emitted
        // after its tenth media packet, so recovery of a loss in that block necessarily trails
        // the last send.
        if finished_sending_at.is_some_and(|at| at.elapsed() > Duration::from_secs(2)) {
            break;
        }

        let next = offerer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + IDLE_TIMEOUT)
            .min(
                answerer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + IDLE_TIMEOUT),
            );
        let delay = next
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if delay.is_zero() {
            offerer_pc.handle_timeout(Instant::now())?;
            answerer_pc.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay.min(Duration::from_millis(2)));
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

    offerer_pc.close()?;
    answerer_pc.close()?;

    // ---- collect ----
    let mut dropped = BTreeSet::new();
    while let Ok(sequence_number) = dropped_rx.try_recv() {
        dropped.insert(sequence_number);
    }

    let mut arrived = BTreeSet::new();
    let mut recovered = BTreeSet::new();
    while let Ok((sequence_number, was_recovered)) = arrivals_rx.try_recv() {
        if was_recovered {
            recovered.insert(sequence_number);
        } else {
            arrived.insert(sequence_number);
        }
    }

    log::info!(
        "sent {packets_sent}, dropped {}, arrived {}, recovered {}",
        dropped.len(),
        arrived.len(),
        recovered.len()
    );

    assert_eq!(
        MEDIA_PACKETS_TO_SEND, packets_sent,
        "the connection did not stay up long enough to send the whole stream"
    );

    // Guards the rest: with nothing dropped, every assertion below holds vacuously and the test
    // would pass on a build where FEC does nothing whatsoever.
    let expected_drops = usize::from(MEDIA_PACKETS_TO_SEND) / DROP_ONE_IN as usize;
    assert_eq!(
        expected_drops,
        dropped.len(),
        "the drop filter should have discarded one packet in {DROP_ONE_IN}"
    );

    // The claim: every packet the sender discarded was rebuilt by the decoder and handed on.
    assert!(
        dropped.is_subset(&recovered),
        "these dropped sequence numbers were never recovered: {:?}\n\
         dropped:   {dropped:?}\n\
         recovered: {recovered:?}",
        dropped.difference(&recovered).collect::<Vec<_>>()
    );

    // And nothing else went astray, so the recovery above is the whole story rather than one
    // effect among several.
    let all: BTreeSet<u16> = (1..=MEDIA_PACKETS_TO_SEND).collect();
    let delivered: BTreeSet<u16> = arrived.union(&recovered).copied().collect();
    assert_eq!(
        all,
        delivered,
        "packets neither delivered nor recovered: {:?}",
        all.difference(&delivered).collect::<Vec<_>>()
    );

    // What was rebuilt that had not been lost.
    //
    // This should be empty and is not: the first packet of the stream is always rebuilt as well,
    // duplicating one the receiver already had. The cause is not in the codec. A remote stream is
    // bound to the interceptors only once its codec can be resolved from an arriving RTP payload
    // type (`endpoint.rs`, `find_track_id_by_ssrc`), and the endpoint sits application-ward of the
    // chain — so the packet that triggers the bind has already traversed the chain by the time the
    // bind happens. The decoder therefore never sees packet one, finds it missing when the first
    // repair packet arrives, and dutifully rebuilds it.
    //
    // Pinned rather than tolerated. If the artifact ever spreads beyond that first packet this
    // fails, and when the bind ordering is fixed the `is_empty` case below starts holding and this
    // assertion can be tightened to set equality.
    let spurious: BTreeSet<u16> = recovered.difference(&dropped).copied().collect();
    assert!(
        spurious.is_empty() || spurious == BTreeSet::from([1]),
        "packets were rebuilt that had not been lost: {spurious:?}\n\
         only sequence number 1 is a known artifact of the late remote-stream bind"
    );

    Ok(())
}

fn host_candidate(addr: &std::net::SocketAddr) -> Result<rtc::ice::candidate::Candidate> {
    Ok(CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?)
}
