//! The side that *accepts* a data channel must send with the channel type the opener chose.
//!
//! RFC 8832 §5.1 defines the Channel Type and Reliability Parameter of a `DATA_CHANNEL_OPEN` for
//! the data channel, not for the opener's direction alone. The accepting side used to keep the
//! SCTP defaults for its own sends — ordered and fully reliable — and to report `None` for
//! `max_retransmits()` / `max_packet_life_time()`.
//!
//! Shape: the offerer opens an unordered `maxRetransmits: 0` channel ("lossy") and a default
//! reliable one ("control"). The answerer checks the getters of both when they open, then sends
//! on them through a relay that drops, by a fixed rule, every datagram the answerer emits right
//! after it sends `lossy-0` and right after it sends the control message:
//!
//! * `lossy-0` is lost and, with no retransmission allowed, must never arrive; `lossy-1..` must
//!   all arrive without waiting for it.
//! * The control message is lost too, but its channel is reliable, so it arrives only once
//!   T3-rtx retransmits it. Any recovery of `lossy-0` would have happened by then — a fast
//!   retransmit, or the same T3-rtx that resends the control message, which resends outstanding
//!   DATA in TSN order — so its absence when the control message arrives is measured against
//!   the peer's own retransmission rather than a wall-clock threshold.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const LOSSY_LABEL: &str = "lossy";
const CONTROL_LABEL: &str = "control";

/// Messages sent on the lossy channel after the lost `lossy-0`.
const LOSSY_FOLLOWERS: usize = 20;

const CONTROL_MESSAGE: &str = "control";

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

async fn build_peer(role: RTCDtlsRole) -> Result<(RTCPeerConnection, UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    let setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(role)
        .build();

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine)
        .build(Instant::now())?;

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    Ok((pc, socket, addr))
}

/// Where the answerer is in its script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for both channels to open on both sides.
    Opening,
    /// `lossy-0` is lost and `lossy-1..` are sent; waiting for them to arrive.
    AwaitingFollowers,
    /// The control message is lost; waiting for its retransmission to arrive.
    AwaitingControl,
    Done,
}

/// Every datagram `pc` has queued, sent unless `drop` is set. Returns how many were dropped.
async fn pump(pc: &mut RTCPeerConnection, socket: &UdpSocket, drop: bool) -> Result<usize> {
    let mut dropped = 0;
    while let Some(msg) = pc.poll_write() {
        if drop {
            dropped += 1;
        } else {
            socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
    }
    Ok(dropped)
}

fn read_into(
    pc: &mut RTCPeerConnection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    buf: &[u8],
) {
    pc.handle_read(TaggedBytesMut {
        now: Instant::now(),
        transport: TransportContext {
            local_addr,
            peer_addr,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(buf),
    })
    .ok();
}

#[tokio::test]
async fn test_accepted_unreliable_channel_is_not_blocked_by_a_lost_message() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let (mut offer_pc, offer_socket, offer_addr) = build_peer(RTCDtlsRole::Server).await?;
    let (mut answer_pc, answer_socket, answer_addr) = build_peer(RTCDtlsRole::Client).await?;

    let offer_lossy = offer_pc
        .create_data_channel(
            LOSSY_LABEL,
            Some(RTCDataChannelInit {
                ordered: false,
                max_retransmits: Some(0),
                ..Default::default()
            }),
        )?
        .id();
    let offer_control = offer_pc.create_data_channel(CONTROL_LABEL, None)?.id();

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answer_pc.create_answer(None)?;
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_opened: BTreeSet<RTCDataChannelId> = BTreeSet::new();
    let mut answer_lossy: Option<RTCDataChannelId> = None;
    let mut answer_control: Option<RTCDataChannelId> = None;

    let mut phase = Phase::Opening;
    let mut dropped_lossy = 0usize;
    let mut dropped_control = 0usize;
    // In arrival order at the offerer.
    let mut lossy_received: Vec<String> = Vec::new();
    let mut lossy_at_control: Option<Vec<String>> = None;

    let mut offer_buf = vec![0u8; 2048];
    let mut answer_buf = vec![0u8; 2048];
    let start = Instant::now();

    while start.elapsed() < TEST_TIMEOUT && phase != Phase::Done {
        pump(&mut offer_pc, &offer_socket, false).await?;
        pump(&mut answer_pc, &answer_socket, false).await?;

        while let Some(event) = offer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                offer_opened.insert(id);
            }
        }
        while let Some(event) = answer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                let dc = answer_pc
                    .data_channel(id)
                    .expect("an opened channel exists");
                // The getters report the channel the peer opened (W3C `RTCDataChannel`).
                let reported = (
                    dc.ordered(),
                    dc.max_retransmits(),
                    dc.max_packet_life_time(),
                    dc.negotiated(),
                );
                match dc.label() {
                    LOSSY_LABEL => {
                        assert_eq!(
                            reported,
                            (false, Some(0), None, false),
                            "accepted lossy channel: (ordered, maxRetransmits, \
                             maxPacketLifeTime, negotiated)"
                        );
                        answer_lossy = Some(id);
                    }
                    CONTROL_LABEL => {
                        assert_eq!(
                            reported,
                            (true, None, None, false),
                            "accepted control channel: (ordered, maxRetransmits, \
                             maxPacketLifeTime, negotiated)"
                        );
                        answer_control = Some(id);
                    }
                    other => panic!("unexpected channel {other:?}"),
                }
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = offer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, msg) = message {
                let text = String::from_utf8_lossy(&msg.data).into_owned();
                if id == offer_lossy {
                    lossy_received.push(text);
                } else if id == offer_control {
                    assert_eq!(text, CONTROL_MESSAGE);
                    lossy_at_control = Some(lossy_received.clone());
                    phase = Phase::Done;
                }
            }
        }
        while answer_pc.poll_read().is_some() {}

        match phase {
            Phase::Opening
                if offer_opened.contains(&offer_lossy)
                    && offer_opened.contains(&offer_control)
                    && answer_lossy.is_some()
                    && answer_control.is_some() =>
            {
                let lossy = answer_lossy.expect("checked above");
                answer_pc
                    .data_channel(lossy)
                    .expect("lossy channel")
                    .send_text(Instant::now(), "lossy-0")?;
                dropped_lossy = pump(&mut answer_pc, &answer_socket, true).await?;
                for i in 1..=LOSSY_FOLLOWERS {
                    answer_pc
                        .data_channel(lossy)
                        .expect("lossy channel")
                        .send_text(Instant::now(), format!("lossy-{i}"))?;
                }
                phase = Phase::AwaitingFollowers;
            }
            Phase::AwaitingFollowers if lossy_received.len() >= LOSSY_FOLLOWERS => {
                let control = answer_control.expect("opened");
                answer_pc
                    .data_channel(control)
                    .expect("control channel")
                    .send_text(Instant::now(), CONTROL_MESSAGE)?;
                dropped_control = pump(&mut answer_pc, &answer_socket, true).await?;
                phase = Phase::AwaitingControl;
            }
            _ => {}
        }
        if phase == Phase::Done {
            break;
        }

        let next = offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + Duration::from_secs(1))
            .min(
                answer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + Duration::from_secs(1)),
            );
        let delay = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));
        if delay.is_zero() {
            offer_pc.handle_timeout(Instant::now()).ok();
            answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        tokio::select! {
            _ = sleep => {
                offer_pc.handle_timeout(Instant::now()).ok();
                answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer)) = offer_socket.recv_from(&mut offer_buf) => {
                read_into(&mut offer_pc, offer_addr, peer, &offer_buf[..n]);
            }
            Ok((n, peer)) = answer_socket.recv_from(&mut answer_buf) => {
                read_into(&mut answer_pc, answer_addr, peer, &answer_buf[..n]);
            }
        }
    }

    assert!(
        answer_lossy.is_some() && answer_control.is_some(),
        "the answerer never accepted both channels (phase {phase:?})"
    );
    assert!(
        dropped_lossy > 0 && dropped_control > 0,
        "the relay dropped nothing (lossy {dropped_lossy}, control {dropped_control}), \
         so no loss was exercised"
    );
    let lossy_at_control = lossy_at_control.unwrap_or_else(|| {
        panic!(
            "the control message never arrived (phase {phase:?}); lossy arrivals: \
             {lossy_received:?}"
        )
    });

    let expected: BTreeSet<String> = (1..=LOSSY_FOLLOWERS)
        .map(|i| format!("lossy-{i}"))
        .collect();
    let arrived: BTreeSet<String> = lossy_at_control.iter().cloned().collect();
    assert!(
        !arrived.contains("lossy-0"),
        "maxRetransmits 0: the lost message must not be retransmitted, yet it arrived \
         before the control message's own retransmission (arrivals: {lossy_at_control:?})"
    );
    assert_eq!(
        arrived, expected,
        "every message after the lost one must arrive without waiting for it"
    );
    assert_eq!(
        lossy_at_control.len(),
        LOSSY_FOLLOWERS,
        "each message arrives once: {lossy_at_control:?}"
    );

    offer_pc.close()?;
    answer_pc.close()?;
    Ok(())
}
