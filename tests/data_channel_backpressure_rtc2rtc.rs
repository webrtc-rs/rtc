//! A receiver that stops consuming must throttle the peer, not lose data.
//!
//! This covers the bounded SCTP drain added for
//! [webrtc#858](https://github.com/webrtc-rs/webrtc/issues/858). The handler stops pulling
//! out of SCTP's reassembly queues once the pipeline is holding more than
//! `SCTP_PIPELINE_READ_BACKLOG_LIMIT` undelivered data-channel messages, which lowers the
//! receiver-window credit advertised in every SACK. Undrained bytes are the mechanism, not a
//! leak — but they only work if the parked stream is later *resumed*.
//!
//! **That resume is the risk this test exists for.** `StreamEvent::Readable` is
//! edge-triggered: it fires when a new DATA chunk arrives, never because unread data remains.
//! So the moment back-pressure succeeds the peer stops sending, nothing arrives to re-trigger
//! the drain, and a stream parked mid-way would stay parked — deadlocking precisely when the
//! feature engages. The resume runs from `poll_read`, and the pipeline walks the handler
//! chain there only when a stream is actually parked; this is the only test that drives that
//! path over a real connection.
//!
//! Shape: the answerer pumps the network but deliberately never calls `poll_read` while the
//! offerer sends far more than the bound, so the backlog builds and streams park. Then it
//! drains and must receive **every** message, **in order**.
//!
//! It is deliberately not a test that "the bound exists" — a core with no bound at all would
//! also deliver everything, just with unbounded memory. It is a test that the bound does not
//! lose or strand anything.

use anyhow::Result;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Well past the 256-message pipeline bound, so parking is structural rather than a matter of
/// timing luck. Small payloads keep SCTP's *send* buffer from being the thing that throttles:
/// the receive side must be the only bottleneck.
const MESSAGE_COUNT: usize = 1_200;

const NEGOTIATED_ID: u16 = 1;

/// How long the answerer refuses to call `poll_read` once the channel is open.
///
/// It must be long enough for messages to actually *arrive* and pile up past the bound.
/// Gating the stall on "the offerer finished sending" is not enough and was the first version
/// of this test: `send_text` only queues into SCTP's send buffer, so that flag flips within a
/// few iterations and the consumer starts before any backlog exists — the test then passes
/// with the resume path entirely disabled, proving nothing.
const CONSUMER_STALL: Duration = Duration::from_secs(3);

struct Peers {
    offer_pc: RTCPeerConnection,
    answer_pc: RTCPeerConnection,
    offer_socket: UdpSocket,
    answer_socket: UdpSocket,
    offer_addr: std::net::SocketAddr,
    answer_addr: std::net::SocketAddr,
}

async fn build_peer(
    role: RTCDtlsRole,
) -> Result<(RTCPeerConnection, UdpSocket, std::net::SocketAddr)> {
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

async fn connect() -> Result<Peers> {
    let (offer_pc, offer_socket, offer_addr) = build_peer(RTCDtlsRole::Server).await?;
    let (answer_pc, answer_socket, answer_addr) = build_peer(RTCDtlsRole::Client).await?;
    Ok(Peers {
        offer_pc,
        answer_pc,
        offer_socket,
        answer_socket,
        offer_addr,
        answer_addr,
    })
}

#[tokio::test]
async fn test_slow_consumer_throttles_the_peer_without_losing_data() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut p = connect().await?;

    // Reliable and ordered on both sides — the contract this test is about.
    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    // `NEGOTIATED_ID` is the SCTP stream id the two sides agree on out-of-band. The handle
    // returned here is a separate, connection-local identifier — it is what addresses the
    // channel through `data_channel()` and what events carry.
    let offer_dc = p
        .offer_pc
        .create_data_channel("backpressure", Some(init.clone()))?
        .id();
    let answer_dc = p
        .answer_pc
        .create_data_channel("backpressure", Some(init))?
        .id();

    let offer = p.offer_pc.create_offer(None)?;
    p.offer_pc
        .set_local_description(Instant::now(), offer.clone())?;
    p.answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = p.answer_pc.create_answer(None)?;
    p.answer_pc
        .set_local_description(Instant::now(), answer.clone())?;
    p.offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_connected = false;
    let mut dc_open = false;
    let mut sent = 0usize;
    let mut received: Vec<usize> = Vec::with_capacity(MESSAGE_COUNT);

    // The stall: until this instant the answerer pumps the network but never calls
    // `poll_read`, so its pipeline backlog grows past the bound and the SCTP handler parks
    // the stream. Set when the channel opens, since nothing arrives before that.
    let mut stall_until: Option<Instant> = None;
    let mut answerer_consuming = false;

    let mut offer_buf = vec![0u8; 2048];
    let mut answer_buf = vec![0u8; 2048];

    let start = Instant::now();
    let deadline = Duration::from_secs(60);

    while start.elapsed() < deadline {
        while let Some(msg) = p.offer_pc.poll_write() {
            p.offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = p.answer_pc.poll_write() {
            p.answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = p.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => offer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    dc_open = true;
                    stall_until.get_or_insert_with(|| Instant::now() + CONSUMER_STALL);
                }
                _ => {}
            }
        }
        while p.answer_pc.poll_event().is_some() {}

        // The offerer receives nothing on this connection; drain so it cannot back up.
        while p.offer_pc.poll_read().is_some() {}

        // The answerer consumes only once the stall is over. Before that, messages pile up in
        // its pipeline — which is exactly what drives the backlog past the bound.
        if answerer_consuming {
            while let Some(TaggedRTCMessage { message, .. }) = p.answer_pc.poll_read() {
                if let RTCMessage::DataChannelMessage(id, msg) = message {
                    assert_eq!(id, answer_dc);
                    let text = String::from_utf8_lossy(&msg.data);
                    let index: usize = text.parse().expect("message payload is its index");
                    received.push(index);
                }
            }
        }

        // Push as fast as SCTP will take it. A refusal here is the send buffer, not a
        // failure: retry on the next iteration.
        if offer_connected
            && dc_open
            && sent < MESSAGE_COUNT
            && let Some(mut dc) = p.offer_pc.data_channel(offer_dc)
            && dc.send_text(Instant::now(), sent.to_string()).is_ok()
        {
            sent += 1;
        }

        // Let the consumer start only once it has been stalled long enough for the backlog to
        // build. Whatever has not been handed over by then is parked in — or behind — the
        // answerer's SCTP reassembly queue, and only the resume path can get it out.
        if !answerer_consuming
            && let Some(until) = stall_until
            && Instant::now() >= until
        {
            answerer_consuming = true;
        }

        if answerer_consuming && received.len() >= MESSAGE_COUNT {
            break;
        }

        let next = p
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + Duration::from_secs(1))
            .min(
                p.answer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + Duration::from_secs(1)),
            );
        let delay = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(5));

        if delay.is_zero() {
            p.offer_pc.handle_timeout(Instant::now()).ok();
            p.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                p.offer_pc.handle_timeout(Instant::now()).ok();
                p.answer_pc.handle_timeout(Instant::now()).ok();
            }
            r = p.offer_socket.recv_from(&mut offer_buf) => {
                if let Ok((n, peer)) = r {
                    p.offer_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: p.offer_addr,
                            peer_addr: peer,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: bytes::BytesMut::from(&offer_buf[..n]),
                    }).ok();
                }
            }
            r = p.answer_socket.recv_from(&mut answer_buf) => {
                if let Ok((n, peer)) = r {
                    p.answer_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: p.answer_addr,
                            peer_addr: peer,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: bytes::BytesMut::from(&answer_buf[..n]),
                    }).ok();
                }
            }
        }
    }

    assert!(
        offer_connected && dc_open,
        "peers never established a channel"
    );
    assert_eq!(
        sent, MESSAGE_COUNT,
        "offerer could not put all messages on the wire, so the receive side was never \
         the bottleneck and this test proved nothing"
    );

    // The property. A parked stream that is never resumed shows up here as a short tail:
    // everything up to the bound arrives and the rest is stranded in the reassembly queue
    // forever, because the peer has been throttled and no new chunk will re-trigger the drain.
    let expected: Vec<usize> = (0..MESSAGE_COUNT).collect();
    assert_eq!(
        received.len(),
        MESSAGE_COUNT,
        "receiver got {} of {} messages — a stream parked by back-pressure was never \
         resumed (delivery stops at index {})",
        received.len(),
        MESSAGE_COUNT,
        received
            .iter()
            .enumerate()
            .find(|(i, got)| **got != *i)
            .map(|(i, _)| i)
            .unwrap_or(received.len()),
    );
    assert_eq!(received, expected, "ordered channel delivered out of order");

    p.offer_pc.close()?;
    p.answer_pc.close()?;
    Ok(())
}
