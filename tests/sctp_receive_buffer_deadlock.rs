//! Reproduction for <https://github.com/webrtc-rs/webrtc/issues/822>, at the `rtc` layer.
//!
//! An SCTP association can reach a receive-buffer state it can never leave: the window is zero,
//! and the only chunk that would reopen it is dropped on arrival — including on every
//! retransmission. The sender retransmits forever, the receiver drops forever, and the message
//! is never delivered.
//!
//! Three facts in `rtc-sctp` combine to produce it:
//!
//! 1. `Association::get_my_receiver_window_credit` is
//!    `max_receive_buffer_size - sum(bytes in every stream's reassembly queue)`. Fragments of an
//!    *incomplete* message count, so an unfinished message pins its bytes indefinitely.
//!
//! 2. `ReassemblyQueue::is_readable` only inspects `ordered[0]`. An incomplete chunk set at the
//!    head blocks delivery of everything behind it, so the application cannot drain those bytes
//!    to make room.
//!
//! 3. `Association::handle_data`'s buffer-full branch accepts a chunk only when
//!    `payload_queue.get_last_tsn_received()` is `Some(last)` **and** `d.tsn < last` — i.e. only
//!    when it fills a gap *below* the highest TSN already queued. When every chunk received so
//!    far was in sequence, `peer_last_tsn` advances over the whole payload queue, the queue
//!    drains empty, `get_last_tsn_received()` returns `None`, and the branch drops the chunk
//!    unconditionally.
//!
//! So once the missing chunk is the *next in-sequence* one and the buffer is full of a pinned
//! incomplete message, nothing can break the cycle.
//!
//! This test provokes it without touching the network: it gives the receiver a small SCTP
//! receive buffer and sends a single message several times that size. The head fragments fill
//! the buffer and pin it; the remaining fragments can then never be accepted.
//!
//! Fixed by having the buffer-full branch also accept the in-sequence chunk that unblocks
//! reassembly, guarded on nothing being readable so a merely slow receiver still gets
//! back-pressure rather than an unbounded buffer.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::{
    SctpMaxMessageSize, SettingEngineBuilder,
};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// The receiver's SCTP receive buffer. Small so a single message can fill it, which is what
/// pins the window at zero.
const RECV_BUFFER: u32 = 16 * 1024;

/// One message, comfortably larger than `RECV_BUFFER` so its own fragments exhaust the buffer
/// before the last one arrives. Within `SctpMaxMessageSize::MAX_MESSAGE_SIZE`.
const MESSAGE_SIZE: usize = 64 * 1024;

/// The stream id both peers agree on out of band.
const NEGOTIATED_ID: u16 = 1;

/// Long enough for many T3-rtx retransmissions of the missing chunk. The bug is that every one
/// of them is dropped, so no amount of waiting helps; a healthy stack delivers in well under a
/// second.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn peer(setting_engine: SettingEngineBuilder) -> Result<RTCPeerConnection> {
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine.build())
        .build(Instant::now())?)
}

/// A single message larger than the receiver's SCTP receive buffer must still be delivered.
///
/// The receiver drains continuously, so nothing here is back-pressure: there is simply never
/// anything readable, because the message is incomplete. Its arrived fragments hold the window
/// at zero, and the fragments that would complete it are refused for that reason.
#[tokio::test]
async fn large_message_is_delivered_when_it_exceeds_the_receive_buffer() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let offer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let answer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let offer_local_addr = offer_socket.local_addr()?;
    let answer_local_addr = answer_socket.local_addr()?;

    // Only the *receiver's* buffer matters; the sender is left at its defaults so nothing about
    // its behaviour is special-cased for this test.
    let mut offer_pc = peer(
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
                SctpMaxMessageSize::MAX_MESSAGE_SIZE,
            )),
    )?;
    let mut answer_pc = peer(
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
                SctpMaxMessageSize::MAX_MESSAGE_SIZE,
            ))
            .with_sctp_max_receive_buffer_size(RECV_BUFFER),
    )?;

    for (pc, addr) in [
        (&mut offer_pc, offer_local_addr),
        (&mut answer_pc, answer_local_addr),
    ] {
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
    }

    // Out-of-band so neither side depends on DCEP timing; this test is about SCTP flow control.
    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    let offer_dc = offer_pc
        .create_data_channel("bulk", Some(init.clone()))?
        .id();
    let answer_dc = answer_pc.create_data_channel("bulk", Some(init))?.id();

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answer_pc.create_answer(None)?;
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    let payload: Vec<u8> = (0..MESSAGE_SIZE).map(|i| (i % 251) as u8).collect();

    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_dc_open = false;
    let mut answer_dc_open = false;
    let mut sent = false;
    let mut received: Option<Vec<u8>> = None;

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];
    let start = Instant::now();

    while start.elapsed() < TEST_TIMEOUT && received.is_none() {
        while let Some(msg) = offer_pc.poll_write() {
            offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = answer_pc.poll_write() {
            answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => offer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if id == offer_dc =>
                {
                    offer_dc_open = true
                }
                _ => {}
            }
        }
        while let Some(event) = answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if id == answer_dc =>
                {
                    answer_dc_open = true
                }
                _ => {}
            }
        }

        // The receiver drains continuously — there is no back-pressure being applied here. It
        // simply has nothing to take: the only message is incomplete, so `is_readable()` is
        // false and its bytes stay pinned.
        while let Some(TaggedRTCMessage { message, .. }) = answer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, msg) = message
                && id == answer_dc
            {
                received = Some(msg.data.to_vec());
            }
        }
        while offer_pc.poll_read().is_some() {}

        if offer_connected && offer_dc_open && !sent {
            let mut dc = offer_pc
                .data_channel(offer_dc)
                .expect("channel exists once open");
            dc.send(Instant::now(), BytesMut::from(&payload[..]))?;
            sent = true;
        }

        let next_timeout = offer_pc
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30))
            .min(
                answer_pc
                    .poll_timeout()
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(30)),
            );
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(5));

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
            Ok((n, peer_addr)) = offer_socket.recv_from(&mut offer_buf) => {
                offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = answer_socket.recv_from(&mut answer_buf) => {
                answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    assert!(
        offer_connected && answer_connected && offer_dc_open && answer_dc_open,
        "test precondition: peers and channel must come up \
         (offer_connected={offer_connected}, answer_connected={answer_connected}, \
          offer_dc_open={offer_dc_open}, answer_dc_open={answer_dc_open})"
    );
    assert!(sent, "test precondition: the message must have been sent");

    let received = received.unwrap_or_else(|| {
        panic!(
            "permanent zero-window deadlock: a {MESSAGE_SIZE}-byte message was never delivered \
             to a receiver with a {RECV_BUFFER}-byte SCTP receive buffer. Its arrived fragments \
             pin the buffer at zero credit, `is_readable()` is false because the head chunk set \
             is incomplete, and `handle_data`'s buffer-full branch refuses the in-sequence chunk \
             that would complete it — on every retransmission, because the payload queue is \
             empty and `get_last_tsn_received()` returns None. \
             See https://github.com/webrtc-rs/webrtc/issues/822"
        )
    });

    assert_eq!(
        received.len(),
        MESSAGE_SIZE,
        "delivered message has the wrong length"
    );
    assert_eq!(received, payload, "delivered message is corrupted");

    offer_pc.close()?;
    answer_pc.close()?;

    Ok(())
}
