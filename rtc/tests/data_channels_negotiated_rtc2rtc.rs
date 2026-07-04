//! Regression test for <https://github.com/webrtc-rs/rtc/issues/61>.
//!
//! An out-of-band *negotiated* data channel could be opened but never exchange
//! data: `DataChannel::dial` emitted no `DATA_CHANNEL_OPEN`, so the underlying
//! SCTP stream was never created and every write failed with "Stream not
//! existed". This test drives two rtc peers that each create a negotiated
//! channel with the same pre-agreed stream id and verifies that application
//! messages flow in *both* directions.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

/// The stream id both peers agree on out-of-band for the negotiated channel.
const NEGOTIATED_ID: u16 = 1;
/// Messages sent offerer -> answerer.
const OFFER_TO_ANSWER: usize = 3;
/// Messages sent answerer -> offerer.
const ANSWER_TO_OFFER: usize = 2;

/// Helper struct to run two peers in an event loop.
struct PeerRunner {
    offer_pc: RTCPeerConnection,
    answer_pc: RTCPeerConnection,
    offer_socket: Arc<UdpSocket>,
    answer_socket: Arc<UdpSocket>,
    offer_local_addr: std::net::SocketAddr,
    answer_local_addr: std::net::SocketAddr,
}

impl PeerRunner {
    async fn new() -> Result<Self> {
        // Create offer peer
        let offer_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let offer_local_addr = offer_socket.local_addr()?;

        let mut offer_setting_engine = SettingEngine::default();
        offer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;

        let offer_config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            }])
            .build();

        let mut offer_pc = RTCPeerConnectionBuilder::new()
            .with_configuration(offer_config)
            .with_setting_engine(offer_setting_engine)
            .build()?;

        let offer_candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: offer_local_addr.ip().to_string(),
                port: offer_local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        offer_pc.add_local_candidate(RTCIceCandidate::from(&offer_candidate).to_json()?)?;

        // Create answer peer
        let answer_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let answer_local_addr = answer_socket.local_addr()?;

        let mut answer_setting_engine = SettingEngine::default();
        answer_setting_engine.set_answering_dtls_role(RTCDtlsRole::Client)?;

        let answer_config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            }])
            .build();

        let mut answer_pc = RTCPeerConnectionBuilder::new()
            .with_configuration(answer_config)
            .with_setting_engine(answer_setting_engine)
            .build()?;

        let answer_candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: answer_local_addr.ip().to_string(),
                port: answer_local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        answer_pc.add_local_candidate(RTCIceCandidate::from(&answer_candidate).to_json()?)?;

        Ok(Self {
            offer_pc,
            answer_pc,
            offer_socket: Arc::new(offer_socket),
            answer_socket: Arc::new(answer_socket),
            offer_local_addr,
            answer_local_addr,
        })
    }
}

/// Both peers create a negotiated channel sharing `NEGOTIATED_ID` and exchange
/// messages in both directions. Before the fix, the negotiated channel's SCTP
/// stream was never opened, so no message could be sent.
#[tokio::test]
async fn test_negotiated_data_channel_bidirectional_messaging() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut runner = PeerRunner::new().await?;

    // Both sides create the SAME out-of-band negotiated channel.
    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    runner
        .offer_pc
        .create_data_channel("negotiated", Some(init.clone()))?;
    runner
        .answer_pc
        .create_data_channel("negotiated", Some(init))?;

    // Exchange offer/answer
    let offer = runner.offer_pc.create_offer(None)?;
    runner.offer_pc.set_local_description(offer.clone())?;
    runner.answer_pc.set_remote_description(offer)?;

    let answer = runner.answer_pc.create_answer(None)?;
    runner.answer_pc.set_local_description(answer.clone())?;
    runner.offer_pc.set_remote_description(answer)?;

    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_dc_open = false;
    let mut answer_dc_open = false;
    let mut offer_sent = 0;
    let mut answer_sent = 0;
    let mut offer_received: Vec<String> = Vec::new();
    let mut answer_received: Vec<String> = Vec::new();

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];

    let start_time = Instant::now();
    let test_timeout = Duration::from_secs(30);

    while start_time.elapsed() < test_timeout {
        // Process offer peer writes
        while let Some(msg) = runner.offer_pc.poll_write() {
            runner
                .offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // Process offer peer events
        while let Some(event) = runner.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => offer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    assert_eq!(id, NEGOTIATED_ID, "offer opened unexpected channel id");
                    offer_dc_open = true;
                }
                _ => {}
            }
        }

        // Read messages arriving at the offer peer (answer -> offer). This
        // connection carries no media, so every read is a data-channel message.
        while let Some(RTCMessage::DataChannelMessage(id, msg)) = runner.offer_pc.poll_read() {
            assert_eq!(id, NEGOTIATED_ID);
            offer_received.push(String::from_utf8_lossy(&msg.data).into_owned());
        }

        // Process answer peer writes
        while let Some(msg) = runner.answer_pc.poll_write() {
            runner
                .answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // Process answer peer events
        while let Some(event) = runner.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    assert_eq!(id, NEGOTIATED_ID, "answer opened unexpected channel id");
                    answer_dc_open = true;
                }
                _ => {}
            }
        }

        // Read messages arriving at the answer peer (offer -> answer). This
        // connection carries no media, so every read is a data-channel message.
        while let Some(RTCMessage::DataChannelMessage(id, msg)) = runner.answer_pc.poll_read() {
            assert_eq!(id, NEGOTIATED_ID);
            answer_received.push(String::from_utf8_lossy(&msg.data).into_owned());
        }

        // Once both ends are up, send in both directions. The channel is
        // guaranteed to be in the map once its OnOpen event has fired.
        if offer_connected && offer_dc_open && offer_sent < OFFER_TO_ANSWER {
            let mut dc = runner
                .offer_pc
                .data_channel(NEGOTIATED_ID)
                .expect("negotiated channel must exist once open");
            dc.send_text(format!("o2a-{offer_sent}"))?;
            offer_sent += 1;
        }
        if answer_connected && answer_dc_open && answer_sent < ANSWER_TO_OFFER {
            let mut dc = runner
                .answer_pc
                .data_channel(NEGOTIATED_ID)
                .expect("negotiated channel must exist once open");
            dc.send_text(format!("a2o-{answer_sent}"))?;
            answer_sent += 1;
        }

        // Done once every message crossed the wire.
        if answer_received.len() >= OFFER_TO_ANSWER && offer_received.len() >= ANSWER_TO_OFFER {
            break;
        }

        // Handle timeouts / socket reads
        let offer_timeout = runner
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_timeout = runner
            .answer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next_timeout = offer_timeout.min(answer_timeout);
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            runner.offer_pc.handle_timeout(Instant::now()).ok();
            runner.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                runner.offer_pc.handle_timeout(Instant::now()).ok();
                runner.answer_pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer_addr)) = runner.offer_socket.recv_from(&mut offer_buf) => {
                runner.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.offer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = runner.answer_socket.recv_from(&mut answer_buf) => {
                runner.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: runner.answer_local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    assert!(offer_connected && answer_connected, "peers should connect");
    assert!(
        offer_dc_open && answer_dc_open,
        "both negotiated channels should open (offer={offer_dc_open}, answer={answer_dc_open})"
    );

    // The core of the regression: messages must actually be delivered both ways.
    answer_received.sort();
    offer_received.sort();
    assert_eq!(
        answer_received,
        (0..OFFER_TO_ANSWER)
            .map(|i| format!("o2a-{i}"))
            .collect::<Vec<_>>(),
        "answer should receive all offer->answer messages"
    );
    assert_eq!(
        offer_received,
        (0..ANSWER_TO_OFFER)
            .map(|i| format!("a2o-{i}"))
            .collect::<Vec<_>>(),
        "offer should receive all answer->offer messages"
    );

    runner.offer_pc.close()?;
    runner.answer_pc.close()?;

    Ok(())
}
