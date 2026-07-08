//! Test: data channel renegotiation tracking.
//!
//! Problem: After the initial SDP exchange, creating additional data channels
//! does not trigger `OnNegotiationNeeded`. The WebRTC spec requires that
//! adding a data channel after negotiation must trigger renegotiation.
//!
//! This test:
//! 1. Two peers complete initial negotiation with one data channel.
//! 2. After `Connected`, the offerer creates a second data channel.
//! 3. Verifies that `OnNegotiationNeededEvent` fires (proving the
//!    `data_channels_negotiated` counter triggered renegotiation).

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
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
use tokio::sync::Mutex;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

struct PeerRunner {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    local_addr: std::net::SocketAddr,
}

impl PeerRunner {
    async fn new(dtls_role: RTCDtlsRole) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;

        let mut setting = SettingEngine::default();
        setting.set_answering_dtls_role(dtls_role)?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(setting)
            .build()?;

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
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        Ok(Self {
            pc,
            socket,
            local_addr,
        })
    }
}

#[derive(Default)]
struct TestState {
    connected: bool,
    first_dc_open: bool,
    second_dc_created: bool,
    negotiation_seen: bool,
}

#[tokio::test]
async fn test_renegotiation_on_post_connection_data_channel() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut offer_peer = PeerRunner::new(RTCDtlsRole::Server).await?;
    let mut answer_peer = PeerRunner::new(RTCDtlsRole::Client).await?;

    // Create one DC before any negotiation.
    offer_peer.pc.create_data_channel("dc1", None)?;

    // Exchange offer/answer.
    let offer = offer_peer.pc.create_offer(None)?;
    offer_peer.pc.set_local_description(offer.clone())?;
    answer_peer.pc.set_remote_description(offer)?;
    let answer = answer_peer.pc.create_answer(None)?;
    answer_peer.pc.set_local_description(answer.clone())?;
    offer_peer.pc.set_remote_description(answer)?;

    let offer_state = Arc::new(Mutex::new(TestState::default()));
    let answer_state = Arc::new(Mutex::new(TestState::default()));

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];

    let start = Instant::now();

    while start.elapsed() < DEFAULT_TIMEOUT_DURATION {
        // --- offer writes ---
        while let Some(msg) = offer_peer.pc.poll_write() {
            offer_peer
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // --- offer events ---
        while let Some(evt) = offer_peer.pc.poll_event() {
            match evt {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => {
                    offer_state.lock().await.connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    offer_state.lock().await.first_dc_open = true;
                }
                RTCPeerConnectionEvent::OnNegotiationNeededEvent => {
                    log::info!("offer: OnNegotiationNeeded fired!");
                    offer_state.lock().await.negotiation_seen = true;
                }
                _ => {}
            }
        }

        // --- offer reads ---
        while offer_peer.pc.poll_read().is_some() {}

        // --- answer writes ---
        while let Some(msg) = answer_peer.pc.poll_write() {
            answer_peer
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        // --- answer events ---
        while let Some(evt) = answer_peer.pc.poll_event() {
            match evt {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => {
                    answer_state.lock().await.connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    answer_state.lock().await.first_dc_open = true;
                }
                _ => {}
            }
        }

        // --- answer reads ---
        while answer_peer.pc.poll_read().is_some() {}

        // --- Create second DC once connected and first DC is open ---
        {
            let mut os = offer_state.lock().await;
            if os.connected && os.first_dc_open && !os.second_dc_created {
                log::info!("offer: creating second data channel (post-connection)");
                offer_peer.pc.create_data_channel("dc2", None)?;
                os.second_dc_created = true;
            }
        }

        // Check for success: OnNegotiationNeeded fired for the second DC.
        {
            let os = offer_state.lock().await;
            if os.second_dc_created && os.negotiation_seen {
                log::info!("TEST PASSED: renegotiation triggered for post-connection DC");
                offer_peer.pc.close()?;
                answer_peer.pc.close()?;
                return Ok(());
            }
        }

        // --- timeouts & socket reads ---
        let offer_to = offer_peer
            .pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let answer_to = answer_peer
            .pc
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);
        let next = offer_to.min(answer_to);
        let delay = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        if delay.is_zero() {
            offer_peer.pc.handle_timeout(Instant::now()).ok();
            answer_peer.pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                offer_peer.pc.handle_timeout(Instant::now()).ok();
                answer_peer.pc.handle_timeout(Instant::now()).ok();
            }
            Ok((n, peer)) = offer_peer.socket.recv_from(&mut offer_buf) => {
                offer_peer.pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: offer_peer.local_addr,
                        peer_addr: peer,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer)) = answer_peer.socket.recv_from(&mut answer_buf) => {
                answer_peer.pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: answer_peer.local_addr,
                        peer_addr: peer,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&answer_buf[..n]),
                }).ok();
            }
        }
    }

    let os = offer_state.lock().await;
    anyhow::bail!(
        "renegotiation test timed out: connected={}, dc1_open={}, dc2_created={}, negotation_seen={}",
        os.connected,
        os.first_dc_open,
        os.second_dc_created,
        os.negotiation_seen,
    );
}
