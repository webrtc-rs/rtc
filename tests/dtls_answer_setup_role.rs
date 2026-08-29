//! An answer must never carry `a=setup:actpass`.
//!
//! RFC 5763 §5:
//!
//! > The answerer MUST use either a setup attribute value of setup:active or setup:passive.
//!
//! `actpass` is an offer-only value: it says "you choose". An answer that repeats it leaves the
//! DTLS role genuinely unnegotiated, and both endpoints then fall back to their own local
//! preference. When those preferences happen to agree, both become the DTLS client, both wait for
//! a ClientHello, and the handshake deadlocks.
//!
//! `create_answer` derives the answer's `setup` value from `SettingEngine::answering_dtls_role`.
//! `RTCDtlsRole::Auto` maps to `ConnectionRole::Actpass`, and the guard that substitutes a
//! concrete default previously tested only for `ConnectionRole::Unspecified` — so configuring an
//! answerer with the seemingly innocuous `Auto` emitted a non-conformant answer.
//!
//! Found while building the reproduction for
//! <https://github.com/webrtc-rs/rtc/issues/199>: the offerer=`Client` / answerer=`Auto` cell of
//! that test's role matrix never connected.

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
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

/// Builds a peer. `None` leaves `answering_dtls_role` at its default (`Unspecified`).
fn peer(answering_dtls_role: Option<RTCDtlsRole>) -> Result<RTCPeerConnection> {
    let mut setting_engine = SettingEngineBuilder::new();
    if let Some(role) = answering_dtls_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine.build())
        .build(Instant::now())?)
}

/// The `a=setup` value carried by a description.
fn setup_attr(desc: &RTCSessionDescription) -> Result<String> {
    Ok(desc
        .unmarshal()?
        .media_descriptions
        .iter()
        .flat_map(|m| m.attributes.iter())
        .find(|a| a.key == "setup")
        .and_then(|a| a.value.clone())
        .unwrap_or_default())
}

/// Produces an answer from a peer configured with the given answering role, and returns the
/// answer's `a=setup` value. A data channel supplies the application m-section.
fn answer_setup(answering_dtls_role: Option<RTCDtlsRole>) -> Result<String> {
    let mut offer_pc = peer(None)?;
    let mut answer_pc = peer(answering_dtls_role)?;

    offer_pc.create_data_channel("data", None)?;

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    assert_eq!(
        setup_attr(&offer)?,
        "actpass",
        "an offer must use actpass (RFC 5763 §5)"
    );
    answer_pc.set_remote_description(Instant::now(), offer)?;

    setup_attr(&answer_pc.create_answer(None)?)
}

/// Every `answering_dtls_role` configuration must produce a conformant answer.
#[test]
fn answer_setup_is_always_active_or_passive() -> Result<()> {
    let cases = [
        (
            None,
            "active",
            "default (Unspecified) → RFC 5763's recommended active",
        ),
        (
            Some(RTCDtlsRole::Auto),
            "active",
            "Auto means 'no preference', which for an answerer must resolve to a concrete role",
        ),
        (Some(RTCDtlsRole::Client), "active", "Client → active"),
        (Some(RTCDtlsRole::Server), "passive", "Server → passive"),
    ];

    for (role, want, why) in cases {
        let got = answer_setup(role)?;
        assert_ne!(
            got, "actpass",
            "answering_dtls_role={role:?} produced a=setup:actpass, which RFC 5763 §5 forbids \
             in an answer ({why})"
        );
        assert_eq!(got, want, "answering_dtls_role={role:?}: {why}");
    }

    Ok(())
}

/// The combination that used to deadlock: an offerer pinned to `Client` answered by a peer
/// configured `Auto`.
///
/// With `actpass` in the answer, the offerer saw no explicit remote role and fell back to its own
/// `Client`, while the answerer fell back through `Auto` to the default answering role — also
/// `Client`. Both waited for a ClientHello and the handshake never completed.
#[tokio::test]
async fn offerer_pinned_to_client_connects_to_answerer_configured_auto() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let offer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let answer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let offer_local_addr = offer_socket.local_addr()?;
    let answer_local_addr = answer_socket.local_addr()?;

    let mut offer_pc = peer(Some(RTCDtlsRole::Client))?;
    let mut answer_pc = peer(Some(RTCDtlsRole::Auto))?;

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

    offer_pc.create_data_channel("data", None)?;

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answer_pc.create_answer(None)?;
    assert_ne!(
        setup_attr(&answer)?,
        "actpass",
        "the answer must pin a concrete DTLS role"
    );
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(8) && !(offer_connected && answer_connected) {
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
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                RTCPeerConnectionState::Connected,
            ) = event
            {
                offer_connected = true;
            }
        }
        while let Some(event) = answer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                RTCPeerConnectionState::Connected,
            ) = event
            {
                answer_connected = true;
            }
        }

        while offer_pc.poll_read().is_some() {}
        while answer_pc.poll_read().is_some() {}

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
        offer_connected && answer_connected,
        "DTLS handshake should complete (offer={offer_connected}, answer={answer_connected}); \
         both peers taking the same role deadlocks it"
    );

    offer_pc.close()?;
    answer_pc.close()?;

    Ok(())
}
