//! Reproduction for <https://github.com/webrtc-rs/rtc/issues/199>.
//!
//! RFC 8832 §6:
//!
//! > The peer that initiates opening a data channel selects a stream identifier for which the
//! > corresponding incoming and outgoing streams are unused. If the side is acting as the DTLS
//! > client, it MUST choose an even stream identifier; if the side is acting as the DTLS server,
//! > it MUST choose an odd one.
//!
//! `RTCPeerConnection::create_data_channel` picks the stream id immediately, by calling
//! `generate_data_channel_id()`, which asks `dtls_transport().role()`. Before any SDP has been
//! exchanged that role is still `RTCDtlsRole::Auto`, and the generator's test is
//!
//! ```ignore
//! if self.dtls_transport().role() != RTCDtlsRole::Client { id += 1; }
//! ```
//!
//! `Auto != Client`, so `Auto` is silently folded into *server* parity and the channel gets an
//! odd id. When the handshake later resolves this peer to the DTLS **client**, it is already
//! committed to odd ids it is not allowed to use — and to the very ids the peer acting as server
//! is simultaneously handing out.
//!
//! Both peers here complete a real DTLS handshake over loopback UDP, so the role each side is
//! checked against is the one it actually negotiated, read back through the public statistics
//! API (`RTCTransportStats::dtls_role`) rather than re-derived by the test.
//!
//! These tests are written against the public API only and are expected to FAIL until the fix
//! lands.

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Channels each peer creates *before* any SDP is exchanged — the window in which the DTLS role
/// is still unresolved and `create_data_channel` nevertheless commits to a stream id.
const CHANNELS_PER_PEER: usize = 2;

/// Ceiling for one loopback connect. Reached only on failure; a healthy handshake settles in far
/// less.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Once both peers are connected and both have recorded a negotiated DTLS role, wait this much
/// longer for data channels to open before giving up on them. With colliding stream ids the
/// remaining channels never open, and waiting out `CONNECT_TIMEOUT` for each of the seven
/// configurations would make the matrix unusable.
const CHANNEL_SETTLE: Duration = Duration::from_secs(1);

fn peer_with_role(answering_dtls_role: RTCDtlsRole) -> Result<RTCPeerConnection> {
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_answering_dtls_role(answering_dtls_role)
                .build(),
        )
        .build(Instant::now())?)
}

/// The DTLS role this peer actually negotiated, as the implementation recorded it when the
/// handshake completed.
///
/// This is the same value `generate_data_channel_id` consults, so asserting stream-id parity
/// against it makes the check a statement about the implementation rather than about the test's
/// own restatement of the derivation rules.
fn negotiated_role(pc: &mut RTCPeerConnection) -> RTCDtlsRole {
    pc.get_stats(Instant::now(), StatsSelector::None)
        .transport()
        .map(|t| t.dtls_role)
        .unwrap_or(RTCDtlsRole::Unspecified)
}

/// What RFC 8832 §6 requires of a peer in the given role.
fn required_parity(role: RTCDtlsRole) -> u16 {
    match role {
        RTCDtlsRole::Client => 0, // even
        _ => 1,                   // odd
    }
}

fn parity_name(parity: u16) -> &'static str {
    if parity == 0 { "even" } else { "odd" }
}

struct Outcome {
    /// Stream ids each peer committed to at `create_data_channel` time.
    offer_ids: Vec<u16>,
    answer_ids: Vec<u16>,
    /// The DTLS role each peer negotiated, per its own transport stats.
    offer_role: RTCDtlsRole,
    answer_role: RTCDtlsRole,
    /// Stream id -> label, for every channel each peer saw open.
    offer_open: BTreeMap<u16, String>,
    answer_open: BTreeMap<u16, String>,
    connected: bool,
}

/// Connects two peers over loopback UDP with the given answering-DTLS-role configuration on each
/// side, both creating in-band data channels *before* signalling.
async fn connect(offer_cfg: RTCDtlsRole, answer_cfg: RTCDtlsRole) -> Result<Outcome> {
    let offer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let answer_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let offer_local_addr = offer_socket.local_addr()?;
    let answer_local_addr = answer_socket.local_addr()?;

    let mut offer_pc = peer_with_role(offer_cfg)?;
    let mut answer_pc = peer_with_role(answer_cfg)?;

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

    // Both sides create channels while their DTLS role is still `Auto`. This is the
    // "both peers rapidly create data channels before the DTLS role is negotiated" case.
    let mut offer_ids = Vec::new();
    let mut answer_ids = Vec::new();
    for i in 0..CHANNELS_PER_PEER {
        offer_ids.push(
            offer_pc
                .create_data_channel(&format!("offerer-{i}"), None)?
                .id(),
        );
        answer_ids.push(
            answer_pc
                .create_data_channel(&format!("answerer-{i}"), None)?
                .id(),
        );
    }

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answer_pc.create_answer(None)?;
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_open: BTreeMap<u16, String> = BTreeMap::new();
    let mut answer_open: BTreeMap<u16, String> = BTreeMap::new();
    let mut offer_connected = false;
    let mut answer_connected = false;
    // When both roles first became readable; starts the `CHANNEL_SETTLE` grace period.
    let mut roles_known_at: Option<Instant> = None;

    let all_channels = 2 * CHANNELS_PER_PEER;

    let mut offer_buf = vec![0u8; 2000];
    let mut answer_buf = vec![0u8; 2000];
    let start = Instant::now();

    while start.elapsed() < CONNECT_TIMEOUT {
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

        let mut newly_open = Vec::new();
        while let Some(event) = offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => offer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    newly_open.push(id)
                }
                _ => {}
            }
        }
        for id in newly_open {
            if let Some(dc) = offer_pc.data_channel(id) {
                offer_open.insert(id, dc.label().to_owned());
            }
        }

        let mut newly_open = Vec::new();
        while let Some(event) = answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    newly_open.push(id)
                }
                _ => {}
            }
        }
        for id in newly_open {
            if let Some(dc) = answer_pc.data_channel(id) {
                answer_open.insert(id, dc.label().to_owned());
            }
        }

        // Drain the read side so the pipeline keeps flowing; this connection carries no media.
        while offer_pc.poll_read().is_some() {}
        while answer_pc.poll_read().is_some() {}

        // Every channel opened: nothing more to observe.
        if offer_open.len() >= all_channels && answer_open.len() >= all_channels {
            break;
        }

        if offer_connected
            && answer_connected
            && negotiated_role(&mut offer_pc) != RTCDtlsRole::Unspecified
            && negotiated_role(&mut answer_pc) != RTCDtlsRole::Unspecified
        {
            match roles_known_at {
                None => roles_known_at = Some(Instant::now()),
                Some(t) if t.elapsed() >= CHANNEL_SETTLE => break,
                Some(_) => {}
            }
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

    let offer_role = negotiated_role(&mut offer_pc);
    let answer_role = negotiated_role(&mut answer_pc);

    offer_pc.close().ok();
    answer_pc.close().ok();

    Ok(Outcome {
        offer_ids,
        answer_ids,
        offer_role,
        answer_role,
        offer_open,
        answer_open,
        connected: offer_connected && answer_connected,
    })
}

/// Checks RFC 8832 §6 for one configuration, returning every violation found rather than
/// panicking, so the matrix can report the whole picture in one run.
fn violations(case: &str, out: &Outcome) -> Vec<String> {
    let mut failures = Vec::new();

    if !out.connected {
        failures.push(format!("{case}: peers failed to connect"));
        return failures;
    }

    for (who, ids, role) in [
        ("offerer", &out.offer_ids, out.offer_role),
        ("answerer", &out.answer_ids, out.answer_role),
    ] {
        if role == RTCDtlsRole::Unspecified {
            failures.push(format!(
                "{case}: {who} never recorded a negotiated DTLS role"
            ));
            continue;
        }
        let want = required_parity(role);
        if ids.iter().any(|id| id % 2 != want) {
            failures.push(format!(
                "{case}: {who} negotiated DTLS {role} so RFC 8832 §6 requires {} stream ids, \
                 but got {ids:?}",
                parity_name(want)
            ));
        }
    }

    // The parity rule exists so the two id spaces cannot overlap. That guarantee only holds if
    // the peers negotiated *different* DTLS roles — check that separately so a role-negotiation
    // defect is reported as itself rather than as a stream-id collision.
    if out.offer_role == out.answer_role {
        failures.push(format!(
            "{case}: both peers negotiated DTLS {} — RFC 5763 requires exactly one client and \
             one server",
            out.offer_role
        ));
    } else {
        let collisions: Vec<_> = out
            .offer_ids
            .iter()
            .copied()
            .filter(|id| out.answer_ids.contains(id))
            .collect();
        if !collisions.is_empty() {
            failures.push(format!(
                "{case}: both peers claimed the same SCTP stream ids {collisions:?} \
                 (offerer {:?} as {}, answerer {:?} as {})",
                out.offer_ids, out.offer_role, out.answer_ids, out.answer_role
            ));
        }
    }

    failures
}

/// The full matrix of answering-DTLS-role configurations, offerer vs answerer.
///
/// Every combination must satisfy RFC 8832 §6 against the role each peer *actually negotiated*:
/// the peer that ends up the DTLS client uses even stream ids, the one that ends up the server
/// uses odd ones, and the two sets are therefore disjoint. Runs all seven and reports every
/// violation at once, so one run shows the whole shape of the bug rather than only the first
/// case that trips.
//TODO: https://github.com/webrtc-rs/rtc/issues/199
#[tokio::test]
#[ignore]
async fn stream_id_parity_matches_negotiated_dtls_role_across_all_role_configurations() -> Result<()>
{
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    use RTCDtlsRole::{Auto, Client, Server};

    let cases = [
        ("1. offer=Client answer=Server", Client, Server),
        ("2. offer=Server answer=Client", Server, Client),
        ("3. offer=Client answer=Auto  ", Client, Auto),
        ("4. offer=Auto   answer=Server", Auto, Server),
        ("5. offer=Server answer=Auto  ", Server, Auto),
        ("6. offer=Auto   answer=Client", Auto, Client),
        ("7. offer=Auto   answer=Auto  ", Auto, Auto),
    ];

    let mut failures = Vec::new();
    for (name, offer_cfg, answer_cfg) in cases {
        let out = connect(offer_cfg, answer_cfg).await?;
        println!(
            "{name}: negotiated offerer={} answerer={}, offerer ids {:?}, answerer ids {:?}, \
             channels open offerer={} answerer={}",
            out.offer_role,
            out.answer_role,
            out.offer_ids,
            out.answer_ids,
            out.offer_open.len(),
            out.answer_open.len(),
        );
        failures.extend(violations(name, &out));
    }

    assert!(
        failures.is_empty(),
        "{} violation(s) across {} role configurations:\n  {}",
        failures.len(),
        cases.len(),
        failures.join("\n  ")
    );

    Ok(())
}

/// End-to-end consequence of the same bug.
///
/// Uses the offerer=`Auto` / answerer=`Server` configuration, which negotiates the offerer to the
/// DTLS client — the peer that must use even ids and does not. Each peer creates
/// `CHANNELS_PER_PEER` channels before signalling, so after connecting each should observe
/// `2 * CHANNELS_PER_PEER` open channels: its own, plus the peer's. With colliding stream ids the
/// remote's `DATA_CHANNEL_OPEN` lands on a stream id a local channel already occupies, so the
/// peer's channels are never surfaced as distinct channels and the expected label set never
/// completes.
//TODO: https://github.com/webrtc-rs/rtc/issues/199
#[tokio::test]
#[ignore]
async fn colliding_stream_ids_prevent_both_peers_channels_from_opening() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let out = connect(RTCDtlsRole::Auto, RTCDtlsRole::Server).await?;

    assert!(out.connected, "peers should connect");

    let mut want: Vec<String> = (0..CHANNELS_PER_PEER)
        .map(|i| format!("offerer-{i}"))
        .chain((0..CHANNELS_PER_PEER).map(|i| format!("answerer-{i}")))
        .collect();
    want.sort();

    let mut got_offer: Vec<String> = out.offer_open.values().cloned().collect();
    let mut got_answer: Vec<String> = out.answer_open.values().cloned().collect();
    got_offer.sort();
    got_answer.sort();

    assert_eq!(
        got_offer, want,
        "offerer should see every channel exactly once, its own and the peer's; \
         open channels by stream id: {:?}",
        out.offer_open
    );
    assert_eq!(
        got_answer, want,
        "answerer should see every channel exactly once, its own and the peer's; \
         open channels by stream id: {:?}",
        out.answer_open
    );

    Ok(())
}
