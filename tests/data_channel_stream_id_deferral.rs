//! Data-channel stream-id deferral: ids are only assigned once the DTLS role is resolved.
//!
//! W3C WebRTC section 6.1 step 18 assigns the stream id after the DTLS role has been negotiated, and
//! section 6.1.1.3 step 4.2 assigns it during the SCTP *connected* procedure. RFC 8832 section 6 then forces
//! the DTLS client onto even ids and the DTLS server onto odd ones. Creating channels *before*
//! the answer is applied must yield a null id that later resolves with the correct
//! role parity, never a guess made while the role is still `Auto`.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
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

/// Both peers create an in-band channel while the DTLS role is still `Auto`. Neither may get a
/// stream id at creation. Each peer also receives the other's DATA_CHANNEL_OPEN as an incoming
/// channel once SCTP connects, so every side must resolve *both* stream ids (its own dialed
/// channel and the peer's announcement) to distinct, role-parity-correct values, with the
/// offerer (DTLS server) on an odd id and the answerer (DTLS client) on an even one. Before the
/// fix the two peers could hand themselves the *same* id and collide on one SCTP stream.
#[tokio::test]
async fn test_deferred_ids_get_role_parity_without_collision() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut p = connect().await?;

    // Created before any offer/answer is exchanged: the DTLS role is unresolved.
    let offer_dc = p.offer_pc.create_data_channel("deferred", None)?;
    let answer_dc = p.answer_pc.create_data_channel("deferred", None)?;
    assert_eq!(
        offer_dc.id(),
        None,
        "a channel created while the role is Auto must have a null stream id"
    );
    assert_eq!(
        answer_dc.id(),
        None,
        "a channel created while the role is Auto must have a null stream id"
    );
    let offer_own_handle = offer_dc.handle();
    let answer_own_handle = answer_dc.handle();
    drop(offer_dc);
    drop(answer_dc);

    let offer = p.offer_pc.create_offer(None)?;
    p.offer_pc
        .set_local_description(Instant::now(), offer.clone())?;
    p.answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = p.answer_pc.create_answer(None)?;
    p.answer_pc
        .set_local_description(Instant::now(), answer.clone())?;
    p.offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_connected = false;
    let mut answer_connected = false;
    // The open event carries a stream id (the public-facing identity).
    let mut offer_opens: Vec<RTCDataChannelId> = Vec::new();
    let mut answer_opens: Vec<RTCDataChannelId> = Vec::new();

    let mut offer_buf = vec![0u8; 2048];
    let mut answer_buf = vec![0u8; 2048];

    let start = Instant::now();
    let deadline = Duration::from_secs(15);

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
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(stream_id)) => {
                    offer_opens.push(stream_id);
                }
                _ => {}
            }
        }
        while let Some(event) = p.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(stream_id)) => {
                    answer_opens.push(stream_id);
                }
                _ => {}
            }
        }
        while p.offer_pc.poll_read().is_some() {}
        while p.answer_pc.poll_read().is_some() {}

        // The open events fire with stream ids; resolve the own channel ids via lookup.
        let offer_own_ok = p
            .offer_pc
            .data_channel_handle(offer_own_handle)
            .and_then(|dc| dc.id())
            .map(|id| offer_opens.contains(&id))
            .unwrap_or(false);
        let answer_own_ok = p
            .answer_pc
            .data_channel_handle(answer_own_handle)
            .and_then(|dc| dc.id())
            .map(|id| answer_opens.contains(&id))
            .unwrap_or(false);

        if offer_connected
            && answer_connected
            && offer_own_ok
            && answer_own_ok
            && offer_opens.len() >= 2
            && answer_opens.len() >= 2
        {
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
            .min(Duration::from_millis(10));
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
            Ok((n, peer_addr)) = p.offer_socket.recv_from(&mut offer_buf) => {
                p.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: p.offer_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = p.answer_socket.recv_from(&mut answer_buf) => {
                p.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: p.answer_addr,
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
        "peers should connect (offer={offer_connected}, answer={answer_connected})"
    );

    // The offerer dials its own channel on an odd stream id; the answerer's announcement arrives
    // there as a distinct incoming channel carrying the answerer's even id.
    let offer_own_id: RTCDataChannelId = p
        .offer_pc
        .data_channel_handle(offer_own_handle)
        .expect("offerer's own channel must still exist")
        .id()
        .expect("offerer's own channel must be assigned an id once connected");
    let answer_own_id: RTCDataChannelId = p
        .answer_pc
        .data_channel_handle(answer_own_handle)
        .expect("answerer's own channel must still exist")
        .id()
        .expect("answerer's own channel must be assigned an id once connected");

    assert_eq!(
        offer_own_id % 2,
        1,
        "the DTLS server must use an odd stream id (got {offer_own_id})"
    );
    assert_eq!(
        answer_own_id % 2,
        0,
        "the DTLS client must use an even stream id (got {answer_own_id})"
    );
    assert_ne!(
        offer_own_id, answer_own_id,
        "the two peers must not collide on a stream id"
    );

    // The remote announcement on each side must carry the peer's stream id: the offerer sees the
    // answerer's even id, the answerer sees the offerer's odd id. Each side's dialed and
    // announced ids must agree.
    let offer_incoming = offer_opens
        .iter()
        .copied()
        .find(|&id| id != offer_own_id)
        .expect("the offerer must also open the peer's announcement");
    let answer_incoming = answer_opens
        .iter()
        .copied()
        .find(|&id| id != answer_own_id)
        .expect("the answerer must also open the peer's announcement");

    let offer_incoming_id = p
        .offer_pc
        .data_channel(offer_incoming)
        .expect("offerer's incoming channel must still exist")
        .id()
        .expect("incoming channels are opened with an assigned id");
    let answer_incoming_id = p
        .answer_pc
        .data_channel(answer_incoming)
        .expect("answerer's incoming channel must still exist")
        .id()
        .expect("incoming channels are opened with an assigned id");

    assert_eq!(
        offer_incoming_id, answer_own_id,
        "the offerer's incoming channel carries the answerer's stream id"
    );
    assert_eq!(
        answer_incoming_id, offer_own_id,
        "the answerer's incoming channel carries the offerer's stream id"
    );

    p.offer_pc.close()?;
    p.answer_pc.close()?;

    Ok(())
}

/// Application data must flow over a channel whose id was deferred and only assigned at the
/// connected procedure: the offerer dials its (odd) stream, the answerer receives it on the
/// incoming channel, echoes, and the offerer receives the echo back.
#[tokio::test]
async fn test_deferred_channel_actually_exchanges_data() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut p = connect().await?;

    let offer_dc = p.offer_pc.create_data_channel(
        "data",
        Some(RTCDataChannelInit {
            ordered: true,
            ..Default::default()
        }),
    )?;
    let offer_own_handle = offer_dc.handle();
    drop(offer_dc);
    let answer_dc = p.answer_pc.create_data_channel(
        "data",
        Some(RTCDataChannelInit {
            ordered: true,
            ..Default::default()
        }),
    )?;
    let answer_own_handle = answer_dc.handle();
    drop(answer_dc);

    let offer = p.offer_pc.create_offer(None)?;
    p.offer_pc
        .set_local_description(Instant::now(), offer.clone())?;
    p.answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = p.answer_pc.create_answer(None)?;
    p.answer_pc
        .set_local_description(Instant::now(), answer.clone())?;
    p.offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut offer_opens: Vec<RTCDataChannelId> = Vec::new();
    let mut answer_opens: Vec<RTCDataChannelId> = Vec::new();
    let mut answer_received_offer = false;
    let mut offer_received_echo = false;
    let mut ping_sent = false;

    let mut offer_buf = vec![0u8; 2048];
    let mut answer_buf = vec![0u8; 2048];

    let start = Instant::now();
    let deadline = Duration::from_secs(15);

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
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(stream_id)) => {
                    offer_opens.push(stream_id);
                }
                _ => {}
            }
        }
        while let Some(event) = p.answer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(stream_id)) => {
                    answer_opens.push(stream_id);
                }
                _ => {}
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = p.offer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(stream_id, msg) = message {
                if String::from_utf8_lossy(&msg.data) == "echo" {
                    // The echo returns on the offerer's own dialed stream (the answerer echoed
                    // on the same stream the ping came in on).
                    let own = p
                        .offer_pc
                        .data_channel_handle(offer_own_handle)
                        .and_then(|dc| dc.id())
                        .unwrap();
                    assert_eq!(stream_id, own);
                    offer_received_echo = true;
                }
            }
        }
        while let Some(TaggedRTCMessage { message, .. }) = p.answer_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(stream_id, msg) = message {
                if String::from_utf8_lossy(&msg.data) == "ping" {
                    let own = p
                        .answer_pc
                        .data_channel_handle(answer_own_handle)
                        .and_then(|dc| dc.id())
                        .unwrap();
                    assert_ne!(
                        stream_id, own,
                        "ping arrives on the incoming channel, not the answerer's own"
                    );
                    answer_received_offer = true;
                    if let Some(mut dc) = p.answer_pc.data_channel(stream_id) {
                        dc.send_text(Instant::now(), "echo".to_string())?;
                    }
                }
            }
        }

        // Send once the offerer's own channel is open.
        let offer_own_open = p
            .offer_pc
            .data_channel_handle(offer_own_handle)
            .and_then(|dc| dc.id())
            .map(|id| offer_opens.contains(&id))
            .unwrap_or(false);
        if offer_own_open && !ping_sent {
            if let Some(mut dc) = p.offer_pc.data_channel_handle(offer_own_handle) {
                dc.send_text(Instant::now(), "ping".to_string())?;
                ping_sent = true;
            }
        }

        if offer_received_echo && answer_received_offer {
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
            .min(Duration::from_millis(10));
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
            Ok((n, peer_addr)) = p.offer_socket.recv_from(&mut offer_buf) => {
                p.offer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: p.offer_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&offer_buf[..n]),
                }).ok();
            }
            Ok((n, peer_addr)) = p.answer_socket.recv_from(&mut answer_buf) => {
                p.answer_pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: p.answer_addr,
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
        answer_received_offer && offer_received_echo,
        "application data must flow both ways over deferred channels"
    );

    p.offer_pc.close()?;
    p.answer_pc.close()?;

    Ok(())
}
