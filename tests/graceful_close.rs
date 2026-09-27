//! Closing a peer connection must tell the remote peer at once (rtc#255).
//!
//! `close()` used to send nothing: the remote only noticed when its ICE consent checks failed,
//! about five seconds later, and its data channels never closed. `close()` now sends a DTLS
//! `close_notify` (RFC 5246 §7.2.1), and a peer that receives one closes its DTLS transport,
//! its SCTP association and every data channel straight away.
//!
//! The remote's peer connection state is not changed by this: per the W3C algorithm a closed
//! DTLS transport alongside a connected ICE transport is still `connected`, until ICE says
//! otherwise. The application learns of the close from its data channels and the DTLS transport.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::transport::RTCDtlsTransportState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const NEGOTIATED_ID: u16 = 1;
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

struct Peer {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    addr: SocketAddr,
    buf: Vec<u8>,
}

impl Peer {
    async fn new(role: RTCDtlsRole) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(role)
                    .build(),
            )
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

        Ok(Self {
            pc,
            socket,
            addr,
            buf: vec![0u8; 2048],
        })
    }

    fn handle_datagram(&mut self, n: usize, peer_addr: SocketAddr) {
        self.pc
            .handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&self.buf[..n]),
            })
            .ok();
    }
}

/// Flushes both peers, then waits for one datagram or the next timer. Returns the number of
/// datagrams peer `a` sent.
async fn pump(a: &mut Peer, b: &mut Peer) -> Result<usize> {
    let mut a_sent = 0;
    while let Some(msg) = a.pc.poll_write() {
        a.socket
            .send_to(&msg.message, msg.transport.peer_addr)
            .await?;
        a_sent += 1;
    }
    while let Some(msg) = b.pc.poll_write() {
        b.socket
            .send_to(&msg.message, msg.transport.peer_addr)
            .await?;
    }

    let fallback = Instant::now() + Duration::from_millis(50);
    let next =
        a.pc.poll_timeout()
            .unwrap_or(fallback)
            .min(b.pc.poll_timeout().unwrap_or(fallback));
    let delay = next
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(5));

    tokio::select! {
        _ = tokio::time::sleep(delay) => {
            a.pc.handle_timeout(Instant::now()).ok();
            b.pc.handle_timeout(Instant::now()).ok();
        }
        Ok((n, peer_addr)) = a.socket.recv_from(&mut a.buf) => a.handle_datagram(n, peer_addr),
        Ok((n, peer_addr)) = b.socket.recv_from(&mut b.buf) => b.handle_datagram(n, peer_addr),
    }
    Ok(a_sent)
}

/// How soon the remote must learn of the close: well below the ~5 s ICE consent timeout that
/// was the only signal before.
const CLOSE_NOTICE: Duration = Duration::from_millis(500);

/// Connects two peers with a negotiated data channel, has `closer` close, and checks what the
/// other peer sees. `closer_is_dtls_server` picks which side closes.
async fn close_is_noticed_by_the_remote(closer_is_dtls_server: bool) -> Result<()> {
    let mut offer = Peer::new(RTCDtlsRole::Server).await?;
    let mut answer = Peer::new(RTCDtlsRole::Client).await?;
    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    let offer_dc = offer
        .pc
        .create_data_channel("close", Some(init.clone()))?
        .id();
    let answer_dc = answer.pc.create_data_channel("close", Some(init))?.id();

    let sdp = offer.pc.create_offer(None)?;
    offer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    answer.pc.set_remote_description(Instant::now(), sdp)?;
    let sdp = answer.pc.create_answer(None)?;
    answer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    offer.pc.set_remote_description(Instant::now(), sdp)?;

    // The offerer is the DTLS server (see `Peer::new`), the answerer the client.
    let (closer, remote, remote_dc) = if closer_is_dtls_server {
        (&mut offer, &mut answer, answer_dc)
    } else {
        (&mut answer, &mut offer, offer_dc)
    };

    let mut remote_open = false;
    let start = Instant::now();
    while start.elapsed() < TEST_TIMEOUT && !remote_open {
        pump(closer, remote).await?;
        while closer.pc.poll_event().is_some() {}
        while closer.pc.poll_read().is_some() {}
        while remote.pc.poll_read().is_some() {}
        while let Some(event) = remote.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event
                && id == remote_dc
            {
                remote_open = true;
            }
        }
    }
    assert!(remote_open, "the peers never opened the channel");

    closer.pc.close()?;
    let closed_at = Instant::now();

    let mut sent_after_close = 0;
    let mut remote_channel_closed = false;
    let mut remote_state_changes = vec![];
    while closed_at.elapsed() < CLOSE_NOTICE && !remote_channel_closed {
        sent_after_close += pump(closer, remote).await?;
        while closer.pc.poll_event().is_some() {}
        while closer.pc.poll_read().is_some() {}
        while remote.pc.poll_read().is_some() {}
        while let Some(event) = remote.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id))
                    if id == remote_dc =>
                {
                    remote_channel_closed = true;
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    remote_state_changes.push(state)
                }
                _ => {}
            }
        }
    }
    let noticed_after = closed_at.elapsed();

    assert!(
        sent_after_close > 0,
        "close() must send the close_notify (closer_is_dtls_server={closer_is_dtls_server})"
    );
    assert!(
        remote_channel_closed,
        "the remote's data channel was not closed within {CLOSE_NOTICE:?} \
         (closer_is_dtls_server={closer_is_dtls_server})"
    );
    assert_eq!(
        Some(RTCDtlsTransportState::Closed),
        remote.pc.sctp().map(|sctp| sctp.transport().state()),
        "the remote's DTLS transport is closed"
    );
    assert!(
        remote_state_changes.is_empty(),
        "per W3C the remote's connection state is not changed by the DTLS close alone, \
         got {remote_state_changes:?}"
    );

    // The closer then receives the remote's close_notify reply on a transport it has closed;
    // that must be ignored quietly.
    for _ in 0..20 {
        pump(closer, remote).await?;
        while closer.pc.poll_event().is_some() {}
        while remote.pc.poll_event().is_some() {}
    }

    println!(
        "remote noticed the close after {noticed_after:?} \
         (closer_is_dtls_server={closer_is_dtls_server})"
    );
    closer.pc.close()?;
    remote.pc.close()?;
    Ok(())
}

#[tokio::test]
async fn closing_the_dtls_server_side_is_noticed_by_the_remote() -> Result<()> {
    close_is_noticed_by_the_remote(true).await
}

#[tokio::test]
async fn closing_the_dtls_client_side_is_noticed_by_the_remote() -> Result<()> {
    close_is_noticed_by_the_remote(false).await
}
