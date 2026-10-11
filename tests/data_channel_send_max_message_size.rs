//! `send` must reject a message larger than the negotiated `maxMessageSize`, as [W3C `send()`]
//! requires.
//!
//! The size check used to run only in `SctpHandler::handle_write`, on the pipeline's write pass,
//! where an `Err` is logged and discarded. `send` returned `Ok(())`, the message was dropped, and
//! its bytes stayed charged to `outstanding_bytes` for good.
//!
//! [W3C `send()`]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannel-send

use anyhow::Result;
use bytes::BytesMut;
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
use rtc::shared::error::Error;
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

/// Flushes both peers, then waits for one datagram or the next timer.
async fn pump(a: &mut Peer, b: &mut Peer) -> Result<()> {
    for p in [&mut *a, &mut *b] {
        while let Some(msg) = p.pc.poll_write() {
            p.socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
    }

    let fallback = Instant::now() + Duration::from_secs(1);
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
    Ok(())
}

#[tokio::test]
async fn send_larger_than_max_message_size_is_rejected() -> Result<()> {
    let mut offer = Peer::new(RTCDtlsRole::Server).await?;
    let mut answer = Peer::new(RTCDtlsRole::Client).await?;

    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    let offer_dc = offer
        .pc
        .create_data_channel("size", Some(init.clone()))?
        .id();
    let answer_dc = answer.pc.create_data_channel("size", Some(init))?.id();

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

    let mut connected = false;
    let mut open = false;
    let mut max_message_size = None;
    let mut received = None;

    let start = Instant::now();
    while start.elapsed() < TEST_TIMEOUT && received.is_none() {
        pump(&mut offer, &mut answer).await?;

        while let Some(event) = offer.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if id == offer_dc =>
                {
                    open = true
                }
                _ => {}
            }
        }
        while answer.pc.poll_event().is_some() {}
        while offer.pc.poll_read().is_some() {}
        while let Some(TaggedRTCMessage { message, .. }) = answer.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, msg) = message
                && id == answer_dc
            {
                received = Some(msg.data.len());
            }
        }

        if connected && open && max_message_size.is_none() {
            let max = offer
                .pc
                .sctp()
                .and_then(|sctp| sctp.max_message_size())
                .expect("negotiated once connected") as usize;
            max_message_size = Some(max);

            let mut dc = offer.pc.data_channel(offer_dc).expect("channel is open");
            assert_eq!(
                dc.send(Instant::now(), BytesMut::zeroed(max + 1)),
                Err(Error::ErrOutboundPacketTooLarge)
            );
            assert_eq!(
                dc.send_text(Instant::now(), "a".repeat(max + 1)),
                Err(Error::ErrOutboundPacketTooLarge)
            );
            assert_eq!(
                dc.outstanding_bytes(),
                0,
                "a rejected send must not be charged"
            );

            dc.send(Instant::now(), BytesMut::zeroed(max))?;
        }
    }

    let max_message_size = max_message_size.expect("peers never opened the channel");
    assert_eq!(
        received,
        Some(max_message_size),
        "a message of exactly max_message_size must be delivered"
    );

    offer.pc.close()?;
    answer.pc.close()?;
    Ok(())
}
