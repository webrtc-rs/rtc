//! The first message on a negotiated data channel must not be lost when it reaches a peer
//! together with the end of that peer's SCTP handshake.
//!
//! The SCTP server comes up when the COOKIE-ECHO arrives, the client only when the COOKIE-ACK
//! the server answers with does. A server that sends the moment its negotiated channel opens puts
//! that message right behind the COOKIE-ACK, and a driver that reads every datagram that is ready
//! before it polls events (the async `webrtc` driver drains bursts of up to 64) hands the client
//! both in one sweep. The client's SCTP handler used to pass the message on before the
//! `SCTPHandshakeComplete` on which the data channel handler opens negotiated channels, so it was
//! dropped for a channel that did not exist yet, after SCTP had already acknowledged it: nothing
//! ever sent it again.
//!
//! The peers exchange datagrams in memory, on a virtual clock, so the outcome does not depend on
//! scheduling. Each turn, a peer reads everything that reached it, then polls its events (and
//! sends as soon as its channel opens), then its reads.

use anyhow::Result;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The stream id both peers agree on out-of-band.
const NEGOTIATED_ID: u16 = 0;

/// How far the virtual clock may run before the test gives up.
const DEADLINE: Duration = Duration::from_secs(30);

/// A bound on the turns, should a timer keep firing without the clock moving.
const MAX_TURNS: usize = 10_000;

struct Peer {
    name: &'static str,
    pc: RTCPeerConnection,
    addr: SocketAddr,
    channel: RTCDataChannelId,
    /// Datagrams that reached this peer and that it has not read yet.
    inbox: Vec<TaggedBytesMut>,
    opened: bool,
    received: Vec<String>,
}

impl Peer {
    fn new(
        name: &'static str,
        addr: SocketAddr,
        answering_dtls_role: RTCDtlsRole,
        now: Instant,
    ) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(answering_dtls_role)
                    .build(),
            )
            .build(now)?;
        let host = CandidateHostConfig {
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
        pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        let channel = pc
            .create_data_channel(
                "negotiated",
                Some(RTCDataChannelInit {
                    negotiated: Some(NEGOTIATED_ID),
                    ..Default::default()
                }),
            )?
            .id();
        Ok(Self {
            name,
            pc,
            addr,
            channel,
            inbox: Vec::new(),
            opened: false,
            received: Vec::new(),
        })
    }

    /// One turn: everything that reached this peer, then its events, sending the moment the
    /// channel opens, then its reads. Returns the datagrams it wrote.
    fn turn(&mut self, now: Instant) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                assert_eq!(
                    id, self.channel,
                    "{}: an unexpected channel opened",
                    self.name
                );
                self.opened = true;
                self.pc
                    .data_channel(id)
                    .expect("an open channel exists")
                    .send_text(now, format!("first from {}", self.name))?;
            }
        }
        while let Some(read) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, message) = read.message {
                assert_eq!(
                    id, self.channel,
                    "{}: a message on another channel",
                    self.name
                );
                self.received
                    .push(String::from_utf8_lossy(&message.data).into_owned());
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    /// Hands this peer the datagrams `from` wrote to it, as its socket would.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            assert_eq!(
                datagram.transport.peer_addr, self.addr,
                "{from} wrote to an address other than its peer's"
            );
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }
}

/// Both peers send on their negotiated channel the moment it opens. The answerer takes the DTLS
/// client role, so it is the SCTP client too: it comes up last, and the offerer's first message
/// reaches it in the same sweep as the COOKIE-ACK.
#[test]
fn first_message_sent_on_open_reaches_the_peer_that_comes_up_last() -> Result<()> {
    let start = Instant::now();
    let mut now = start;
    let mut offerer = Peer::new(
        "offerer",
        "127.0.0.1:50000".parse()?,
        RTCDtlsRole::Server,
        now,
    )?;
    let mut answerer = Peer::new(
        "answerer",
        "127.0.0.1:50001".parse()?,
        RTCDtlsRole::Client,
        now,
    )?;

    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer.pc.set_remote_description(now, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;

    let mut turns = 0;
    while (offerer.received.is_empty() || answerer.received.is_empty())
        && now.duration_since(start) < DEADLINE
        && turns < MAX_TURNS
    {
        turns += 1;
        let written = offerer.turn(now)?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn(now)?;
        offerer.deliver(answerer.addr, written, now);

        // Nothing in flight: move the clock to the next timer.
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }

    assert!(
        offerer.opened && answerer.opened,
        "both negotiated channels should open (offerer={}, answerer={})",
        offerer.opened,
        answerer.opened
    );
    assert_eq!(
        answerer.received,
        ["first from offerer"],
        "the answerer must get the message the offerer sent the moment its channel opened"
    );
    assert_eq!(
        offerer.received,
        ["first from answerer"],
        "the offerer must get the message the answerer sent the moment its channel opened"
    );

    offerer.pc.close()?;
    answerer.pc.close()?;
    Ok(())
}
