//! A deterministic in-memory network for two sans-I/O peer connections: datagrams cross
//! instantly, time is virtual and advances only to the next deadline, so a whole ICE + DTLS +
//! SCTP/SRTP session runs in milliseconds with no sockets and no sleeping.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::rtp_transceiver::RTCRtpSenderId;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

/// One peer and what it has reported so far.
pub struct Side {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    /// Every event, in order, until drained by the test.
    pub events: Vec<RTCPeerConnectionEvent>,
    /// Every inbound message (RTP, RTCP, data channel), in order.
    pub messages: Vec<RTCMessage>,
    /// The next RTP sequence number per SSRC for [`Sim::send_video`], so successive calls keep
    /// counting (a repeat would be dropped by SRTP replay protection).
    pub next_seq: std::collections::HashMap<u32, u16>,
}

impl Side {
    pub fn connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }
}

pub struct Sim {
    pub a: Side,
    pub b: Side,
    pub now: Instant,
    candidates_exchanged: bool,
}

fn host_candidate(addr: SocketAddr) -> RTCIceCandidateInit {
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
    .new_candidate_host()
    .expect("a host candidate");
    RTCIceCandidate::from(&candidate)
        .to_json()
        .expect("candidate json")
}

impl Sim {
    pub fn new(a: RTCPeerConnection, b: RTCPeerConnection) -> Sim {
        Sim {
            a: Side {
                pc: a,
                addr: "10.0.0.1:5000".parse().unwrap(),
                events: vec![],
                messages: vec![],
                next_seq: Default::default(),
            },
            b: Side {
                pc: b,
                addr: "10.0.0.2:5000".parse().unwrap(),
                events: vec![],
                messages: vec![],
                next_seq: Default::default(),
            },
            now: Instant::now(),
            candidates_exchanged: false,
        }
    }

    /// A full offer/answer exchange from `a` to `b` (or `b` to `a`), then the candidates the
    /// first time, then ICE, DTLS and SCTP run for up to a virtual second.
    pub fn negotiate(&mut self, a_offers: bool) {
        let now = self.now;
        {
            let (offerer, answerer) = if a_offers {
                (&mut self.a, &mut self.b)
            } else {
                (&mut self.b, &mut self.a)
            };
            let offer = offerer.pc.create_offer(None).expect("create_offer");
            offerer
                .pc
                .set_local_description(now, offer.clone())
                .expect("set local offer");
            answerer
                .pc
                .set_remote_description(now, offer)
                .expect("set remote offer");
            let answer = answerer.pc.create_answer(None).expect("create_answer");
            answerer
                .pc
                .set_local_description(now, answer.clone())
                .expect("set local answer");
            offerer
                .pc
                .set_remote_description(now, answer)
                .expect("set remote answer");
        }
        if !self.candidates_exchanged {
            self.candidates_exchanged = true;
            let (ca, cb) = (host_candidate(self.a.addr), host_candidate(self.b.addr));
            self.a.pc.add_local_candidate(ca.clone()).unwrap();
            self.b.pc.add_local_candidate(cb.clone()).unwrap();
            self.a.pc.add_remote_candidate(cb).unwrap();
            self.b.pc.add_remote_candidate(ca).unwrap();
        }
        self.run_for(Duration::from_secs(1));
    }

    /// Moves datagrams, events and timers until nothing is left to do right now.
    fn settle(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            for from_a in [true, false] {
                loop {
                    let (src, dst) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let Some(msg) = src.pc.poll_write() else {
                        break;
                    };
                    moved = true;
                    // Datagrams for an address the other side does not own go nowhere.
                    if msg.transport.peer_addr != dst.addr {
                        continue;
                    }
                    let _ = dst.pc.handle_read(TaggedBytesMut {
                        now: self.now,
                        transport: TransportContext {
                            local_addr: dst.addr,
                            peer_addr: src.addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&msg.message[..]),
                    });
                }
            }
            for side in [&mut self.a, &mut self.b] {
                while let Some(event) = side.pc.poll_event() {
                    moved = true;
                    side.events.push(event);
                }
                while let Some(TaggedRTCMessage { message, .. }) = side.pc.poll_read() {
                    moved = true;
                    side.messages.push(message);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the simulated network never went quiet");
    }

    /// Runs the network for `span` of virtual time, firing each side's timers when due.
    pub fn run_for(&mut self, span: Duration) {
        let end = self.now + span;
        loop {
            self.settle();
            let next = [self.a.pc.poll_timeout(), self.b.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            match next {
                Some(t) if t <= end => {
                    self.now = t.max(self.now);
                    let now = self.now;
                    let _ = self.a.pc.handle_timeout(now);
                    let _ = self.b.pc.handle_timeout(now);
                }
                _ => {
                    self.now = end;
                    self.settle();
                    return;
                }
            }
        }
    }

    /// Runs until `done` holds or `limit` of virtual time has passed; returns whether it held.
    pub fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Sim) -> bool) -> bool {
        let end = self.now + limit;
        while self.now < end {
            self.run_for(Duration::from_millis(50));
            if done(self) {
                return true;
            }
        }
        done(self)
    }
}

impl Side {
    /// How many `OnTrack(OnOpen)` events this side has reported.
    pub fn tracks_opened(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_))))
            .count()
    }

    /// How many `OnTrack(OnClose)` events this side has reported.
    pub fn tracks_closed(&self) -> usize {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(_))
                )
            })
            .count()
    }

    /// How many RTP packets this side has received.
    pub fn rtp_received(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| matches!(m, RTCMessage::RtpPacket(_, _)))
            .count()
    }

    /// How many `OnNegotiationNeeded` events this side has reported.
    pub fn negotiation_needed(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent))
            .count()
    }

    /// Sends one RTP packet from `sender` with the payload type negotiated for it.
    pub fn send_rtp(&mut self, now: Instant, sender: RTCRtpSenderId, ssrc: u32, seq: u16) {
        let payload_type = self
            .pc
            .rtp_sender(sender)
            .and_then(|mut s| {
                s.get_parameters()
                    .rtp_parameters
                    .codecs
                    .first()
                    .map(|c| c.payload_type)
            })
            .unwrap_or(96);
        self.pc
            .rtp_sender(sender)
            .expect("the sender exists")
            .write_rtp(
                now,
                rtp::packet::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        marker: true,
                        payload_type,
                        sequence_number: seq,
                        timestamp: u32::from(seq) * 3000,
                        ssrc,
                        ..Default::default()
                    },
                    payload: bytes::Bytes::from_static(&[0x10, 0x00, 0x00]),
                },
            )
            .expect("write_rtp");
    }
}

impl Sim {
    pub fn side(&mut self, a: bool) -> &mut Side {
        if a { &mut self.a } else { &mut self.b }
    }

    /// Sends `count` RTP packets from `sender` on side `a_sends`, one per 20 ms of virtual time.
    pub fn send_video(&mut self, a_sends: bool, sender: RTCRtpSenderId, ssrc: u32, count: u16) {
        for _ in 0..count {
            let now = self.now;
            let side = self.side(a_sends);
            let seq = side.next_seq.entry(ssrc).or_insert(0);
            let current = *seq;
            *seq = seq.wrapping_add(1);
            side.send_rtp(now, sender, ssrc, current);
            self.run_for(Duration::from_millis(20));
        }
    }
}
