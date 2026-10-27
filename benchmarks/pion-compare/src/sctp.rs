//! One SCTP association between two in-memory endpoints, as `rtc-sctp/examples/sctp_e2e.rs` sets
//! it up: a zero-latency wire, a virtual clock, one reliable ordered stream. An operation writes a
//! message at the client and drives both sides until the server has read it. The Go half is
//! `go/sctp.go` (pion/sctp over an in-memory packet pipe, a reader goroutine on the server).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ServerConfig, TransportConfig,
};
use shared::TransportProtocol;

struct Node {
    endpoint: Endpoint,
    peer: SocketAddr,
    handle: Option<AssociationHandle>,
    assoc: Option<Association>,
    timeout: Option<Instant>,
    connected: bool,
}

impl Node {
    fn drive(&mut self, now: Instant, inbound: &mut VecDeque<Bytes>, outbound: &mut VecDeque<Bytes>) -> bool {
        let mut worked = false;
        while let Some(data) = inbound.pop_front() {
            worked = true;
            if let Some((ch, event)) = self.endpoint.handle(now, self.peer, None, data) {
                match event {
                    DatagramEvent::NewAssociation(a) => {
                        self.handle = Some(ch);
                        self.assoc = Some(a);
                    }
                    DatagramEvent::AssociationEvent(e) => {
                        if let Some(a) = self.assoc.as_mut() {
                            a.handle_event(e);
                        }
                    }
                    _ => {}
                }
            }
        }
        let Some(assoc) = self.assoc.as_mut() else { return worked };
        if self.timeout.is_some_and(|t| t <= now) {
            self.timeout = None;
            assoc.handle_timeout(now);
        }
        while let Some(event) = assoc.poll() {
            if matches!(event, Event::Connected) {
                self.connected = true;
            }
        }
        while let Some(event) = assoc.poll_endpoint_event() {
            if let Some(ch) = self.handle {
                self.endpoint.handle_event(ch, event);
            }
        }
        while let Some(t) = assoc.poll_transmit(now) {
            if let Payload::RawEncode(contents) = t.message {
                for c in contents {
                    outbound.push_back(c);
                    worked = true;
                }
            }
        }
        self.timeout = assoc.poll_timeout();
        worked
    }
}

pub struct Association1 {
    client: Node,
    server: Node,
    c2s: VecDeque<Bytes>,
    s2c: VecDeque<Bytes>,
    now: Instant,
    msg: Bytes,
    read_buf: Vec<u8>,
    accepted: bool,
}

impl Association1 {
    pub fn new(msg_len: usize) -> Self {
        let c_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let s_addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let cfg = Arc::new(EndpointConfig::default());
        let node = |addr, peer, server: bool| Node {
            endpoint: Endpoint::new(
                addr,
                TransportProtocol::UDP,
                cfg.clone(),
                server.then(|| Arc::new(ServerConfig::new(TransportConfig::default()))),
            ),
            peer,
            handle: None,
            assoc: None,
            timeout: None,
            connected: false,
        };
        let mut client = node(c_addr, s_addr, false);
        let server = node(s_addr, c_addr, true);
        let (ch, assoc) = client
            .endpoint
            .connect(Instant::now(), ClientConfig::new(TransportConfig::default()), s_addr)
            .unwrap();
        client.handle = Some(ch);
        client.assoc = Some(assoc);
        let mut a = Self {
            client,
            server,
            c2s: VecDeque::new(),
            s2c: VecDeque::new(),
            now: Instant::now(),
            msg: Bytes::from(vec![0x5au8; msg_len]),
            read_buf: vec![0u8; msg_len],
            accepted: false,
        };
        while !(a.client.connected && a.server.connected) {
            let worked = a.step();
            if !worked {
                let t = [a.client.timeout, a.server.timeout].into_iter().flatten().min();
                a.now = t.expect("handshake deadlocked").max(a.now);
            }
        }
        a.client
            .assoc
            .as_mut()
            .unwrap()
            .open_stream(0, PayloadProtocolIdentifier::Binary)
            .unwrap();
        a
    }

    fn step(&mut self) -> bool {
        self.client.drive(self.now, &mut self.s2c, &mut self.c2s)
            | self.server.drive(self.now, &mut self.c2s, &mut self.s2c)
    }

    /// Writes one message and drives both sides until the server has read it.
    pub fn transfer(&mut self) {
        let now = self.now;
        self.client
            .assoc
            .as_mut()
            .unwrap()
            .stream(0)
            .unwrap()
            .write_sctp(now, &self.msg, PayloadProtocolIdentifier::Binary)
            .unwrap();
        loop {
            let worked = self.step();
            let assoc = self.server.assoc.as_mut().unwrap();
            if !self.accepted {
                self.accepted = assoc.accept_stream().is_some();
            }
            if self.accepted {
                let mut stream = assoc.stream(0).unwrap();
                if let Some(chunks) = stream.read_sctp().unwrap_or(None) {
                    let n = chunks.read(&mut self.read_buf).unwrap();
                    std::hint::black_box(&self.read_buf[..n]);
                    // let the SACK travel back so the next write finds window
                    while self.step() {}
                    return;
                }
            }
            if !worked {
                let t = [self.client.timeout, self.server.timeout].into_iter().flatten().min();
                self.now = t.expect("transfer deadlocked").max(self.now);
            }
        }
    }
}
