use super::*;
use crate::{AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

/// 100 Mbit/s, in bytes per second.
const LINE_RATE: u64 = 12_500_000;
const ONE_WAY: Duration = Duration::from_millis(20);
const PIECE: usize = 16 * 1024;
const HIGH_WATER: usize = 1024 * 1024;
const STREAM: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fate {
    Deliver,
    /// Skips the propagation delay, as a reordering router sends a displaced packet ahead.
    Early,
    Drop,
}

/// One packet carrying DATA, as the impairment sees it.
struct Sent {
    index: u64,
    tsns: Vec<u32>,
}

/// One direction of the link: a bottleneck of `rate` bytes per second, then `delay`.
struct Path {
    rate: u64,
    delay: Duration,
    busy_until: Instant,
    queued: BTreeMap<(Instant, u64), Bytes>,
    seq: u64,
}

impl Path {
    fn new(now: Instant) -> Self {
        Self {
            rate: LINE_RATE,
            delay: ONE_WAY,
            busy_until: now,
            queued: BTreeMap::new(),
            seq: 0,
        }
    }

    fn send(&mut self, now: Instant, packet: Bytes, fate: Fate) {
        if fate == Fate::Drop {
            return;
        }
        let start = self.busy_until.max(now);
        let wire = Duration::from_nanos(packet.len() as u64 * 1_000_000_000 / self.rate);
        self.busy_until = start + wire;
        let arrival = match fate {
            Fate::Early => self.busy_until,
            _ => self.busy_until + self.delay,
        };
        self.seq += 1;
        self.queued.insert((arrival, self.seq), packet);
    }

    fn next_arrival(&self) -> Option<Instant> {
        self.queued.keys().next().map(|(at, _)| *at)
    }

    fn take_due(&mut self, now: Instant) -> Vec<Bytes> {
        let later = self.queued.split_off(&(now, u64::MAX));
        std::mem::replace(&mut self.queued, later)
            .into_values()
            .collect()
    }
}

struct Peer {
    endpoint: Endpoint,
    addr: SocketAddr,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
}

impl Peer {
    fn new(endpoint: Endpoint, addr: SocketAddr) -> Self {
        Self {
            endpoint,
            addr,
            handle: None,
            association: None,
        }
    }

    fn receive(&mut self, now: Instant, from: SocketAddr, packet: Bytes) {
        match self.endpoint.handle(now, from, None, packet) {
            Some((handle, DatagramEvent::NewAssociation(association))) => {
                self.handle = Some(handle);
                self.association = Some(association);
            }
            Some((_, DatagramEvent::AssociationEvent(event))) => {
                if let Some(association) = self.association.as_mut() {
                    association.handle_event(event);
                }
            }
            None => {}
        }
    }

    fn settle(&mut self, now: Instant) {
        let Some(association) = self.association.as_mut() else {
            return;
        };
        if association.poll_timeout().is_some_and(|at| at <= now) {
            association.handle_timeout(now);
        }
        while association.poll().is_some() {}
        if let Some(handle) = self.handle {
            while let Some(event) = association.poll_endpoint_event() {
                self.endpoint.handle_event(handle, event);
            }
        }
    }

    fn transmit(&mut self, now: Instant) -> Vec<Bytes> {
        let mut packets = vec![];
        if let Some(association) = self.association.as_mut() {
            while let Some(transmit) = association.poll_transmit(now) {
                if let Payload::RawEncode(contents) = transmit.message {
                    packets.extend(contents);
                }
            }
        }
        packets
    }

    fn association(&mut self) -> &mut Association {
        self.association.as_mut().expect("association established")
    }

    fn timeout(&self) -> Option<Instant> {
        self.association
            .as_ref()
            .and_then(Association::poll_timeout)
    }
}

/// Counters read off the sender at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Reading {
    cuts: u64,
    undone: u64,
    probes: u64,
    t3: u64,
    cwnd: u32,
    bytes_read: usize,
}

/// A client sending messages on one stream to a server, over a link the test impairs.
struct Sim {
    now: Instant,
    client: Peer,
    server: Peer,
    forward: Path,
    reverse: Path,
    fate: Box<dyn FnMut(&Sent) -> Fate>,
    impaired: bool,
    data_packets: u64,
    to_write: usize,
    written: usize,
    messages_written: usize,
    messages_read: usize,
    bytes_read: usize,
}

fn message(index: usize, len: usize) -> Bytes {
    Bytes::from(vec![(index % 251) as u8; len])
}

fn data_tsns(packet: &Bytes) -> Vec<u32> {
    Packet::unmarshal(packet)
        .map(|p| {
            p.chunks
                .iter()
                .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>())
                .map(|d| d.tsn)
                .collect()
        })
        .unwrap_or_default()
}

impl Sim {
    fn connect(config: TransportConfig, fate: Box<dyn FnMut(&Sent) -> Fate>) -> Self {
        let now = Instant::now();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002);
        let endpoint_config = Arc::new(EndpointConfig::default());
        let server = Endpoint::new(
            server_addr,
            TransportProtocol::UDP,
            Arc::clone(&endpoint_config),
            Some(Arc::new(ServerConfig::new(config.clone()))),
        );
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, endpoint_config, None);
        let (handle, association) = client
            .connect(now, ClientConfig::new(config), server_addr)
            .expect("connect");
        let mut client = Peer::new(client, client_addr);
        client.handle = Some(handle);
        client.association = Some(association);
        let mut sim = Self {
            now,
            client,
            server: Peer::new(server, server_addr),
            forward: Path::new(now),
            reverse: Path::new(now),
            fate,
            impaired: false,
            data_packets: 0,
            to_write: 0,
            written: 0,
            messages_written: 0,
            messages_read: 0,
            bytes_read: 0,
        };
        sim.run_until(Duration::from_secs(5), |s| {
            s.server
                .association
                .as_ref()
                .is_some_and(|a| !a.is_handshaking())
                && !s.client.association().is_handshaking()
        });
        sim.client
            .association()
            .open_stream(STREAM, PayloadProtocolIdentifier::Binary)
            .expect("open stream");
        sim.impaired = true;
        sim
    }

    fn step(&mut self) {
        let now = self.now;
        for packet in self.forward.take_due(now) {
            self.server.receive(now, self.client.addr, packet);
        }
        for packet in self.reverse.take_due(now) {
            self.client.receive(now, self.server.addr, packet);
        }
        self.client.settle(now);
        self.server.settle(now);
        self.read();
        self.write();
        for packet in self.client.transmit(now) {
            let tsns = data_tsns(&packet);
            let fate = if self.impaired && !tsns.is_empty() {
                self.data_packets += 1;
                (self.fate)(&Sent {
                    index: self.data_packets,
                    tsns,
                })
            } else {
                Fate::Deliver
            };
            self.forward.send(now, packet, fate);
        }
        for packet in self.server.transmit(now) {
            self.reverse.send(now, packet, Fate::Deliver);
        }
        self.client.settle(now);
        self.server.settle(now);
    }

    fn next_event(&self) -> Option<Instant> {
        [
            self.forward.next_arrival(),
            self.reverse.next_arrival(),
            self.client.timeout(),
            self.server.timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let end = self.now + limit;
        loop {
            self.step();
            if done(self) {
                return true;
            }
            match self.next_event() {
                Some(at) if at <= end => self.now = self.now.max(at),
                _ => {
                    self.now = end;
                    self.step();
                    return done(self);
                }
            }
        }
    }

    fn run_for(&mut self, span: Duration) {
        self.run_until(span, |_| false);
    }

    fn send(&mut self, bytes: usize) {
        self.to_write += bytes;
    }

    fn write(&mut self) {
        let now = self.now;
        while self.written < self.to_write {
            let Some(association) = self.client.association.as_mut() else {
                return;
            };
            let mut stream = association.stream(STREAM).expect("client stream");
            if stream.buffered_amount().expect("buffered amount") >= HIGH_WATER {
                return;
            }
            let len = PIECE.min(self.to_write - self.written);
            stream
                .write_sctp(
                    now,
                    &message(self.messages_written, len),
                    PayloadProtocolIdentifier::Binary,
                )
                .expect("write");
            self.written += len;
            self.messages_written += 1;
        }
    }

    fn read(&mut self) {
        let Some(association) = self.server.association.as_mut() else {
            return;
        };
        while association.accept_stream().is_some() {}
        while let Ok(Some(chunks)) = association.stream(STREAM).and_then(|mut s| s.read_sctp()) {
            let payload = chunks.to_payload(PIECE).expect("message fits a piece");
            assert!(
                payload
                    .iter()
                    .all(|b| *b == (self.messages_read % 251) as u8),
                "message {} arrived out of order or corrupted",
                self.messages_read
            );
            self.messages_read += 1;
            self.bytes_read += payload.len();
        }
    }

    fn reading(&mut self) -> Reading {
        let association = self.client.association.as_mut().expect("association");
        let mut stats = association.stats;
        Reading {
            cuts: stats.get_num_cwnd_cuts(),
            undone: stats.get_num_cwnd_cuts_undone(),
            probes: stats.get_num_loss_probes(),
            t3: stats.get_num_t3timeouts(),
            cwnd: association.cwnd,
            bytes_read: self.bytes_read,
        }
    }

    fn delivered_all(&mut self) -> bool {
        self.bytes_read == self.written && self.written == self.to_write
    }
}

fn rack_tlp() -> TransportConfig {
    TransportConfig::default().with_rack_tlp(true)
}

fn every(period: u64, offset: u64, fate: Fate) -> Box<dyn FnMut(&Sent) -> Fate> {
    Box::new(move |sent| {
        if sent.index % period == offset {
            fate
        } else {
            Fate::Deliver
        }
    })
}

#[test]
fn reordering_alone_leaves_no_cut_standing() {
    let mut sim = Sim::connect(rack_tlp(), every(100, 37, Fate::Early));
    sim.send(usize::MAX / 2);
    sim.run_for(Duration::from_secs(2));
    let settled = sim.reading();
    sim.run_for(Duration::from_secs(1));
    let end = sim.reading();

    assert!(
        settled.cuts > 0,
        "a 20 ms displacement outruns the starting allowance: {settled:?}"
    );
    assert_eq!(
        settled.cuts, end.cuts,
        "the grown allowance covers the displacement"
    );
    assert_eq!(end.cuts, end.undone, "every cut is undone: {end:?}");
    assert_eq!(0, end.t3, "no retransmission timeout: {end:?}");
}

#[test]
fn reordering_without_rack_tlp_keeps_its_cuts() {
    let mut sim = Sim::connect(TransportConfig::default(), every(100, 37, Fate::Early));
    sim.send(usize::MAX / 2);
    sim.run_for(Duration::from_secs(3));
    let end = sim.reading();

    assert!(
        end.cuts > 0,
        "the three-report rule fires on reordering: {end:?}"
    );
    assert_eq!(
        0, end.undone,
        "nothing undoes a cut with the setting off: {end:?}"
    );
    assert_eq!(0, end.probes, "no loss probe with the setting off: {end:?}");
}

#[test]
fn real_loss_keeps_its_cuts() {
    let mut sim = Sim::connect(rack_tlp(), every(500, 37, Fate::Drop));
    sim.send(4 * 1024 * 1024);
    let arrived = sim.run_until(Duration::from_secs(20), Sim::delivered_all);
    assert!(arrived, "every message arrives: {:?}", sim.reading());
    let end = sim.reading();

    assert!(end.cuts > 0, "a loss cuts the window: {end:?}");
    assert_eq!(
        0, end.undone,
        "a needed retransmission is never undone: {end:?}"
    );
    assert_eq!(
        0, end.t3,
        "loss is found by time, before the timer: {end:?}"
    );
}

#[test]
fn tail_loss_is_recovered_by_the_probe_before_the_timer() {
    let mut sim = Sim::connect(rack_tlp(), Box::new(|_| Fate::Deliver));
    sim.send(64 * 1024);
    assert!(sim.run_until(Duration::from_secs(2), Sim::delivered_all));
    sim.run_for(Duration::from_millis(500));

    let association = sim.client.association();
    let chunks_per_piece = PIECE.div_ceil(association.max_payload_size as usize) as u32;
    let tail = association
        .my_next_tsn
        .wrapping_add(4 * chunks_per_piece - 1);
    let mut dropped = false;
    sim.fate = Box::new(move |sent| {
        if !dropped && sent.tsns.contains(&tail) {
            dropped = true;
            Fate::Drop
        } else {
            Fate::Deliver
        }
    });
    let start = sim.now;
    sim.send(4 * PIECE);
    let arrived = sim.run_until(Duration::from_secs(3), Sim::delivered_all);
    let end = sim.reading();

    assert!(arrived, "every message arrives: {end:?}");
    assert!(
        end.probes > 0,
        "a probe goes out at the end of the burst: {end:?}"
    );
    assert_eq!(
        0, end.t3,
        "the probe recovers the tail before the timer: {end:?}"
    );
    assert!(
        sim.now - start < Duration::from_millis(500),
        "recovered within a few round trips, took {:?}",
        sim.now - start
    );
}

#[test]
fn a_round_trip_moving_40_20_40_ms_leaves_no_cut_standing() {
    let mut sim = Sim::connect(rack_tlp(), every(100, 37, Fate::Early));
    sim.send(usize::MAX / 2);
    sim.run_for(Duration::from_secs(2));
    for one_way in [10, 20] {
        sim.forward.delay = Duration::from_millis(one_way);
        sim.reverse.delay = Duration::from_millis(one_way);
        sim.run_for(Duration::from_secs(2));
    }
    let end = sim.reading();

    assert_eq!(end.cuts, end.undone, "every cut is undone: {end:?}");
    assert_eq!(0, end.t3, "no retransmission timeout: {end:?}");
}

#[test]
fn delayed_acknowledgements_draw_no_probe() {
    let mut sim = Sim::connect(rack_tlp(), Box::new(|_| Fate::Deliver));
    for _ in 0..10 {
        sim.send(1000);
        sim.run_for(Duration::from_millis(700));
    }
    let end = sim.reading();

    assert!(sim.delivered_all());
    assert_eq!(
        0, end.probes,
        "a lone chunk waits out the delayed SACK: {end:?}"
    );
    assert_eq!(0, end.cuts, "nothing was lost: {end:?}");
}

#[test]
fn reordering_and_loss_together_undo_only_the_needless_cuts() {
    let mut reorder = every(100, 37, Fate::Early);
    let mut lose = every(500, 91, Fate::Drop);
    let mut sim = Sim::connect(
        rack_tlp(),
        Box::new(move |sent| match lose(sent) {
            Fate::Drop => Fate::Drop,
            _ => reorder(sent),
        }),
    );
    sim.send(4 * 1024 * 1024);
    let arrived = sim.run_until(Duration::from_secs(20), Sim::delivered_all);
    let end = sim.reading();

    assert!(arrived, "every message arrives: {end:?}");

    assert!(end.undone > 0, "the needless cuts are undone: {end:?}");
    assert!(
        end.cuts > end.undone,
        "the cuts for real loss stand: {end:?}"
    );
    assert_eq!(0, end.t3, "no retransmission timeout: {end:?}");
}
