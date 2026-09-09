//! Identical, public-API fixed-work workloads for two rtc-sctp source snapshots.
//! Build with build_perf.py; this file is not part of the library or its API.

use bytes::Bytes;
use rtc_sctp::{
    Association, AssociationError, AssociationHandle, ClientConfig, DatagramEvent, Endpoint,
    EndpointConfig, Event, Payload, PayloadProtocolIdentifier, ReliabilityType, ServerConfig,
    TransportConfig,
};
use shared::TransportProtocol;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;
const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;
const SEND_CAP: usize = 1 << 20;

#[cfg(feature = "allocation-probe")]
mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);
    struct Probe;
    #[global_allocator]
    static ALLOCATOR: Probe = Probe;

    fn record(size: usize, realloc: bool, succeeded: bool) {
        if succeeded && ENABLED.load(Relaxed) {
            if realloc { &REALLOCS } else { &CALLS }.fetch_add(1, Relaxed);
            BYTES.fetch_add(size as u64, Relaxed);
        }
    }
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let result = unsafe { System.alloc(layout) };
            record(layout.size(), false, !result.is_null());
            result
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let result = unsafe { System.alloc_zeroed(layout) };
            record(layout.size(), false, !result.is_null());
            result
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let result = unsafe { System.realloc(ptr, layout, size) };
            record(size, true, !result.is_null());
            result
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
        }
    }
    pub fn start() {
        ENABLED.store(true, Relaxed);
    }
    pub fn finish() -> String {
        ENABLED.store(false, Relaxed);
        format!(
            "\"allocation_probe\":true,\"allocations\":{},\"reallocations\":{},\"allocated_bytes\":{}",
            CALLS.load(Relaxed),
            REALLOCS.load(Relaxed),
            BYTES.load(Relaxed)
        )
    }
}

struct Config {
    scenario: String,
    messages: u64,
    size: usize,
    streams: usize,
    cycles: u64,
    iterations: u64,
    seed: u64,
    rwnd: u32,
    reliability: String,
    unordered: bool,
    packet_budget: usize,
}

impl Config {
    fn parse() -> Result<Self> {
        let mut value = Self {
            scenario: "multi-stream".into(),
            messages: 60_000,
            size: 32,
            streams: 32,
            cycles: 512,
            iterations: 1,
            seed: 237,
            rwnd: 1 << 20,
            reliability: "reliable".into(),
            unordered: false,
            packet_budget: usize::MAX,
        };
        let mut args = std::env::args().skip(1);
        while let Some(name) = args.next() {
            let arg = args
                .next()
                .ok_or_else(|| format!("missing value for {name}"))?;
            if name == "--scenario" {
                value.scenario = arg;
                continue;
            }
            if name == "--reliability" {
                value.reliability = arg;
                continue;
            }
            let number = arg.parse::<u64>().map_err(|e| format!("{name}: {e}"))?;
            match name.as_str() {
                "--messages" => value.messages = number,
                "--size" => value.size = usize::try_from(number).map_err(|e| e.to_string())?,
                "--streams" => {
                    value.streams = usize::try_from(number).map_err(|e| e.to_string())?
                }
                "--cycles" => value.cycles = number,
                "--iterations" => value.iterations = number,
                "--seed" => value.seed = number,
                "--rwnd" => value.rwnd = u32::try_from(number).map_err(|e| e.to_string())?,
                "--unordered" if number <= 1 => value.unordered = number != 0,
                "--packet-budget" => {
                    value.packet_budget = usize::try_from(number).map_err(|e| e.to_string())?
                }
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        if !matches!(
            value.scenario.as_str(),
            "small-rwnd" | "multi-stream" | "reset-reuse"
        ) {
            return Err("--scenario must be small-rwnd, multi-stream or reset-reuse".into());
        }
        if !(1..=1_000_000).contains(&value.messages)
            || !(16..=65_536).contains(&value.size)
            || !(1..=4096).contains(&value.streams)
            || !(1..=10_000).contains(&value.cycles)
            || !(1..=100).contains(&value.iterations)
            || value.rwnd < value.size as u32
            || value.packet_budget == 0
            || !matches!(value.reliability.as_str(), "reliable" | "rexmit:0")
        {
            return Err("invalid workload bounds (messages 1..1M, size 16..64KiB, streams 1..4096, cycles 1..10000, iterations 1..100, rwnd >= size, packet-budget >= 1, reliability reliable|rexmit:0)".into());
        }
        Ok(value)
    }

    fn messages_per_direction(&self) -> u64 {
        if self.scenario == "reset-reuse" {
            (self.cycles + 1) * self.streams as u64
        } else {
            self.messages
        }
    }
}

#[derive(Default)]
struct Totals {
    sent: u64,
    received: u64,
    bytes: u64,
    opened: u64,
    closed: u64,
    reopened: u64,
    packets: u64,
    timers: u64,
    virtual_ms: u128,
    data_chunks: u64,
    retransmitted_data_chunks: u64,
    sack_chunks: u64,
    gap_sack_chunks: u64,
    forward_tsn_chunks: u64,
    max_wire_inflight: u32,
    sack_observations: u64,
    remaining_after_sack: u64,
    max_remaining_after_sack: u32,
}

struct Node {
    endpoint: Endpoint,
    peer_addr: SocketAddr,
    handle: Option<AssociationHandle>,
    assoc: Option<Association>,
    connected: bool,
    sent: u64,
    received: u64,
    received_per_stream: Vec<u64>,
    closed_per_stream: Vec<u64>,
    packets: u64,
    timers: u64,
    min_rwnd: u32,
    wire: WireStats,
}

/// Observe the actual cumulative-ACK window through public wire bytes. This
/// is not cwnd or private outstanding-byte accounting. On the no-loss transfer
/// workloads it measures precisely how many DATA TSNs remain after each SACK.
#[derive(Default)]
struct WireStats {
    last_data_tsn: Option<u32>,
    cumulative_ack: Option<u32>,
    data_chunks: u64,
    retransmitted_data_chunks: u64,
    sack_chunks: u64,
    gap_sack_chunks: u64,
    forward_tsn_chunks: u64,
    max_inflight: u32,
    sack_observations: u64,
    remaining_after_sack: u64,
    max_remaining_after_sack: u32,
}

impl WireStats {
    fn observe(&mut self, packet: &[u8], outgoing: bool) -> Result<()> {
        let mut offset = 12;
        while offset + 4 <= packet.len() {
            let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            if length < 4 || offset + length > packet.len() {
                return Err("invalid observed chunk".into());
            }
            let kind = packet[offset];
            if outgoing && kind == 0 && length >= 16 {
                self.data_chunks += 1;
                let tsn = u32::from_be_bytes(packet[offset + 4..offset + 8].try_into().unwrap());
                if self
                    .last_data_tsn
                    .is_some_and(|last| tsn.wrapping_sub(last) >= 1 << 31 || tsn == last)
                {
                    self.retransmitted_data_chunks += 1;
                } else {
                    self.last_data_tsn = Some(tsn);
                    let acknowledged = *self.cumulative_ack.get_or_insert(tsn.wrapping_sub(1));
                    self.max_inflight = self.max_inflight.max(tsn.wrapping_sub(acknowledged));
                }
            } else if outgoing && kind == 3 {
                self.sack_chunks += 1;
                if length >= 16 && packet[offset + 12..offset + 14] != [0, 0] {
                    self.gap_sack_chunks += 1;
                }
            } else if outgoing && kind == 192 {
                self.forward_tsn_chunks += 1;
            } else if !outgoing && kind == 3 && length >= 16 {
                let tsn = u32::from_be_bytes(packet[offset + 4..offset + 8].try_into().unwrap());
                if let Some(last) = self.last_data_tsn {
                    let remaining = last.wrapping_sub(tsn);
                    if remaining >= 1 << 31 {
                        return Err("SACK acknowledges unobserved DATA".into());
                    }
                    self.cumulative_ack = Some(tsn);
                    self.sack_observations += 1;
                    self.remaining_after_sack += remaining as u64;
                    self.max_remaining_after_sack = self.max_remaining_after_sack.max(remaining);
                }
            }
            offset += (length + 3) & !3;
        }
        Ok(())
    }
}

impl Node {
    fn new(endpoint: Endpoint, peer_addr: SocketAddr, streams: usize) -> Self {
        Self {
            endpoint,
            peer_addr,
            handle: None,
            assoc: None,
            connected: false,
            sent: 0,
            received: 0,
            received_per_stream: vec![0; streams],
            closed_per_stream: vec![0; streams],
            packets: 0,
            timers: 0,
            min_rwnd: u32::MAX,
            wire: WireStats::default(),
        }
    }

    fn drive(
        &mut self,
        now: Instant,
        inbound: &mut VecDeque<Bytes>,
        outbound: &mut VecDeque<Bytes>,
        packet_budget: usize,
    ) -> Result<bool> {
        let mut worked = false;
        for _ in 0..packet_budget.min(inbound.len()) {
            let data = inbound.pop_front().unwrap();
            self.wire.observe(&data, false)?;
            worked = true;
            if let Some((handle, event)) = self.endpoint.handle(now, self.peer_addr, None, data) {
                match event {
                    DatagramEvent::NewAssociation(assoc) => {
                        if self.assoc.is_some() {
                            return Err("unexpected second association".into());
                        }
                        self.handle = Some(handle);
                        self.assoc = Some(assoc);
                    }
                    DatagramEvent::AssociationEvent(event) => self
                        .assoc
                        .as_mut()
                        .ok_or("packet without association")?
                        .handle_event(event),
                    _ => return Err("unsupported endpoint event".into()),
                }
            }
        }
        let Some(assoc) = &mut self.assoc else {
            return Ok(worked);
        };
        if assoc.poll_timeout().is_some_and(|deadline| deadline <= now) {
            assoc.handle_timeout(now);
            self.timers += 1;
            worked = true;
        }
        while let Some(transmit) = assoc.poll_transmit(now) {
            let Payload::RawEncode(packets) = transmit.message else {
                return Err("unexpected encoded payload type".into());
            };
            for packet in packets {
                self.packets += 1;
                self.wire.observe(&packet, true)?;
                // Observe only public wire bytes; no benchmark-only SCTP hooks.
                let mut offset = 12;
                while offset + 4 <= packet.len() {
                    let length =
                        u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
                    if length < 4 || offset + length > packet.len() {
                        return Err("invalid emitted chunk".into());
                    }
                    if packet[offset] == 3 && length >= 16 {
                        self.min_rwnd = self.min_rwnd.min(u32::from_be_bytes(
                            packet[offset + 8..offset + 12].try_into().unwrap(),
                        ));
                    }
                    offset += (length + 3) & !3;
                }
                outbound.push_back(packet);
            }
            worked = true;
        }
        while let Some(event) = assoc.poll() {
            match event {
                Event::Connected => self.connected = true,
                Event::HandshakeFailed { reason } => {
                    return Err(format!("handshake failed: {reason}"));
                }
                Event::AssociationLost { reason, id } => {
                    if assoc.is_closed() || reason != AssociationError::Reset {
                        return Err(format!("association lost: {reason}"));
                    }
                    *self
                        .closed_per_stream
                        .get_mut(id as usize)
                        .ok_or("close for unexpected SID")? += 1;
                }
                _ => {}
            }
            worked = true;
        }
        if let Some(event) = assoc.poll_endpoint_event() {
            self.endpoint
                .handle_event(self.handle.ok_or("missing endpoint handle")?, event);
            return Err("association unexpectedly drained".into());
        }
        if outbound.len() > 100_000 {
            return Err("wire queue bound exceeded".into());
        }
        Ok(worked)
    }

    fn buffered(&mut self, streams: usize) -> Result<usize> {
        let assoc = self.assoc.as_mut().ok_or("missing association")?;
        (0..streams).try_fold(0, |sum, sid| {
            let amount = assoc
                .stream(sid as u16)
                .map_err(|e| e.to_string())?
                .buffered_amount()
                .map_err(|e| e.to_string())?;
            Ok(sum + amount)
        })
    }

    fn write_to(&mut self, target: u64, source: usize, cfg: &Config, now: Instant) -> Result<bool> {
        let mut buffered = self.buffered(cfg.streams)?;
        let before = self.sent;
        while self.sent < target && buffered < SEND_CAP {
            let mut data = vec![payload_byte(cfg.seed, source, self.sent); cfg.size];
            data[..8].copy_from_slice(&self.sent.to_le_bytes());
            let sid = (self.sent % cfg.streams as u64) as u16;
            let count = self
                .assoc
                .as_mut()
                .unwrap()
                .stream(sid)
                .map_err(|e| e.to_string())?
                .write_sctp(now, &Bytes::from(data), PPI)
                .map_err(|e| e.to_string())?;
            if count != cfg.size {
                return Err(format!("short write: {count}/{}", cfg.size));
            }
            buffered += count;
            self.sent += 1;
        }
        Ok(self.sent != before)
    }

    fn read_all(&mut self, source: usize, cfg: &Config, buffer: &mut [u8]) -> Result<bool> {
        let before = self.received;
        let assoc = self.assoc.as_mut().ok_or("missing association")?;
        for sid in 0..cfg.streams {
            let mut stream = assoc.stream(sid as u16).map_err(|e| e.to_string())?;
            while let Some(chunks) = stream.read_sctp().map_err(|e| e.to_string())? {
                let size = chunks.read(buffer).map_err(|e| e.to_string())?;
                if size != cfg.size || chunks.ppi != PPI {
                    return Err("invalid complete message".into());
                }
                let expected = self.received_per_stream[sid] * cfg.streams as u64 + sid as u64;
                let sequence = u64::from_le_bytes(buffer[..8].try_into().unwrap());
                let fill = payload_byte(cfg.seed, source, expected);
                if sequence != expected || buffer[8..size].iter().any(|byte| *byte != fill) {
                    return Err(format!(
                        "wrong/duplicate message on SID {sid}: {sequence}, expected {expected}"
                    ));
                }
                std::hint::black_box(&buffer[..size]);
                self.received_per_stream[sid] += 1;
                self.received += 1;
            }
        }
        Ok(self.received != before)
    }
}

fn payload_byte(seed: u64, source: usize, sequence: u64) -> u8 {
    (seed ^ sequence.rotate_left(7) ^ (source as u64 + 1).wrapping_mul(0x9e37_79b9)) as u8
}

struct Pair {
    nodes: [Node; 2],
    c2s: VecDeque<Bytes>,
    s2c: VecDeque<Bytes>,
    now: Instant,
    started: Instant,
    steps: u64,
    buffer: Vec<u8>,
}

impl Pair {
    fn new(cfg: &Config) -> Result<Self> {
        let started = Instant::now();
        let addresses: [SocketAddr; 2] = [
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:5001".parse().unwrap(),
        ];
        let endpoint = Arc::new(EndpointConfig::default());
        let transport = || {
            TransportConfig::default()
                .with_max_message_size(cfg.size as u32)
                .with_max_receive_buffer_size(cfg.rwnd)
                .with_max_num_inbound_streams(cfg.streams as u16)
                .with_max_num_outbound_streams(cfg.streams as u16)
        };
        let mut client = Node::new(
            Endpoint::new(addresses[0], TransportProtocol::UDP, endpoint.clone(), None),
            addresses[1],
            cfg.streams,
        );
        let server = Node::new(
            Endpoint::new(
                addresses[1],
                TransportProtocol::UDP,
                endpoint,
                Some(Arc::new(ServerConfig::new(transport()))),
            ),
            addresses[0],
            cfg.streams,
        );
        let (handle, assoc) = client
            .endpoint
            .connect(started, ClientConfig::new(transport()), addresses[1])
            .map_err(|e| e.to_string())?;
        client.handle = Some(handle);
        client.assoc = Some(assoc);
        let mut pair = Self {
            nodes: [client, server],
            c2s: VecDeque::new(),
            s2c: VecDeque::new(),
            now: started,
            started,
            steps: 0,
            buffer: vec![0; cfg.size],
        };
        while !pair.nodes.iter().all(|node| node.connected) {
            if !pair.step(cfg, false)? {
                pair.advance()?;
            }
        }
        Ok(pair)
    }

    fn step(&mut self, cfg: &Config, read: bool) -> Result<bool> {
        self.steps += 1;
        if self.steps > 20_000_000
            || (self.steps % 1024 == 0 && self.started.elapsed() > Duration::from_secs(90))
        {
            return Err("workload exceeded its step/wall-clock bound".into());
        }
        // A small-window workload handles one datagram per application read
        // turn. This bounds each receive burst below rwnd, instead of making a
        // throughput comparison depend on a pre-existing zero-window deadlock.
        let budget = if cfg.scenario == "small-rwnd" {
            1
        } else {
            cfg.packet_budget
        };
        let mut worked = self.nodes[0].drive(self.now, &mut self.s2c, &mut self.c2s, budget)?;
        worked |= self.nodes[1].drive(self.now, &mut self.c2s, &mut self.s2c, budget)?;
        if read {
            worked |= self.nodes[0].read_all(1, cfg, &mut self.buffer)?;
            worked |= self.nodes[1].read_all(0, cfg, &mut self.buffer)?;
        }
        Ok(worked)
    }

    fn advance(&mut self) -> Result<()> {
        let deadline = self
            .nodes
            .iter()
            .filter_map(|node| node.assoc.as_ref().and_then(Association::poll_timeout))
            .min()
            .ok_or_else(|| {
                format!(
                    "deadlock without timer: sent={:?}, received={:?}",
                    self.nodes.each_ref().map(|n| n.sent),
                    self.nodes.each_ref().map(|n| n.received)
                )
            })?;
        if deadline <= self.now
            || deadline.duration_since(self.started) > Duration::from_secs(86_400)
        {
            return Err("timer did not advance or exceeded the virtual-time bound".into());
        }
        self.now = deadline;
        Ok(())
    }

    fn open(&mut self, cfg: &Config) -> Result<()> {
        for node in &mut self.nodes {
            for sid in 0..cfg.streams {
                node.assoc
                    .as_mut()
                    .unwrap()
                    .open_stream(sid as u16, PPI)
                    .map_err(|e| format!("open/reopen SID {sid}: {e}"))?
                    .set_reliability_params(
                        cfg.unordered,
                        if cfg.reliability == "rexmit:0" {
                            ReliabilityType::Rexmit
                        } else {
                            ReliabilityType::Reliable
                        },
                        0,
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn transfer(&mut self, cfg: &Config, target: u64) -> Result<()> {
        loop {
            let mut worked = false;
            for (source, node) in self.nodes.iter_mut().enumerate() {
                worked |= node.write_to(target, source, cfg, self.now)?;
            }
            worked |= self.step(cfg, true)?;
            if self.nodes.iter().any(|node| node.received > target) {
                return Err("extra delivery".into());
            }
            if self
                .nodes
                .iter()
                .all(|node| node.sent == target && node.received == target)
                && self.nodes[0].buffered(cfg.streams)? == 0
                && self.nodes[1].buffered(cfg.streams)? == 0
                && self.c2s.is_empty()
                && self.s2c.is_empty()
            {
                return Ok(());
            }
            if !worked {
                self.advance()?;
            }
        }
    }

    fn reset(&mut self, cfg: &Config, cycle: u64) -> Result<()> {
        for sid in 0..cfg.streams {
            self.nodes[0]
                .assoc
                .as_mut()
                .unwrap()
                .stream(sid as u16)
                .map_err(|e| e.to_string())?
                .close(self.now)
                .map_err(|e| e.to_string())?;
        }
        loop {
            let worked = self.step(cfg, false)?;
            if self
                .nodes
                .iter()
                .any(|node| node.closed_per_stream.iter().any(|count| *count > cycle))
            {
                return Err("duplicate close notification".into());
            }
            if self.nodes.iter().all(|node| {
                node.closed_per_stream.iter().all(|count| *count == cycle)
                    && node.assoc.as_ref().unwrap().stream_ids().is_empty()
            }) && self.c2s.is_empty()
                && self.s2c.is_empty()
            {
                return Ok(());
            }
            if !worked {
                self.advance()?;
            }
        }
    }
}

fn run(cfg: &Config) -> Result<(Totals, u32)> {
    let mut total = Totals::default();
    let mut min_rwnd = u32::MAX;
    for _ in 0..cfg.iterations {
        let mut pair = Pair::new(cfg)?;
        pair.open(cfg)?;
        total.opened += 2 * cfg.streams as u64;
        if cfg.scenario == "reset-reuse" {
            for cycle in 1..=cfg.cycles {
                pair.transfer(cfg, cycle * cfg.streams as u64)?;
                pair.reset(cfg, cycle)?;
                pair.open(cfg)?;
                total.reopened += 2 * cfg.streams as u64;
                total.opened += 2 * cfg.streams as u64;
            }
        }
        pair.transfer(cfg, cfg.messages_per_direction())?;
        total.virtual_ms += pair.now.duration_since(pair.started).as_millis();
        for node in &pair.nodes {
            total.sent += node.sent;
            total.received += node.received;
            total.bytes += node.received * cfg.size as u64;
            total.closed += node.closed_per_stream.iter().sum::<u64>();
            total.packets += node.packets;
            total.timers += node.timers;
            total.data_chunks += node.wire.data_chunks;
            total.retransmitted_data_chunks += node.wire.retransmitted_data_chunks;
            total.sack_chunks += node.wire.sack_chunks;
            total.gap_sack_chunks += node.wire.gap_sack_chunks;
            total.forward_tsn_chunks += node.wire.forward_tsn_chunks;
            total.max_wire_inflight = total.max_wire_inflight.max(node.wire.max_inflight);
            total.sack_observations += node.wire.sack_observations;
            total.remaining_after_sack += node.wire.remaining_after_sack;
            total.max_remaining_after_sack = total
                .max_remaining_after_sack
                .max(node.wire.max_remaining_after_sack);
            min_rwnd = min_rwnd.min(node.min_rwnd);
        }
    }
    let expected = 2 * cfg.iterations * cfg.messages_per_direction();
    if total.sent != expected || total.received != expected || total.closed != total.reopened {
        return Err("final workload count mismatch".into());
    }
    Ok((total, min_rwnd))
}

fn main() {
    let cfg = Config::parse().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    #[cfg(feature = "allocation-probe")]
    allocation::start();
    let started = Instant::now();
    let result = run(&cfg);
    let elapsed_ns = started.elapsed().as_nanos();
    #[cfg(feature = "allocation-probe")]
    let allocation = allocation::finish();
    #[cfg(not(feature = "allocation-probe"))]
    let allocation = "\"allocation_probe\":false,\"allocations\":null,\"reallocations\":null,\"allocated_bytes\":null";
    let (total, min_rwnd) = result.unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1)
    });
    println!(
        "{{\"scenario\":\"{}\",\"iterations\":{},\"messages_per_direction\":{},\"streams\":{},\"message_size\":{},\"cycles\":{},\"seed\":{},\"rwnd\":{},\"sent_messages\":{},\"delivered_messages\":{},\"delivered_bytes\":{},\"opened_streams\":{},\"closed_streams\":{},\"reopened_streams\":{},\"packets\":{},\"timer_firings\":{},\"virtual_elapsed_ms\":{},\"elapsed_ns\":{},\"min_advertised_rwnd\":{},\"reliability\":\"{}\",\"unordered\":{},\"packet_budget\":{},\"data_chunks\":{},\"retransmitted_data_chunks\":{},\"sack_chunks\":{},\"gap_sack_chunks\":{},\"forward_tsn_chunks\":{},\"max_wire_inflight_chunks\":{},\"sack_observations\":{},\"remaining_after_sack_sum\":{},\"max_remaining_after_sack_chunks\":{},{}}}",
        cfg.scenario,
        cfg.iterations,
        cfg.messages_per_direction(),
        cfg.streams,
        cfg.size,
        cfg.cycles,
        cfg.seed,
        cfg.rwnd,
        total.sent,
        total.received,
        total.bytes,
        total.opened,
        total.closed,
        total.reopened,
        total.packets,
        total.timers,
        total.virtual_ms,
        elapsed_ns,
        min_rwnd,
        cfg.reliability,
        cfg.unordered,
        cfg.packet_budget,
        total.data_chunks,
        total.retransmitted_data_chunks,
        total.sack_chunks,
        total.gap_sack_chunks,
        total.forward_tsn_chunks,
        total.max_wire_inflight,
        total.sack_observations,
        total.remaining_after_sack,
        total.max_remaining_after_sack,
        allocation
    );
}
