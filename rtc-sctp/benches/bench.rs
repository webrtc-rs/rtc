//! SCTP benchmarks: association throughput, and the packet codec.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-sctp --bench bench                    # Transfer/* only
//! cargo bench --package rtc-sctp --bench bench --features bench   # adds Packet/*
//! ```
//!
//! * `Transfer/*` connects two associations in memory — no sockets, virtual clock — and streams
//!   256 KiB per iteration over one reliable ordered stream until the receiver has read it all.
//!   That exercises the whole steady-state path on both sides: fragmentation, the pending and
//!   payload queues, congestion control, bundling, marshal, endpoint demultiplexing, unmarshal,
//!   SACK generation and processing, and reassembly. The association is established once, outside
//!   the measurement. Throughput is for both ends together on one core.
//! * `Packet/*` marshals and unmarshals a DATA packet in isolation. The codec is `pub(crate)`, so
//!   these go through the `fuzzing` shims and need the crate's `bench` feature.
//!
//! `rtc-bench`'s `DataChannel/Throughput/*` runs the same transfer with DTLS and the data-channel
//! layer on top; the difference between the two is what those layers cost. The `sctp_e2e` and
//! `sctp_micro` examples are fixed-work versions of these for `perf` and `poop`, where a
//! statistical harness gets in the way.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use criterion::{BatchSize, Criterion, SamplingMode, Throughput, criterion_main};
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ServerConfig, TransportConfig,
};
use shared::TransportProtocol;

/// Bytes moved per `Transfer` iteration.
const BATCH_BYTES: usize = 256 * 1024;

/// Unacknowledged bytes the writer allows before it lets the wire drain, as in `sctp_e2e`.
const SEND_BUFFER_LIMIT: usize = 1 << 20;

/// Virtual time a drive may consume before it is declared stalled.
const VIRTUAL_TIME_BUDGET: Duration = Duration::from_secs(120);

/// One endpoint with its single association.
struct Node {
    endpoint: Endpoint,
    peer_addr: SocketAddr,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
    timeout: Option<Instant>,
    connected: bool,
}

impl Node {
    fn new(endpoint: Endpoint, peer_addr: SocketAddr) -> Self {
        Self {
            endpoint,
            peer_addr,
            handle: None,
            association: None,
            timeout: None,
            connected: false,
        }
    }

    fn association(&mut self) -> &mut Association {
        self.association.as_mut().expect("association established")
    }

    /// Delivers inbound datagrams, fires a due timer, and drains events and transmits. Returns
    /// whether any datagram was consumed or produced.
    fn drive(
        &mut self,
        now: Instant,
        inbound: &mut VecDeque<Bytes>,
        outbound: &mut VecDeque<Bytes>,
    ) -> bool {
        let mut worked = false;

        while let Some(datagram) = inbound.pop_front() {
            worked = true;
            if let Some((handle, event)) = self.endpoint.handle(now, self.peer_addr, None, datagram)
            {
                match event {
                    DatagramEvent::NewAssociation(association) => {
                        self.handle = Some(handle);
                        self.association = Some(association);
                    }
                    DatagramEvent::AssociationEvent(event) => {
                        if let Some(association) = self.association.as_mut() {
                            association.handle_event(event);
                        }
                    }
                    _ => {}
                }
            }
        }

        let Some(association) = self.association.as_mut() else {
            return worked;
        };

        if self.timeout.is_some_and(|deadline| deadline <= now) {
            self.timeout = None;
            association.handle_timeout(now);
        }

        while let Some(event) = association.poll() {
            if matches!(event, Event::Connected) {
                self.connected = true;
            }
        }

        while let Some(event) = association.poll_endpoint_event() {
            if let Some(handle) = self.handle {
                self.endpoint.handle_event(handle, event);
            }
        }

        while let Some(transmit) = association.poll_transmit(now) {
            if let Payload::RawEncode(contents) = transmit.message {
                worked |= !contents.is_empty();
                outbound.extend(contents);
            }
        }
        self.timeout = association.poll_timeout();

        worked
    }
}

/// A client and server association joined by a lossless, zero-latency in-memory wire.
struct AssociationPair {
    client: Node,
    server: Node,
    to_server: VecDeque<Bytes>,
    to_client: VecDeque<Bytes>,
    now: Instant,
    accepted: bool,
    read_buffer: Vec<u8>,
}

impl AssociationPair {
    fn connect() -> Self {
        let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let endpoint_config = Arc::new(EndpointConfig::default());

        let mut client = Node::new(
            Endpoint::new(
                client_addr,
                TransportProtocol::UDP,
                Arc::clone(&endpoint_config),
                None,
            ),
            server_addr,
        );
        let server = Node::new(
            Endpoint::new(
                server_addr,
                TransportProtocol::UDP,
                endpoint_config,
                Some(Arc::new(ServerConfig::new(TransportConfig::default()))),
            ),
            client_addr,
        );

        let now = Instant::now();
        let (handle, association) = client
            .endpoint
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_addr,
            )
            .unwrap();
        client.handle = Some(handle);
        client.association = Some(association);

        let mut pair = Self {
            client,
            server,
            to_server: VecDeque::new(),
            to_client: VecDeque::new(),
            now,
            accepted: false,
            read_buffer: vec![0; 64 * 1024],
        };
        pair.drive_until("associated", |pair| {
            pair.client.connected && pair.server.connected
        });
        pair.client
            .association()
            .open_stream(0, PayloadProtocolIdentifier::Binary)
            .unwrap();
        pair
    }

    fn step(&mut self) -> bool {
        let client = self
            .client
            .drive(self.now, &mut self.to_client, &mut self.to_server);
        let server = self
            .server
            .drive(self.now, &mut self.to_server, &mut self.to_client);
        client || server
    }

    fn advance_to_next_deadline(&mut self, what: &str, deadline: Instant) {
        let next = [self.client.timeout, self.server.timeout]
            .into_iter()
            .flatten()
            .filter(|at| *at > self.now)
            .min();
        self.now = next.unwrap_or(self.now + Duration::from_millis(1));
        assert!(
            self.now <= deadline,
            "stalled: {what} not reached within {VIRTUAL_TIME_BUDGET:?} of virtual time"
        );
    }

    fn drive_until(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        let deadline = self.now + VIRTUAL_TIME_BUDGET;
        while !done(self) {
            if !self.step() {
                self.advance_to_next_deadline(what, deadline);
            }
        }
    }

    /// Writes `count` copies of `message` on stream 0 and drives until the server has read them.
    fn transfer(&mut self, message: &Bytes, count: usize) {
        let expected = message.len() * count;
        let deadline = self.now + VIRTUAL_TIME_BUDGET;
        let mut written = 0;
        let mut read = 0;

        while read < expected {
            let mut wrote = false;
            {
                let now = self.now;
                let mut stream = self.client.association().stream(0).unwrap();
                while written < count && stream.buffered_amount().unwrap() < SEND_BUFFER_LIMIT {
                    stream
                        .write_sctp(now, message, PayloadProtocolIdentifier::Binary)
                        .unwrap();
                    written += 1;
                    wrote = true;
                }
            }

            let worked = self.step();

            let mut drained = false;
            {
                let association = self.server.association.as_mut().unwrap();
                if !self.accepted {
                    self.accepted = association.accept_stream().is_some();
                }
                if self.accepted {
                    let mut stream = association.stream(0).unwrap();
                    while let Some(chunks) = stream.read_sctp().unwrap() {
                        let n = chunks.read(&mut self.read_buffer).unwrap();
                        std::hint::black_box(&self.read_buffer[..n]);
                        read += n;
                        drained = true;
                    }
                }
            }

            if !(worked || wrote || drained) {
                self.advance_to_next_deadline("transfer complete", deadline);
            }
        }
    }
}

fn size_label(size: usize) -> String {
    if size >= 1024 && size.is_multiple_of(1024) {
        format!("{}KiB", size / 1024)
    } else {
        format!("{size}B")
    }
}

fn benchmark_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("SCTP/Transfer");
    group.sampling_mode(SamplingMode::Flat).sample_size(30);

    for size in [64, 1024, 16 * 1024, 64 * 1024] {
        let mut pair = AssociationPair::connect();
        let message = Bytes::from((0..size).map(|index| index as u8).collect::<Vec<_>>());
        let count = (BATCH_BYTES / size).max(1);

        group.throughput(Throughput::Bytes((count * size) as u64));
        group.bench_function(format!("reliable/{}", size_label(size)), |b| {
            b.iter_batched(
                || (),
                |()| pair.transfer(&message, count),
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

#[cfg(feature = "bench")]
fn benchmark_packet(c: &mut Criterion) {
    use rtc_sctp::fuzzing;

    let mut group = c.benchmark_group("SCTP/Packet");

    // One full-MTU DATA chunk is the data-channel common case; sixteen small chunks bundled into
    // one packet is the chatty case, where per-chunk overhead dominates.
    for (payload_len, chunks) in [(1200, 1), (64, 16)] {
        let packet = fuzzing::sample_data_packet(payload_len, chunks);
        let label = format!("{chunks}x{}", size_label(payload_len));
        group.throughput(Throughput::Bytes(packet.len() as u64));

        group.bench_function(format!("unmarshal/{label}"), |b| {
            b.iter(|| fuzzing::packet_unmarshal(std::hint::black_box(&packet)).unwrap());
        });

        // `bench_packet_marshal` parses once and then marshals `iterations` times, so the one
        // parse is amortised across the whole sample.
        group.bench_function(format!("marshal/{label}"), |b| {
            b.iter_custom(|iterations| {
                let started = Instant::now();
                fuzzing::bench_packet_marshal(&packet, iterations).unwrap();
                started.elapsed()
            });
        });
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_transfer(&mut c);
    #[cfg(feature = "bench")]
    benchmark_packet(&mut c);
}

criterion_main!(benches);
