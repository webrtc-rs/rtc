//! Bounded stateful SCTP test driver. Compiled only for tests/fuzzing/bench.
//!
//! Application commands and packet scheduling are derived from input bytes;
//! packets always come from a real handshake and keep their original checksum.
//! In particular, a delayed packet is checked against its transmission time,
//! never its arrival time. No production state is patched to arrange a test.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use shared::TransportProtocol;

use crate::packet::Packet;
use crate::{
    Association, AssociationHandle, ChunkPayloadData, ClientConfig, DatagramEvent, Endpoint,
    EndpointConfig, Event, Payload, PayloadProtocolIdentifier, ReliabilityType, ServerConfig,
    StreamEvent, TransportConfig,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Policy {
    Reliable,
    Timed(u32),
    Rexmit(u32),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CloseKind {
    Stop,
    Finish,
    Close,
}

struct Node {
    endpoint: Endpoint,
    remote: SocketAddr,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
    connected: bool,
}

#[derive(Clone)]
struct WirePacket {
    from: usize,
    bytes: Bytes,
}

struct Message {
    from: usize,
    sid: u16,
    ordered: bool,
    policy: Policy,
    written_at: Instant,
    bytes: Bytes,
    // A close is allowed to discard an application delivery. The generator
    // therefore requires reliable delivery only while that SID stays open.
    required: bool,
}

/// Shared property oracle for hand-written tests and libFuzzer inputs.
pub(crate) struct Model {
    nodes: [Node; 2],
    pub(crate) now: Instant,
    start: Instant,
    wire: VecDeque<WirePacket>,
    messages: BTreeMap<u64, Message>,
    delivered: BTreeSet<u64>,
    last_ordered: BTreeMap<(usize, u16), u64>,
    sent_tsns: BTreeMap<(usize, u32), (u64, usize)>,
    fragment_message: BTreeMap<(usize, u16, bool, u16), u64>,
    accepted: BTreeMap<(usize, u16), usize>,
    released: BTreeMap<(usize, u16), usize>,
    trace: VecDeque<String>,
    next_message: u64,
    had_reset: bool,
    // App delivery may advance through an EOF fence without scheduling a timer.
    // Fair draining therefore tracks synchronous progress as well as deadlines.
    progress: u64,
}

impl Model {
    pub(crate) fn new(now: Instant) -> Self {
        let addresses: [SocketAddr; 2] = [
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:5001".parse().unwrap(),
        ];
        let endpoint_config = Arc::new(EndpointConfig::default());
        let transport = TransportConfig::default()
            .with_max_message_size(16384)
            .with_max_num_inbound_streams(32)
            .with_max_num_outbound_streams(32);
        let mut nodes = [
            Node {
                endpoint: Endpoint::new(
                    addresses[0],
                    TransportProtocol::UDP,
                    endpoint_config.clone(),
                    None,
                ),
                remote: addresses[1],
                handle: None,
                association: None,
                connected: false,
            },
            Node {
                endpoint: Endpoint::new(
                    addresses[1],
                    TransportProtocol::UDP,
                    endpoint_config,
                    Some(Arc::new(ServerConfig::new(transport.clone()))),
                ),
                remote: addresses[0],
                handle: None,
                association: None,
                connected: false,
            },
        ];
        let (handle, association) = nodes[0]
            .endpoint
            .connect(now, ClientConfig::new(transport), addresses[1])
            .unwrap();
        nodes[0].handle = Some(handle);
        nodes[0].association = Some(association);
        let mut model = Self {
            nodes,
            now,
            start: now,
            wire: VecDeque::new(),
            messages: BTreeMap::new(),
            delivered: BTreeSet::new(),
            last_ordered: BTreeMap::new(),
            sent_tsns: BTreeMap::new(),
            fragment_message: BTreeMap::new(),
            accepted: BTreeMap::new(),
            released: BTreeMap::new(),
            trace: VecDeque::new(),
            next_message: 1,
            had_reset: false,
            progress: 0,
        };
        model.poll();
        model.deliver_all();
        model.require(
            model.nodes.iter().all(|n| n.connected),
            "handshake did not complete",
        );
        model
    }

    fn record(&mut self, action: String) {
        if self.trace.len() == 2048 {
            // Keep the first application actions even when a stuck procedure
            // generates many repeated timer events at the end of a trace.
            self.trace.remove(128);
        }
        self.trace.push_back(format!(
            "t={}ms {action}",
            self.now.duration_since(self.start).as_millis()
        ));
    }

    fn require(&self, predicate: bool, message: &str) {
        assert!(
            predicate,
            "{message}\n{}",
            self.trace.iter().cloned().collect::<Vec<_>>().join("\n")
        );
    }

    pub(crate) fn open(&mut self, side: usize, sid: u16) -> bool {
        self.record(format!("open {side} {sid}"));
        let association = self.nodes[side].association.as_mut().unwrap();
        if association.is_closed() {
            return false;
        }
        association
            .open_stream(sid, PayloadProtocolIdentifier::Binary)
            .is_ok()
    }

    pub(crate) fn send(
        &mut self,
        side: usize,
        sid: u16,
        ordered: bool,
        policy: Policy,
        length: usize,
    ) -> Option<u64> {
        let id = self.next_message;
        self.next_message += 1;
        self.record(format!(
            "send {side} {sid} {ordered} {policy:?} len={length} id={id}"
        ));
        let mut bytes = vec![0; length.max(8)];
        for (index, value) in bytes.iter_mut().enumerate() {
            *value = (id.wrapping_mul(37).wrapping_add(index as u64 * 13) % 251) as u8;
        }
        bytes[..8].copy_from_slice(&id.to_be_bytes());
        let bytes = Bytes::from(bytes);
        // A peer which explicitly stopped its read half is allowed to discard
        // later arrivals. An absent receiver stream is different: DATA opens it.
        let receiver_reading = self.nodes[1 - side]
            .association
            .as_mut()
            .unwrap()
            .stream(sid)
            .map_or(true, |stream| stream.is_readable());
        let association = self.nodes[side].association.as_mut().unwrap();
        if association.is_closed() {
            return None;
        }
        let Ok(mut stream) = association.stream(sid) else {
            return None;
        };
        let (kind, value) = match policy {
            Policy::Reliable => (ReliabilityType::Reliable, 0),
            Policy::Timed(value) => (ReliabilityType::Timed, value),
            Policy::Rexmit(value) => (ReliabilityType::Rexmit, value),
        };
        stream
            .set_reliability_params(!ordered, kind, value)
            .unwrap();
        let before = stream.buffered_amount().unwrap();
        let Ok(written) = stream.write_sctp(self.now, &bytes, PayloadProtocolIdentifier::Binary)
        else {
            return None;
        };
        let after = stream.buffered_amount().unwrap();
        self.require(
            written == bytes.len(),
            "accepted a partial application message",
        );
        self.require(
            after == before + written,
            "write did not account for every payload byte",
        );
        *self.accepted.entry((side, sid)).or_default() += written;
        self.messages.insert(
            id,
            Message {
                from: side,
                sid,
                ordered,
                policy,
                written_at: self.now,
                bytes,
                required: matches!(policy, Policy::Reliable) && receiver_reading,
            },
        );
        Some(id)
    }

    pub(crate) fn close(&mut self, side: usize, sid: u16, kind: CloseKind) {
        self.record(format!("close {side} {sid} {kind:?}"));
        let association = self.nodes[side].association.as_mut().unwrap();
        let Ok(mut stream) = association.stream(sid) else {
            return;
        };
        let result = match kind {
            CloseKind::Stop => stream.stop(self.now),
            CloseKind::Finish => stream.finish(),
            CloseKind::Close => stream.close(self.now),
        };
        if result.is_ok() {
            self.had_reset = true;
            if matches!(kind, CloseKind::Stop | CloseKind::Close) {
                for message in self
                    .messages
                    .values_mut()
                    .filter(|m| m.sid == sid && m.from == 1 - side)
                {
                    message.required = false;
                }
            }
        }
    }

    fn inspect_transmission(&mut self, from: usize, bytes: &Bytes) {
        let packet = Packet::unmarshal(bytes).expect("stack emitted malformed packet");
        for chunk in packet.chunks {
            let Some(data) = chunk.as_any().downcast_ref::<ChunkPayloadData>() else {
                self.record(format!("control {from} {chunk}"));
                continue;
            };
            let fragment_key = (
                from,
                data.stream_identifier,
                data.unordered,
                data.stream_sequence_number,
            );
            let key = (from, data.tsn);
            let previous = self.sent_tsns.get(&key).copied();
            let id = if let Some((id, _)) = previous {
                id
            } else if data.beginning_fragment {
                self.require(
                    data.user_data.len() >= 8,
                    "empty/synthetic DATA escaped to wire",
                );
                let id = u64::from_be_bytes(data.user_data[..8].try_into().unwrap());
                self.fragment_message.insert(fragment_key, id);
                id
            } else {
                *self
                    .fragment_message
                    .get(&fragment_key)
                    .expect("fragment emitted without its initial message fragment")
            };
            let message = self
                .messages
                .get(&id)
                .expect("DATA references unaccepted message");
            self.require(
                message.from == from && message.sid == data.stream_identifier,
                "DATA changed message owner",
            );
            let attempts = previous.map_or(1, |(_, attempts)| attempts + 1);
            match message.policy {
                Policy::Timed(0) => self.require(attempts == 1, "Timed(0) DATA was retransmitted"),
                Policy::Timed(lifetime) => self.require(
                    self.now < message.written_at + Duration::from_millis(lifetime.into()),
                    "Timed DATA was sent at or after its deadline",
                ),
                Policy::Rexmit(retries) => self.require(
                    attempts <= retries as usize + 1,
                    "Rexmit DATA exceeded its fragment retry budget",
                ),
                Policy::Reliable => {}
            }
            self.sent_tsns.insert(key, (id, attempts));
            self.record(format!(
                "DATA {from} tsn={} sid={} ssn={} id={id} attempt={attempts} len={}",
                data.tsn,
                data.stream_identifier,
                data.stream_sequence_number,
                data.user_data.len()
            ));
        }
    }

    pub(crate) fn poll(&mut self) {
        for side in 0..2 {
            let Some(association) = self.nodes[side].association.as_mut() else {
                continue;
            };
            let mut packets = Vec::new();
            for iteration in 0..256 {
                let Some(transmit) = association.poll_transmit(self.now) else {
                    break;
                };
                assert!(iteration < 255, "poll_transmit did not quiesce");
                if let Payload::RawEncode(contents) = transmit.message {
                    packets.extend(contents);
                }
            }
            for bytes in packets {
                self.progress += 1;
                self.inspect_transmission(side, &bytes);
                self.record(format!(
                    "packet {side} kind={} len={}",
                    bytes[12],
                    bytes.len()
                ));
                self.wire.push_back(WirePacket { from: side, bytes });
            }
            let mut events = Vec::new();
            let node = &mut self.nodes[side];
            let association = node.association.as_mut().unwrap();
            association.assert_receive_accounting();
            while let Some(event) = association.poll() {
                events.push(event);
            }
            while let Some(event) = association.poll_endpoint_event() {
                node.endpoint.handle_event(node.handle.unwrap(), event);
            }
            for event in events {
                self.progress += 1;
                self.record(format!("event {side} {event:?}"));
                match event {
                    Event::Connected => self.nodes[side].connected = true,
                    Event::Stream(StreamEvent::BufferedAmountReleased { id, n_bytes }) => {
                        *self.released.entry((side, id)).or_default() += n_bytes;
                        self.require(
                            self.released[&(side, id)]
                                <= *self.accepted.get(&(side, id)).unwrap_or(&0),
                            "released more bytes than the application accepted",
                        );
                    }
                    _ => {}
                }
            }
        }
        self.require(
            self.wire.len() <= 4096,
            "wire queue exceeded bounded scenario budget",
        );
    }

    pub(crate) fn wire_len(&self) -> usize {
        self.wire.len()
    }

    pub(crate) fn drop_packet(&mut self, index: usize) {
        if self.wire.is_empty() {
            return;
        }
        let index = index % self.wire.len();
        self.record(format!("drop {index}"));
        self.wire.remove(index);
    }

    pub(crate) fn duplicate(&mut self, index: usize) {
        if self.wire.is_empty() {
            return;
        }
        let index = index % self.wire.len();
        self.record(format!("duplicate {index}"));
        self.wire.push_back(self.wire[index].clone());
    }

    pub(crate) fn deliver(&mut self, index: usize) {
        if self.wire.is_empty() {
            return;
        }
        let index = index % self.wire.len();
        self.record(format!("deliver {index}"));
        let packet = self.wire.remove(index).unwrap();
        self.progress += 1;
        let node = &mut self.nodes[1 - packet.from];
        if let Some((handle, event)) =
            node.endpoint
                .handle(self.now, node.remote, None, packet.bytes)
        {
            match event {
                DatagramEvent::NewAssociation(association) => {
                    node.handle = Some(handle);
                    node.association = Some(association);
                }
                DatagramEvent::AssociationEvent(event) => {
                    node.association.as_mut().unwrap().handle_event(event);
                }
            }
        }
        self.poll();
    }

    pub(crate) fn deliver_all(&mut self) {
        for _ in 0..4096 {
            if self.wire.is_empty() {
                return;
            }
            self.deliver(0);
        }
        self.require(false, "loss-free packet exchange did not quiesce");
    }

    pub(crate) fn advance(&mut self, millis: u64) {
        self.record(format!("advance {millis}"));
        self.now += Duration::from_millis(millis);
        for node in &mut self.nodes {
            if let Some(association) = &mut node.association
                && association
                    .poll_timeout()
                    .is_some_and(|deadline| deadline <= self.now)
            {
                association.handle_timeout(self.now);
            }
        }
        self.poll();
    }

    pub(crate) fn read(&mut self, side: usize) {
        self.record(format!("read {side}"));
        let association = self.nodes[side].association.as_mut().unwrap();
        while association.accept_stream().is_some() {}
        let mut received = Vec::new();
        for sid in association.stream_ids() {
            for _ in 0..256 {
                let Some(chunks) = association
                    .stream(sid)
                    .ok()
                    .and_then(|mut stream| stream.read_sctp().ok().flatten())
                else {
                    break;
                };
                let mut bytes = vec![0; chunks.len()];
                assert_eq!(chunks.read(&mut bytes).unwrap(), bytes.len());
                received.push((sid, bytes));
            }
        }
        for (sid, bytes) in received {
            self.require(
                bytes.len() >= 8,
                "application received an incomplete message header",
            );
            let id = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            self.record(format!("message {side} {sid} id={id} len={}", bytes.len()));
            let message = self
                .messages
                .get(&id)
                .expect("delivered unaccepted message");
            self.require(
                message.from == 1 - side && message.sid == sid,
                "message reached wrong peer/SID",
            );
            self.require(
                bytes == message.bytes,
                "message payload was truncated or mixed",
            );
            self.require(
                !self.delivered.contains(&id),
                "application received duplicate message",
            );
            if message.ordered {
                let key = (message.from, sid);
                self.require(
                    self.last_ordered.get(&key).is_none_or(|last| id > *last),
                    "ordered application messages were reordered",
                );
                self.last_ordered.insert(key, id);
            }
            self.delivered.insert(id);
            self.progress += 1;
        }
        self.poll();
    }

    pub(crate) fn received(&self, id: u64) -> bool {
        self.delivered.contains(&id)
    }

    pub(crate) fn buffered(&mut self, side: usize, sid: u16) -> Option<usize> {
        self.nodes[side]
            .association
            .as_mut()
            .unwrap()
            .stream(sid)
            .ok()
            .and_then(|stream| stream.buffered_amount().ok())
    }

    /// Network losses stop and applications read every available message. All
    /// accepted reliable messages on untouched SIDs must become readable, and
    /// every live stream's send buffer must eventually be released.
    pub(crate) fn finish(&mut self) {
        self.record("fair network begins".into());
        let mut quiescent = false;
        for _ in 0..128 {
            let previous_progress = self.progress;
            self.deliver_all();
            self.read(0);
            self.read(1);
            self.deliver_all();
            if self.progress != previous_progress {
                // Reading old ready data can expose a new receiver for the
                // same SID during poll(). Drain its app events/messages before
                // advancing time or declaring timer-free quiescence.
                continue;
            }
            let next = self
                .nodes
                .iter()
                .filter_map(|node| {
                    node.association
                        .as_ref()
                        .and_then(Association::poll_timeout)
                })
                .min();
            let Some(next) = next else {
                quiescent = true;
                break;
            };
            let delta = next.saturating_duration_since(self.now).as_millis() as u64;
            self.advance(delta.max(1));
        }
        self.require(
            quiescent,
            "protocol did not quiesce after losses stopped and applications read",
        );
        for (id, message) in &self.messages {
            let association = self.nodes[message.from].association.as_ref().unwrap();
            if message.required && !association.is_closed() {
                self.require(self.received(*id), &format!(
                    "reliable message id={id} side={} sid={} not delivered after losses stopped",
                    message.from, message.sid));
            }
        }
        for side in 0..2 {
            let ids = self.nodes[side].association.as_ref().unwrap().stream_ids();
            for sid in ids {
                let buffered = self.buffered(side, sid);
                self.require(buffered == Some(0), "send buffer leaked after fair drain");
            }
        }
        if !self.had_reset
            && self
                .nodes
                .iter()
                .all(|node| !node.association.as_ref().unwrap().is_closed())
        {
            self.require(
                self.accepted.iter().all(|(key, bytes)| {
                    self.released.get(key).copied().unwrap_or_default() == *bytes
                }),
                "payload release events did not exactly account for accepted bytes",
            );
        }
    }
}

/// Decode at most 128 four-byte actions; libFuzzer can shrink the input directly.
pub(crate) fn run(input: &[u8], now: Instant) {
    let mut model = Model::new(now);
    for side in 0..2 {
        for sid in 0..3 {
            model.open(side, sid);
        }
    }
    for action in input.chunks_exact(4).take(128) {
        let side = usize::from(action[1] & 1);
        let sid = u16::from((action[1] >> 1) % 3);
        let ordered = action[2] & 1 == 0;
        let length = [32, 1200, 4000][usize::from(action[3] % 3)];
        match action[0] % 12 {
            0 => {
                model.send(side, sid, ordered, Policy::Reliable, length);
            }
            1 => {
                model.send(
                    side,
                    sid,
                    ordered,
                    Policy::Timed([0, 1, 100][usize::from(action[2] % 3)]),
                    length,
                );
            }
            2 => {
                model.send(
                    side,
                    sid,
                    ordered,
                    Policy::Rexmit(u32::from(action[2] % 3)),
                    length,
                );
            }
            3 => model.deliver(usize::from(action[2])),
            4 => model.drop_packet(usize::from(action[2])),
            5 => model.duplicate(usize::from(action[2])),
            6 => model.advance([0, 1, 100, 500, 1100][usize::from(action[2] % 5)]),
            7 => model.read(side),
            8 => model.close(
                side,
                sid,
                [CloseKind::Stop, CloseKind::Finish, CloseKind::Close][usize::from(action[2] % 3)],
            ),
            9 => {
                model.open(side, sid);
            }
            10 => model.deliver(model.wire_len().saturating_sub(1)),
            _ => model.poll(),
        }
        model.poll();
    }
    model.finish();
}
