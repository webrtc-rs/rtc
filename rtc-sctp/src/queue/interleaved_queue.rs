//! The send queue once user message interleaving ([RFC 8260]) is negotiated.
//!
//! Without interleaving a message goes out in full before the next one starts, so one large
//! message holds up every stream behind it. With I-DATA the fragments of different messages may
//! share the wire, and a scheduler decides whose fragment is next. Messages of the same stream
//! still leave in the order they were written; the scheduler only chooses between streams.
//!
//! A stream-reset marker queues behind the data of its own stream, as it does in the plain
//! queue, so a RE-CONFIG request never overtakes data the stream wrote before closing.
//!
//! [RFC 8260]: https://www.rfc-editor.org/rfc/rfc8260.html

use super::pending_queue::{QueuedMessage, ResetMarker};
use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId};
use shared::error::{Error, Result};

use rustc_hash::FxHashMap;
use std::collections::{BTreeSet, VecDeque};
use std::num::NonZeroU16;

/// How streams take turns.
#[derive(Debug, Clone)]
pub(crate) enum SchedulerKind {
    /// One chunk from each backlogged stream in turn.
    RoundRobin,
    /// Weighted fair queueing over virtual finish times, as pion does: a chunk of `n` bytes on a
    /// stream of weight `w` finishes `n / w` after the previous chunk of that stream (or after
    /// the scheduler's virtual time, if the stream was idle), and the chunk that finishes first
    /// goes next. Streams not in the map weigh 1.
    WeightedFairQueueing { weights: FxHashMap<u16, NonZeroU16> },
}

#[derive(Debug)]
enum Entry {
    Message {
        message: QueuedMessage,
        /// Virtual time the first still-queued chunk started at (WFQ only).
        start: f64,
    },
    Reset {
        marker: ResetMarker,
        start: f64,
    },
}

#[derive(Debug, Default)]
struct StreamQueue {
    entries: VecDeque<Entry>,
    /// Virtual finish time of the last chunk queued on this stream (WFQ only). Survives the
    /// queue running empty: a stream that just sent must not jump the line.
    last_finish: f64,
    /// Virtual finish time of the chunk at the front (WFQ only; meaningful while non-empty).
    head_finish: f64,
}

#[derive(Debug)]
pub(crate) struct InterleavedQueue {
    kind: SchedulerKind,
    streams: FxHashMap<u16, StreamQueue>,
    /// Round robin: backlogged streams, next to serve first.
    order: VecDeque<u16>,
    /// WFQ: backlogged streams by (virtual finish of their front chunk, stream id). Finish
    /// times are never negative, so the bit pattern of an `f64` sorts like the value.
    heads: BTreeSet<(u64, u16)>,
    virtual_time: f64,
}

/// What `InterleavedQueue::pop` took off the queue.
pub(crate) struct Popped {
    pub(crate) chunk: ChunkPayloadData,
}

impl InterleavedQueue {
    pub(crate) fn new(kind: SchedulerKind) -> Self {
        Self {
            kind,
            streams: FxHashMap::default(),
            order: VecDeque::new(),
            heads: BTreeSet::new(),
            virtual_time: 0.0,
        }
    }

    fn weight(&self, stream: u16) -> f64 {
        match &self.kind {
            SchedulerKind::WeightedFairQueueing { weights } => {
                weights.get(&stream).map_or(1.0, |w| f64::from(w.get()))
            }
            SchedulerKind::RoundRobin => 1.0,
        }
    }

    fn is_wfq(&self) -> bool {
        matches!(self.kind, SchedulerKind::WeightedFairQueueing { .. })
    }

    fn key(finish: f64, stream: u16) -> (u64, u16) {
        (finish.to_bits(), stream)
    }

    /// Queue a whole message behind the earlier ones of its stream.
    pub(super) fn push_message(&mut self, stream: u16, message: QueuedMessage) {
        let weight = self.weight(stream);
        let wfq = self.is_wfq();
        let virtual_time = self.virtual_time;
        let sq = self.streams.entry(stream).or_default();
        let was_empty = sq.entries.is_empty();

        let start = if wfq {
            virtual_time.max(sq.last_finish)
        } else {
            0.0
        };
        if wfq {
            // Each fragment finishes after the one before it, as if queued one by one.
            let mut finish = start;
            let mut first = None;
            for len in message.chunk_lengths() {
                finish += len as f64 / weight;
                first.get_or_insert(finish);
            }
            sq.last_finish = finish;
            if was_empty {
                sq.head_finish = first.unwrap_or(start);
            }
        }
        sq.entries.push_back(Entry::Message { message, start });
        if was_empty {
            self.activate(stream);
        }
    }

    /// Queue a stream-reset marker behind the data of its stream.
    pub(crate) fn push_reset(&mut self, marker: ResetMarker) {
        let stream = marker.stream_identifier;
        let wfq = self.is_wfq();
        let virtual_time = self.virtual_time;
        let sq = self.streams.entry(stream).or_default();
        let was_empty = sq.entries.is_empty();
        let start = if wfq {
            virtual_time.max(sq.last_finish)
        } else {
            0.0
        };
        if wfq {
            sq.last_finish = start;
            if was_empty {
                sq.head_finish = start;
            }
        }
        sq.entries.push_back(Entry::Reset { marker, start });
        if was_empty {
            self.activate(stream);
        }
    }

    /// A stream went from idle to backlogged.
    fn activate(&mut self, stream: u16) {
        match self.kind {
            SchedulerKind::RoundRobin => self.order.push_back(stream),
            SchedulerKind::WeightedFairQueueing { .. } => {
                if let Some(sq) = self.streams.get(&stream) {
                    self.heads.insert(Self::key(sq.head_finish, stream));
                }
            }
        }
    }

    /// The stream whose front chunk goes next.
    fn selected(&self) -> Option<u16> {
        match self.kind {
            SchedulerKind::RoundRobin => self.order.front().copied(),
            SchedulerKind::WeightedFairQueueing { .. } => self.heads.first().map(|&(_, si)| si),
        }
    }

    /// The chunk that goes next, or `None` if nothing is queued or the stream due next is at a
    /// reset marker (see [`pop_ready_reset`](Self::pop_ready_reset)).
    pub(crate) fn peek(&self) -> Option<&ChunkPayloadData> {
        let sq = self.streams.get(&self.selected()?)?;
        match sq.entries.front()? {
            Entry::Message { message, .. } => message.peek(),
            Entry::Reset { .. } => None,
        }
    }

    /// The reset marker the scheduler has reached, if it is the next thing to go.
    pub(crate) fn pop_ready_reset(&mut self) -> Option<ResetMarker> {
        let stream = self.selected()?;
        let sq = self.streams.get_mut(&stream)?;
        if !matches!(sq.entries.front()?, Entry::Reset { .. }) {
            return None;
        }
        let finish = sq.head_finish;
        let Some(Entry::Reset { marker, .. }) = sq.entries.pop_front() else {
            return None;
        };
        // A marker is not a transmission: the stream keeps its turn.
        self.front_removed(stream, finish, false);
        Some(marker)
    }

    /// Take the next chunk of the stream the scheduler picked.
    pub(crate) fn pop(&mut self) -> Option<Popped> {
        let stream = self.selected()?;
        let weight = self.weight(stream);
        let wfq = self.is_wfq();
        let sq = self.streams.get_mut(&stream)?;
        if !matches!(sq.entries.front()?, Entry::Message { .. }) {
            return None;
        }
        let finish = sq.head_finish;
        let Some(Entry::Message { message, start }) = sq.entries.pop_front() else {
            return None;
        };
        let (chunk, rest) = message.pop_fragment()?;
        match rest {
            Some(rest) => {
                // The next fragment of the same message follows the one just taken.
                if wfq {
                    self.heads.remove(&Self::key(finish, stream));
                    let next_len = rest.peek().map_or(0, |c| c.user_data.len());
                    let next_finish = finish + next_len as f64 / weight;
                    if let Some(sq) = self.streams.get_mut(&stream) {
                        sq.head_finish = next_finish;
                    }
                    self.heads.insert(Self::key(next_finish, stream));
                    self.advance_virtual_time(finish);
                } else if self.order.front() == Some(&stream) {
                    self.order.rotate_left(1);
                }
                if let Some(sq) = self.streams.get_mut(&stream) {
                    sq.entries.push_front(Entry::Message {
                        message: rest,
                        start,
                    });
                }
            }
            None => self.front_removed(stream, finish, true),
        }
        Some(Popped { chunk })
    }

    fn advance_virtual_time(&mut self, finish: f64) {
        if self.is_wfq() && finish > self.virtual_time {
            self.virtual_time = finish;
        }
    }

    /// The whole front entry of `stream` (the stream the scheduler picked) has just left its
    /// queue; `finish` is the virtual finish time it had. `rotate` is whether the stream used
    /// up its turn (round robin).
    fn front_removed(&mut self, stream: u16, finish: f64, rotate: bool) {
        let wfq = self.is_wfq();
        if wfq {
            self.heads.remove(&Self::key(finish, stream));
        }
        self.advance_virtual_time(finish);
        let weight = self.weight(stream);
        let virtual_time = self.virtual_time;
        let Some(sq) = self.streams.get_mut(&stream) else {
            return;
        };
        match sq.entries.front() {
            Some(entry) => {
                if wfq {
                    sq.head_finish = match entry {
                        Entry::Message { message, start } => {
                            *start + message.peek().map_or(0, |c| c.user_data.len()) as f64 / weight
                        }
                        Entry::Reset { start, .. } => *start,
                    };
                    self.heads.insert(Self::key(sq.head_finish, stream));
                } else if rotate && self.order.front() == Some(&stream) {
                    self.order.rotate_left(1);
                }
            }
            None => {
                if !wfq && self.order.front() == Some(&stream) {
                    self.order.pop_front();
                }
                // A stream whose virtual clock is behind the scheduler's has nothing worth
                // remembering: it would restart at the scheduler's time anyway.
                if sq.last_finish <= virtual_time {
                    self.streams.remove(&stream);
                }
            }
        }
    }

    /// Remove the rest of the message at the front of the picked stream, once. Anything but
    /// that message (another one, a reset marker) is left alone. Returns the fragments with
    /// their count and byte total.
    pub(crate) fn drain_message(
        &mut self,
        id: MessageId,
    ) -> Result<Option<(Vec<ChunkPayloadData>, usize, usize)>> {
        let Some(stream) = self.selected() else {
            return Ok(None);
        };
        let Some(sq) = self.streams.get_mut(&stream) else {
            return Ok(None);
        };
        let Some(Entry::Message { message, .. }) = sq.entries.front() else {
            return Ok(None);
        };
        if message.snapshot().id != Some(id) {
            return Ok(None);
        }
        let (count, bytes) = message.validate_tail()?;
        let finish = sq.head_finish;
        let Some(Entry::Message { message, .. }) = sq.entries.pop_front() else {
            return Err(Error::OtherSctpErr("missing pending message".into()));
        };
        // The tail never goes out, so the scheduler's clock does not move for it; and as the
        // stream sent nothing, it keeps its turn.
        self.front_removed_without_clock(stream, finish);
        Ok(Some((message.into_fragments(), count, bytes)))
    }

    fn front_removed_without_clock(&mut self, stream: u16, finish: f64) {
        let before = self.virtual_time;
        self.front_removed(stream, finish, false);
        // `front_removed` advances the clock; a drained tail was never served.
        self.virtual_time = before;
    }
}

#[cfg(test)]
mod test {
    use super::super::pending_queue::PendingQueue;
    use super::*;
    use bytes::Bytes;

    /// pion's `makeStreamDataChunk`: an unfragmented chunk on `stream`, whose TSN field serves as
    /// a chunk id (the pending queue never looks at it).
    fn stream_chunk(tsn: u32, stream: u16, len: usize) -> ChunkPayloadData {
        ChunkPayloadData {
            tsn,
            stream_identifier: stream,
            beginning_fragment: true,
            ending_fragment: true,
            user_data: Bytes::from(vec![0u8; len]),
            ..Default::default()
        }
    }

    fn queue(kind: SchedulerKind) -> PendingQueue {
        let mut q = PendingQueue::new();
        q.set_interleaving(Some(kind)).unwrap();
        q
    }

    fn rr() -> SchedulerKind {
        SchedulerKind::RoundRobin
    }

    fn wfq(weights: &[(u16, u16)]) -> SchedulerKind {
        SchedulerKind::WeightedFairQueueing {
            weights: weights
                .iter()
                .map(|&(s, w)| (s, NonZeroU16::new(w).unwrap()))
                .collect(),
        }
    }

    fn push(q: &mut PendingQueue, c: ChunkPayloadData) {
        q.push_message(vec![c]);
    }

    fn pop_tsn(q: &mut PendingQueue) -> Option<u32> {
        let c = q.peek()?;
        let tsn = c.tsn;
        let (begin, unordered) = (c.beginning_fragment, c.unordered);
        assert_eq!(tsn, q.pop(begin, unordered)?.tsn);
        Some(tsn)
    }

    #[test]
    fn test_round_robin_pending_queue_policy() {
        // pion: TestRoundRobinPendingQueuePolicy
        // round robin across streams
        let mut q = queue(rr());
        push(&mut q, stream_chunk(1, 1, 10));
        push(&mut q, stream_chunk(2, 2, 10));
        push(&mut q, stream_chunk(3, 1, 10));
        for want in [1, 2, 3] {
            assert_eq!(Some(want), pop_tsn(&mut q));
        }
        assert!(q.peek().is_none());
        assert!(q.is_empty());

        // peek keeps the selected stream until pop
        let mut q = queue(rr());
        push(&mut q, stream_chunk(10, 1, 10));
        push(&mut q, stream_chunk(20, 2, 10));
        let first = q.peek().map(|c| (c.tsn, c.stream_identifier));
        let second = q.peek().map(|c| (c.tsn, c.stream_identifier));
        assert_eq!(first, second);
        assert_eq!(
            Some((10, 1)),
            first,
            "the first backlogged stream is selected"
        );
        assert_eq!(Some(10), pop_tsn(&mut q));
        assert_eq!(Some(20), q.peek().map(|c| c.tsn));

        // pion's "pop errors" subtests check a caller handing Pop the wrong chunk. Here the queue
        // hands the chunk out itself (`pop` takes no chunk), so there is no way to name the wrong
        // one; popping from an empty queue is the remaining misuse.
        let mut q = queue(rr());
        assert!(q.pop(true, false).is_none());
    }

    #[test]
    fn test_weighted_fair_queueing_pending_queue_policy() {
        // pion: TestWeightedFairQueueingPendingQueuePolicy
        // selects lowest virtual finish time
        let mut q = queue(wfq(&[]));
        push(&mut q, stream_chunk(1, 1, 100));
        push(&mut q, stream_chunk(2, 1, 100));
        push(&mut q, stream_chunk(3, 2, 10));
        for want in [3, 1, 2] {
            assert_eq!(Some(want), pop_tsn(&mut q));
        }
        assert!(q.peek().is_none());

        // applies stream weights
        let mut q = queue(wfq(&[(1, 2)]));
        push(&mut q, stream_chunk(1, 1, 100));
        push(&mut q, stream_chunk(2, 2, 60));
        assert_eq!(
            Some(1),
            pop_tsn(&mut q),
            "100 bytes at weight 2 finish at 50, before 60"
        );
        assert_eq!(Some(2), pop_tsn(&mut q));

        // pop errors: see the round robin test.
        let mut q = queue(wfq(&[]));
        assert!(q.pop(true, false).is_none());
    }

    #[test]
    fn test_pending_queue_set_interleaving() {
        // pion: TestPendingQueue "set interleaving ..." subtests
        // rejects non-empty queue
        let mut q = PendingQueue::new();
        push(&mut q, stream_chunk(1, 1, 10));
        assert!(q.set_interleaving(Some(rr())).is_err());
        assert!(!q.is_interleaving());
        assert_eq!(Some(1), q.peek().map(|c| c.tsn));

        // swaps policy when empty, and is idempotent
        let mut q = PendingQueue::new();
        q.set_interleaving(Some(wfq(&[]))).unwrap();
        assert!(q.is_interleaving());
        q.set_interleaving(Some(wfq(&[]))).unwrap();
        assert!(q.is_interleaving());
        q.set_interleaving(None).unwrap();
        assert!(!q.is_interleaving());
        // and the plain policy is back: unordered wins over ordered
        let mut ordered = stream_chunk(1, 1, 10);
        ordered.unordered = false;
        let mut unordered = stream_chunk(2, 1, 10);
        unordered.unordered = true;
        push(&mut q, ordered);
        push(&mut q, unordered);
        assert_eq!(Some(2), pop_tsn(&mut q));
        assert_eq!(Some(1), pop_tsn(&mut q));

        // uses the configured scheduler: RR alternates, WFQ with equal sizes does too
        for kind in [rr(), wfq(&[])] {
            let mut q = queue(kind);
            for (tsn, si) in [(1, 1), (2, 1), (3, 2), (4, 2)] {
                push(&mut q, stream_chunk(tsn, si, 10));
            }
            let order: Vec<u32> = std::iter::from_fn(|| pop_tsn(&mut q)).collect();
            assert_eq!(vec![1, 3, 2, 4], order);
        }
        // pion also covers a caller-supplied scheduler (`lifoStreamScheduler`); schedulers are
        // an enum here, so only the two built-in ones exist.
    }

    #[test]
    fn a_reset_marker_waits_for_the_data_of_its_own_stream_only() {
        let mut q = queue(rr());
        push(&mut q, stream_chunk(1, 1, 10));
        q.push_reset(ResetMarker {
            stream_identifier: 1,
        });
        push(&mut q, stream_chunk(2, 2, 10));
        // stream 1 goes first: its data, then (on its next turn) its reset marker
        assert_eq!(Some(1), pop_tsn(&mut q));
        // stream 2 is next in the round; the marker of stream 1 does not hold it up
        assert_eq!(Some(2), pop_tsn(&mut q));
        assert!(q.peek().is_none(), "the marker is control state, not data");
        assert_eq!(1, q.pop_ready_reset().unwrap().stream_identifier);
        assert!(q.is_empty());
    }

    #[test]
    fn draining_an_unsent_tail_leaves_other_streams_alone() {
        use crate::chunk::chunk_payload_data::MessageId;
        let mut q = queue(rr());
        let message = |id, si, n| {
            (0..n)
                .map(|i| ChunkPayloadData {
                    message_id: MessageId::new(id),
                    stream_identifier: si,
                    beginning_fragment: i == 0,
                    ending_fragment: i == n - 1,
                    user_data: Bytes::from_static(b"data"),
                    ..Default::default()
                })
                .collect::<Vec<_>>()
        };
        q.push_message(message(0, 1, 3));
        q.push_message(message(1, 2, 2));
        assert_eq!(5, q.len());
        assert_eq!(20, q.get_num_bytes());

        let first = q.peek().unwrap().message_id.unwrap();
        assert_eq!(MessageId::new(0), Some(first));
        q.pop(true, false).unwrap();
        // stream 2 has the turn now; its message is not the one asked for
        assert!(q.drain_message(first).unwrap().is_empty());
        q.pop(true, false).unwrap(); // stream 2, first fragment
        // back to stream 1: drain its remaining two fragments
        let tail = q.drain_message(first).unwrap();
        assert_eq!(2, tail.len());
        assert!(q.drain_message(first).unwrap().is_empty(), "drained once");
        assert_eq!(1, q.len());
        assert_eq!(4, q.get_num_bytes());
        assert_eq!(
            Some(MessageId::new(1).unwrap()),
            q.peek().unwrap().message_id
        );
    }

    /// Replays `tests/data/pion_sched_golden.jsonl`: random push/pop sequences through pion's
    /// round-robin and weighted-fair-queueing schedulers (v1.12.0), which must hand out the same
    /// chunks in the same order. `PION_SCHED_GOLDEN=<file>` replays another file.
    #[test]
    fn matches_pion_stream_schedulers() {
        let path = std::env::var("PION_SCHED_GOLDEN").unwrap_or_else(|_| {
            format!(
                "{}/tests/data/pion_sched_golden.jsonl",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        let data = std::fs::read_to_string(path).unwrap();
        let mut total = 0;
        for line in data.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let kind = match v["policy"].as_str().unwrap() {
                "rr" => rr(),
                _ => {
                    let weights: Vec<(u16, u16)> = v["weights"]
                        .as_object()
                        .map(|m| {
                            m.iter()
                                .map(|(k, w)| (k.parse().unwrap(), w.as_u64().unwrap() as u16))
                                .collect()
                        })
                        .unwrap_or_default();
                    wfq(&weights)
                }
            };
            let mut q = queue(kind);
            let mut got = vec![];
            for op in v["ops"].as_array().unwrap() {
                let field = |k: &str| op[k].as_u64().unwrap_or(0);
                match op["k"].as_str().unwrap() {
                    "push" => push(
                        &mut q,
                        stream_chunk(field("t") as u32, field("s") as u16, field("n") as usize),
                    ),
                    _ => got.push(pop_tsn(&mut q).map_or(-1, i64::from)),
                }
            }
            let want: Vec<i64> = v["out"]
                .as_array()
                .map(|a| a.iter().map(|x| x.as_i64().unwrap()).collect())
                .unwrap_or_default();
            assert_eq!(want, got, "diverges from pion: {line}");
            total += 1;
        }
        eprintln!("{total} scheduler sequences agree with pion");
    }
}
