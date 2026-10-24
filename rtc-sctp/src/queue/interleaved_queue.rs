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
