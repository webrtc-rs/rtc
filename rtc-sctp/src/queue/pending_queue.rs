use crate::chunk::chunk_payload_data::{
    ChunkPayloadData, MessageId, MessageReliability, PayloadProtocolIdentifier,
};
use crate::config::StreamScheduler;
use rustc_hash::FxHashMap;
use shared::error::{Error, Result};

use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

/// The weight of a stream no one has weighted: the normal data channel priority (RFC 8832).
pub(crate) const DEFAULT_STREAM_WEIGHT: u16 = 256;

pub(crate) type PendingBaseQueue = VecDeque<ChunkPayloadData>;

/// Ownership and policy remain available after the first fragment is sent or
/// the API stream closes. Later fragments cannot replace this message snapshot.
#[derive(Debug, Copy, Clone)]
struct MessageSnapshot {
    id: Option<MessageId>,
    stream_identifier: u16,
    stream_sequence_number: u16,
    stream_generation: u64,
    unordered: bool,
    payload_type: PayloadProtocolIdentifier,
    created_at: Option<Instant>,
    reliability: MessageReliability,
}

impl MessageSnapshot {
    fn from_chunk(c: &ChunkPayloadData) -> Self {
        Self {
            id: c.message_id,
            stream_identifier: c.stream_identifier,
            stream_sequence_number: c.stream_sequence_number,
            stream_generation: c.stream_generation,
            unordered: c.unordered,
            payload_type: c.payload_type,
            created_at: c.created_at,
            reliability: c.reliability,
        }
    }

    fn matches(&self, c: &ChunkPayloadData) -> bool {
        self.id == c.message_id
            && self.stream_identifier == c.stream_identifier
            && self.stream_sequence_number == c.stream_sequence_number
            && self.stream_generation == c.stream_generation
            && self.unordered == c.unordered
    }

    fn apply(&self, c: &mut ChunkPayloadData) {
        c.payload_type = self.payload_type;
        c.created_at = self.created_at;
        c.reliability = self.reliability;
    }
}

/// One message owns its unsent tail. Whole messages stay inline; fragmented
/// messages reuse the packetization buffer.
#[derive(Debug)]
enum QueuedMessage {
    Whole(ChunkPayloadData),
    Fragmented {
        snapshot: MessageSnapshot,
        fragments: PendingBaseQueue,
        next_fragment: usize,
        bytes: usize,
    },
}

impl QueuedMessage {
    fn new(mut chunks: Vec<ChunkPayloadData>) -> Option<Self> {
        let first = chunks.first()?;
        if chunks.len() == 1 && first.beginning_fragment && first.ending_fragment {
            return chunks.pop().map(Self::Whole);
        }
        let snapshot = MessageSnapshot::from_chunk(first);
        let mut bytes = 0;
        for c in &mut chunks {
            snapshot.apply(c);
            bytes += c.user_data.len();
        }
        Some(Self::Fragmented {
            snapshot,
            bytes,
            fragments: VecDeque::from(chunks),
            next_fragment: 0,
        })
    }

    fn peek(&self) -> Option<&ChunkPayloadData> {
        match self {
            Self::Whole(c) => Some(c),
            Self::Fragmented { fragments, .. } => fragments.front(),
        }
    }

    fn snapshot(&self) -> MessageSnapshot {
        match self {
            Self::Whole(c) => MessageSnapshot::from_chunk(c),
            Self::Fragmented { snapshot, .. } => *snapshot,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Whole(_) => 1,
            Self::Fragmented { fragments, .. } => fragments.len(),
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Whole(c) => c.user_data.len(),
            Self::Fragmented { bytes, .. } => *bytes,
        }
    }

    /// Check the complete remaining tail before changing ownership or counters.
    fn validate_tail(&self) -> Result<(usize, usize)> {
        let (snapshot, fragments, next_fragment, bytes) = match self {
            Self::Whole(c) => return Ok((1, c.user_data.len())),
            Self::Fragmented {
                snapshot,
                fragments,
                next_fragment,
                bytes,
            } => (snapshot, fragments, next_fragment, bytes),
        };
        if !fragments.back().is_some_and(|c| c.ending_fragment) {
            return Err(Error::OtherSctpErr(
                "pending message has no ending fragment".into(),
            ));
        }
        let mut actual_bytes = 0;
        for (i, c) in fragments.iter().enumerate() {
            if !snapshot.matches(c)
                || c.beginning_fragment != (*next_fragment == 0 && i == 0)
                || c.ending_fragment != (i + 1 == fragments.len())
            {
                return Err(Error::OtherSctpErr(
                    "invalid pending message fragments".into(),
                ));
            }
            actual_bytes += c.user_data.len();
        }
        if actual_bytes != *bytes {
            return Err(Error::OtherSctpErr(
                "invalid pending message accounting".into(),
            ));
        }
        Ok((fragments.len(), *bytes))
    }

    fn into_fragments(self) -> Vec<ChunkPayloadData> {
        match self {
            Self::Whole(c) => vec![c],
            Self::Fragmented { fragments, .. } => Vec::from(fragments),
        }
    }
}

/// Takes the next fragment of the message at the front of `queue` after checking it against the
/// message, and removes the message once its last fragment leaves.
fn pop_front_fragment<T>(
    queue: &mut VecDeque<T>,
    message: fn(&mut T) -> Option<&mut QueuedMessage>,
    whole: fn(T) -> Option<ChunkPayloadData>,
) -> Option<ChunkPayloadData> {
    match message(queue.front_mut()?)? {
        QueuedMessage::Whole(_) => whole(queue.pop_front()?),
        QueuedMessage::Fragmented {
            snapshot,
            fragments,
            next_fragment,
            bytes,
        } => {
            let first = fragments.front()?;
            if !snapshot.matches(first)
                || first.beginning_fragment != (*next_fragment == 0)
                || first.ending_fragment != (fragments.len() == 1)
            {
                return None;
            }
            let remaining_bytes = bytes.checked_sub(first.user_data.len())?;
            let next = next_fragment.checked_add(1)?;
            let c = fragments.pop_front()?;
            *next_fragment = next;
            *bytes = remaining_bytes;
            if c.ending_fragment {
                queue.pop_front();
            }
            Some(c)
        }
    }
}

fn entry_message(entry: &mut PendingEntry) -> Option<&mut QueuedMessage> {
    match entry {
        PendingEntry::Message(message) => Some(message),
        PendingEntry::Reset(_) => None,
    }
}

fn entry_whole(entry: PendingEntry) -> Option<ChunkPayloadData> {
    match entry {
        PendingEntry::Message(QueuedMessage::Whole(c)) => Some(c),
        _ => None,
    }
}

fn tagged_message(entry: &mut (u128, PendingEntry)) -> Option<&mut QueuedMessage> {
    entry_message(&mut entry.1)
}

fn tagged_whole(entry: (u128, PendingEntry)) -> Option<ChunkPayloadData> {
    entry_whole(entry.1)
}

/// A reset is control state, with no DATA payload or reliability policy.
#[derive(Debug)]
pub(crate) struct ResetMarker {
    pub(crate) stream_identifier: u16,
}

#[derive(Debug)]
enum PendingEntry {
    Message(QueuedMessage),
    Reset(ResetMarker),
}

/// One stream's queue under weighted fair queueing, each entry with its finish tag.
#[derive(Debug)]
struct WfqStream {
    entries: VecDeque<(u128, PendingEntry)>,
    weight: u16,
    last_finish: u128,
}

impl Default for WfqStream {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            weight: DEFAULT_STREAM_WEIGHT,
            last_finish: 0,
        }
    }
}

/// Self-clocked fair queueing: a message's finish tag is the later of the virtual time and its
/// stream's last tag, plus its bytes over the stream's weight, and the lowest head tag goes next.
#[derive(Debug, Default)]
struct Wfq {
    streams: FxHashMap<u16, WfqStream>,
    /// Each non-empty stream keyed by its head: a reset head sorts first, then message head tags.
    heads: BTreeSet<(u128, u16)>,
    /// The finish tag of the message most recently started.
    virtual_time: u128,
}

impl Wfq {
    fn head_key(&self, stream: u16) -> Option<(u128, u16)> {
        match self.streams.get(&stream)?.entries.front()? {
            (_, PendingEntry::Reset(_)) => Some((0, stream)),
            (tag, PendingEntry::Message(_)) => Some((tag.saturating_add(1), stream)),
        }
    }

    /// Runs `change` on one stream's queue and re-keys the stream by its new head.
    fn update<T>(&mut self, stream: u16, change: impl FnOnce(&mut WfqStream, u128) -> T) -> T {
        if let Some(key) = self.head_key(stream) {
            self.heads.remove(&key);
        }
        let virtual_time = self.virtual_time;
        let result = change(self.streams.entry(stream).or_default(), virtual_time);
        if let Some(key) = self.head_key(stream) {
            self.heads.insert(key);
        }
        result
    }

    fn push(&mut self, stream: u16, bytes: usize, entry: PendingEntry) {
        self.update(stream, |s, virtual_time| {
            let start = s.last_finish.max(virtual_time);
            let tag = start + ((bytes as u128) << 16) / u128::from(s.weight);
            s.last_finish = tag;
            s.entries.push_back((tag, entry));
        });
    }

    /// The stream whose head goes next, and whether that head is a reset.
    fn next(&self) -> Option<(u16, bool)> {
        self.heads.first().map(|&(key, stream)| (stream, key == 0))
    }

    fn queue_mut(&mut self, stream: u16) -> Option<&mut VecDeque<(u128, PendingEntry)>> {
        self.streams.get_mut(&stream).map(|s| &mut s.entries)
    }
}

#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    unordered_queue: VecDeque<PendingEntry>,
    ordered_queue: VecDeque<PendingEntry>,
    queue_len: usize,
    n_bytes: usize,
    selected: bool,
    unordered_is_selected: bool,
    /// Present when messages are scheduled by weighted fair queueing.
    wfq: Option<Wfq>,
    /// Under weighted fair queueing, the stream whose message is part sent.
    selected_stream: u16,
}

impl PendingQueue {
    pub(crate) fn new() -> Self {
        PendingQueue::default()
    }

    pub(crate) fn with_scheduler(scheduler: StreamScheduler) -> Self {
        PendingQueue {
            wfq: (scheduler == StreamScheduler::WeightedFairQueueing).then(Wfq::default),
            ..PendingQueue::default()
        }
    }

    /// Sets the weight a stream's later messages are scheduled with; zero counts as one.
    pub(crate) fn set_weight(&mut self, stream: u16, weight: u16) {
        if let Some(wfq) = self.wfq.as_mut() {
            wfq.streams.entry(stream).or_default().weight = weight.max(1);
        }
    }

    /// Enqueue one complete packetized message. An empty packetization is a
    /// no-op, matching an empty application write.
    pub(crate) fn push_message(&mut self, chunks: Vec<ChunkPayloadData>) {
        let Some(message) = QueuedMessage::new(chunks) else {
            return;
        };
        self.n_bytes += message.bytes();
        self.queue_len += message.len();
        let snapshot = message.snapshot();
        if let Some(wfq) = self.wfq.as_mut() {
            wfq.push(
                snapshot.stream_identifier,
                message.bytes(),
                PendingEntry::Message(message),
            );
            return;
        }
        let queue = if snapshot.unordered {
            &mut self.unordered_queue
        } else {
            &mut self.ordered_queue
        };
        queue.push_back(PendingEntry::Message(message));
    }

    pub(crate) fn push_reset(&mut self, reset: ResetMarker) {
        self.queue_len += 1;
        if let Some(wfq) = self.wfq.as_mut() {
            wfq.push(reset.stream_identifier, 0, PendingEntry::Reset(reset));
            return;
        }
        self.ordered_queue.push_back(PendingEntry::Reset(reset));
    }

    /// Under weighted fair queueing, the stream whose message goes next; `None` while a reset
    /// waits at a stream's head and no message is part sent.
    fn next_wfq_stream(&self) -> Option<u16> {
        let wfq = self.wfq.as_ref()?;
        if self.selected {
            return Some(self.selected_stream);
        }
        match wfq.next()? {
            (stream, false) => Some(stream),
            (_, true) => None,
        }
    }

    fn next_wfq_message(&self) -> Option<&QueuedMessage> {
        let stream = self.next_wfq_stream()?;
        match self.wfq.as_ref()?.streams.get(&stream)?.entries.front()? {
            (_, PendingEntry::Message(message)) => Some(message),
            (_, PendingEntry::Reset(_)) => None,
        }
    }

    fn front_queue(&self) -> &VecDeque<PendingEntry> {
        if self.selected {
            if self.unordered_is_selected {
                &self.unordered_queue
            } else {
                &self.ordered_queue
            }
        } else if !self.unordered_queue.is_empty() {
            &self.unordered_queue
        } else {
            &self.ordered_queue
        }
    }

    pub(crate) fn peek(&self) -> Option<&ChunkPayloadData> {
        if self.wfq.is_some() {
            return self.next_wfq_message()?.peek();
        }
        match self.front_queue().front()? {
            PendingEntry::Message(message) => message.peek(),
            PendingEntry::Reset(_) => None,
        }
    }

    /// Preserve the existing ordered/unordered scheduling and reset position. Under weighted fair
    /// queueing a reset leaves once its stream's earlier messages have, ahead of other streams.
    pub(crate) fn pop_ready_reset(&mut self) -> Option<ResetMarker> {
        if let Some(wfq) = self.wfq.as_mut() {
            if self.selected {
                return None;
            }
            let (stream, true) = wfq.next()? else {
                return None;
            };
            let queue_len = self.queue_len.checked_sub(1)?;
            let reset = wfq.update(stream, |s, _| match s.entries.front()? {
                (_, PendingEntry::Reset(_)) => match s.entries.pop_front()? {
                    (_, PendingEntry::Reset(reset)) => Some(reset),
                    _ => None,
                },
                _ => None,
            })?;
            self.queue_len = queue_len;
            return Some(reset);
        }
        if self.selected || !self.unordered_queue.is_empty() {
            return None;
        }
        let PendingEntry::Reset(_) = self.ordered_queue.front()? else {
            return None;
        };
        let queue_len = self.queue_len.checked_sub(1)?;
        let PendingEntry::Reset(reset) = self.ordered_queue.pop_front()? else {
            return None;
        };
        self.queue_len = queue_len;
        Some(reset)
    }

    /// Remove the rest of this message once. A repeated call cannot consume
    /// the next message, even when it has the same stream and policy metadata.
    pub(crate) fn drain_message(&mut self, id: MessageId) -> Result<Vec<ChunkPayloadData>> {
        let next = if self.wfq.is_some() {
            self.next_wfq_message()
        } else {
            match self.front_queue().front() {
                Some(PendingEntry::Message(message)) => Some(message),
                _ => None,
            }
        };
        let Some(message) = next else {
            return Ok(vec![]);
        };
        let snapshot = message.snapshot();
        if snapshot.id != Some(id) {
            return Ok(vec![]);
        }
        let (count, bytes) = message.validate_tail()?;
        if count > self.queue_len || bytes > self.n_bytes {
            return Err(Error::OtherSctpErr(
                "invalid pending message accounting".into(),
            ));
        }
        let entry = match self.wfq.as_mut() {
            Some(wfq) => wfq
                .update(snapshot.stream_identifier, |s, _| s.entries.pop_front())
                .map(|(_, entry)| entry),
            None if snapshot.unordered => self.unordered_queue.pop_front(),
            None => self.ordered_queue.pop_front(),
        };
        let Some(PendingEntry::Message(message)) = entry else {
            return Err(Error::OtherSctpErr("missing pending message".into()));
        };
        self.queue_len -= count;
        self.n_bytes -= bytes;
        self.selected = false;
        Ok(message.into_fragments())
    }

    pub(crate) fn pop(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
    ) -> Option<ChunkPayloadData> {
        if self.wfq.is_some() {
            return self.pop_wfq(beginning_fragment);
        }
        let unordered = if self.selected {
            self.unordered_is_selected
        } else if beginning_fragment {
            unordered
        } else {
            return None;
        };
        let queue = if unordered {
            &mut self.unordered_queue
        } else {
            &mut self.ordered_queue
        };
        let PendingEntry::Message(message) = queue.front()? else {
            return None;
        };
        let n_bytes = self.n_bytes.checked_sub(message.peek()?.user_data.len())?;
        let queue_len = self.queue_len.checked_sub(1)?;
        let c = pop_front_fragment(queue, entry_message, entry_whole)?;
        self.selected = !c.ending_fragment;
        self.unordered_is_selected = unordered;
        self.n_bytes = n_bytes;
        self.queue_len = queue_len;
        Some(c)
    }

    /// Takes the next fragment from the stream weighted fair queueing picks, moving the virtual
    /// time to a message's finish tag as the message starts.
    fn pop_wfq(&mut self, beginning_fragment: bool) -> Option<ChunkPayloadData> {
        if !self.selected && !beginning_fragment {
            return None;
        }
        let stream = self.next_wfq_stream()?;
        let n_bytes = self
            .n_bytes
            .checked_sub(self.next_wfq_message()?.peek()?.user_data.len())?;
        let queue_len = self.queue_len.checked_sub(1)?;
        let starting = !self.selected;
        let wfq = self.wfq.as_mut()?;
        let (c, tag) = wfq.update(stream, |s, _| {
            let tag = s.entries.front()?.0;
            pop_front_fragment(&mut s.entries, tagged_message, tagged_whole).map(|c| (c, tag))
        })?;
        if starting {
            wfq.virtual_time = wfq.virtual_time.max(tag);
        }
        self.selected = !c.ending_fragment;
        self.selected_stream = stream;
        self.n_bytes = n_bytes;
        self.queue_len = queue_len;
        Some(c)
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        self.n_bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.queue_len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    fn fragment(beginning: bool, ending: bool, unordered: bool) -> ChunkPayloadData {
        ChunkPayloadData {
            message_id: MessageId::new(0),
            beginning_fragment: beginning,
            ending_fragment: ending,
            unordered,
            user_data: Bytes::from_static(b"data"),
            ..Default::default()
        }
    }

    #[test]
    fn invalid_message_drain_preserves_fragments_and_accounting() {
        for unordered in [false, true] {
            for next_message in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, false, unordered),
                    fragment(false, false, unordered),
                ]);
                if next_message {
                    // Even a malformed tail must not consume the next owner.
                    queue.push_message(vec![fragment(true, true, unordered)]);
                }
                let id = queue.peek().unwrap().message_id.unwrap();
                let (len, bytes) = (queue.len(), queue.get_num_bytes());
                assert!(queue.drain_message(id).is_err());
                assert_eq!(Some(id), queue.peek().unwrap().message_id);
                assert_eq!(len, queue.len());
                assert_eq!(bytes, queue.get_num_bytes());
                assert!(!queue.selected);
            }
        }
    }

    #[test]
    fn missing_beginning_is_an_error_without_mutation() {
        let mut queue = PendingQueue::new();
        queue.push_message(vec![fragment(false, true, false)]);
        let id = queue.peek().unwrap().message_id.unwrap();
        assert!(queue.drain_message(id).is_err());
        assert_eq!(Some(id), queue.peek().unwrap().message_id);
        assert_eq!(1, queue.len());
        assert_eq!(4, queue.get_num_bytes());
    }

    #[test]
    fn invalid_batch_pop_preserves_fragments_and_accounting() {
        for unordered in [false, true] {
            for early_end in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, early_end, unordered),
                    fragment(!early_end, true, unordered),
                ]);
                let mut later = fragment(true, true, unordered);
                later.message_id = MessageId::new(1);
                queue.push_message(vec![later]);
                if !early_end {
                    // The first fragment is valid, but the tail repeats B.
                    assert!(queue.pop(true, unordered).is_some());
                }
                let (len, bytes) = (queue.len(), queue.get_num_bytes());
                let first = queue.peek().unwrap();
                let id = first.message_id.unwrap();
                assert!(queue.pop(first.beginning_fragment, unordered).is_none());
                assert!(queue.drain_message(id).is_err());
                assert_eq!(Some(id), queue.peek().unwrap().message_id);
                assert_eq!(len, queue.len());
                assert_eq!(bytes, queue.get_num_bytes());
                assert_eq!(!early_end, queue.selected);
            }
        }
    }

    #[test]
    fn draining_selected_tail_preserves_other_queue_and_is_idempotent() -> Result<()> {
        for unordered in [false, true] {
            let mut queue = PendingQueue::new();
            let chunks = vec![
                fragment(true, false, unordered),
                fragment(false, true, unordered),
            ];
            let buffer = chunks.as_ptr();
            queue.push_message(chunks);
            assert!(queue.pop(true, unordered).is_some());
            queue.push_message(vec![]);
            let mut other = fragment(true, true, !unordered);
            other.message_id = MessageId::new(1);
            queue.push_message(vec![other]);
            let id = queue.peek().unwrap().message_id.unwrap();
            let tail = queue.drain_message(id)?;
            assert_eq!(1, tail.len());
            assert_eq!(buffer, tail.as_ptr());
            assert!(queue.drain_message(id)?.is_empty());
            assert!(!queue.selected);
            assert_eq!(1, queue.len());
            assert_eq!(4, queue.get_num_bytes());
            assert_eq!(!unordered, queue.peek().unwrap().unordered);
        }
        Ok(())
    }

    #[test]
    fn message_reuses_fragment_buffer_and_keeps_policy_after_a_sent_prefix() {
        let mut queue = PendingQueue::new();
        let created = Instant::now();
        let deadline = created + Duration::from_millis(100);
        let mut first = fragment(true, false, false);
        first.stream_generation = 7;
        first.created_at = Some(created);
        first.payload_type = PayloadProtocolIdentifier::Binary;
        first.reliability = MessageReliability::Timed { deadline };
        let mut tail = fragment(false, true, false);
        tail.stream_generation = 7;
        tail.reliability = MessageReliability::Rexmit {
            max_retransmits: 99,
        };
        let chunks = vec![first, tail];
        let buffer = chunks.as_ptr();
        let capacity = chunks.capacity();
        queue.push_message(chunks);
        let Some(PendingEntry::Message(QueuedMessage::Fragmented { fragments, .. })) =
            queue.ordered_queue.front()
        else {
            panic!("expected a fragmented message");
        };
        assert_eq!(buffer, fragments.as_slices().0.as_ptr());
        assert_eq!(capacity, fragments.capacity());
        queue.pop(true, false).unwrap();
        // A different unordered message cannot interrupt the remaining tail.
        let mut other = fragment(true, true, true);
        other.message_id = MessageId::new(1);
        queue.push_message(vec![other]);
        assert_eq!(MessageId::new(0), queue.peek().unwrap().message_id);
        assert!(matches!(
            queue.ordered_queue.front(),
            Some(PendingEntry::Message(QueuedMessage::Fragmented {
                next_fragment: 1,
                ..
            }))
        ));
        let tail = queue.pop(false, false).unwrap();
        assert_eq!(Some(created), tail.created_at);
        assert_eq!(Some(deadline), tail.reliability.deadline());
        assert_eq!(PayloadProtocolIdentifier::Binary, tail.payload_type);
        assert_eq!(7, tail.stream_generation);
        assert_eq!(MessageId::new(1), queue.peek().unwrap().message_id);
        queue.pop(true, true).unwrap();
        assert!(queue.is_empty());
        assert_eq!(0, queue.get_num_bytes());
    }

    #[test]
    fn zero_size_data_is_not_a_reset_marker() {
        for id in [None, MessageId::new(1)] {
            let mut queue = PendingQueue::new();
            let mut data = fragment(true, true, false);
            data.message_id = id;
            data.user_data = Bytes::new();
            queue.push_message(vec![data]);
            assert_eq!(1, queue.len());
            assert_eq!(0, queue.get_num_bytes());
            assert!(queue.pop_ready_reset().is_none());
            assert_eq!(id, queue.peek().unwrap().message_id);
            queue.pop(true, false).unwrap();
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn sending_or_abandoning_a_tail_preserves_the_reset_boundary() -> Result<()> {
        for unordered in [false, true] {
            for abandon in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, false, unordered),
                    fragment(false, true, unordered),
                ]);
                queue.push_reset(ResetMarker {
                    stream_identifier: 0,
                });
                let mut later = fragment(true, true, false);
                later.message_id = MessageId::new(1);
                later.stream_generation += 1;
                queue.push_message(vec![later]);

                let id = queue.pop(true, unordered).unwrap().message_id.unwrap();
                assert!(queue.pop_ready_reset().is_none());
                assert_eq!(3, queue.len());
                assert_eq!(8, queue.get_num_bytes());
                if abandon {
                    assert_eq!(1, queue.drain_message(id)?.len());
                    assert!(queue.drain_message(id)?.is_empty());
                } else {
                    assert!(queue.pop(false, unordered).unwrap().ending_fragment);
                }
                // Neither DATA operation can consume a control marker.
                assert!(queue.peek().is_none());
                assert!(queue.pop(true, false).is_none());
                assert_eq!(0, queue.pop_ready_reset().unwrap().stream_identifier);
                assert!(queue.pop_ready_reset().is_none());
                assert_eq!(1, queue.len());
                assert_eq!(4, queue.get_num_bytes());
                assert!(queue.drain_message(id)?.is_empty());
                let later = queue.pop(true, false).unwrap();
                assert_eq!(MessageId::new(1), later.message_id);
                assert_eq!(1, later.stream_generation);
                assert!(queue.is_empty());
                assert_eq!(0, queue.get_num_bytes());
            }
        }
        Ok(())
    }

    fn wfq() -> PendingQueue {
        PendingQueue::with_scheduler(StreamScheduler::WeightedFairQueueing)
    }

    fn message(stream: u16, id: u64, pieces: &[usize]) -> Vec<ChunkPayloadData> {
        pieces
            .iter()
            .enumerate()
            .map(|(i, len)| ChunkPayloadData {
                message_id: MessageId::new(id),
                beginning_fragment: i == 0,
                ending_fragment: i + 1 == pieces.len(),
                stream_identifier: stream,
                user_data: Bytes::from(vec![0; *len]),
                ..Default::default()
            })
            .collect()
    }

    fn pop_next(queue: &mut PendingQueue) -> Option<ChunkPayloadData> {
        let next = queue.peek()?;
        let (beginning, unordered) = (next.beginning_fragment, next.unordered);
        queue.pop(beginning, unordered)
    }

    #[test]
    fn busy_streams_share_the_bytes_sent_within_one_message() {
        let mut queue = wfq();
        for i in 0..64 {
            queue.push_message(message(1, 2 * i, &[16 * 1024]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        let mut sent = [0usize; 3];
        while sent[2] < 64 * 4 * 1024 {
            let c = pop_next(&mut queue).unwrap();
            sent[c.stream_identifier as usize] += c.user_data.len();
            assert!(sent[1].abs_diff(sent[2]) <= 16 * 1024, "{sent:?}");
        }
    }

    #[test]
    fn first_come_first_served_sends_in_arrival_order() {
        let mut queue = PendingQueue::new();
        for i in 0..4 {
            queue.push_message(message(1, 2 * i, &[16 * 1024]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        let order: Vec<_> = std::iter::from_fn(|| pop_next(&mut queue))
            .map(|c| c.stream_identifier)
            .collect();
        assert_eq!(vec![1, 2, 1, 2, 1, 2, 1, 2], order);
    }

    #[test]
    fn a_keystroke_waits_for_the_message_in_flight_and_at_most_one_more_per_busy_stream() {
        let mut queue = wfq();
        for i in 0..8 {
            queue.push_message(message(1, 2 * i, &[4 * 1024; 4]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        for _ in 0..5 {
            pop_next(&mut queue).unwrap();
        }
        let in_flight = queue.selected;
        queue.push_message(message(3, 100, &[10]));

        let mut ahead = 0;
        let keystroke = loop {
            let c = pop_next(&mut queue).unwrap();
            if c.stream_identifier == 3 {
                break c;
            }
            ahead += c.user_data.len();
        };
        assert!(
            in_flight,
            "the keystroke arrives while a 16 KiB message is part sent"
        );
        assert_eq!(10, keystroke.user_data.len());
        assert!(
            ahead <= 3 * 4 * 1024 + 16 * 1024 + 4 * 1024,
            "{ahead} bytes went first"
        );
    }

    #[test]
    fn weights_share_the_bytes_in_proportion() {
        let mut queue = wfq();
        queue.set_weight(1, 512);
        queue.set_weight(2, 256);
        for i in 0..300 {
            queue.push_message(message(1, 2 * i, &[1024]));
            queue.push_message(message(2, 2 * i + 1, &[1024]));
        }
        let mut sent = [0usize; 3];
        for _ in 0..300 {
            let c = pop_next(&mut queue).unwrap();
            sent[c.stream_identifier as usize] += c.user_data.len();
        }
        assert!(sent[1].abs_diff(2 * sent[2]) <= 2 * 1024, "{sent:?}");
    }

    #[test]
    fn a_reset_waits_only_for_its_own_streams_messages() {
        let mut queue = wfq();
        queue.push_message(message(1, 0, &[100]));
        queue.push_reset(ResetMarker {
            stream_identifier: 1,
        });
        for i in 1..10 {
            queue.push_message(message(2, i, &[100]));
        }

        assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);
        assert!(queue.peek().is_none(), "the reset goes ahead of stream 2");
        assert_eq!(1, queue.pop_ready_reset().unwrap().stream_identifier);
        assert_eq!(2, pop_next(&mut queue).unwrap().stream_identifier);
        assert_eq!(8, queue.len());
    }

    #[test]
    fn draining_drops_the_message_the_scheduler_would_send_next() -> Result<()> {
        let mut queue = wfq();
        queue.push_message(message(1, 0, &[1024; 4]));
        queue.push_message(message(2, 1, &[8 * 1024]));
        assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);

        let next = queue.peek().unwrap().message_id.unwrap();
        assert_eq!(MessageId::new(0), Some(next));
        assert_eq!(3, queue.drain_message(next)?.len());
        assert!(!queue.selected);
        assert_eq!(2, pop_next(&mut queue).unwrap().stream_identifier);
        assert!(queue.is_empty());
        assert_eq!(0, queue.get_num_bytes());
        Ok(())
    }
}
