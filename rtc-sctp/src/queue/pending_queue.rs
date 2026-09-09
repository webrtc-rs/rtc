use super::receive_queue::ReceiveEpoch;
use crate::chunk::chunk_payload_data::{
    ChunkPayloadData, MessageId, MessageReliability, PayloadProtocolIdentifier,
};
use rustc_hash::FxHashMap;
use slab::Slab;

use std::collections::{BTreeMap, VecDeque};

pub(crate) type PendingBaseQueue = VecDeque<ChunkPayloadData>;

/// Ownership and policy remain available after the first fragment is sent or
/// the API stream closes. Later fragments cannot replace this message snapshot.
#[derive(Debug, Copy, Clone)]
struct MessageSnapshot {
    id: Option<MessageId>,
    stream_identifier: u16,
    stream_generation: u64,
    unordered: bool,
    payload_type: PayloadProtocolIdentifier,
    reliability: MessageReliability,
}

impl MessageSnapshot {
    fn from_chunk(c: &ChunkPayloadData) -> Self {
        Self {
            id: c.message_id,
            stream_identifier: c.stream_identifier,
            stream_generation: c.stream_generation,
            unordered: c.unordered,
            payload_type: c.payload_type,
            reliability: c.reliability,
        }
    }

    fn apply(&self, c: &mut ChunkPayloadData) {
        debug_assert_eq!(self.id, c.message_id);
        debug_assert_eq!(self.stream_identifier, c.stream_identifier);
        debug_assert_eq!(self.stream_generation, c.stream_generation);
        debug_assert_eq!(self.unordered, c.unordered);
        c.payload_type = self.payload_type;
        c.reliability = self.reliability;
    }
}

/// One message owns its complete unsent tail. Unfragmented messages stay inline
/// to avoid allocating a fragment deque for every small application write.
#[derive(Debug)]
enum QueuedMessage {
    Whole(ChunkPayloadData),
    Fragmented {
        snapshot: MessageSnapshot,
        fragments: PendingBaseQueue,
        /// Position of the next fragment, including those already transmitted.
        next_fragment: usize,
        /// The ending fragment has been enqueued, even if the head was sent.
        complete: bool,
        bytes: usize,
    },
}

impl QueuedMessage {
    fn new(c: ChunkPayloadData) -> Self {
        if c.beginning_fragment && c.ending_fragment {
            Self::Whole(c)
        } else {
            Self::Fragmented {
                snapshot: MessageSnapshot::from_chunk(&c),
                complete: c.ending_fragment,
                bytes: c.user_data.len(),
                fragments: VecDeque::from([c]),
                next_fragment: 0,
            }
        }
    }

    fn snapshot(&self) -> MessageSnapshot {
        match self {
            Self::Whole(c) => MessageSnapshot::from_chunk(c),
            Self::Fragmented { snapshot, .. } => *snapshot,
        }
    }

    /// Only Timed whole messages can expire before their first transmission.
    /// Rexmit and Reliable whole messages need no pending group lookup.
    fn indexed_id(&self) -> Option<MessageId> {
        match self {
            Self::Whole(c) if !matches!(c.reliability, MessageReliability::Timed { .. }) => None,
            Self::Whole(c) => c.message_id,
            Self::Fragmented { snapshot, .. } => snapshot.id,
        }
    }

    fn accepts_anonymous_fragment(&self, c: &ChunkPayloadData) -> bool {
        matches!(
            self,
            Self::Fragmented {
                complete: false,
                ..
            }
        ) && self.snapshot().id.is_none()
            && self.snapshot().stream_identifier == c.stream_identifier
            && self.snapshot().stream_generation == c.stream_generation
            && self.snapshot().unordered == c.unordered
    }

    fn push_fragment(&mut self, mut c: ChunkPayloadData) {
        let Self::Fragmented {
            snapshot,
            fragments,
            complete,
            bytes,
            ..
        } = self
        else {
            panic!("cannot append to an unfragmented message");
        };
        debug_assert!(!*complete && !c.beginning_fragment);
        snapshot.apply(&mut c);
        *complete = c.ending_fragment;
        *bytes += c.user_data.len();
        fragments.push_back(c);
    }

    fn peek(&self) -> Option<&ChunkPayloadData> {
        match self {
            Self::Whole(c) => Some(c),
            Self::Fragmented { fragments, .. } => fragments.front(),
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

    fn is_last_fragment(&self) -> bool {
        match self {
            Self::Whole(_) => true,
            Self::Fragmented {
                fragments,
                complete,
                ..
            } => *complete && fragments.len() == 1,
        }
    }

    fn pop_fragment(&mut self) -> Option<ChunkPayloadData> {
        let Self::Fragmented {
            fragments,
            next_fragment,
            bytes,
            ..
        } = self
        else {
            unreachable!("the final fragment removes its message owner");
        };
        let c = fragments.pop_front()?;
        *next_fragment += 1;
        *bytes -= c.user_data.len();
        Some(c)
    }

    fn into_last_fragment(self) -> ChunkPayloadData {
        match self {
            Self::Whole(c) => c,
            Self::Fragmented { mut fragments, .. } => {
                debug_assert_eq!(fragments.len(), 1);
                fragments.pop_front().unwrap()
            }
        }
    }

    fn into_fragments(self) -> Vec<ChunkPayloadData> {
        match self {
            Self::Whole(c) => vec![c],
            Self::Fragmented { fragments, .. } => fragments.into_iter().collect(),
        }
    }
}

/// A reset boundary belongs to control state, not to a DATA chunk. It waits
/// for earlier messages of its own stream and holds later writes until the
/// peer completes the reset. No payload or partial-reliability policy applies.
#[derive(Debug, Default)]
pub(crate) struct ResetMarker {
    pub(crate) stream_identifier: u16,
    pub(crate) receive_epoch: ReceiveEpoch,
}

#[derive(Debug)]
enum WaitingEntry {
    Message(QueuedMessage),
    Reset(ResetMarker),
}

/// Stable slots and explicit links allow O(1) removal without shifting other
/// message indexes. Vacant slots are reused even while the queue head is blocked;
/// abandoned messages cannot leave an ever-growing sequence of tombstones.
#[derive(Debug)]
struct IndexedQueue<T> {
    entries: Slab<QueueEntry<T>>,
    first: Option<usize>,
    last: Option<usize>,
}

// Slab slots cannot reach usize::MAX. Compact links avoid two Option tags
// being copied along with every (potentially large) message on removal.
const NO_LINK: usize = usize::MAX;

#[derive(Debug)]
struct QueueEntry<T> {
    value: T,
    previous: usize,
    next: usize,
}

impl<T> Default for IndexedQueue<T> {
    fn default() -> Self {
        Self {
            entries: Slab::new(),
            first: None,
            last: None,
        }
    }
}

impl<T> IndexedQueue<T> {
    #[inline]
    fn push(&mut self, value: T) -> usize {
        let position = self.entries.insert(QueueEntry {
            value,
            previous: self.last.unwrap_or(NO_LINK),
            next: NO_LINK,
        });
        if let Some(last) = self.last {
            self.entries[last].next = position;
        } else {
            self.first = Some(position);
        }
        self.last = Some(position);
        position
    }

    #[inline]
    fn front(&self) -> Option<(usize, &T)> {
        let first = self.first?;
        Some((first, &self.entries[first].value))
    }

    fn back(&self) -> Option<(usize, &T)> {
        let last = self.last?;
        Some((last, &self.entries[last].value))
    }

    #[inline]
    fn get(&self, position: usize) -> Option<&T> {
        Some(&self.entries.get(position)?.value)
    }

    #[inline]
    fn get_mut(&mut self, position: usize) -> Option<&mut T> {
        Some(&mut self.entries.get_mut(position)?.value)
    }

    #[inline]
    fn remove(&mut self, position: usize) -> Option<T> {
        let entry = self.entries.try_remove(position)?;
        if entry.previous != NO_LINK {
            self.entries[entry.previous].next = entry.next;
        } else {
            self.first = (entry.next != NO_LINK).then_some(entry.next);
        }
        if entry.next != NO_LINK {
            self.entries[entry.next].previous = entry.previous;
        } else {
            self.last = (entry.previous != NO_LINK).then_some(entry.previous);
        }
        Some(entry.value)
    }

    fn pop_front(&mut self) -> Option<T> {
        self.remove(self.front()?.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MessageLocation {
    Ordered(usize),
    Unordered(usize),
    Waiting {
        stream_identifier: u16,
        position: usize,
    },
}

#[derive(Debug, Default)]
struct PendingStreamData {
    /// DATA before this stream's first queued or in-flight reset.
    ready_chunks: usize,
    resetting: bool,
    /// A reset waiting for its own DATA, together with its activation order.
    blocked_reset: Option<(u64, ResetMarker)>,
    /// Message ownership and subsequent reset boundaries retain write order.
    waiting: IndexedQueue<WaitingEntry>,
}

/// Keep the usual single ready reset inline, retaining ordered insertion for
/// earlier boundaries that become ready after a later stream's boundary.
#[derive(Debug, Default)]
struct ReadyResets {
    first: Option<(u64, ResetMarker)>,
    remaining: BTreeMap<u64, ResetMarker>,
}

impl ReadyResets {
    fn insert(&mut self, order: u64, reset: ResetMarker) -> Option<ResetMarker> {
        match self.first.as_mut() {
            None => {
                self.first = Some((order, reset));
                None
            }
            Some((first_order, first)) if order == *first_order => {
                Some(std::mem::replace(first, reset))
            }
            Some((first_order, _)) if order < *first_order => {
                let (old_order, old_reset) = self.first.replace((order, reset)).unwrap();
                self.remaining.insert(old_order, old_reset);
                None
            }
            Some(_) => self.remaining.insert(order, reset),
        }
    }

    fn pop_first(&mut self) -> Option<(u64, ResetMarker)> {
        let first = self.first.take()?;
        self.first = self.remaining.pop_first();
        Some(first)
    }
}

#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    unordered_queue: IndexedQueue<QueuedMessage>,
    ordered_queue: IndexedQueue<QueuedMessage>,
    /// Only ready markers appear here. Per-fragment drains never scan blocked
    /// resets; activation order preserves the previous reset selection order.
    ready_resets: ReadyResets,
    next_reset_order: u64,
    messages: FxHashMap<MessageId, MessageLocation>,
    stream_data: FxHashMap<u16, PendingStreamData>,
    queue_len: usize,
    n_bytes: usize,
    selected: Option<MessageLocation>,
}

impl PendingQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, c: ChunkPayloadData) {
        let stream_identifier = c.stream_identifier;
        self.n_bytes += c.user_data.len();
        self.queue_len += 1;

        if let Some(location) = self.continuation_location(&c) {
            self.message_mut(location).unwrap().push_fragment(c);
            if !matches!(location, MessageLocation::Waiting { .. }) {
                self.stream_data
                    .entry(stream_identifier)
                    .or_default()
                    .ready_chunks += 1;
            }
            return;
        }

        let message = QueuedMessage::new(c);
        let id = message.indexed_id();
        let data = self.stream_data.entry(stream_identifier).or_default();
        if data.resetting {
            let position = data.waiting.push(WaitingEntry::Message(message));
            if let Some(id) = id {
                self.messages.insert(
                    id,
                    MessageLocation::Waiting {
                        stream_identifier,
                        position,
                    },
                );
            }
        } else {
            data.ready_chunks += 1;
            self.push_ready_message(message);
        }
    }

    pub(crate) fn push_reset(&mut self, reset: ResetMarker) {
        self.queue_len += 1;
        let stream_identifier = reset.stream_identifier;
        let data = self.stream_data.entry(stream_identifier).or_default();
        if data.resetting {
            data.waiting.push(WaitingEntry::Reset(reset));
        } else {
            let mut data = self.stream_data.remove(&stream_identifier).unwrap();
            self.activate_reset(&mut data, reset);
            self.stream_data.insert(stream_identifier, data);
        }
    }

    fn continuation_location(&self, c: &ChunkPayloadData) -> Option<MessageLocation> {
        // A beginning fragment creates its owner. Avoid probing the message
        // index on the common path of one unfragmented application write.
        if c.beginning_fragment {
            return None;
        }
        if let Some(id) = c.message_id {
            return self.messages.get(&id).copied();
        }
        // Queue fixtures can omit MessageId. Preserve their B/E grouping without
        // treating a repeated timestamp or SSN as a production message identity.
        if let Some(data) = self.stream_data.get(&c.stream_identifier)
            && data.resetting
        {
            let (position, WaitingEntry::Message(message)) = data.waiting.back()? else {
                return None;
            };
            return message
                .accepts_anonymous_fragment(c)
                .then_some(MessageLocation::Waiting {
                    stream_identifier: c.stream_identifier,
                    position,
                });
        }
        let (position, message) = if c.unordered {
            self.unordered_queue.back()?
        } else {
            self.ordered_queue.back()?
        };
        message
            .accepts_anonymous_fragment(c)
            .then_some(if c.unordered {
                MessageLocation::Unordered(position)
            } else {
                MessageLocation::Ordered(position)
            })
    }

    fn push_ready_message(&mut self, message: QueuedMessage) {
        let unordered = message.snapshot().unordered;
        let id = message.indexed_id();
        let location = if unordered {
            MessageLocation::Unordered(self.unordered_queue.push(message))
        } else {
            MessageLocation::Ordered(self.ordered_queue.push(message))
        };
        if let Some(id) = id {
            self.messages.insert(id, location);
        }
    }

    #[inline]
    fn message(&self, location: MessageLocation) -> Option<&QueuedMessage> {
        match location {
            MessageLocation::Ordered(position) => self.ordered_queue.get(position),
            MessageLocation::Unordered(position) => self.unordered_queue.get(position),
            MessageLocation::Waiting {
                stream_identifier,
                position,
            } => {
                match self
                    .stream_data
                    .get(&stream_identifier)?
                    .waiting
                    .get(position)?
                {
                    WaitingEntry::Message(message) => Some(message),
                    WaitingEntry::Reset(_) => None,
                }
            }
        }
    }

    #[inline]
    fn message_mut(&mut self, location: MessageLocation) -> Option<&mut QueuedMessage> {
        match location {
            MessageLocation::Ordered(position) => self.ordered_queue.get_mut(position),
            MessageLocation::Unordered(position) => self.unordered_queue.get_mut(position),
            MessageLocation::Waiting {
                stream_identifier,
                position,
            } => {
                match self
                    .stream_data
                    .get_mut(&stream_identifier)?
                    .waiting
                    .get_mut(position)?
                {
                    WaitingEntry::Message(message) => Some(message),
                    WaitingEntry::Reset(_) => None,
                }
            }
        }
    }

    #[inline]
    fn remove_message(&mut self, location: MessageLocation) -> Option<QueuedMessage> {
        match location {
            MessageLocation::Ordered(position) => self.ordered_queue.remove(position),
            MessageLocation::Unordered(position) => self.unordered_queue.remove(position),
            MessageLocation::Waiting {
                stream_identifier,
                position,
            } => {
                match self
                    .stream_data
                    .get_mut(&stream_identifier)?
                    .waiting
                    .remove(position)?
                {
                    WaitingEntry::Message(message) => Some(message),
                    WaitingEntry::Reset(_) => unreachable!("message index points to a reset"),
                }
            }
        }
    }

    #[inline]
    fn front_location(&self, unordered: bool) -> Option<MessageLocation> {
        if unordered {
            Some(MessageLocation::Unordered(self.unordered_queue.front()?.0))
        } else {
            Some(MessageLocation::Ordered(self.ordered_queue.front()?.0))
        }
    }

    pub(crate) fn peek(&self) -> Option<&ChunkPayloadData> {
        let location = self
            .selected
            .or_else(|| self.front_location(true))
            .or_else(|| self.front_location(false))?;
        self.message(location)?.peek()
    }

    /// Includes queued boundaries as well as the request already on the wire.
    pub(crate) fn is_resetting(&self, stream_identifier: u16) -> bool {
        self.stream_data
            .get(&stream_identifier)
            .is_some_and(|data| data.resetting)
    }

    /// Release complete owners up to the next reset boundary. Unsent messages
    /// have no SSN; the TX direction assigns it on their first transmission.
    pub(crate) fn complete_reset(&mut self, stream_identifier: u16) {
        let Some(mut data) = self.stream_data.remove(&stream_identifier) else {
            return;
        };
        debug_assert!(data.resetting && data.ready_chunks == 0);
        data.resetting = false;
        while let Some(entry) = data.waiting.pop_front() {
            match entry {
                WaitingEntry::Reset(reset) => {
                    self.activate_reset(&mut data, reset);
                    break;
                }
                WaitingEntry::Message(message) => {
                    data.ready_chunks += message.len();
                    self.push_ready_message(message);
                }
            }
        }
        if data.resetting || data.ready_chunks > 0 {
            self.stream_data.insert(stream_identifier, data);
        }
    }

    /// Remove an abandonment candidate anywhere, including behind a reset.
    /// The caller has already selected a partial-reliability message. Its index remains
    /// valid when other messages are sent or removed. Repetition cannot consume
    /// a neighboring message or reset with the same SID, SSN or creation time.
    pub(crate) fn drain_message(&mut self, id: MessageId) -> Vec<ChunkPayloadData> {
        let Some(location) = self.messages.remove(&id) else {
            return vec![];
        };
        let message = self
            .remove_message(location)
            .expect("indexed pending message exists");
        if self.selected == Some(location) {
            self.selected = None;
        }
        self.n_bytes -= message.bytes();
        self.queue_len -= message.len();
        if !matches!(location, MessageLocation::Waiting { .. }) {
            self.release_ready_chunks(message.snapshot().stream_identifier, message.len());
        }
        message.into_fragments()
    }

    pub(crate) fn pop(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
    ) -> Option<ChunkPayloadData> {
        let location = match self.selected {
            Some(location) => location,
            None if beginning_fragment => self.front_location(unordered)?,
            None => return None,
        };
        let message = self.message(location)?;
        message.peek()?;
        let c = if message.is_last_fragment() {
            let message = self.remove_message(location).unwrap();
            if let Some(id) = message.indexed_id() {
                self.messages.remove(&id);
            }
            message.into_last_fragment()
        } else {
            self.message_mut(location).unwrap().pop_fragment()?
        };
        self.selected = (!c.ending_fragment).then_some(location);
        self.n_bytes -= c.user_data.len();
        self.queue_len -= 1;
        self.release_ready_chunks(c.stream_identifier, 1);
        Some(c)
    }

    fn release_ready_chunks(&mut self, stream_identifier: u16, count: usize) {
        if count == 0 {
            return;
        }
        let data = self.stream_data.get_mut(&stream_identifier).unwrap();
        data.ready_chunks -= count;
        if data.ready_chunks == 0 {
            if let Some((order, reset)) = data.blocked_reset.take() {
                self.ready_resets.insert(order, reset);
            }
            if !data.resetting {
                self.stream_data.remove(&stream_identifier);
            }
        }
    }

    fn activate_reset(&mut self, data: &mut PendingStreamData, reset: ResetMarker) {
        let order = self.next_reset_order;
        self.next_reset_order = order.checked_add(1).expect("reset queue order exhausted");
        data.resetting = true;
        if data.ready_chunks == 0 {
            self.ready_resets.insert(order, reset);
        } else {
            data.blocked_reset = Some((order, reset));
        }
    }

    /// Each fragment updates only its stream's count. A reset becomes ready
    /// once, when that count reaches zero, instead of being rescanned per DATA.
    pub(crate) fn pop_ready_reset(&mut self) -> Option<ResetMarker> {
        let (_, reset) = self.ready_resets.pop_first()?;
        self.queue_len -= 1;
        Some(reset)
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
    use std::time::{Duration, Instant};

    #[test]
    fn inline_ready_resets_preserve_order_replacement_and_refill() {
        let mut resets = ReadyResets::default();
        let mut expected = BTreeMap::new();
        assert!(resets.pop_first().is_none());
        // Includes replacement of the inline minimum and of a tree entry,
        // plus an earlier boundary becoming ready after a later one.
        for (step, order) in [7, 7, 9, 1, 9, 4, 0, 8, 4, 12].into_iter().enumerate() {
            let sid = step as u16;
            let replaced = resets.insert(
                order,
                ResetMarker {
                    stream_identifier: sid,
                    ..Default::default()
                },
            );
            assert_eq!(
                replaced.map(|marker| marker.stream_identifier),
                expected.insert(order, sid)
            );
            if step % 3 == 2 {
                assert_eq!(
                    resets
                        .pop_first()
                        .map(|(key, marker)| (key, marker.stream_identifier)),
                    expected.pop_first()
                );
            }
        }
        while !expected.is_empty() {
            assert_eq!(
                resets
                    .pop_first()
                    .map(|(key, marker)| (key, marker.stream_identifier)),
                expected.pop_first()
            );
        }
        assert!(resets.pop_first().is_none());
        resets.insert(3, ResetMarker::default());
        assert!(
            resets.remaining.is_empty(),
            "one ready reset has no tree node"
        );
        assert_eq!(resets.pop_first().unwrap().0, 3);
        assert!(resets.pop_first().is_none());
    }

    fn fragment(
        id: u64,
        sid: u16,
        unordered: bool,
        beginning: bool,
        ending: bool,
    ) -> ChunkPayloadData {
        ChunkPayloadData {
            message_id: Some(MessageId::new(id)),
            stream_identifier: sid,
            stream_generation: 7,
            reliability: MessageReliability::Rexmit { max_retransmits: 0 },
            unordered,
            beginning_fragment: beginning,
            ending_fragment: ending,
            user_data: Bytes::from_static(b"payload"),
            ..Default::default()
        }
    }

    fn reset(sid: u16) -> ResetMarker {
        ResetMarker {
            stream_identifier: sid,
            ..Default::default()
        }
    }

    // Pending abandonment of a whole message requires a deadline: a Rexmit
    // budget cannot be exhausted before that message's first transmission.
    fn expiring_whole(id: u64, sid: u16, unordered: bool) -> ChunkPayloadData {
        let mut c = fragment(id, sid, unordered, true, true);
        c.reliability = MessageReliability::Timed {
            deadline: Instant::now(),
        };
        c
    }

    #[test]
    fn queued_reset_retains_its_receive_epoch_after_an_earlier_result() {
        let mut receive = super::super::receive_queue::ReceiveQueue::new(1);
        let first = receive.note_outgoing_reset();
        receive.reset();
        receive.open();
        let next = receive.note_outgoing_reset();
        let mut queue = PendingQueue::new();
        assert!(!queue.is_resetting(1));
        for receive_epoch in [first, next] {
            queue.push_reset(ResetMarker {
                stream_identifier: 1,
                receive_epoch,
            });
        }
        assert!(queue.is_resetting(1));
        assert_eq!(queue.pop_ready_reset().unwrap().receive_epoch, first);
        queue.complete_reset(1);
        assert!(queue.is_resetting(1));
        assert_eq!(queue.pop_ready_reset().unwrap().receive_epoch, next);
        queue.complete_reset(1);
        assert!(!queue.is_resetting(1));
    }

    #[test]
    fn index_tracks_continuations_and_abandonment_candidates_only() {
        let mut queue = PendingQueue::new();
        let mut whole = fragment(0, 1, false, true, true);
        whole.reliability = MessageReliability::Reliable;
        queue.push(whole);
        for (beginning, ending) in [(true, false), (false, true)] {
            let mut part = fragment(1, 1, false, beginning, ending);
            part.reliability = MessageReliability::Reliable;
            queue.push(part);
        }
        queue.push(expiring_whole(2, 1, false));
        queue.push_reset(reset(1));
        queue.push(fragment(3, 1, false, true, true));
        assert!(!queue.messages.contains_key(&MessageId::new(0)));
        assert!(queue.messages.contains_key(&MessageId::new(1)));
        assert!(queue.messages.contains_key(&MessageId::new(2)));
        assert!(!queue.messages.contains_key(&MessageId::new(3)));
        assert_eq!(queue.messages.len(), 2);
        assert_eq!(
            Some(MessageId::new(0)),
            queue.pop(true, false).unwrap().message_id
        );
        assert_eq!(1, queue.drain_message(MessageId::new(2)).len());
        assert_eq!(
            Some(MessageId::new(1)),
            queue.pop(true, false).unwrap().message_id
        );
        assert_eq!(
            Some(MessageId::new(1)),
            queue.pop(false, false).unwrap().message_id
        );
        assert_eq!(1, queue.pop_ready_reset().unwrap().stream_identifier);
        queue.complete_reset(1);
        assert_eq!(
            Some(MessageId::new(3)),
            queue.pop(true, false).unwrap().message_id
        );
        assert!(queue.is_empty());
        assert!(queue.messages.is_empty());
    }

    #[test]
    fn drain_nonselected_message_preserves_active_fragmentation() {
        let mut queue = PendingQueue::new();
        queue.push(fragment(1, 5, false, true, false));
        queue.push(fragment(1, 5, false, false, true));
        assert_eq!(
            Some(MessageId::new(1)),
            queue.pop(true, false).unwrap().message_id
        );
        queue.push(fragment(2, 5, false, true, false));
        queue.push(fragment(2, 5, false, false, true));
        queue.push(fragment(3, 5, true, true, true));

        // Matching SID/SSN/policy does not make these fragments one message.
        let abandoned = queue.drain_message(MessageId::new(2));
        assert_eq!(2, abandoned.len());
        assert!(
            abandoned
                .iter()
                .all(|c| c.message_id == Some(MessageId::new(2)))
        );
        assert!(queue.drain_message(MessageId::new(2)).is_empty());
        assert_eq!(Some(MessageId::new(1)), queue.peek().unwrap().message_id);
        assert_eq!(2, queue.len());
        assert_eq!(14, queue.get_num_bytes());

        // Abandoning the selected tail releases its scheduling reservation.
        assert_eq!(1, queue.drain_message(MessageId::new(1)).len());
        assert_eq!(Some(MessageId::new(3)), queue.peek().unwrap().message_id);
        assert_eq!(
            Some(MessageId::new(3)),
            queue.pop(true, true).unwrap().message_id
        );
        assert!(queue.is_empty());
        assert_eq!(0, queue.get_num_bytes());
        assert!(queue.messages.is_empty());
    }

    #[test]
    fn drain_messages_behind_resets_keeps_each_boundary_and_generation() {
        for unordered in [false, true] {
            let mut queue = PendingQueue::new();
            queue.push_reset(reset(1));
            queue.push(fragment(1, 1, unordered, true, false));
            queue.push(fragment(1, 1, unordered, false, true));
            queue.push_reset(reset(1));
            let mut next_generation = expiring_whole(2, 1, !unordered);
            next_generation.stream_generation += 1;
            queue.push(next_generation);
            queue.push(fragment(3, 2, false, true, true));

            let abandoned = queue.drain_message(MessageId::new(2));
            assert_eq!(1, abandoned.len());
            assert_eq!(8, abandoned[0].stream_generation);
            assert_eq!(1, queue.pop_ready_reset().unwrap().stream_identifier);
            queue.complete_reset(1);
            assert!(queue.pop_ready_reset().is_none());
            assert_eq!(2, queue.drain_message(MessageId::new(1)).len());
            assert_eq!(1, queue.pop_ready_reset().unwrap().stream_identifier);
            queue.complete_reset(1);
            assert!(queue.pop_ready_reset().is_none());
            assert_eq!(Some(MessageId::new(3)), queue.peek().unwrap().message_id);
            assert_eq!(1, queue.len());
            assert_eq!(7, queue.get_num_bytes());
            queue.pop(true, false).unwrap();
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn message_snapshot_and_cursor_survive_a_sent_prefix() {
        let mut queue = PendingQueue::new();
        let created = Instant::now();
        let deadline = created + Duration::from_millis(100);
        let mut first = fragment(1, 1, false, true, false);
        first.reliability = MessageReliability::Timed { deadline };
        queue.push(first);
        queue.pop(true, false).unwrap();
        // An incomplete owner survives even when no fragment is currently
        // pending. A different unordered message cannot steal its reservation.
        queue.push(fragment(2, 2, true, true, true));
        assert!(queue.peek().is_none());
        let mut tail = fragment(1, 1, false, false, true);
        tail.reliability = MessageReliability::Rexmit {
            max_retransmits: 99,
        };
        queue.push(tail);
        let location = queue.messages[&MessageId::new(1)];
        assert!(matches!(
            queue.message(location).unwrap(),
            QueuedMessage::Fragmented {
                next_fragment: 1,
                ..
            }
        ));
        let tail = queue.pop(false, false).unwrap();
        assert_eq!(Some(deadline), tail.reliability.deadline());
        assert_eq!(7, tail.stream_generation);
        assert_eq!(Some(MessageId::new(2)), queue.peek().unwrap().message_id);
        queue.pop(true, true).unwrap();
        assert!(queue.is_empty());
    }

    #[test]
    fn zero_size_data_is_not_a_reset_marker() {
        for id in [None, Some(MessageId::new(1))] {
            let mut queue = PendingQueue::new();
            let mut data = fragment(1, 2, false, true, true);
            data.message_id = id;
            data.user_data = Bytes::new();
            queue.push(data);
            assert_eq!(1, queue.len());
            assert_eq!(0, queue.get_num_bytes());
            assert!(queue.pop_ready_reset().is_none());
            assert_eq!(id, queue.peek().unwrap().message_id);
            queue.pop(true, false).unwrap();
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn abandoned_slots_are_reused_while_an_earlier_message_waits() {
        let mut queue = PendingQueue::new();
        queue.push(fragment(0, 1, false, true, true));
        queue.push(expiring_whole(1, 1, false));
        for id in 2..4096 {
            queue.push(expiring_whole(id, 1, false));
            assert_eq!(1, queue.drain_message(MessageId::new(id - 1)).len());
            assert_eq!(Some(MessageId::new(0)), queue.peek().unwrap().message_id);
            assert_eq!(2, queue.len());
            assert_eq!(14, queue.get_num_bytes());
        }
        // Only three message owners were simultaneously present. Removed
        // middle messages must not leave unbounded reserved queue storage.
        assert!(queue.ordered_queue.entries.capacity() <= 4);
        assert_eq!(
            Some(MessageId::new(0)),
            queue.pop(true, false).unwrap().message_id
        );
        assert_eq!(
            Some(MessageId::new(4095)),
            queue.pop(true, false).unwrap().message_id
        );
        assert!(queue.messages.is_empty());
        assert_eq!(0, queue.ordered_queue.entries.len());
    }

    #[test]
    fn reset_readiness_preserves_activation_order_without_scanning_data() {
        let mut queue = PendingQueue::new();
        queue.push(expiring_whole(1, 1, false));
        queue.push_reset(reset(1));
        queue.push(expiring_whole(2, 2, false));
        queue.push_reset(reset(2));
        queue.push_reset(reset(3));
        queue.drain_message(MessageId::new(2));
        queue.drain_message(MessageId::new(1));
        for sid in 1..=3 {
            assert_eq!(sid, queue.pop_ready_reset().unwrap().stream_identifier);
        }
        assert!(queue.pop_ready_reset().is_none());
        assert!(queue.is_empty());
    }
}
