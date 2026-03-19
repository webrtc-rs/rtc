use crate::chunk::chunk_payload_data::ChunkPayloadData;
use crate::FlushIds;

use std::collections::VecDeque;

/// pendingBaseQueue
pub(crate) type PendingBaseQueue = VecDeque<QueueEntry>;

/// pendingQueue
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    unordered_queue: PendingBaseQueue,
    ordered_queue: PendingBaseQueue,
    queue_len: usize,
    n_bytes: usize,
    selected: bool,
    unordered_is_selected: bool,
}

impl PendingQueue {
    pub(crate) fn new() -> Self {
        PendingQueue::default()
    }

    pub(crate) fn push(&mut self, e: QueueEntry) {
        self.n_bytes += e.len();
        if e.unordered() {
            self.unordered_queue.push_back(e);
        } else {
            self.ordered_queue.push_back(e);
        }
        self.queue_len += 1;
    }

    pub(crate) fn peek(&self) -> Option<&QueueEntry> {
        if self.selected {
            if self.unordered_is_selected {
                return self.unordered_queue.front();
            } else {
                return self.ordered_queue.front();
            }
        }

        let e = self.unordered_queue.front();

        if e.is_some() {
            return e;
        }

        self.ordered_queue.front()
    }

    pub(crate) fn pop(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
    ) -> Option<QueueEntry> {
        let popped = if self.selected {
            let popped = if self.unordered_is_selected {
                self.unordered_queue.pop_front()
            } else {
                self.ordered_queue.pop_front()
            };
            if let Some(e) = &popped
                && e.ending_fragment() == Some(true)
            {
                self.selected = false;
            }
            popped
        } else {
            if !beginning_fragment {
                return None;
            }
            if unordered {
                let popped = { self.unordered_queue.pop_front() };
                if let Some(e) = &popped
                    && e.ending_fragment() == Some(false)
                {
                    self.selected = true;
                    self.unordered_is_selected = true;
                }
                popped
            } else {
                let popped = { self.ordered_queue.pop_front() };
                if let Some(e) = &popped
                    && e.ending_fragment() == Some(false)
                {
                    self.selected = true;
                    self.unordered_is_selected = false;
                }
                popped
            }
        };

        if let Some(e) = &popped {
            self.n_bytes -= e.len();
            self.queue_len -= 1;
        }

        popped
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


#[derive(Debug)]
pub(crate) struct FlushEntry {
    pub(crate) ids: FlushIds,
    pub(crate) unordered: bool
}

/// A queue entry can either be a chunk payload, or a flush signal
#[derive(Debug)]
pub(crate) enum QueueEntry {
    Payload(ChunkPayloadData),
    Flush(FlushEntry)
}

impl QueueEntry {

    fn len(&self) -> usize {
        match self {
            Self::Payload(data) => data.user_data.len(),
            Self::Flush(_) => 0
        }
    }

    fn unordered(&self) -> bool {
        match self {
            Self::Payload(data) => data.unordered,
            Self::Flush(flush) => flush.unordered
        }
    }

    fn ending_fragment(&self) -> Option<bool> {
        match self {
            Self::Payload(data) => Some(data.ending_fragment),
            Self::Flush(_) => None
        }
    }
    
    pub fn as_payload(&self) -> &ChunkPayloadData {
        match self {
            Self::Payload(data) => data,
            Self::Flush(_) => panic!("Expected QueueEntry::Payload, but was QueueEntry::Flush instead")
        }
    }

    pub fn into_payload(self) -> ChunkPayloadData {
        match self {
            Self::Payload(data) => data,
            Self::Flush(_) => panic!("Expected QueueEntry::Payload, but was QueueEntry::Flush instead")
        }
    }
}
