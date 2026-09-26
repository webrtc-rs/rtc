use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId};
use shared::error::{Error, Result};

use std::collections::VecDeque;

/// pendingBaseQueue
pub(crate) type PendingBaseQueue = VecDeque<ChunkPayloadData>;

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

    pub(crate) fn push(&mut self, c: ChunkPayloadData) {
        self.n_bytes += c.user_data.len();
        if c.unordered {
            self.unordered_queue.push_back(c);
        } else {
            self.ordered_queue.push_back(c);
        }
        self.queue_len += 1;
    }

    pub(crate) fn peek(&self) -> Option<&ChunkPayloadData> {
        if self.selected {
            if self.unordered_is_selected {
                return self.unordered_queue.front();
            } else {
                return self.ordered_queue.front();
            }
        }

        let c = self.unordered_queue.front();

        if c.is_some() {
            return c;
        }

        self.ordered_queue.front()
    }

    /// Remove the rest of this message once. A repeated call cannot consume
    /// the next message, even when it has the same stream and policy metadata.
    pub(crate) fn drain_message(&mut self, id: MessageId) -> Result<Vec<ChunkPayloadData>> {
        let Some(first) = self.peek() else {
            return Ok(vec![]);
        };
        if first.message_id != Some(id) {
            return Ok(vec![]);
        }
        let unordered = first.unordered;
        let queue = if unordered {
            &mut self.unordered_queue
        } else {
            &mut self.ordered_queue
        };
        let Some(first) = queue.front() else {
            return Err(Error::OtherSctpErr("missing pending message".into()));
        };
        if !self.selected && !first.beginning_fragment {
            return Err(Error::OtherSctpErr(
                "missing pending message beginning".into(),
            ));
        }

        // Validate the complete tail before removing anything. In particular,
        // a missing E bit must not consume the next message's beginning.
        let mut bytes = 0;
        let mut count = None;
        for (i, c) in queue.iter().enumerate() {
            if (i != 0 && c.beginning_fragment)
                || c.message_id != Some(id)
                || c.stream_identifier != first.stream_identifier
                || c.stream_sequence_number != first.stream_sequence_number
                || c.stream_generation != first.stream_generation
                || c.unordered != unordered
            {
                return Err(Error::OtherSctpErr(
                    "invalid pending message fragments".into(),
                ));
            }
            bytes += c.user_data.len();
            if c.ending_fragment {
                count = Some(i + 1);
                break;
            }
        }
        let count = count
            .ok_or_else(|| Error::OtherSctpErr("pending message has no ending fragment".into()))?;
        if count > self.queue_len || bytes > self.n_bytes {
            return Err(Error::OtherSctpErr(
                "invalid pending message accounting".into(),
            ));
        }

        let chunks = queue.drain(..count).collect();
        self.queue_len -= count;
        self.n_bytes -= bytes;
        self.selected = false;
        Ok(chunks)
    }

    pub(crate) fn pop(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
    ) -> Option<ChunkPayloadData> {
        let popped = if self.selected {
            let popped = if self.unordered_is_selected {
                self.unordered_queue.pop_front()
            } else {
                self.ordered_queue.pop_front()
            };
            if let Some(p) = &popped
                && p.ending_fragment
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
                if let Some(p) = &popped
                    && !p.ending_fragment
                {
                    self.selected = true;
                    self.unordered_is_selected = true;
                }
                popped
            } else {
                let popped = { self.ordered_queue.pop_front() };
                if let Some(p) = &popped
                    && !p.ending_fragment
                {
                    self.selected = true;
                    self.unordered_is_selected = false;
                }
                popped
            }
        };

        if let Some(p) = &popped {
            self.n_bytes -= p.user_data.len();
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

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
                queue.push(fragment(true, false, unordered));
                queue.push(fragment(false, false, unordered));
                if next_message {
                    // Same SID/SSN: only the B bit distinguishes this message.
                    queue.push(fragment(true, true, unordered));
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
        queue.push(fragment(false, true, false));
        let id = queue.peek().unwrap().message_id.unwrap();
        assert!(queue.drain_message(id).is_err());
        assert_eq!(Some(id), queue.peek().unwrap().message_id);
        assert_eq!(1, queue.len());
        assert_eq!(4, queue.get_num_bytes());
    }

    #[test]
    fn draining_selected_tail_preserves_other_queue_and_is_idempotent() -> Result<()> {
        for unordered in [false, true] {
            let mut queue = PendingQueue::new();
            queue.push(fragment(true, false, unordered));
            queue.push(fragment(false, true, unordered));
            assert!(queue.pop(true, unordered).is_some());
            let mut other = fragment(true, true, !unordered);
            other.message_id = MessageId::new(1);
            queue.push(other);
            let id = queue.peek().unwrap().message_id.unwrap();
            assert_eq!(1, queue.drain_message(id)?.len());
            assert!(queue.drain_message(id)?.is_empty());
            assert!(!queue.selected);
            assert_eq!(1, queue.len());
            assert_eq!(4, queue.get_num_bytes());
            assert_eq!(!unordered, queue.peek().unwrap().unordered);
        }
        Ok(())
    }
}
