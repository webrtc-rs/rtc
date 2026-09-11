use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId, MessageReliability};
use crate::util::sna32lt;

use bytes::Bytes;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;

#[cfg(test)]
#[path = "payload_queue_model_test.rs"]
mod model_test;

#[cfg(test)]
#[path = "payload_queue_shrink_test.rs"]
mod shrink_test;

pub(crate) enum GapAck<'a> {
    Duplicate,
    New {
        chunk: &'a ChunkPayloadData,
        released_buffer: usize,
        delivery_credit: usize,
    },
}

/// Most messages fit in a single DATA chunk. Keep that TSN in the index itself
/// rather than allocating a separate collection on every send and SACK.
#[derive(Debug)]
enum MessageTsns {
    One(u32),
    Fragmented(VecDeque<u32>),
}

impl MessageTsns {
    fn insert(&mut self, tsn: u32) {
        match self {
            Self::One(first) => {
                let pair = if sna32lt(tsn, *first) {
                    [tsn, *first]
                } else {
                    [*first, tsn]
                };
                *self = Self::Fragmented(VecDeque::from(pair));
            }
            Self::Fragmented(tsns) => {
                if tsns.back().is_none_or(|last| sna32lt(*last, tsn)) {
                    tsns.push_back(tsn);
                } else {
                    let index = tsns.partition_point(|&item| sna32lt(item, tsn));
                    tsns.insert(index, tsn);
                }
            }
        }
    }

    /// Cumulative acknowledgment removes only a prefix of a message's TSNs.
    /// Returns true when the whole index entry can be removed.
    fn pop(&mut self, tsn: u32) -> bool {
        match self {
            Self::One(first) => {
                debug_assert_eq!(*first, tsn);
                true
            }
            Self::Fragmented(tsns) => {
                debug_assert_eq!(tsns.front(), Some(&tsn));
                tsns.pop_front();
                tsns.is_empty()
            }
        }
    }

    fn to_vec(&self) -> Vec<u32> {
        match self {
            Self::One(tsn) => vec![*tsn],
            Self::Fragmented(tsns) => tsns.iter().copied().collect(),
        }
    }
}

/// Sending credit follows the original DATA size, even when its payload can
/// no longer be retransmitted and has been released after a revocable gap ACK.
#[derive(Debug)]
struct InflightData {
    chunk: ChunkPayloadData,
    payload_len: usize,
}

#[derive(Default, Debug)]
pub(crate) struct PayloadQueue {
    /// Assigned DATA in serial TSN order, including acknowledged and abandoned
    /// records retained until cumulative ACK. Sender assignment is contiguous;
    /// ordered insertion also supports unique sparse/reordered queue users.
    inflight: VecDeque<InflightData>,
    n_bytes: usize,
    outstanding_bytes: usize,
    buffered_bytes: usize,
    /// Sent fragments of messages eligible for abandonment. A whole message
    /// uses its candidate TSN directly; only fragmented messages need a group.
    message_tsns: FxHashMap<MessageId, MessageTsns>,
}

impl PayloadQueue {
    pub(crate) fn new() -> Self {
        PayloadQueue::default()
    }

    /// Contiguous sender TSNs have a direct deque index. Check the stored TSN
    /// before accepting it so sparse/reordered insertions need no empty slots.
    fn position(&self, tsn: u32) -> Option<usize> {
        let first = self.inflight.front()?;
        let index = tsn.wrapping_sub(first.chunk.tsn) as usize;
        if self
            .inflight
            .get(index)
            .is_some_and(|data| data.chunk.tsn == tsn)
        {
            return Some(index);
        }
        let index = self
            .inflight
            .partition_point(|data| sna32lt(data.chunk.tsn, tsn));
        self.inflight
            .get(index)
            .filter(|data| data.chunk.tsn == tsn)
            .map(|_| index)
    }

    pub(crate) fn tsns(&self) -> impl Iterator<Item = u32> + '_ {
        self.inflight.iter().map(|data| data.chunk.tsn)
    }

    fn insert_sorted(&mut self, data: InflightData) {
        let tsn = data.chunk.tsn;
        if self
            .inflight
            .back()
            .is_none_or(|last| sna32lt(last.chunk.tsn, tsn))
        {
            self.inflight.push_back(data);
        } else {
            let index = self
                .inflight
                .partition_point(|item| sna32lt(item.chunk.tsn, tsn));
            self.inflight.insert(index, data);
        }
    }

    fn abandonment_id(p: &ChunkPayloadData) -> Option<MessageId> {
        if p.beginning_fragment && p.ending_fragment {
            return None;
        }
        match p.reliability {
            MessageReliability::Reliable => None,
            _ => p.message_id,
        }
    }

    /// The caller must not insert a TSN already retained in the queue.
    pub(crate) fn push_no_check(&mut self, p: ChunkPayloadData) {
        debug_assert!(
            self.position(p.tsn).is_none(),
            "inflight TSNs must be unique"
        );
        if let Some(id) = Self::abandonment_id(&p) {
            self.message_tsns
                .entry(id)
                .and_modify(|tsns| tsns.insert(p.tsn))
                .or_insert(MessageTsns::One(p.tsn));
        }
        self.n_bytes += p.user_data.len();
        if p.is_outstanding() {
            self.outstanding_bytes += p.user_data.len();
        }
        if !p.buffer_released {
            self.buffered_bytes += p.user_data.len();
        }
        self.insert_sorted(InflightData {
            payload_len: p.user_data.len(),
            chunk: p,
        });
    }

    /// pop pops only if the oldest chunk's TSN matches the given TSN.
    // SACK consumers use only some fields. Inline so they need not copy the
    // entire DATA metadata through a separate struct-return calling convention.
    #[inline(always)]
    pub(crate) fn pop(&mut self, tsn: u32) -> Option<ChunkPayloadData> {
        if self.inflight.front().map(|data| data.chunk.tsn) != Some(tsn) {
            return None;
        }
        let InflightData {
            chunk: c,
            payload_len,
        } = self.inflight.pop_front()?;
        if let Some(id) = Self::abandonment_id(&c) {
            let tsns = self.message_tsns.get_mut(&id).unwrap();
            if tsns.pop(tsn) {
                self.message_tsns.remove(&id);
            }
        }
        self.n_bytes -= c.user_data.len();
        if c.is_outstanding() {
            self.outstanding_bytes -= payload_len;
        }
        if !c.buffer_released {
            self.buffered_bytes -= payload_len;
        }
        Some(c)
    }

    /// Release oversized storage after a successful cumulative-ACK batch.
    /// Keep headroom and a small floor so ordinary flights do not resize.
    pub(crate) fn shrink_after_cumulative_ack(&mut self) {
        let capacity = self.inflight.capacity();
        let len = self.inflight.len();
        if capacity > 4096 && len <= capacity / 4 {
            self.inflight.shrink_to((2 * len).max(1024));
        }
    }

    pub(crate) fn message_tsns(&self, id: MessageId) -> Vec<u32> {
        self.message_tsns
            .get(&id)
            .map_or_else(Vec::new, MessageTsns::to_vec)
    }

    /// get returns reference to chunkPayloadData with the given TSN value.
    pub(crate) fn get(&self, tsn: u32) -> Option<&ChunkPayloadData> {
        let index = self.position(tsn)?;
        Some(&self.inflight[index].chunk)
    }
    pub(crate) fn get_mut(&mut self, tsn: u32) -> Option<&mut ChunkPayloadData> {
        let index = self.position(tsn)?;
        Some(&mut self.inflight[index].chunk)
    }

    pub(crate) fn payload_len(&self, tsn: u32) -> Option<usize> {
        let index = self.position(tsn)?;
        Some(self.inflight[index].payload_len)
    }

    /// Apply a gap ACK and return its accounting and metadata in one lookup.
    /// Retain retransmittable payload because a gap ACK can still be revoked.
    /// An exhausted Rexmit policy forbids any future retransmission, so only
    /// its metadata and original size need survive (RFC 7496 section 3.1).
    /// Eviction does not abandon the message or affect its pending fragments.
    /// Repeated ACKs do not change recovery state or return credit again.
    #[inline]
    pub(crate) fn acknowledge(&mut self, tsn: u32, use_forward_tsn: bool) -> Option<GapAck<'_>> {
        let index = self.position(tsn)?;
        let data = &mut self.inflight[index];
        let c = &mut data.chunk;
        if c.acknowledged {
            return Some(GapAck::Duplicate);
        }
        if c.is_outstanding() {
            self.outstanding_bytes -= data.payload_len;
        }
        c.acknowledge();
        let released_buffer = c.release_buffer();
        self.buffered_bytes -= released_buffer;
        let delivery_credit = c.take_delivery_credit();
        if use_forward_tsn
            && matches!(c.reliability, MessageReliability::Rexmit { max_retransmits } if c.nsent > max_retransmits)
        {
            self.n_bytes -= c.user_data.len();
            c.user_data = Bytes::new();
        }
        Some(GapAck::New {
            chunk: c,
            released_buffer,
            delivery_credit,
        })
    }

    pub(crate) fn revoke_gap_ack(&mut self, tsn: u32) -> bool {
        let Some(index) = self.position(tsn) else {
            return false;
        };
        let data = &mut self.inflight[index];
        let c = &mut data.chunk;
        if c.acknowledged && !c.abandoned {
            c.acknowledged = false;
            self.outstanding_bytes += data.payload_len;
            true
        } else {
            false
        }
    }

    pub(crate) fn abandon(&mut self, tsn: u32) -> (bool, usize) {
        let Some(index) = self.position(tsn) else {
            return (false, 0);
        };
        let data = &mut self.inflight[index];
        let c = &mut data.chunk;
        let changed = !c.abandoned;
        if c.is_outstanding() {
            self.outstanding_bytes -= data.payload_len;
        }
        c.mark_abandoned();
        let released = c.release_buffer();
        self.buffered_bytes -= released;
        self.n_bytes -= c.user_data.len();
        // Bytes::clear() retains the backing allocation. Abandonment is final,
        // so keep only the TSN/message metadata needed for FORWARD TSN and ACKs.
        c.user_data = Bytes::new();
        (changed, released)
    }

    pub(crate) fn mark_all_to_retrasmit(&mut self) {
        for data in &mut self.inflight {
            let c = &mut data.chunk;
            if !c.is_outstanding() {
                continue;
            }
            c.retransmit = true;
        }
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        self.n_bytes
    }

    pub(crate) fn outstanding_bytes(&self) -> usize {
        self.outstanding_bytes
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.inflight.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
