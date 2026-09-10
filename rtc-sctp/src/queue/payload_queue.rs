use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId, MessageReliability};
use crate::util::sna32lt;

use bytes::Bytes;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;

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
    // length: usize,
    /// Keyed by TSN for sender in-flight lookups.
    chunk_map: FxHashMap<u32, InflightData>,
    /// TSNs in serial-number order. A `VecDeque` so that `pop` — which almost
    /// always removes the front, once per acked chunk — is O(1)
    /// instead of shifting the whole in-flight window left (`Vec::remove(0)`
    /// showed up as ~9% of the end-to-end transfer profile as memmove).
    pub(crate) sorted: VecDeque<u32>,
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

    /// Insert `tsn` into `sorted`, keeping SCTP serial-number order. Binary-search
    /// the insertion point instead of re-sorting the whole vector on every push:
    /// re-sorting made a burst of N chunks O(N^2 log N). In-order arrivals — the
    /// common case, since TSNs are assigned sequentially — land at the
    /// end in O(1) amortized.
    fn insert_sorted(&mut self, tsn: u32) {
        if self.sorted.back().is_none_or(|last| sna32lt(*last, tsn)) {
            self.sorted.push_back(tsn);
        } else {
            let idx = self.sorted.partition_point(|&x| sna32lt(x, tsn));
            self.sorted.insert(idx, tsn);
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

    pub(crate) fn push_no_check(&mut self, p: ChunkPayloadData) {
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
        self.insert_sorted(p.tsn);
        self.chunk_map.insert(
            p.tsn,
            InflightData {
                payload_len: p.user_data.len(),
                chunk: p,
            },
        );
        //self.length += 1;
    }

    /// pop pops only if the oldest chunk's TSN matches the given TSN.
    // SACK consumers use only some fields. Inline so they need not copy the
    // entire DATA metadata through a separate struct-return calling convention.
    #[inline(always)]
    pub(crate) fn pop(&mut self, tsn: u32) -> Option<ChunkPayloadData> {
        if self.sorted.front() == Some(&tsn) {
            self.sorted.pop_front();
            if let Some(InflightData {
                chunk: c,
                payload_len,
            }) = self.chunk_map.remove(&tsn)
            {
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
                return Some(c);
            }
        }

        None
    }

    pub(crate) fn message_tsns(&self, id: MessageId) -> Vec<u32> {
        self.message_tsns
            .get(&id)
            .map_or_else(Vec::new, MessageTsns::to_vec)
    }

    /// get returns reference to chunkPayloadData with the given TSN value.
    pub(crate) fn get(&self, tsn: u32) -> Option<&ChunkPayloadData> {
        self.chunk_map.get(&tsn).map(|data| &data.chunk)
    }
    pub(crate) fn get_mut(&mut self, tsn: u32) -> Option<&mut ChunkPayloadData> {
        self.chunk_map.get_mut(&tsn).map(|data| &mut data.chunk)
    }

    pub(crate) fn payload_len(&self, tsn: u32) -> Option<usize> {
        self.chunk_map.get(&tsn).map(|data| data.payload_len)
    }

    /// Apply a gap ACK and return its accounting and metadata in one lookup.
    /// Retain retransmittable payload because a gap ACK can still be revoked.
    /// An exhausted Rexmit policy forbids any future retransmission, so only
    /// its metadata and original size need survive (RFC 7496 section 3.1).
    /// Eviction does not abandon the message or affect its pending fragments.
    /// Repeated ACKs do not change recovery state or return credit again.
    #[inline]
    pub(crate) fn acknowledge(&mut self, tsn: u32, use_forward_tsn: bool) -> Option<GapAck<'_>> {
        let data = self.chunk_map.get_mut(&tsn)?;
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
        let Some(data) = self.chunk_map.get_mut(&tsn) else {
            return false;
        };
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
        let Some(data) = self.chunk_map.get_mut(&tsn) else {
            return (false, 0);
        };
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
        for data in self.chunk_map.values_mut() {
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
        //assert_eq!(self.chunk_map.len(), self.length);
        self.chunk_map.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
