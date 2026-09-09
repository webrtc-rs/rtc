use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId, MessageReliability};
use crate::chunk::chunk_selective_ack::GapAckBlock;
use crate::util::*;

use rustc_hash::FxHashMap;
use std::collections::VecDeque;

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

#[derive(Default, Debug)]
pub(crate) struct PayloadQueue {
    // length: usize,
    /// Keyed by TSN; per-chunk lookups on both the send (in-flight) and
    /// receive paths. TSNs are window-bounded, so the faster non-SipHash
    /// hasher is safe.
    chunk_map: FxHashMap<u32, ChunkPayloadData>,
    /// TSNs in serial-number order. A `VecDeque` so that `pop` — which almost
    /// always removes the front, once per acked/received chunk — is O(1)
    /// instead of shifting the whole in-flight window left (`Vec::remove(0)`
    /// showed up as ~9% of the end-to-end transfer profile as memmove).
    pub(crate) sorted: VecDeque<u32>,
    dup_tsn: Vec<u32>,
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
    /// common case, since TSNs are assigned/received sequentially — land at the
    /// end in O(1) amortized.
    fn insert_sorted(&mut self, tsn: u32) {
        if self.sorted.back().is_none_or(|last| sna32lt(*last, tsn)) {
            self.sorted.push_back(tsn);
        } else {
            let idx = self.sorted.partition_point(|&x| sna32lt(x, tsn));
            self.sorted.insert(idx, tsn);
        }
    }

    pub(crate) fn can_push(&self, p: &ChunkPayloadData, cumulative_tsn: u32) -> bool {
        !(self.chunk_map.contains_key(&p.tsn) || sna32lte(p.tsn, cumulative_tsn))
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
        self.chunk_map.insert(p.tsn, p);
        //self.length += 1;
    }

    /// push pushes a payload data. If the payload data is already in our queue or
    /// older than our cumulative_tsn marker, it will be recored as duplications,
    /// which can later be retrieved using popDuplicates.
    pub(crate) fn push(&mut self, p: ChunkPayloadData, cumulative_tsn: u32) -> bool {
        let ok = self.chunk_map.contains_key(&p.tsn);
        if ok || sna32lte(p.tsn, cumulative_tsn) {
            // Found the packet, log in dups
            self.dup_tsn.push(p.tsn);
            return false;
        }

        self.push_no_check(p);

        true
    }

    /// pop pops only if the oldest chunk's TSN matches the given TSN.
    // SACK/RX consumers use only some fields. Inline so they need not copy the
    // entire DATA metadata through a separate struct-return calling convention.
    #[inline(always)]
    pub(crate) fn pop(&mut self, tsn: u32) -> Option<ChunkPayloadData> {
        if self.sorted.front() == Some(&tsn) {
            self.sorted.pop_front();
            if let Some(c) = self.chunk_map.remove(&tsn) {
                if let Some(id) = Self::abandonment_id(&c) {
                    let tsns = self.message_tsns.get_mut(&id).unwrap();
                    if tsns.pop(tsn) {
                        self.message_tsns.remove(&id);
                    }
                }
                self.n_bytes -= c.user_data.len();
                if c.is_outstanding() {
                    self.outstanding_bytes -= c.user_data.len();
                }
                if !c.buffer_released {
                    self.buffered_bytes -= c.user_data.len();
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
        self.chunk_map.get(&tsn)
    }
    pub(crate) fn get_mut(&mut self, tsn: u32) -> Option<&mut ChunkPayloadData> {
        self.chunk_map.get_mut(&tsn)
    }

    /// popDuplicates returns an array of TSN values that were found duplicate.
    pub(crate) fn pop_duplicates(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.dup_tsn)
    }

    pub(crate) fn get_gap_ack_blocks(&self, cumulative_tsn: u32) -> Vec<GapAckBlock> {
        if self.chunk_map.is_empty() {
            return vec![];
        }

        let mut blocks: Vec<GapAckBlock> = vec![];
        for tsn in &self.sorted {
            let offset = tsn.wrapping_sub(cumulative_tsn);
            if offset == 0 || offset > u16::MAX as u32 {
                continue; // This SACK cannot represent a larger gap offset.
            }
            let offset = offset as u16;
            if let Some(last) = blocks.last_mut()
                && last.end.checked_add(1) == Some(offset)
            {
                last.end = offset;
            } else {
                blocks.push(GapAckBlock {
                    start: offset,
                    end: offset,
                });
            }
        }
        blocks
    }

    pub(crate) fn get_gap_ack_blocks_string(&self, cumulative_tsn: u32) -> String {
        let mut s = format!("cumTSN={}", cumulative_tsn);
        for b in self.get_gap_ack_blocks(cumulative_tsn) {
            s += format!(",{}-{}", b.start, b.end).as_str();
        }
        s
    }

    pub(crate) fn acknowledge(&mut self, tsn: u32) -> bool {
        let Some(c) = self.chunk_map.get_mut(&tsn) else {
            return false;
        };
        if c.is_outstanding() {
            self.outstanding_bytes -= c.user_data.len();
        }
        c.acknowledge()
    }

    /// A gap ACK can be revoked. Retain its Bytes until cumulative ACK or
    /// abandonment while returning the existing API's buffer credit once.
    pub(crate) fn release_buffer(&mut self, tsn: u32) -> usize {
        let Some(c) = self.chunk_map.get_mut(&tsn) else {
            return 0;
        };
        let released = c.release_buffer();
        self.buffered_bytes -= released;
        released
    }

    pub(crate) fn revoke_gap_ack(&mut self, tsn: u32) -> bool {
        let Some(c) = self.chunk_map.get_mut(&tsn) else {
            return false;
        };
        if c.acknowledged && !c.abandoned {
            c.acknowledged = false;
            self.outstanding_bytes += c.user_data.len();
            true
        } else {
            false
        }
    }

    pub(crate) fn abandon(&mut self, tsn: u32) -> (bool, usize) {
        let Some(c) = self.chunk_map.get_mut(&tsn) else {
            return (false, 0);
        };
        let changed = !c.abandoned;
        if c.is_outstanding() {
            self.outstanding_bytes -= c.user_data.len();
        }
        c.mark_abandoned();
        let released = c.release_buffer();
        self.buffered_bytes -= released;
        self.n_bytes -= c.user_data.len();
        c.user_data.clear();
        (changed, released)
    }

    pub(crate) fn get_last_tsn_received(&self) -> Option<&u32> {
        self.sorted.back()
    }

    pub(crate) fn mark_all_to_retrasmit(&mut self) {
        for c in self.chunk_map.values_mut() {
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
