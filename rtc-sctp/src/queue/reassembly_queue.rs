use crate::StreamId;
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use crate::util::*;
use shared::error::{Error, Result};

use bytes::{Bytes, BytesMut};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;

/// A chunk of data from the stream
#[derive(Debug, PartialEq)]
pub struct Chunk {
    /// The contents of the chunk
    pub bytes: Bytes,
}

/// Chunks is a set of chunks that share the same SSN
#[derive(Debug, Clone)]
pub struct Chunks {
    /// used only with the ordered chunks
    pub ssn: u16,
    /// The payload protocol identifier shared by every fragment of this message.
    pub ppi: PayloadProtocolIdentifier,
    /// The fragments, in order, that make up one complete message.
    pub chunks: Vec<ChunkPayloadData>,
    offset: usize,
    index: usize,
    /// Arrival order, used only to decide which of two ready messages came first.
    /// A counter rather than an instant: this is sequencing, not time.
    arrival: u64,
}

impl Chunks {
    /// Whether the reassembled message carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The total length in bytes of the reassembled message.
    pub fn len(&self) -> usize {
        let mut l = 0;
        for c in &self.chunks {
            l += c.user_data.len();
        }
        l
    }

    /// Reassemble all fragments into a single freshly-allocated, exactly-sized
    /// buffer with one copy.
    ///
    /// Unlike [`read`](Self::read), this does not round-trip through a
    /// caller-provided scratch buffer, eliminating one full-payload copy on the
    /// receive path (the reassembled message would otherwise be copied into the
    /// scratch buffer and then again into the delivered `BytesMut`). Returns
    /// [`Error::ErrShortBuffer`] when the message exceeds `max_len`, mirroring
    /// `read`'s bound so oversized inbound messages are still rejected.
    pub fn to_payload(&self, max_len: usize) -> Result<BytesMut> {
        let total = self.len();
        if total > max_len {
            return Err(Error::ErrShortBuffer);
        }
        let mut buf = BytesMut::with_capacity(total);
        for c in &self.chunks {
            buf.extend_from_slice(&c.user_data);
        }
        Ok(buf)
    }

    /// Concatenates every fragment into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrShortBuffer`](shared::error::Error::ErrShortBuffer) if `buf` cannot
    /// hold the whole message; the partial copy is left in place.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut n_written = 0;
        for c in &self.chunks {
            let to_copy = c.user_data.len();
            let n = std::cmp::min(to_copy, buf.len() - n_written);
            buf[n_written..n_written + n].copy_from_slice(&c.user_data[..n]);
            n_written += n;
            if n < to_copy {
                return Err(Error::ErrShortBuffer);
            }
        }
        Ok(n_written)
    }

    /// Yields the next slice of the reassembled message, up to `max_length` bytes.
    ///
    /// Advances an internal cursor, so repeated calls walk the message; returns `None` once it is
    /// exhausted.
    pub fn next(&mut self, max_length: usize) -> Option<Chunk> {
        if self.index >= self.chunks.len() {
            return None;
        }

        let mut buf = BytesMut::with_capacity(max_length);

        let mut n_written = 0;
        while self.index < self.chunks.len() {
            let to_copy = self.chunks[self.index].user_data[self.offset..].len();
            let n = std::cmp::min(to_copy, max_length - n_written);
            buf.extend_from_slice(&self.chunks[self.index].user_data[self.offset..self.offset + n]);
            n_written += n;
            if n < to_copy {
                self.offset += n;
                return Some(Chunk {
                    bytes: buf.freeze(),
                });
            }
            self.index += 1;
            self.offset = 0;
        }

        Some(Chunk {
            bytes: buf.freeze(),
        })
    }

    pub(crate) fn new(
        arrival: u64,
        ssn: u16,
        ppi: PayloadProtocolIdentifier,
        chunks: Vec<ChunkPayloadData>,
    ) -> Self {
        Chunks {
            ssn,
            ppi,
            chunks,
            offset: 0,
            index: 0,
            arrival,
        }
    }

    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        // Binary-search the insertion point (fragments are kept in TSN order),
        // which also detects duplicates -- instead of an O(n) dup scan plus a
        // full re-sort of every fragment on each push.
        let idx = self.chunks.partition_point(|c| sna32lt(c.tsn, chunk.tsn));
        if idx < self.chunks.len() && self.chunks[idx].tsn == chunk.tsn {
            return false;
        }
        self.chunks.insert(idx, chunk);

        // Check if we now have a complete set
        self.is_complete()
    }

    pub(crate) fn is_complete(&self) -> bool {
        // Condition for complete set
        //   0. Has at least one chunk.
        //   1. Begins with beginningFragment set to true
        //   2. Ends with endingFragment set to true
        //   3. TSN monotinically increase by 1 from beginning to end

        // 0.
        let n_chunks = self.chunks.len();
        if n_chunks == 0 {
            return false;
        }

        // 1.
        if !self.chunks[0].beginning_fragment {
            return false;
        }

        // 2.
        if !self.chunks[n_chunks - 1].ending_fragment {
            return false;
        }

        // 3.
        let mut last_tsn = 0u32;
        for (i, c) in self.chunks.iter().enumerate() {
            if i > 0 {
                // Fragments must have contiguous TSN
                // From RFC 4960 Section 3.3.1:
                //   When a user message is fragmented into multiple chunks, the TSNs are
                //   used by the receiver to reassemble the message.  This means that the
                //   TSNs for each fragment of a fragmented user message MUST be strictly
                //   sequential.
                if c.tsn != last_tsn.wrapping_add(1) {
                    // mid or end fragment is missing
                    return false;
                }
            }

            last_tsn = c.tsn;
        }

        true
    }
}

#[derive(Default, Debug)]
pub(crate) struct ReassemblyQueue {
    pub(crate) si: StreamId,
    pub(crate) next_ssn: u16,
    /// expected SSN for next ordered chunk
    ///
    /// `ordered`/`unordered` are consumed strictly from the front by `read`;
    /// `VecDeque` makes that O(1) instead of `Vec::remove(0)`'s full shift.
    pub(crate) ordered: VecDeque<Chunks>,
    pub(crate) unordered: VecDeque<Chunks>,
    pub(crate) unordered_chunks: Vec<ChunkPayloadData>,
    pub(crate) n_bytes: usize,
    /// Monotonic counter stamped onto each reassembled message so `read` can tell which of a
    /// ready ordered and a ready unordered message arrived first.
    next_arrival: u64,

    /// Expected message identifier of the next ordered I-DATA message (RFC 8260).
    pub(crate) next_mid: u32,
    /// Ordered I-DATA messages, complete or not, sorted by message identifier.
    ordered_mid: VecDeque<MidSet>,
    /// Unordered I-DATA messages still missing fragments, by message identifier.
    unordered_mid_open: FxHashMap<u32, MidSet>,
    /// Complete unordered I-DATA messages, oldest first.
    unordered_mid: VecDeque<MidSet>,
    /// Set by the first I-DATA chunk; from then on the MID structures serve reads.
    use_interleaving: bool,
    /// Per-stream cap on queued DATA entries / I-DATA messages; zero disables it.
    max_entries: u32,
}

/// The fragments of one I-DATA message: sorted by fragment sequence number, and complete once
/// they run from the beginning fragment (FSN 0) to the ending one without a gap.
#[derive(Debug)]
struct MidSet {
    mid: u32,
    ppi: PayloadProtocolIdentifier,
    chunks: Vec<ChunkPayloadData>,
    arrival: u64,
}

impl MidSet {
    fn new(mid: u32, ppi: PayloadProtocolIdentifier, arrival: u64) -> Self {
        Self {
            mid,
            ppi,
            chunks: vec![],
            arrival,
        }
    }

    fn is_complete(&self) -> bool {
        // Fragments are unique and sorted, so a run of `n` of them that starts at FSN 0 and
        // ends at FSN n - 1 has no gap.
        match (self.chunks.first(), self.chunks.last()) {
            (Some(first), Some(last)) => {
                first.beginning_fragment
                    && last.ending_fragment
                    && first.fragment_sequence_number == 0
                    && last.fragment_sequence_number as usize == self.chunks.len() - 1
            }
            _ => false,
        }
    }

    /// Returns (complete, accepted).
    fn push_and_check(&mut self, chunk: ChunkPayloadData) -> (bool, bool) {
        if self.is_complete() {
            return (false, false);
        }
        let idx = self
            .chunks
            .partition_point(|c| c.fragment_sequence_number < chunk.fragment_sequence_number);
        if self
            .chunks
            .get(idx)
            .is_some_and(|c| c.fragment_sequence_number == chunk.fragment_sequence_number)
        {
            return (false, false);
        }
        if chunk.beginning_fragment {
            self.ppi = chunk.payload_type;
        }
        self.chunks.insert(idx, chunk);
        (self.is_complete(), true)
    }

    fn n_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.user_data.len()).sum()
    }

    fn into_chunks(self) -> Chunks {
        Chunks::new(self.arrival, self.mid as u16, self.ppi, self.chunks)
    }
}

impl ReassemblyQueue {
    /// From RFC 4960 Sec 6.5:
    ///   The Stream Sequence Number in all the streams MUST start from 0 when
    ///   the association is Established.  Also, when the Stream Sequence
    ///   Number reaches the value 65535 the next Stream Sequence Number MUST
    ///   be set to 0.
    pub(crate) fn new(si: StreamId) -> Self {
        ReassemblyQueue {
            si,
            next_ssn: 0, // From RFC 4960 Sec 6.5:
            ordered: VecDeque::new(),
            unordered: VecDeque::new(),
            unordered_chunks: vec![],
            n_bytes: 0,
            next_arrival: 0,
            next_mid: 0,
            ordered_mid: VecDeque::new(),
            unordered_mid_open: FxHashMap::default(),
            unordered_mid: VecDeque::new(),
            use_interleaving: false,
            max_entries: 0,
        }
    }

    /// Caps the DATA entries (or I-DATA messages) this queue will hold; zero lifts the cap.
    pub(crate) fn with_max_entries(mut self, max_entries: u32) -> Self {
        self.max_entries = max_entries;
        self
    }

    fn limit_reached(&self, n_entries: usize) -> bool {
        self.max_entries > 0 && n_entries as u64 >= u64::from(self.max_entries)
    }

    fn ordered_data_entry_count(&self) -> usize {
        self.ordered.iter().map(|s| s.chunks.len()).sum()
    }

    fn unordered_data_entry_count(&self) -> usize {
        self.unordered_chunks.len() + self.unordered.iter().map(|s| s.chunks.len()).sum::<usize>()
    }

    /// Queue a chunk, discarding the reason it was refused.
    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        self.push_checked(chunk).unwrap_or(false)
    }

    /// Queue a chunk. `Ok(true)` means its message is now complete; an error means the
    /// configured entry cap would be exceeded.
    pub(crate) fn push_checked(&mut self, chunk: ChunkPayloadData) -> Result<bool> {
        if chunk.idata {
            self.use_interleaving = true;
            return self.push_idata(chunk);
        }
        self.push_data(chunk)
    }

    fn push_data(&mut self, chunk: ChunkPayloadData) -> Result<bool> {
        if chunk.stream_identifier != self.si {
            return Ok(false);
        }

        if chunk.unordered {
            if self.max_entries > 0 && self.limit_reached(self.unordered_data_entry_count()) {
                return Err(Error::ErrReassemblyQueueLimitExceeded);
            }

            // First, insert into unordered_chunks array
            self.n_bytes += chunk.user_data.len();
            let idx = self
                .unordered_chunks
                .partition_point(|c| sna32lt(c.tsn, chunk.tsn));
            self.unordered_chunks.insert(idx, chunk);

            // Scan unordered_chunks that are contiguous (in TSN)
            // If found, append the complete set to the unordered array
            if let Some(cset) = self.find_complete_unordered_chunk_set() {
                self.unordered.push_back(cset);
                return Ok(true);
            }

            Ok(false)
        } else {
            // This is an ordered chunk
            if sna16lt(chunk.stream_sequence_number, self.next_ssn) {
                return Ok(false);
            }

            // `ordered` is kept sorted by SSN, so binary-search for the chunk
            // set instead of scanning linearly (O(N) per arriving chunk when
            // the application drains slower than data arrives).
            let ssn = chunk.stream_sequence_number;
            let first = self.ordered.partition_point(|s| sna16lt(s.ssn, ssn));
            let end = first
                + self
                    .ordered
                    .iter()
                    .skip(first)
                    .take_while(|s| s.ssn == ssn)
                    .count();

            // A fragment joins the fragmented set of its SSN. An unfragmented message never
            // does, in either direction: a lone chunk that happens to share an SSN with a
            // fragment (the SSN wrapped, or the peer is misbehaving) is a different message,
            // and gluing the two would deliver bytes nobody sent.
            let is_fragmented = |c: &ChunkPayloadData| !(c.beginning_fragment && c.ending_fragment);
            let target = if is_fragmented(&chunk) {
                (first..end).find(|&i| self.ordered[i].chunks.first().is_some_and(is_fragmented))
            } else {
                None
            };

            if self.max_entries > 0 && self.limit_reached(self.ordered_data_entry_count()) {
                // A fragment that is already queued is a duplicate, not growth.
                let duplicate = target
                    .is_some_and(|i| self.ordered[i].chunks.iter().any(|c| c.tsn == chunk.tsn));
                if !duplicate {
                    return Err(Error::ErrReassemblyQueueLimitExceeded);
                }
            }

            if let Some(i) = target {
                let before = self.ordered[i].chunks.len();
                let len = chunk.user_data.len();
                let complete = self.ordered[i].push(chunk);
                // A duplicate fragment is dropped by the set without growing it.
                if self.ordered[i].chunks.len() > before {
                    self.n_bytes += len;
                }
                return Ok(complete);
            }

            // Otherwise start a new set, after the ones that already hold this SSN.
            self.n_bytes += chunk.user_data.len();
            let mut cset = Chunks::new(self.next_arrival, ssn, chunk.payload_type, vec![]);
            self.next_arrival += 1;
            let ok = cset.push(chunk);
            self.ordered.insert(end, cset);

            Ok(ok)
        }
    }

    fn push_idata(&mut self, chunk: ChunkPayloadData) -> Result<bool> {
        if chunk.stream_identifier != self.si {
            return Ok(false);
        }
        if chunk.unordered {
            self.push_unordered_idata(chunk)
        } else {
            self.push_ordered_idata(chunk)
        }
    }

    fn push_unordered_idata(&mut self, chunk: ChunkPayloadData) -> Result<bool> {
        let mid = chunk.message_identifier;
        // A message that completed but has not been read yet must not be rebuilt from a
        // retransmitted fragment.
        if self.unordered_mid.iter().any(|s| s.mid == mid) {
            return Ok(false);
        }

        if !self.unordered_mid_open.contains_key(&mid) {
            if self.limit_reached(self.unordered_mid_open.len() + self.unordered_mid.len()) {
                return Err(Error::ErrReassemblyQueueMidLimitExceeded);
            }
            let set = MidSet::new(mid, chunk.payload_type, self.next_arrival);
            self.next_arrival += 1;
            self.unordered_mid_open.insert(mid, set);
        }
        let Some(set) = self.unordered_mid_open.get_mut(&mid) else {
            return Ok(false);
        };

        let len = chunk.user_data.len();
        let (complete, accepted) = set.push_and_check(chunk);
        if !accepted {
            return Ok(false);
        }
        self.n_bytes += len;
        if complete {
            if let Some(set) = self.unordered_mid_open.remove(&mid) {
                self.unordered_mid.push_back(set);
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn push_ordered_idata(&mut self, chunk: ChunkPayloadData) -> Result<bool> {
        let mid = chunk.message_identifier;
        if sna32lt(mid, self.next_mid) {
            return Ok(false);
        }

        let idx = self.ordered_mid.partition_point(|s| sna32lt(s.mid, mid));
        if !self.ordered_mid.get(idx).is_some_and(|s| s.mid == mid) {
            if self.limit_reached(self.ordered_mid.len()) {
                return Err(Error::ErrReassemblyQueueMidLimitExceeded);
            }
            let set = MidSet::new(mid, chunk.payload_type, self.next_arrival);
            self.next_arrival += 1;
            self.ordered_mid.insert(idx, set);
        }

        let len = chunk.user_data.len();
        let (complete, accepted) = self.ordered_mid[idx].push_and_check(chunk);
        if accepted {
            self.n_bytes += len;
        }
        Ok(complete && accepted)
    }

    pub(crate) fn find_complete_unordered_chunk_set(&mut self) -> Option<Chunks> {
        let mut start_idx = -1isize;
        let mut n_chunks = 0usize;
        let mut last_tsn = 0u32;
        let mut found = false;

        for (i, c) in self.unordered_chunks.iter().enumerate() {
            // seek beginning
            if c.beginning_fragment {
                start_idx = i as isize;
                n_chunks = 1;
                last_tsn = c.tsn;

                if c.ending_fragment {
                    found = true;
                    break;
                }
                continue;
            }

            if start_idx < 0 {
                continue;
            }

            // Check if contiguous in TSN
            if c.tsn != last_tsn.wrapping_add(1) {
                start_idx = -1;
                continue;
            }

            last_tsn = c.tsn;
            n_chunks += 1;

            if c.ending_fragment {
                found = true;
                break;
            }
        }

        if !found {
            return None;
        }

        // Extract the range of chunks
        let chunks: Vec<ChunkPayloadData> = self
            .unordered_chunks
            .drain(start_idx as usize..(start_idx as usize) + n_chunks)
            .collect();
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        Some(Chunks::new(arrival, 0, chunks[0].payload_type, chunks))
    }

    pub(crate) fn is_readable(&self) -> bool {
        if self.use_interleaving {
            return self.readable_mid_sources().is_some();
        }

        // Check unordered first
        if !self.unordered.is_empty() {
            // The chunk sets in self.unordered should all be complete.
            return true;
        }

        // Check ordered sets
        if !self.ordered.is_empty() {
            let cset = &self.ordered[0];
            if cset.is_complete() && sna16lte(cset.ssn, self.next_ssn) {
                return true;
            }
        }
        false
    }

    fn readable_unordered_chunks(&self) -> Option<&Chunks> {
        self.unordered.front()
    }

    fn readable_ordered_chunks(&self) -> Option<&Chunks> {
        let ordered = self.ordered.front();
        if let Some(chunks) = ordered {
            if !chunks.is_complete() {
                return None;
            }
            if sna16gt(chunks.ssn, self.next_ssn) {
                return None;
            }
            Some(chunks)
        } else {
            None
        }
    }

    /// Which I-DATA queue the next read would take from: `Some(true)` for the unordered one,
    /// `Some(false)` for the ordered one, `None` when nothing is deliverable. When both hold a
    /// message, the one whose first fragment arrived earlier goes first.
    fn readable_mid_sources(&self) -> Option<bool> {
        let unordered = self.unordered_mid.front();
        let ordered = self
            .ordered_mid
            .front()
            .filter(|s| s.is_complete() && sna32lte(s.mid, self.next_mid));
        match (unordered, ordered) {
            (Some(u), Some(o)) => Some(u.arrival < o.arrival),
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
    }

    fn read_mid(&mut self) -> Option<Chunks> {
        let set = if self.readable_mid_sources()? {
            self.unordered_mid.pop_front()?
        } else {
            let set = self.ordered_mid.pop_front()?;
            if set.mid == self.next_mid {
                self.next_mid = self.next_mid.wrapping_add(1);
            }
            set
        };
        self.subtract_num_bytes(set.n_bytes());
        Some(set.into_chunks())
    }

    pub(crate) fn read(&mut self) -> Option<Chunks> {
        if self.use_interleaving {
            return self.read_mid();
        }

        let chunks = if let (Some(unordered_chunks), Some(ordered_chunks)) = (
            self.readable_unordered_chunks(),
            self.readable_ordered_chunks(),
        ) {
            if unordered_chunks.arrival < ordered_chunks.arrival {
                self.unordered.pop_front().unwrap()
            } else {
                if ordered_chunks.ssn == self.next_ssn {
                    self.next_ssn = self.next_ssn.wrapping_add(1);
                }
                self.ordered.pop_front().unwrap()
            }
        } else {
            // Check unordered first
            if !self.unordered.is_empty() {
                self.unordered.pop_front().unwrap()
            } else if !self.ordered.is_empty() {
                // Now, check ordered
                let chunks = &self.ordered[0];
                if !chunks.is_complete() {
                    return None;
                }
                if sna16gt(chunks.ssn, self.next_ssn) {
                    return None;
                }
                if chunks.ssn == self.next_ssn {
                    self.next_ssn = self.next_ssn.wrapping_add(1);
                }
                self.ordered.pop_front().unwrap()
            } else {
                return None;
            }
        };

        self.subtract_num_bytes(chunks.len());

        Some(chunks)
    }

    /// Use last_ssn to locate a chunkSet then remove it if the set has
    /// not been complete
    pub(crate) fn forward_tsn_for_ordered(&mut self, last_ssn: u16) {
        let num_bytes = self
            .ordered
            .iter()
            .filter(|s| sna16lte(s.ssn, last_ssn) && !s.is_complete())
            .fold(0, |n, s| {
                n + s.chunks.iter().fold(0, |acc, c| acc + c.user_data.len())
            });
        self.subtract_num_bytes(num_bytes);

        self.ordered
            .retain(|s| !sna16lte(s.ssn, last_ssn) || s.is_complete());

        // Finally, forward next_ssn
        if sna16lte(self.next_ssn, last_ssn) {
            self.next_ssn = last_ssn.wrapping_add(1);
        }
    }

    /// Remove all fragments in the unordered sets that contains chunks
    /// equal to or older than `new_cumulative_tsn`.
    /// We know all sets in the r.unordered are complete ones.
    /// Just remove chunks that are equal to or older than new_cumulative_tsn
    /// from the unordered_chunks
    pub(crate) fn forward_tsn_for_unordered(&mut self, new_cumulative_tsn: u32) {
        let mut last_idx: isize = -1;
        for (i, c) in self.unordered_chunks.iter().enumerate() {
            if sna32gt(c.tsn, new_cumulative_tsn) {
                break;
            }
            last_idx = i as isize;
        }
        if last_idx >= 0 {
            for i in 0..(last_idx + 1) as usize {
                self.subtract_num_bytes(self.unordered_chunks[i].user_data.len());
            }
            self.unordered_chunks.drain(..(last_idx + 1) as usize);
        }
    }

    /// An I-FORWARD-TSN skipped the ordered messages of this stream up to `last_mid`: drop the
    /// ones still missing fragments, and let delivery continue after them. A complete message
    /// is kept, since it can be delivered.
    pub(crate) fn forward_tsn_for_ordered_mid(&mut self, last_mid: u32) {
        let mut dropped = 0;
        self.ordered_mid.retain(|s| {
            let drop = sna32lte(s.mid, last_mid) && !s.is_complete();
            if drop {
                dropped += s.n_bytes();
            }
            !drop
        });
        self.subtract_num_bytes(dropped);

        if sna32lte(self.next_mid, last_mid) {
            self.next_mid = last_mid.wrapping_add(1);
        }
    }

    /// An I-FORWARD-TSN skipped the unordered messages of this stream up to `last_mid`: drop the
    /// ones still missing fragments.
    pub(crate) fn forward_tsn_for_unordered_mid(&mut self, last_mid: u32) {
        let mut dropped = 0;
        self.unordered_mid_open.retain(|&mid, s| {
            let drop = sna32lte(mid, last_mid);
            if drop {
                dropped += s.n_bytes();
            }
            !drop
        });
        self.subtract_num_bytes(dropped);
    }

    pub(crate) fn subtract_num_bytes(&mut self, n_bytes: usize) {
        if self.n_bytes >= n_bytes {
            self.n_bytes -= n_bytes;
        } else {
            self.n_bytes = 0;
        }
    }

    /// Number of ordered I-DATA messages queued, complete or not.
    #[cfg(test)]
    pub(crate) fn ordered_mid_len(&self) -> usize {
        self.ordered_mid.len()
    }

    /// Message identifiers of the queued ordered I-DATA messages, in delivery order.
    #[cfg(test)]
    pub(crate) fn ordered_mids(&self) -> Vec<u32> {
        self.ordered_mid.iter().map(|s| s.mid).collect()
    }

    /// Message identifiers of the complete unordered I-DATA messages waiting to be read.
    #[cfg(test)]
    pub(crate) fn unordered_ready_mids(&self) -> Vec<u32> {
        self.unordered_mid.iter().map(|s| s.mid).collect()
    }

    /// Message identifiers of the unordered I-DATA messages still missing fragments.
    #[cfg(test)]
    pub(crate) fn unordered_open_mids(&self) -> Vec<u32> {
        let mut mids: Vec<u32> = self.unordered_mid_open.keys().copied().collect();
        mids.sort_unstable();
        mids
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        self.n_bytes
    }
}
