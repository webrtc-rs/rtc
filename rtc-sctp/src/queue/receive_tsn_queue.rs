use crate::chunk::chunk_selective_ack::GapAckBlock;
use crate::util::{sna32lt, sna32lte};
use std::collections::VecDeque;

/// Received TSNs above the cumulative ACK, independent of message delivery.
///
/// Unordered messages can be read while an earlier TSN is missing. Receipt
/// tracking must survive those reads for duplicate detection and SACKs, but
/// must not keep the delivered payload backing alive.
#[derive(Debug, Default)]
pub(crate) struct ReceiveTsnQueue {
    // Serial-number order within the receive window. Sequential arrivals and
    // cumulative advancement append/pop in amortized O(1), without a second index.
    tsns: VecDeque<u32>,
    duplicates: Vec<u32>,
}

impl ReceiveTsnQueue {
    /// The common increasing-TSN path needs no binary search. Reordered DATA
    /// uses the same serial ordering for membership and insertion.
    fn position(&self, tsn: u32) -> std::result::Result<usize, usize> {
        if self.tsns.back().is_none_or(|&last| sna32lt(last, tsn)) {
            return Err(self.tsns.len());
        }
        let index = self
            .tsns
            .partition_point(|&received| sna32lt(received, tsn));
        if self.tsns.get(index) == Some(&tsn) {
            Ok(index)
        } else {
            Err(index)
        }
    }

    /// Eligibility checks do not record duplicates; the caller may reject
    /// DATA for other reasons before committing its receipt with `push`.
    pub(crate) fn can_push(&self, tsn: u32, cumulative_tsn: u32) -> bool {
        !sna32lte(tsn, cumulative_tsn) && self.position(tsn).is_err()
    }

    /// Record receipt, or remember a duplicate in arrival order for a SACK.
    pub(crate) fn push(&mut self, tsn: u32, cumulative_tsn: u32) -> bool {
        if !sna32lte(tsn, cumulative_tsn)
            && let Err(index) = self.position(tsn)
        {
            if index == self.tsns.len() {
                self.tsns.push_back(tsn);
            } else {
                self.tsns.insert(index, tsn);
            }
            true
        } else {
            self.duplicates.push(tsn);
            false
        }
    }

    /// Remove only the oldest receipt when it matches the next cumulative TSN.
    pub(crate) fn pop(&mut self, tsn: u32) -> Option<u32> {
        if self.tsns.front() == Some(&tsn) {
            self.tsns.pop_front()
        } else {
            None
        }
    }

    /// FORWARD-TSN retires every receipt covered by its new cumulative point.
    pub(crate) fn discard_through(&mut self, cumulative_tsn: u32) {
        while self
            .tsns
            .front()
            .is_some_and(|&tsn| sna32lte(tsn, cumulative_tsn))
        {
            self.tsns.pop_front();
        }
    }

    pub(crate) fn get_last_tsn_received(&self) -> Option<&u32> {
        self.tsns.back()
    }

    pub(crate) fn pop_duplicates(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.duplicates)
    }

    pub(crate) fn get_gap_ack_blocks(&self, cumulative_tsn: u32) -> Vec<GapAckBlock> {
        let mut blocks: Vec<GapAckBlock> = vec![];
        for &tsn in &self.tsns {
            let offset = tsn.wrapping_sub(cumulative_tsn);
            if offset == 0 || offset > u16::MAX as u32 {
                continue; // Retain receipts that this SACK cannot represent yet.
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
        let mut result = format!("cumTSN={cumulative_tsn}");
        for block in self.get_gap_ack_blocks(cumulative_tsn) {
            result += format!(",{}-{}", block.start, block.end).as_str();
        }
        result
    }

    pub(crate) fn len(&self) -> usize {
        self.tsns.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gaps(queue: &ReceiveTsnQueue, cumulative_tsn: u32) -> Vec<(u16, u16)> {
        queue
            .get_gap_ack_blocks(cumulative_tsn)
            .iter()
            .map(|gap| (gap.start, gap.end))
            .collect()
    }

    #[test]
    fn reordered_receipts_and_duplicates_cross_tsn_wrap() {
        let mut queue = ReceiveTsnQueue::default();
        let cumulative = u32::MAX - 2;
        for offset in [4, 2, 5, 3] {
            let tsn = cumulative.wrapping_add(offset);
            assert!(queue.can_push(tsn, cumulative));
            assert!(queue.push(tsn, cumulative));
        }
        assert_eq!(queue.len(), 4);
        assert_eq!(queue.get_last_tsn_received(), Some(&2));
        assert_eq!(gaps(&queue, cumulative), [(2, 5)]);
        assert_eq!(queue.pop(0), None, "only the oldest receipt may be popped");

        let duplicate = 0;
        assert!(!queue.can_push(duplicate, cumulative));
        assert!(!queue.can_push(cumulative, cumulative));
        assert!(
            queue.pop_duplicates().is_empty(),
            "eligibility is read-only"
        );
        for tsn in [duplicate, cumulative, cumulative.wrapping_sub(1), duplicate] {
            assert!(!queue.push(tsn, cumulative));
        }
        assert_eq!(
            queue.pop_duplicates(),
            [duplicate, cumulative, cumulative.wrapping_sub(1), duplicate]
        );
        assert!(queue.pop_duplicates().is_empty());
        assert_eq!(gaps(&queue, cumulative), [(2, 5)]);

        assert!(queue.push(cumulative.wrapping_add(1), cumulative));
        assert_eq!(gaps(&queue, cumulative), [(1, 5)]);
        for offset in 1..=5 {
            let tsn = cumulative.wrapping_add(offset);
            assert_eq!(queue.pop(tsn), Some(tsn));
        }
        assert!(queue.is_empty());
        assert_eq!(queue.get_last_tsn_received(), None);
    }

    #[test]
    fn sack_offset_limit_does_not_forget_later_receipts() {
        for cumulative in [123u32, u32::MAX - 12] {
            let mut queue = ReceiveTsnQueue::default();
            for offset in [65536, 1, 65535, 65537, 65534] {
                assert!(queue.push(cumulative.wrapping_add(offset), cumulative));
            }
            assert_eq!(gaps(&queue, cumulative), [(1, 1), (65534, 65535)]);
            let outside_sack = cumulative.wrapping_add(65536);
            assert!(!queue.can_push(outside_sack, cumulative));
            assert!(!queue.push(outside_sack, cumulative));
            assert_eq!(queue.pop_duplicates(), [outside_sack]);

            // Once the cumulative point advances, formerly unrepresentable
            // receipts reappear in the SACK without receiving DATA again.
            let advanced = cumulative.wrapping_add(65534);
            queue.discard_through(advanced);
            assert_eq!(queue.len(), 3);
            assert_eq!(gaps(&queue, advanced), [(1, 3)]);
            for offset in 1..=3 {
                let tsn = advanced.wrapping_add(offset);
                assert_eq!(queue.pop(tsn), Some(tsn));
            }
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn forward_tsn_discards_only_covered_receipts_across_wrap() {
        let cumulative = u32::MAX - 2;
        let mut queue = ReceiveTsnQueue::default();
        for offset in [2, 4, 7] {
            assert!(queue.push(cumulative.wrapping_add(offset), cumulative));
        }
        let duplicate = cumulative.wrapping_add(2);
        assert!(!queue.push(duplicate, cumulative));
        let forwarded = cumulative.wrapping_add(3);
        queue.discard_through(forwarded);
        assert_eq!(gaps(&queue, forwarded), [(1, 1), (4, 4)]);
        assert_eq!(queue.pop_duplicates(), [duplicate]);

        // The association can advance through the receipt immediately after
        // FORWARD-TSN, but must stop at the next missing TSN.
        assert_eq!(queue.pop(forwarded.wrapping_add(1)), Some(1));
        assert_eq!(queue.pop(forwarded.wrapping_add(2)), None);
        assert_eq!(queue.len(), 1);
        queue.discard_through(cumulative.wrapping_add(7));
        assert!(queue.is_empty());
        assert!(gaps(&queue, cumulative.wrapping_add(7)).is_empty());
    }
}
