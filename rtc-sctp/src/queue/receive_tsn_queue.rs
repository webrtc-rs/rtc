use crate::chunk::chunk_selective_ack::GapAckBlock;
use crate::util::{sna32lt, sna32lte};
use std::collections::VecDeque;

#[derive(Debug)]
struct ReceivedRange {
    start: u32,
    end: u32,
}

impl ReceivedRange {
    fn contains(&self, tsn: u32) -> bool {
        tsn.wrapping_sub(self.start) <= self.end.wrapping_sub(self.start)
    }
}

/// Received TSNs above the cumulative ACK, independent of message delivery.
///
/// Unordered messages can be read while an earlier TSN is missing. Receipt
/// tracking must survive those reads for duplicate detection and SACKs, but
/// must not keep the delivered payload backing alive.
#[derive(Debug, Default)]
pub(crate) struct ReceiveTsnQueue {
    // Canonical, nonadjacent ranges in serial-number order within the receive
    // window. A range may cross u32::MAX. Increasing contiguous DATA extends
    // the tail in O(1); sparse tail appends remain amortized O(1).
    ranges: VecDeque<ReceivedRange>,
    n_tsns: usize,
    duplicates: Vec<u32>,
}

impl ReceiveTsnQueue {
    /// Locate the containing range, or the gap where a receipt belongs.
    fn position(&self, tsn: u32) -> std::result::Result<usize, usize> {
        if self.ranges.back().is_none_or(|last| sna32lt(last.end, tsn)) {
            return Err(self.ranges.len());
        }
        let index = self.ranges.partition_point(|range| sna32lt(range.end, tsn));
        if self
            .ranges
            .get(index)
            .is_some_and(|range| range.contains(tsn))
        {
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
            let joins_previous = index != 0 && self.ranges[index - 1].end.wrapping_add(1) == tsn;
            let joins_next = self
                .ranges
                .get(index)
                .is_some_and(|next| tsn.wrapping_add(1) == next.start);
            match (joins_previous, joins_next) {
                (true, true) => {
                    let next = self.ranges.remove(index).unwrap();
                    self.ranges[index - 1].end = next.end;
                }
                (true, false) => self.ranges[index - 1].end = tsn,
                (false, true) => self.ranges[index].start = tsn,
                (false, false) => self.ranges.insert(
                    index,
                    ReceivedRange {
                        start: tsn,
                        end: tsn,
                    },
                ),
            }
            self.n_tsns += 1;
            true
        } else {
            self.duplicates.push(tsn);
            false
        }
    }

    /// Remove only the oldest receipt when it matches the next cumulative TSN.
    pub(crate) fn pop(&mut self, tsn: u32) -> Option<u32> {
        let first = self.ranges.front_mut()?;
        if first.start != tsn {
            return None;
        }
        if first.start == first.end {
            self.ranges.pop_front();
        } else {
            first.start = first.start.wrapping_add(1);
        }
        self.n_tsns -= 1;
        Some(tsn)
    }

    /// FORWARD-TSN retires every receipt covered by its new cumulative point.
    pub(crate) fn discard_through(&mut self, cumulative_tsn: u32) {
        while let Some(first) = self.ranges.front_mut() {
            if !sna32lte(first.start, cumulative_tsn) {
                break;
            }
            // Widen before adding one: inclusive endpoints can cross u32::MAX.
            let length = u64::from(first.end.wrapping_sub(first.start)) + 1;
            let removed = length.min(u64::from(cumulative_tsn.wrapping_sub(first.start)) + 1);
            self.n_tsns -= removed as usize;
            if removed == length {
                self.ranges.pop_front();
            } else {
                first.start = cumulative_tsn.wrapping_add(1);
                break;
            }
        }
    }

    pub(crate) fn get_last_tsn_received(&self) -> Option<&u32> {
        self.ranges.back().map(|range| &range.end)
    }

    pub(crate) fn pop_duplicates(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.duplicates)
    }

    pub(crate) fn get_gap_ack_blocks(&self, cumulative_tsn: u32) -> Vec<GapAckBlock> {
        fn append_clipped(blocks: &mut Vec<GapAckBlock>, start: u32, end: u32) {
            let start = start.max(1);
            let end = end.min(u16::MAX as u32);
            if start > end {
                return;
            }
            // Receipt ranges are already maximal. Clipping to the SACK
            // window cannot close a hole between two surviving ranges.
            blocks.push(GapAckBlock {
                start: start as u16,
                end: end as u16,
            });
        }

        let mut blocks = vec![];
        for range in &self.ranges {
            let start = range.start.wrapping_sub(cumulative_tsn);
            let end = range.end.wrapping_sub(cumulative_tsn);
            if start <= end {
                append_clipped(&mut blocks, start, end);
            } else {
                // The queried cumulative point may lie inside this range.
                // Match per-TSN filtering on both sides of offset zero without
                // forgetting receipts outside this SACK's 16-bit window.
                append_clipped(&mut blocks, start, u32::MAX);
                append_clipped(&mut blocks, 0, end);
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
        self.n_tsns
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

    #[derive(Default)]
    struct ReceiptModel {
        origin: u32,
        cumulative: i64,
        received: std::collections::BTreeSet<i64>,
        duplicates: Vec<u32>,
    }

    impl ReceiptModel {
        fn wire(&self, logical: i64) -> u32 {
            self.origin.wrapping_add(logical as u32)
        }

        fn push(&mut self, queue: &mut ReceiveTsnQueue, logical: i64) {
            let tsn = self.wire(logical);
            let cumulative = self.wire(self.cumulative);
            let accepted = logical > self.cumulative && !self.received.contains(&logical);
            assert_eq!(queue.can_push(tsn, cumulative), accepted);
            assert_eq!(
                queue.can_push(tsn, cumulative),
                accepted,
                "eligibility is read-only"
            );
            assert_eq!(queue.push(tsn, cumulative), accepted);
            if accepted {
                assert!(self.received.insert(logical));
            } else {
                self.duplicates.push(tsn);
            }
        }

        fn pop_next(&mut self, queue: &mut ReceiveTsnQueue) {
            let next = self.cumulative + 1;
            let expected = self.received.first().copied() == Some(next);
            assert_eq!(
                queue.pop(self.wire(next)),
                expected.then_some(self.wire(next))
            );
            if expected {
                assert!(self.received.remove(&next));
                self.cumulative = next;
            }
        }

        fn discard(&mut self, queue: &mut ReceiveTsnQueue, through: i64) {
            queue.discard_through(self.wire(through));
            self.received.retain(|&logical| logical > through);
            self.cumulative = self.cumulative.max(through);
        }

        fn drain_duplicates(&mut self, queue: &mut ReceiveTsnQueue) {
            assert_eq!(queue.pop_duplicates(), std::mem::take(&mut self.duplicates));
            assert!(queue.pop_duplicates().is_empty());
        }

        fn assert_matches(&self, queue: &ReceiveTsnQueue) {
            assert_eq!(queue.len(), self.received.len());
            assert_eq!(queue.is_empty(), self.received.is_empty());
            assert_eq!(
                queue.get_last_tsn_received().copied(),
                self.received.last().map(|&n| self.wire(n))
            );
            let mut previous = None;
            let mut runs = 0;
            for &logical in &self.received {
                runs += usize::from(previous != Some(logical - 1));
                previous = Some(logical);
                assert!(
                    !queue.can_push(self.wire(logical), self.wire(self.cumulative)),
                    "receipt outside the SACK window must still suppress duplicates"
                );
            }
            assert_eq!(
                queue.ranges.len(),
                runs,
                "each maximal receipt run has one range"
            );
            for offset in [-1, 0, 1, 2, 3, 17, 65534, 65535, 65536, 65537] {
                let logical = self.cumulative + offset;
                assert_eq!(
                    queue.can_push(self.wire(logical), self.wire(self.cumulative)),
                    logical > self.cumulative && !self.received.contains(&logical)
                );
            }
            // Independent oracle: enumerate individual logical receipts and apply
            // modulo arithmetic. It never uses the range search/merge/clip logic.
            // Some queries intentionally use a stale cumulative point or one that
            // lies inside a retained run, without first trimming the queue.
            for cumulative in [
                self.cumulative,
                self.cumulative - 1,
                self.cumulative + 1,
                self.cumulative + 32768,
                self.cumulative - 65535,
            ] {
                let expected: Vec<u16> = self
                    .received
                    .iter()
                    .filter_map(|&logical| {
                        let offset = (logical - cumulative).rem_euclid(1_i64 << 32);
                        (1..=65535).contains(&offset).then_some(offset as u16)
                    })
                    .collect();
                let blocks = queue.get_gap_ack_blocks(self.wire(cumulative));
                for block in &blocks {
                    assert!(block.start != 0 && block.start <= block.end);
                }
                for pair in blocks.windows(2) {
                    assert!(
                        u32::from(pair[0].end) + 1 < u32::from(pair[1].start),
                        "SACK blocks must be ordered, disjoint and maximal"
                    );
                }
                let actual: Vec<u16> = blocks
                    .iter()
                    .flat_map(|block| block.start..=block.end)
                    .collect();
                assert_eq!(
                    actual, expected,
                    "origin {}, queried cumulative {cumulative}",
                    self.origin
                );
            }
        }
    }

    #[test]
    fn range_receipts_match_individual_set_across_interleaved_operations() {
        fn next(seed: &mut u64) -> u64 {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        }

        for origin in [0, u32::MAX - 8, u32::MAX - 65535] {
            for mut seed in [1, 237, 9260] {
                let mut queue = ReceiveTsnQueue::default();
                let mut model = ReceiptModel {
                    origin,
                    ..Default::default()
                };
                for logical in [2, 4, 3, 65535, 65536, 65537] {
                    model.push(&mut queue, logical);
                }
                for _ in 0..768 {
                    let choice = next(&mut seed);
                    match choice % 8 {
                        0..=2 => {
                            let offsets = [-2, 0, 1, 2, 3, 17, 65534, 65535, 65536, 65537];
                            let offset = if choice & 8 == 0 {
                                offsets[(next(&mut seed) as usize) % offsets.len()]
                            } else {
                                (next(&mut seed) % 128) as i64 + 1
                            };
                            model.push(&mut queue, model.cumulative + offset);
                        }
                        3 => {
                            let duplicate = if model.received.is_empty() {
                                model.cumulative - 1
                            } else {
                                *model
                                    .received
                                    .iter()
                                    .nth(next(&mut seed) as usize % model.received.len())
                                    .unwrap()
                            };
                            model.push(&mut queue, duplicate);
                        }
                        4 => model.pop_next(&mut queue),
                        5 => {
                            let advance = match next(&mut seed) % 4 {
                                0 => -1,
                                1 => 1,
                                2 => 65535,
                                _ => 65536,
                            };
                            model.discard(&mut queue, model.cumulative + advance);
                        }
                        6 => {
                            let wrong_front =
                                model.received.first().copied().unwrap_or(model.cumulative) + 1;
                            assert_eq!(
                                queue.pop(model.wire(wrong_front)),
                                None,
                                "pop cannot skip the oldest receipt"
                            );
                        }
                        _ => model.drain_duplicates(&mut queue),
                    }
                    model.assert_matches(&queue);
                }
                model.drain_duplicates(&mut queue);
                model.discard(&mut queue, model.cumulative + 65537);
                model.assert_matches(&queue);
            }
        }
    }

    #[test]
    fn dense_receipt_runs_merge_and_clip_without_losing_unrepresentable_tsns() {
        for origin in [123, u32::MAX - 32767] {
            let mut queue = ReceiveTsnQueue::default();
            let mut model = ReceiptModel {
                origin,
                ..Default::default()
            };
            // Two dense runs with one missing bridge. In the second case, that
            // bridge is wire TSN 0, between u32::MAX and 1.
            for logical in (2..=65540).filter(|&logical| logical != 32768) {
                model.push(&mut queue, logical);
            }
            assert_eq!(queue.ranges.len(), 2);
            model.assert_matches(&queue);
            model.push(&mut queue, 32768);
            assert_eq!(queue.ranges.len(), 1);
            model.assert_matches(&queue);
            assert_eq!(gaps(&queue, origin), [(2, 65535)]);
            model.pop_next(&mut queue); // TSN 1 remains missing.
            for duplicate in [65536, 65536, 0, 65540] {
                model.push(&mut queue, duplicate);
            }
            model.drain_duplicates(&mut queue);

            model.push(&mut queue, 1); // Extend the run backwards.
            model.pop_next(&mut queue);
            model.assert_matches(&queue);
            model.discard(&mut queue, 65534); // Trim through the middle of the run.
            model.assert_matches(&queue);
            assert_eq!(gaps(&queue, model.wire(model.cumulative)), [(1, 6)]);
            assert_eq!(queue.len(), 6);
            for _ in 0..6 {
                model.pop_next(&mut queue);
            }
            model.assert_matches(&queue);
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn long_sparse_receipts_survive_interior_bridges_and_front_tail_churn() {
        const SPARSE: usize = 8192;
        for origin in [12345, u32::MAX - 7] {
            let mut queue = ReceiveTsnQueue::default();
            let mut model = ReceiptModel {
                origin,
                ..Default::default()
            };
            for index in 1..=SPARSE {
                model.push(&mut queue, (2 * index) as i64);
            }
            model.assert_matches(&queue);
            assert_eq!(queue.ranges.len(), SPARSE);
            let capacity = queue.ranges.capacity();
            assert!(capacity >= SPARSE);

            // Retire a singleton range from the front and append one at the tail,
            // keeping a missing TSN between every retained receipt. Two complete
            // turns through the sparse set exercise the deque's wrapped storage.
            let mut last = (2 * SPARSE) as i64;
            for step in 0..2 * SPARSE {
                model.push(&mut queue, model.cumulative + 1);
                model.pop_next(&mut queue);
                model.pop_next(&mut queue);
                last += 2;
                model.push(&mut queue, last);
                assert_eq!(queue.len(), SPARSE);
                assert_eq!(queue.ranges.len(), SPARSE);
                assert_eq!(
                    queue.ranges.capacity(),
                    capacity,
                    "bounded churn must reuse storage"
                );
                if step % 512 == 0 {
                    // Keep repeated duplicates queued across later front removals.
                    model.push(&mut queue, last);
                    model.push(&mut queue, model.cumulative);
                    model.assert_matches(&queue);
                }
            }
            model.drain_duplicates(&mut queue);
            model.assert_matches(&queue);

            // Fill holes around the median in alternating directions. These
            // bridge insertions remove interior range records, with long tails on
            // either side; they must preserve all the untouched sparse receipts.
            let middle = model.cumulative + SPARSE as i64;
            for distance in 1..=256 {
                for bridge in [middle - (2 * distance - 1), middle + (2 * distance - 1)] {
                    model.push(&mut queue, bridge);
                }
                assert_eq!(queue.ranges.len(), SPARSE - 2 * distance as usize);
                if distance % 64 == 0 {
                    model.assert_matches(&queue);
                }
            }
            model.push(&mut queue, middle - 1);
            model.push(&mut queue, middle - 1);

            // Collapse all remaining interior holes. The logical set becomes one
            // range, while its historical sparse allocation remains available for
            // reuse. This checks count preservation independently of range count.
            for bridge in (model.cumulative + 3..last).step_by(2) {
                if !model.received.contains(&bridge) {
                    model.push(&mut queue, bridge);
                }
            }
            model.assert_matches(&queue);
            assert_eq!(queue.ranges.len(), 1);
            assert_eq!(queue.len(), 2 * SPARSE - 1);
            assert_eq!(queue.ranges.capacity(), capacity);
            assert_eq!(
                gaps(&queue, model.wire(model.cumulative)),
                [(2, (2 * SPARSE) as u16)]
            );
            model.drain_duplicates(&mut queue);

            model.discard(&mut queue, last);
            model.assert_matches(&queue);
            assert!(queue.is_empty());
            assert_eq!(queue.ranges.capacity(), capacity);
            for offset in [2, 4, 6, 3, 5] {
                model.push(&mut queue, model.cumulative + offset);
            }
            model.assert_matches(&queue);
            assert_eq!(queue.ranges.capacity(), capacity);
        }
    }

    #[test]
    fn long_dense_run_pops_through_tsn_wrap_then_accepts_a_new_run() {
        const COUNT: i64 = 65540;
        for origin in [12345, u32::MAX - 32767] {
            let mut queue = ReceiveTsnQueue::default();
            let mut model = ReceiptModel {
                origin,
                ..Default::default()
            };
            for logical in 1..=COUNT {
                model.push(&mut queue, logical);
            }
            assert_eq!(queue.ranges.len(), 1);
            model.assert_matches(&queue);
            for duplicate in [1, 65536, 65536] {
                model.push(&mut queue, duplicate);
            }
            let mut popped_max = false;
            let mut popped_zero = false;
            for logical in 1..=COUNT {
                assert_eq!(
                    queue.pop(model.wire(logical + 1)),
                    None,
                    "pop must not jump ahead inside a dense range"
                );
                model.pop_next(&mut queue);
                assert_eq!(queue.len(), (COUNT - logical) as usize);
                assert_eq!(queue.ranges.len(), usize::from(logical != COUNT));
                let wire = model.wire(logical);
                popped_max |= wire == u32::MAX;
                popped_zero |= wire == 0;
                if logical % 4096 == 0 || wire == u32::MAX || wire == 0 {
                    model.assert_matches(&queue);
                }
            }
            assert_eq!(
                popped_max && popped_zero,
                u64::from(origin) + COUNT as u64 > u64::from(u32::MAX)
            );
            model.assert_matches(&queue);
            model.drain_duplicates(&mut queue);
            assert!(queue.is_empty());
            assert!(queue.get_last_tsn_received().is_none());

            // Reuse the emptied tracker with a fresh hole and a dense tail; old
            // receipt endpoints/counts must not survive the completed front drain.
            let prefix = model.cumulative;
            for logical in prefix + 2..=prefix + 1025 {
                model.push(&mut queue, logical);
            }
            model.pop_next(&mut queue);
            model.assert_matches(&queue);
            assert_eq!(gaps(&queue, model.wire(prefix)), [(2, 1025)]);
            model.push(&mut queue, prefix + 1);
            for _ in 0..1025 {
                model.pop_next(&mut queue);
            }
            model.assert_matches(&queue);
            assert!(queue.is_empty());
        }
    }
}
