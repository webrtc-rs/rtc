//! Packet arrival time map for TWCC feedback generation.
//!
//! Adapted from Chrome's implementation:
//! <https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/webrtc/modules/remote_bitrate_estimator/packet_arrival_map.h>

use wide::i64x4;

const MIN_CAPACITY: usize = 128;
const MAX_NUMBER_OF_PACKETS: i64 = 1 << 15;

/// A map tracking packet arrival times, indexed by unwrapped sequence number.
///
/// Uses a circular buffer where packets are stored at index `seq % capacity`.
/// Automatically grows/shrinks as needed.
pub(crate) struct PacketArrivalTimeMap {
    /// Circular buffer of arrival times. -1 indicates not received.
    arrival_times: Vec<i64>,
    /// First valid sequence number (inclusive).
    begin_sequence_number: i64,
    /// First sequence number after the valid range (exclusive).
    end_sequence_number: i64,
}

impl PacketArrivalTimeMap {
    pub(crate) fn new() -> Self {
        Self {
            arrival_times: Vec::new(),
            begin_sequence_number: 0,
            end_sequence_number: 0,
        }
    }

    /// Record that a packet with the given sequence number arrived at the given time.
    pub(crate) fn add_packet(&mut self, sequence_number: i64, arrival_time: i64) {
        if self.arrival_times.is_empty() {
            // First packet
            self.reallocate(MIN_CAPACITY);
            self.begin_sequence_number = sequence_number;
            self.end_sequence_number = sequence_number + 1;
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if sequence_number >= self.begin_sequence_number
            && sequence_number < self.end_sequence_number
        {
            // The packet is within the buffer, no need to resize.
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if sequence_number < self.begin_sequence_number {
            // The packet goes before the current buffer. Expand to add packet,
            // but only if it fits within the maximum number of packets.
            let new_size = (self.end_sequence_number - sequence_number) as usize;
            if new_size > MAX_NUMBER_OF_PACKETS as usize {
                // Don't expand the buffer back for this packet, as it would remove newer received
                // packets.
                return;
            }
            self.adjust_to_size(new_size);
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            let begin = self.begin_sequence_number;
            self.set_not_received(sequence_number + 1, begin);
            self.begin_sequence_number = sequence_number;
            return;
        }

        // The packet goes after the buffer.
        let new_end_sequence_number = sequence_number + 1;

        if new_end_sequence_number >= self.end_sequence_number + MAX_NUMBER_OF_PACKETS {
            // All old packets have to be removed.
            self.begin_sequence_number = sequence_number;
            self.end_sequence_number = new_end_sequence_number;
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if self.begin_sequence_number < new_end_sequence_number - MAX_NUMBER_OF_PACKETS {
            // Remove oldest entries.
            self.begin_sequence_number = new_end_sequence_number - MAX_NUMBER_OF_PACKETS;
        }

        self.adjust_to_size((new_end_sequence_number - self.begin_sequence_number) as usize);

        // Packets can be received out of order. If this isn't the next expected packet,
        // add enough placeholders to fill the gap.
        let end = self.end_sequence_number;
        self.set_not_received(end, sequence_number);
        self.end_sequence_number = new_end_sequence_number;
        let idx = self.index(sequence_number);
        self.arrival_times[idx] = arrival_time;
    }

    /// Marks `start_inclusive..end_exclusive` as not received (`-1`).
    ///
    /// The range is split where it wraps the circular buffer into at most two contiguous
    /// slices, each filled at once, rather than indexed one sequence number at a time. The
    /// callers only pass ranges inside the window they have just sized the buffer for, so the
    /// range fits the capacity; a longer one would cover every slot, and fills the whole buffer.
    fn set_not_received(&mut self, start_inclusive: i64, end_exclusive: i64) {
        if end_exclusive <= start_inclusive {
            return;
        }
        let len = (end_exclusive - start_inclusive) as u64;
        if len >= self.capacity() as u64 {
            self.arrival_times.fill(-1);
            return;
        }
        let (head, tail) = self.slices_mut(start_inclusive, len as usize);
        head.fill(-1);
        tail.fill(-1);
    }

    /// Returns the first valid sequence number in the map.
    pub(crate) fn begin_sequence_number(&self) -> i64 {
        self.begin_sequence_number
    }

    /// Returns the first sequence number after the last valid sequence number.
    pub(crate) fn end_sequence_number(&self) -> i64 {
        self.end_sequence_number
    }

    /// Find the next received packet at or after the given sequence number.
    /// Returns (sequence_number, arrival_time) if found.
    ///
    /// Scans the stored times in sequence order as at most two contiguous slices (split where
    /// the range wraps the buffer), eight at a time ([`first_after`]), rather than one circular
    /// index per sequence number — a long run of lost packets is one long run of `-1`s.
    pub(crate) fn find_next_at_or_after(&self, sequence_number: i64) -> Option<(i64, i64)> {
        let start = self.clamp(sequence_number);
        if start >= self.end_sequence_number {
            return None;
        }
        let len = (self.end_sequence_number - start) as usize;
        // Received packets have a non-negative arrival time: greater than -1.
        let offset = self.position_after(start, len, -1)?;
        let seq = start + offset as i64;
        Some((seq, self.arrival_times[self.index(seq)]))
    }

    /// Erase all elements from the beginning of the map until sequence_number.
    #[allow(dead_code)]
    pub(crate) fn erase_to(&mut self, sequence_number: i64) {
        if sequence_number < self.begin_sequence_number {
            return;
        }
        if sequence_number >= self.end_sequence_number {
            // Erase all.
            self.begin_sequence_number = self.end_sequence_number;
            return;
        }
        // Remove some
        self.begin_sequence_number = sequence_number;
        self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
    }

    /// Remove packets from the beginning as long as they are before sequence_number
    /// and older than arrival_time_limit.
    ///
    /// Stops at the first packet, in sequence order, whose arrival time is after the limit,
    /// even if later ones are older. Packets not received are stored as `-1`, so they count as
    /// old for any limit of `-1` or more. The scan runs over at most two contiguous slices,
    /// eight values at a time ([`first_after`]).
    pub(crate) fn remove_old_packets(&mut self, sequence_number: i64, arrival_time_limit: i64) {
        let check_to = sequence_number.min(self.end_sequence_number);
        if self.begin_sequence_number < check_to {
            let len = (check_to - self.begin_sequence_number) as usize;
            let removed = self
                .position_after(self.begin_sequence_number, len, arrival_time_limit)
                .unwrap_or(len);
            self.begin_sequence_number += removed as i64;
        }
        self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
    }

    /// Check if a packet with the given sequence number has been received.
    pub(crate) fn has_received(&self, sequence_number: i64) -> bool {
        self.get(sequence_number) >= 0
    }

    /// Clamp sequence_number to [begin_sequence_number, end_sequence_number].
    pub(crate) fn clamp(&self, sequence_number: i64) -> i64 {
        sequence_number.clamp(self.begin_sequence_number, self.end_sequence_number)
    }

    fn get(&self, sequence_number: i64) -> i64 {
        if sequence_number < self.begin_sequence_number
            || sequence_number >= self.end_sequence_number
        {
            return -1;
        }
        self.arrival_times[self.index(sequence_number)]
    }

    fn index(&self, sequence_number: i64) -> usize {
        // Sequence number might be negative, and we always guarantee that arrival_times
        // length is a power of 2, so it's easier to use "&" instead of "%"
        (sequence_number & (self.capacity() as i64 - 1)) as usize
    }

    /// The slots of `len` consecutive sequence numbers from `start`, in sequence order: the run
    /// up to the end of the buffer, then the part that wraps to its front. `len` must not exceed
    /// the capacity.
    fn slices(&self, start: i64, len: usize) -> (&[i64], &[i64]) {
        debug_assert!(len <= self.capacity());
        let index = self.index(start);
        let head_len = len.min(self.capacity() - index);
        let (front, back) = self.arrival_times.split_at(index);
        (&back[..head_len], &front[..len - head_len])
    }

    /// [`Self::slices`], mutably.
    fn slices_mut(&mut self, start: i64, len: usize) -> (&mut [i64], &mut [i64]) {
        debug_assert!(len <= self.capacity());
        let index = self.index(start);
        let head_len = len.min(self.capacity() - index);
        let (front, back) = self.arrival_times.split_at_mut(index);
        (&mut back[..head_len], &mut front[..len - head_len])
    }

    /// The offset from `start` of the first of the `len` sequence numbers from `start`, in
    /// sequence order, whose stored arrival time is greater than `threshold`.
    ///
    /// All `len` numbers must lie in the window. The window never exceeds the capacity; if it
    /// did, the numbers past the first `capacity` would revisit the same slots, so one pass
    /// over the buffer decides the answer.
    fn position_after(&self, start: i64, len: usize, threshold: i64) -> Option<usize> {
        let (head, tail) = self.slices(start, len.min(self.capacity()));
        first_after(head, threshold)
            .or_else(|| first_after(tail, threshold).map(|offset| head.len() + offset))
    }

    fn adjust_to_size(&mut self, new_size: usize) {
        if new_size > self.capacity() {
            let mut new_capacity = self.capacity();
            while new_capacity < new_size {
                new_capacity *= 2;
            }
            self.reallocate(new_capacity);
        }
        if self.capacity() > MIN_CAPACITY.max(new_size * 4) {
            let mut new_capacity = self.capacity();
            while new_capacity >= 2 * new_size.max(MIN_CAPACITY) {
                new_capacity /= 2;
            }
            self.reallocate(new_capacity);
        }
    }

    fn capacity(&self) -> usize {
        self.arrival_times.len()
    }

    /// Moves the window's arrival times into a buffer of `new_capacity` slots (a power of
    /// two), leaving every other slot not received.
    ///
    /// Copies runs of consecutive sequence numbers that are contiguous in both the old and the
    /// new buffer — at most three, split where either buffer wraps — instead of indexing each
    /// sequence number twice.
    fn reallocate(&mut self, new_capacity: usize) {
        let mut new_buffer = vec![-1i64; new_capacity];
        let old_capacity = self.capacity();
        // The window always fits both buffers. If it did not fit the new one, the newest
        // `new_capacity` numbers would be the ones left in their slots; if it did not fit the
        // old one, it would re-read that buffer's slots cyclically. The copy below starts from
        // the newest `new_capacity` numbers and advances through the old buffer modulo its
        // capacity, so it stays exact either way.
        let mut sn = self
            .begin_sequence_number
            .max(self.end_sequence_number - new_capacity as i64);
        while sn < self.end_sequence_number {
            let old_index = self.index(sn);
            let new_index = (sn & (new_capacity as i64 - 1)) as usize;
            let run = ((self.end_sequence_number - sn) as usize)
                .min(old_capacity - old_index)
                .min(new_capacity - new_index);
            new_buffer[new_index..new_index + run]
                .copy_from_slice(&self.arrival_times[old_index..old_index + run]);
            sn += run as i64;
        }
        self.arrival_times = new_buffer;
    }
}

/// Values [`first_after`] checks one at a time before switching to vectors.
const SCALAR_PREFIX: usize = 8;

/// The index of the first value in `values` greater than `threshold`.
///
/// Without loss the answer is almost always among the first few values — `remove_old_packets`
/// runs for every received packet and usually stops at once — so the first [`SCALAR_PREFIX`]
/// are checked one at a time. Only a longer scan, typically a run of lost packets (`-1`s), goes
/// on to compare eight values per step as two `wide::i64x4` vectors, which compile to the
/// target's 64-bit lane comparisons (NEON on AArch64, SSE4.2 or AVX2 on x86-64 where enabled,
/// simd128 on WebAssembly) and to per-lane scalar code elsewhere; the block holding the first
/// match, and any tail shorter than a block, is then searched one value at a time. That skips a
/// long run about three times as fast as a scalar `position` on AArch64.
fn first_after(values: &[i64], threshold: i64) -> Option<usize> {
    let prefix = values.len().min(SCALAR_PREFIX);
    if let Some(index) = values[..prefix].iter().position(|&value| value > threshold) {
        return Some(index);
    }

    let limit = i64x4::splat(threshold);
    let (blocks, _) = values[prefix..].as_chunks::<8>();
    let mut skipped = prefix;
    for &[a, b, c, d, e, f, g, h] in blocks {
        let low = i64x4::new([a, b, c, d]).simd_gt(limit);
        let high = i64x4::new([e, f, g, h]).simd_gt(limit);
        if (low | high).any() {
            break;
        }
        skipped += 8;
    }
    values[skipped..]
        .iter()
        .position(|&value| value > threshold)
        .map(|offset| skipped + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The block search agrees with a plain scan for every length through three blocks and a
    /// tail, every position of the first match (or none), and values equal to, just above and
    /// far from the threshold, including the extremes of `i64`.
    #[test]
    fn test_first_after_matches_position() {
        for threshold in [-1, 0, 499_999, i64::MIN, i64::MAX - 1] {
            for len in 0..=27 {
                for hit in 0..=len {
                    for above in [threshold.saturating_add(1), i64::MAX] {
                        if above <= threshold {
                            continue;
                        }
                        let mut values: Vec<i64> = (0..len)
                            .map(|i| if i % 3 == 0 { threshold } else { i64::MIN })
                            .collect();
                        if hit < len {
                            values[hit] = above;
                            // Later matches must not be reported instead.
                            for later in values.iter_mut().skip(hit + 1).step_by(2) {
                                *later = above;
                            }
                        }
                        let expected = values.iter().position(|&value| value > threshold);
                        assert_eq!(
                            first_after(&values, threshold),
                            expected,
                            "{values:?} > {threshold}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_arrival_time_map_basic() {
        let mut map = PacketArrivalTimeMap::new();

        // Add first packet
        map.add_packet(0, 1000);
        assert!(map.has_received(0));
        assert!(!map.has_received(1));
        assert_eq!(map.begin_sequence_number(), 0);
        assert_eq!(map.end_sequence_number(), 1);
    }

    #[test]
    fn test_arrival_time_map_sequential() {
        let mut map = PacketArrivalTimeMap::new();

        for i in 0..10 {
            map.add_packet(i, i * 1000);
        }

        for i in 0..10 {
            assert!(map.has_received(i));
        }
        assert_eq!(map.begin_sequence_number(), 0);
        assert_eq!(map.end_sequence_number(), 10);
    }

    #[test]
    fn test_arrival_time_map_with_gaps() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(0, 1000);
        map.add_packet(5, 5000);

        assert!(map.has_received(0));
        assert!(!map.has_received(1));
        assert!(!map.has_received(2));
        assert!(!map.has_received(3));
        assert!(!map.has_received(4));
        assert!(map.has_received(5));
    }

    #[test]
    fn test_arrival_time_map_find_next() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(0, 1000);
        map.add_packet(5, 5000);
        map.add_packet(10, 10000);

        assert_eq!(map.find_next_at_or_after(0), Some((0, 1000)));
        assert_eq!(map.find_next_at_or_after(1), Some((5, 5000)));
        assert_eq!(map.find_next_at_or_after(5), Some((5, 5000)));
        assert_eq!(map.find_next_at_or_after(6), Some((10, 10000)));
        assert_eq!(map.find_next_at_or_after(11), None);
    }

    #[test]
    fn test_arrival_time_map_out_of_order() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(5, 5000);
        map.add_packet(3, 3000);
        map.add_packet(7, 7000);

        assert!(map.has_received(3));
        assert!(!map.has_received(4));
        assert!(map.has_received(5));
        assert!(!map.has_received(6));
        assert!(map.has_received(7));
    }

    #[test]
    fn test_arrival_time_map_remove_old() {
        let mut map = PacketArrivalTimeMap::new();

        for i in 0..10 {
            map.add_packet(i, i * 1000);
        }

        // Remove packets older than 5000 up to seq 7
        map.remove_old_packets(7, 5000);

        // Packets 0-5 should be removed (arrival time <= 5000)
        assert!(!map.has_received(0));
        assert!(!map.has_received(5));
        assert!(map.has_received(6));
        assert!(map.has_received(9));
    }

    #[test]
    fn test_arrival_time_map_clamp() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(5, 5000);
        map.add_packet(10, 10000);

        assert_eq!(map.clamp(0), 5);
        assert_eq!(map.clamp(7), 7);
        assert_eq!(map.clamp(100), 11);
    }

    /// The map as it was before its gap filling, reallocation and scans worked on contiguous
    /// slices: one circular index per sequence number. Kept as the reference the slice
    /// versions must match exactly, down to the contents of every slot.
    struct ReferenceMap {
        arrival_times: Vec<i64>,
        begin_sequence_number: i64,
        end_sequence_number: i64,
    }

    impl ReferenceMap {
        fn new() -> Self {
            Self {
                arrival_times: Vec::new(),
                begin_sequence_number: 0,
                end_sequence_number: 0,
            }
        }

        fn add_packet(&mut self, sequence_number: i64, arrival_time: i64) {
            if self.arrival_times.is_empty() {
                self.reallocate(MIN_CAPACITY);
                self.begin_sequence_number = sequence_number;
                self.end_sequence_number = sequence_number + 1;
                let idx = self.index(sequence_number);
                self.arrival_times[idx] = arrival_time;
                return;
            }

            if sequence_number >= self.begin_sequence_number
                && sequence_number < self.end_sequence_number
            {
                let idx = self.index(sequence_number);
                self.arrival_times[idx] = arrival_time;
                return;
            }

            if sequence_number < self.begin_sequence_number {
                let new_size = (self.end_sequence_number - sequence_number) as usize;
                if new_size > MAX_NUMBER_OF_PACKETS as usize {
                    return;
                }
                self.adjust_to_size(new_size);
                let idx = self.index(sequence_number);
                self.arrival_times[idx] = arrival_time;
                let begin = self.begin_sequence_number;
                self.set_not_received(sequence_number + 1, begin);
                self.begin_sequence_number = sequence_number;
                return;
            }

            let new_end_sequence_number = sequence_number + 1;

            if new_end_sequence_number >= self.end_sequence_number + MAX_NUMBER_OF_PACKETS {
                self.begin_sequence_number = sequence_number;
                self.end_sequence_number = new_end_sequence_number;
                let idx = self.index(sequence_number);
                self.arrival_times[idx] = arrival_time;
                return;
            }

            if self.begin_sequence_number < new_end_sequence_number - MAX_NUMBER_OF_PACKETS {
                self.begin_sequence_number = new_end_sequence_number - MAX_NUMBER_OF_PACKETS;
            }

            self.adjust_to_size((new_end_sequence_number - self.begin_sequence_number) as usize);

            let end = self.end_sequence_number;
            self.set_not_received(end, sequence_number);
            self.end_sequence_number = new_end_sequence_number;
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
        }

        fn set_not_received(&mut self, start_inclusive: i64, end_exclusive: i64) {
            for sn in start_inclusive..end_exclusive {
                let idx = self.index(sn);
                self.arrival_times[idx] = -1;
            }
        }

        fn find_next_at_or_after(&self, sequence_number: i64) -> Option<(i64, i64)> {
            let mut seq = self.clamp(sequence_number);
            while seq < self.end_sequence_number {
                let arrival_time = self.get(seq);
                if arrival_time >= 0 {
                    return Some((seq, arrival_time));
                }
                seq += 1;
            }
            None
        }

        fn erase_to(&mut self, sequence_number: i64) {
            if sequence_number < self.begin_sequence_number {
                return;
            }
            if sequence_number >= self.end_sequence_number {
                self.begin_sequence_number = self.end_sequence_number;
                return;
            }
            self.begin_sequence_number = sequence_number;
            self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
        }

        fn remove_old_packets(&mut self, sequence_number: i64, arrival_time_limit: i64) {
            let check_to = sequence_number.min(self.end_sequence_number);
            while self.begin_sequence_number < check_to
                && self.get(self.begin_sequence_number) <= arrival_time_limit
            {
                self.begin_sequence_number += 1;
            }
            self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
        }

        fn has_received(&self, sequence_number: i64) -> bool {
            self.get(sequence_number) >= 0
        }

        fn clamp(&self, sequence_number: i64) -> i64 {
            sequence_number.clamp(self.begin_sequence_number, self.end_sequence_number)
        }

        fn get(&self, sequence_number: i64) -> i64 {
            if sequence_number < self.begin_sequence_number
                || sequence_number >= self.end_sequence_number
            {
                return -1;
            }
            self.arrival_times[self.index(sequence_number)]
        }

        fn index(&self, sequence_number: i64) -> usize {
            (sequence_number & (self.capacity() as i64 - 1)) as usize
        }

        fn adjust_to_size(&mut self, new_size: usize) {
            if new_size > self.capacity() {
                let mut new_capacity = self.capacity();
                while new_capacity < new_size {
                    new_capacity *= 2;
                }
                self.reallocate(new_capacity);
            }
            if self.capacity() > MIN_CAPACITY.max(new_size * 4) {
                let mut new_capacity = self.capacity();
                while new_capacity >= 2 * new_size.max(MIN_CAPACITY) {
                    new_capacity /= 2;
                }
                self.reallocate(new_capacity);
            }
        }

        fn capacity(&self) -> usize {
            self.arrival_times.len()
        }

        fn reallocate(&mut self, new_capacity: usize) {
            let mut new_buffer = vec![-1i64; new_capacity];
            for sn in self.begin_sequence_number..self.end_sequence_number {
                let old_val = self.get(sn);
                new_buffer[(sn & (new_capacity as i64 - 1)) as usize] = old_val;
            }
            self.arrival_times = new_buffer;
        }
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> i64 {
            (self.next() % n) as i64
        }
    }

    fn assert_same(map: &PacketArrivalTimeMap, reference: &ReferenceMap, context: &str) {
        assert_eq!(
            map.begin_sequence_number, reference.begin_sequence_number,
            "begin, {context}"
        );
        assert_eq!(
            map.end_sequence_number, reference.end_sequence_number,
            "end, {context}"
        );
        // Every slot, not only the window: stale slots outside it must match too, since a
        // later gap or reallocation decides which of them survive.
        assert_eq!(
            map.arrival_times, reference.arrival_times,
            "slots, {context}"
        );
    }

    /// Random operation sequences give the same window, the same slot contents and the same
    /// answers as the per-sequence-number reference: in-order arrivals, gaps short and long,
    /// reordering into and before the window, jumps that reset it (`MAX_NUMBER_OF_PACKETS`
    /// ahead) or are refused (that far behind), negative and positive unwrapped sequence
    /// numbers, arrival times that are not in sequence order, removal of old packets with
    /// limits that stop early, erasures, and the growth and shrinking all of these cause.
    #[test]
    fn test_arrival_time_map_matches_reference() {
        let mut rng = XorShift(0x3c6e_f372_fe94_f82b);
        // Which paths the walk reached, checked at the end so the test cannot quietly stop
        // covering them.
        let (mut largest, mut shrunk, mut reset, mut refused, mut stopped_early) =
            (0, false, false, false, false);
        for run in 0..16 {
            let mut map = PacketArrivalTimeMap::new();
            let mut reference = ReferenceMap::new();
            let mut seq: i64 = match run % 3 {
                0 => 0,
                1 => -rng.below(1 << 20),
                _ => rng.below(1 << 40) - (1 << 39),
            };
            let mut time: i64 = rng.below(1 << 30);
            let max = MAX_NUMBER_OF_PACKETS;
            let steps = if run % 4 == 0 { 1_000 } else { 250 };
            for step in 0..steps {
                let begin = map.begin_sequence_number;
                let end = map.end_sequence_number;
                let capacity = map.capacity();
                let op = rng.below(100);
                let context = format!("run {run}, step {step}, op {op}, window {begin}..{end}");
                match op {
                    0..=74 => {
                        seq = match rng.below(100) {
                            0..=49 => end,
                            50..=64 => end + 1 + rng.below(40),
                            65..=74 => end - 1 - rng.below(64),
                            75..=79 => begin - 1 - rng.below(300),
                            // Long gaps: up to, at and past the retained window.
                            80..=87 => end + rng.below(max as u64 + 2),
                            88..=89 => end + max - 2 + rng.below(4),
                            90..=91 => begin - rng.below(max as u64 + 300),
                            92..=93 => end - max + rng.below(4),
                            _ => seq + rng.below(1 << 17) - (1 << 16),
                        };
                        time = match rng.below(10) {
                            // Not time-ordered.
                            0 => time - rng.below(100_000),
                            // Occasionally a stored time below zero other than -1.
                            1 => -rng.below(3) - 2,
                            _ => time.max(0) + rng.below(40_000),
                        };
                        map.add_packet(seq, time);
                        reference.add_packet(seq, time);
                        reset |= end - begin > 1
                            && map.end_sequence_number - map.begin_sequence_number == 1;
                        refused |= seq < begin && map.begin_sequence_number == begin;
                    }
                    75..=86 => {
                        let sequence_number = match rng.below(4) {
                            0 => end + rng.below(10),
                            1 => begin + rng.below((end - begin + 1) as u64),
                            2 => begin - rng.below(10),
                            _ => end - rng.below(max as u64),
                        };
                        let limit = match rng.below(5) {
                            0 => -2,
                            1 => -1,
                            2 => i64::MAX,
                            _ => time - rng.below(500_000),
                        };
                        map.remove_old_packets(sequence_number, limit);
                        reference.remove_old_packets(sequence_number, limit);
                        stopped_early |= map.begin_sequence_number > begin
                            && map.begin_sequence_number < sequence_number.min(end);
                    }
                    87..=89 => {
                        let sequence_number = begin + rng.below((end - begin + 2) as u64) - 1;
                        map.erase_to(sequence_number);
                        reference.erase_to(sequence_number);
                    }
                    _ => {
                        for _ in 0..4 {
                            let query = begin + rng.below((end - begin + 20) as u64) - 10;
                            assert_eq!(
                                map.find_next_at_or_after(query),
                                reference.find_next_at_or_after(query),
                                "find_next_at_or_after({query}), {context}"
                            );
                            assert_eq!(
                                map.has_received(query),
                                reference.has_received(query),
                                "{context}"
                            );
                        }
                    }
                }
                assert_same(&map, &reference, &context);
                let query = map.begin_sequence_number + rng.below(8);
                assert_eq!(
                    map.find_next_at_or_after(query),
                    reference.find_next_at_or_after(query),
                    "find_next_at_or_after({query}), {context}"
                );
                shrunk |= map.capacity() < capacity;
                largest = largest.max(map.capacity());
            }
        }
        assert_eq!(
            largest, MAX_NUMBER_OF_PACKETS as usize,
            "never grew to the maximum"
        );
        assert!(shrunk, "never shrank");
        assert!(reset, "never jumped past the retained window");
        assert!(refused, "never refused a packet too far behind");
        assert!(
            stopped_early,
            "remove_old_packets never stopped at a newer packet"
        );
    }

    /// `set_not_received` and `reallocate` match the reference for every placement of a range
    /// in the buffer: empty ranges, ranges that wrap and ranges that fill the whole capacity,
    /// at negative and positive sequence numbers, for capacities from the minimum to the
    /// maximum; and the scans match from arbitrary slot contents.
    #[test]
    fn test_arrival_time_map_kernels_match_reference_from_any_state() {
        let mut rng = XorShift(0xa54f_f53a_5f1d_36f1);
        let mut capacity = MIN_CAPACITY;
        while capacity <= MAX_NUMBER_OF_PACKETS as usize {
            for scenario in 0..24 {
                let slots: Vec<i64> = (0..capacity)
                    .map(|_| match scenario % 3 {
                        0 => -1,
                        1 => rng.below(1_000_000),
                        _ => {
                            if rng.below(8) == 0 {
                                rng.below(1_000_000)
                            } else {
                                -1
                            }
                        }
                    })
                    .collect();
                let base = rng.below(1 << 24) - (1 << 23);
                let len = match scenario % 6 {
                    0 => 0,
                    1 => capacity as i64,
                    2 => capacity as i64 - 1,
                    _ => rng.below(capacity as u64 + 1),
                };
                let begin = base;
                let end = base + len;
                let mut map = PacketArrivalTimeMap::new();
                let mut reference = ReferenceMap::new();
                map.arrival_times = slots.clone();
                reference.arrival_times = slots;
                map.begin_sequence_number = begin;
                reference.begin_sequence_number = begin;
                map.end_sequence_number = end;
                reference.end_sequence_number = end;
                let context = format!("capacity {capacity}, window {begin}..{end}");

                for _ in 0..6 {
                    let query = begin + rng.below(len as u64 + 4) - 2;
                    assert_eq!(
                        map.find_next_at_or_after(query),
                        reference.find_next_at_or_after(query),
                        "find_next_at_or_after({query}), {context}"
                    );
                }

                // Gaps anywhere in and around the window, up to the full capacity.
                let start = begin + rng.below(len as u64 + 1);
                let gap = match scenario % 4 {
                    0 => 0,
                    1 => capacity as i64,
                    _ => rng.below(capacity as u64 + 1),
                };
                map.set_not_received(start, start + gap);
                reference.set_not_received(start, start + gap);
                assert_same(&map, &reference, &format!("gap {start}+{gap}, {context}"));

                for new_capacity in [capacity / 2, capacity, capacity * 2, capacity * 4] {
                    if new_capacity < len as usize {
                        continue;
                    }
                    let mut map_copy = PacketArrivalTimeMap {
                        arrival_times: map.arrival_times.clone(),
                        begin_sequence_number: begin,
                        end_sequence_number: end,
                    };
                    let mut reference_copy = ReferenceMap {
                        arrival_times: reference.arrival_times.clone(),
                        begin_sequence_number: begin,
                        end_sequence_number: end,
                    };
                    map_copy.reallocate(new_capacity);
                    reference_copy.reallocate(new_capacity);
                    assert_same(
                        &map_copy,
                        &reference_copy,
                        &format!("reallocate to {new_capacity}, {context}"),
                    );
                }

                let limit = rng.below(1_000_000);
                let upto = begin + rng.below(len as u64 + 3);
                map.remove_old_packets(upto, limit);
                reference.remove_old_packets(upto, limit);
                assert_same(&map, &reference, &format!("remove to {upto}, {context}"));
            }
            capacity *= 2;
        }
    }
}
