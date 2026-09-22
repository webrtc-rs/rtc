//! Receive log for tracking received RTP packets and finding missing sequences.

use crate::bitmap;

/// Half of u16 max value, used for sequence number wraparound detection.
const UINT16_SIZE_HALF: u16 = 1 << 15;

/// Tracks received RTP packets using a bitmap and identifies missing sequence numbers.
///
/// The receive log uses a circular bitmap to track which sequence numbers have been
/// received. It can efficiently report missing sequence numbers for NACK generation.
pub(crate) struct ReceiveLog {
    /// Bitmap for tracking received packets. Each u64 tracks 64 packets.
    packets: Vec<u64>,
    /// Size of the tracking window (must be power of 2, minimum 64).
    size: u16,
    /// `size - 1`. `size` is a power of two, so packets are indexed with
    /// `& size_mask` instead of `% size`, avoiding a hardware division per
    /// received packet.
    size_mask: u16,
    /// Highest sequence number received.
    end: u16,
    /// Whether any packet has been received yet.
    started: bool,
    /// Last consecutive sequence number (no gaps before this).
    last_consecutive: u16,
}

impl ReceiveLog {
    /// Create a new receive log with the specified size.
    ///
    /// Size must be a power of 2 between 64 and 32768 (inclusive).
    /// Returns `None` if the size is invalid.
    pub(crate) fn new(size: u16) -> Option<Self> {
        // Valid sizes: 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
        let is_valid = (6..=15).any(|i| size == 1 << i);
        if !is_valid {
            return None;
        }

        Some(Self {
            packets: vec![0u64; (size / 64) as usize],
            size,
            size_mask: size - 1,
            end: 0,
            started: false,
            last_consecutive: 0,
        })
    }

    /// Add a received sequence number to the log.
    pub(crate) fn add(&mut self, seq: u16) {
        if !self.started {
            self.set_received(seq);
            self.end = seq;
            self.started = true;
            self.last_consecutive = seq;
            return;
        }

        let diff = seq.wrapping_sub(self.end);
        match diff {
            0 => {
                // Duplicate packet, ignore
                return;
            }
            d if d < UINT16_SIZE_HALF => {
                // Positive diff: seq > end (with wraparound handling)
                // Clear the bits of the skipped numbers `end + 1 .. seq`: they may hold a
                // receipt from a window ago. Word at a time, masking the partial edge words;
                // a gap at least as wide as the window covers every bit and clears the whole
                // bitmap (a jump can skip up to 32,767 numbers). A narrower gap leaves `seq`'s
                // own bit alone; either way it is set below, after `fix_last_consecutive` has
                // looked.
                bitmap::clear(
                    &mut self.packets,
                    self.end.wrapping_add(1) as usize,
                    (d - 1) as usize,
                );
                self.end = seq;

                if self.last_consecutive.wrapping_add(1) == seq {
                    self.last_consecutive = seq;
                } else if seq.wrapping_sub(self.last_consecutive) > self.size {
                    self.last_consecutive = seq.wrapping_sub(self.size);
                    self.fix_last_consecutive();
                }
            }
            _ => {
                // Negative diff: seq < end (out of order packet)
                if self.last_consecutive.wrapping_add(1) == seq {
                    self.last_consecutive = seq;
                    self.fix_last_consecutive();
                }
            }
        }

        self.set_received(seq);
    }

    /// Check if a sequence number has been received.
    pub(crate) fn get(&self, seq: u16) -> bool {
        let diff = self.end.wrapping_sub(seq);
        if diff >= UINT16_SIZE_HALF {
            return false;
        }
        if diff >= self.size {
            return false;
        }
        self.get_received(seq)
    }

    /// Get missing sequence numbers, optionally skipping the last N packets.
    ///
    /// Returns the sequence numbers from `last_consecutive + 1` through `end - skip_last_n`
    /// (inclusive, wrapping) whose bit is clear, in ascending sequence order.
    ///
    /// The bitmap is read a word at a time: received words are skipped with one compare and
    /// each missing bit is found with `trailing_zeros`. A span longer than the window re-reads
    /// the bitmap cyclically, reporting a clear bit once per pass, exactly as reading one
    /// sequence number at a time would.
    pub(crate) fn missing_seq_numbers(&self, skip_last_n: u16) -> Vec<u16> {
        let until = self.end.wrapping_sub(skip_last_n);

        // Check if until < last_consecutive (with wraparound)
        let span = until.wrapping_sub(self.last_consecutive);
        if span >= UINT16_SIZE_HALF {
            return Vec::new();
        }

        let first = self.last_consecutive.wrapping_add(1);
        let mut missing = Vec::new();
        bitmap::for_each_zero(&self.packets, first as usize, span as usize, |offset| {
            // `span` < 2^15, so every offset fits a sequence number.
            missing.push(first.wrapping_add(offset as u16));
        });

        missing
    }

    /// Whether `seq` is one [`Self::missing_seq_numbers`] would report for `skip_last_n`, in
    /// constant time.
    pub(crate) fn is_missing(&self, seq: u16, skip_last_n: u16) -> bool {
        let until = self.end.wrapping_sub(skip_last_n);
        let span = until.wrapping_sub(self.last_consecutive);
        if span >= UINT16_SIZE_HALF {
            return false;
        }
        // `missing_seq_numbers` walks `last_consecutive + 1 ..= until`.
        let offset = seq.wrapping_sub(self.last_consecutive);
        offset != 0 && offset <= span && !self.get_received(seq)
    }

    fn set_received(&mut self, seq: u16) {
        let pos = seq & self.size_mask;
        self.packets[(pos / 64) as usize] |= 1 << (pos % 64);
    }

    fn get_received(&self, seq: u16) -> bool {
        let pos = seq & self.size_mask;
        (self.packets[(pos / 64) as usize] & (1 << (pos % 64))) != 0
    }

    /// Advances `last_consecutive` over the received packets that follow it, stopping before
    /// the first missing one or at `end`.
    ///
    /// Searches a word at a time for the first clear bit after `last_consecutive`. Only one
    /// pass over the bitmap is needed even if `end` is further than the window: a pass with no
    /// clear bit means the cyclic re-reads would find none either.
    fn fix_last_consecutive(&mut self) {
        let first = self.last_consecutive.wrapping_add(1);
        let span = self.end.wrapping_sub(self.last_consecutive);
        self.last_consecutive =
            match bitmap::first_zero(&self.packets, first as usize, span as usize) {
                // The number before the first missing one.
                Some(offset) => self.last_consecutive.wrapping_add(offset as u16),
                None => self.end,
            };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receive_log_invalid_size() {
        assert!(ReceiveLog::new(5).is_none());
        assert!(ReceiveLog::new(32).is_none());
        assert!(ReceiveLog::new(100).is_none());
    }

    #[test]
    fn test_receive_log_valid_sizes() {
        assert!(ReceiveLog::new(64).is_some());
        assert!(ReceiveLog::new(128).is_some());
        assert!(ReceiveLog::new(256).is_some());
        assert!(ReceiveLog::new(512).is_some());
        assert!(ReceiveLog::new(1024).is_some());
        assert!(ReceiveLog::new(32768).is_some());
    }

    #[test]
    fn test_receive_log_basic() {
        let mut rl = ReceiveLog::new(128).unwrap();

        // Add first packet
        rl.add(0);
        assert!(rl.get(0));
        assert!(rl.missing_seq_numbers(0).is_empty());
        assert_eq!(rl.last_consecutive, 0);

        // Add consecutive packets
        for i in 1..=127 {
            rl.add(i);
        }
        assert!(rl.missing_seq_numbers(0).is_empty());
        assert_eq!(rl.last_consecutive, 127);

        // Add packet that wraps the buffer
        rl.add(128);
        assert!(rl.get(128));
        assert!(!rl.get(0)); // Old packet should be cleared
        assert!(rl.missing_seq_numbers(0).is_empty());
        assert_eq!(rl.last_consecutive, 128);
    }

    #[test]
    fn test_receive_log_with_gap() {
        let mut rl = ReceiveLog::new(128).unwrap();

        rl.add(0);
        rl.add(1);
        rl.add(128); // Skip 2-127, receive 128

        // Should report 127 missing packets (2-128 range, but only last 127 fit)
        let missing = rl.missing_seq_numbers(0);
        assert!(!missing.is_empty());
        assert!(missing.contains(&2) || !missing.is_empty());
    }

    #[test]
    fn test_receive_log_skip_last_n() {
        let mut rl = ReceiveLog::new(128).unwrap();

        rl.add(0);
        rl.add(5); // Gap: 1, 2, 3, 4

        let missing_all = rl.missing_seq_numbers(0);
        assert_eq!(missing_all, vec![1, 2, 3, 4]);

        // Skip last 2 means: until = end(5) - skip_last_n(2) = 3
        // Check from last_consecutive+1 (1) to until (3) inclusive
        let missing_skip_2 = rl.missing_seq_numbers(2);
        assert_eq!(missing_skip_2, vec![1, 2, 3]);
    }

    #[test]
    fn test_receive_log_out_of_order() {
        let mut rl = ReceiveLog::new(128).unwrap();

        rl.add(0);
        rl.add(3); // Gap: 1, 2
        assert_eq!(rl.missing_seq_numbers(0), vec![1, 2]);

        rl.add(1); // Fill gap partially
        assert_eq!(rl.missing_seq_numbers(0), vec![2]);
        assert_eq!(rl.last_consecutive, 1);

        rl.add(2); // Fill remaining gap
        assert!(rl.missing_seq_numbers(0).is_empty());
        assert_eq!(rl.last_consecutive, 3);
    }

    #[test]
    fn test_receive_log_wraparound() {
        let mut rl = ReceiveLog::new(128).unwrap();

        // Start near wraparound point
        rl.add(65534);
        assert_eq!(rl.last_consecutive, 65534);

        rl.add(65535);
        assert_eq!(rl.last_consecutive, 65535);

        rl.add(0); // Wrap to 0
        assert_eq!(rl.last_consecutive, 0);

        rl.add(2); // Gap at 1
        let missing = rl.missing_seq_numbers(0);
        assert_eq!(missing, vec![1]);
    }

    // Port of pion's TestReceivedBuffer with various start points
    #[test]
    fn test_receive_log_pion_compat() {
        for start in [
            0u16, 1, 127, 128, 129, 511, 512, 513, 32767, 32768, 65534, 65535,
        ] {
            let mut rl = ReceiveLog::new(128).unwrap();

            // Add first packet
            rl.add(start);
            assert!(rl.get(start));
            assert!(rl.missing_seq_numbers(0).is_empty());
            assert_eq!(rl.last_consecutive, start);

            // Add consecutive packets 1-127
            for i in 1..=127u16 {
                rl.add(start.wrapping_add(i));
            }
            assert!(rl.missing_seq_numbers(0).is_empty());
            assert_eq!(rl.last_consecutive, start.wrapping_add(127));

            // Add packet 128 (wraps buffer)
            rl.add(start.wrapping_add(128));
            assert!(rl.get(start.wrapping_add(128)));
            assert!(!rl.get(start)); // Should be cleared
            assert!(rl.missing_seq_numbers(0).is_empty());
            assert_eq!(rl.last_consecutive, start.wrapping_add(128));

            // Add packet 130 (gap at 129)
            rl.add(start.wrapping_add(130));
            assert!(rl.get(start.wrapping_add(130)));
            let missing = rl.missing_seq_numbers(0);
            assert_eq!(missing, vec![start.wrapping_add(129)]);
            assert_eq!(rl.last_consecutive, start.wrapping_add(128));
        }
    }

    /// `is_missing` answers exactly the membership question `missing_seq_numbers` implies, for
    /// every sequence number, across loss, reordering, a large jump and the wrap.
    #[test]
    fn test_receive_log_is_missing_matches_missing_seq_numbers() {
        let mut log = ReceiveLog::new(128).unwrap();
        let arrivals = [
            65_500u16, 65_501, 65_503, 65_510, 65_502, 65_535, 3, 7, 6, 20, 500, 505, 501,
        ];
        for &seq in &arrivals {
            log.add(seq);
            for skip_last_n in [0, 2, 5] {
                let missing = log.missing_seq_numbers(skip_last_n);
                for candidate in 0..=u16::MAX {
                    assert_eq!(
                        log.is_missing(candidate, skip_last_n),
                        missing.contains(&candidate),
                        "seq {candidate} after adding {seq}, skip_last_n {skip_last_n}"
                    );
                }
            }
        }
    }

    /// Clearing the whole bitmap for a jump wider than the window leaves exactly what clearing
    /// each skipped number would.
    #[test]
    fn test_receive_log_large_jump_clears_the_window() {
        let mut log = ReceiveLog::new(64).unwrap();
        for seq in 0..64 {
            log.add(seq);
        }
        log.add(10_000);
        for seq in 10_000u16 - 63..10_000 {
            assert!(!log.get(seq), "{seq} was never received");
        }
        assert!(log.get(10_000));
        assert!(!log.get(0), "outside the window");
    }

    /// The per-bit implementation that `add`, `missing_seq_numbers` and
    /// `fix_last_consecutive` had before they worked a word at a time, kept as the reference
    /// the word versions must match exactly.
    struct ReferenceLog {
        packets: Vec<u64>,
        size: u16,
        size_mask: u16,
        end: u16,
        started: bool,
        last_consecutive: u16,
    }

    impl ReferenceLog {
        fn new(size: u16) -> Self {
            Self {
                packets: vec![0u64; (size / 64) as usize],
                size,
                size_mask: size - 1,
                end: 0,
                started: false,
                last_consecutive: 0,
            }
        }

        fn add(&mut self, seq: u16) {
            if !self.started {
                self.set_received(seq);
                self.end = seq;
                self.started = true;
                self.last_consecutive = seq;
                return;
            }

            let diff = seq.wrapping_sub(self.end);
            match diff {
                0 => return,
                d if d < UINT16_SIZE_HALF => {
                    if d > self.size {
                        self.packets.fill(0);
                    } else {
                        let mut i = self.end.wrapping_add(1);
                        while i != seq {
                            self.del_received(i);
                            i = i.wrapping_add(1);
                        }
                    }
                    self.end = seq;

                    if self.last_consecutive.wrapping_add(1) == seq {
                        self.last_consecutive = seq;
                    } else if seq.wrapping_sub(self.last_consecutive) > self.size {
                        self.last_consecutive = seq.wrapping_sub(self.size);
                        self.fix_last_consecutive();
                    }
                }
                _ => {
                    if self.last_consecutive.wrapping_add(1) == seq {
                        self.last_consecutive = seq;
                        self.fix_last_consecutive();
                    }
                }
            }

            self.set_received(seq);
        }

        fn missing_seq_numbers(&self, skip_last_n: u16) -> Vec<u16> {
            let until = self.end.wrapping_sub(skip_last_n);
            if until.wrapping_sub(self.last_consecutive) >= UINT16_SIZE_HALF {
                return Vec::new();
            }
            let mut missing = Vec::new();
            let mut i = self.last_consecutive.wrapping_add(1);
            while i != until.wrapping_add(1) {
                if !self.get_received(i) {
                    missing.push(i);
                }
                i = i.wrapping_add(1);
            }
            missing
        }

        fn set_received(&mut self, seq: u16) {
            let pos = seq & self.size_mask;
            self.packets[(pos / 64) as usize] |= 1 << (pos % 64);
        }

        fn del_received(&mut self, seq: u16) {
            let pos = seq & self.size_mask;
            self.packets[(pos / 64) as usize] &= !(1u64 << (pos % 64));
        }

        fn get_received(&self, seq: u16) -> bool {
            let pos = seq & self.size_mask;
            (self.packets[(pos / 64) as usize] & (1 << (pos % 64))) != 0
        }

        fn fix_last_consecutive(&mut self) {
            let mut i = self.last_consecutive.wrapping_add(1);
            while i != self.end.wrapping_add(1) && self.get_received(i) {
                i = i.wrapping_add(1);
            }
            self.last_consecutive = i.wrapping_sub(1);
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

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    const SIZES: [u16; 10] = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

    fn assert_same(log: &ReceiveLog, reference: &ReferenceLog, context: &str) {
        assert_eq!(log.packets, reference.packets, "bitmap, {context}");
        assert_eq!(log.end, reference.end, "end, {context}");
        assert_eq!(log.started, reference.started, "started, {context}");
        assert_eq!(
            log.last_consecutive, reference.last_consecutive,
            "last_consecutive, {context}"
        );
    }

    /// Random arrival sequences for every window size give the same bitmap, `end`,
    /// `last_consecutive` and missing lists as the per-bit implementation: in-order runs,
    /// losses, reordering, duplicates, jumps just short of, equal to and past the window, jumps
    /// of up to half the sequence space, arrivals from anywhere, and sequence wraparound.
    #[test]
    fn test_receive_log_matches_per_bit_reference() {
        let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
        for size in SIZES {
            for run in 0..4 {
                let mut log = ReceiveLog::new(size).unwrap();
                let mut reference = ReferenceLog::new(size);
                // Start near the wrap in some runs so it is crossed early.
                let mut last = if run % 2 == 0 {
                    0u16.wrapping_sub(rng.below(3 * size as u64) as u16)
                } else {
                    rng.next() as u16
                };
                let steps = if size <= 1024 { 400 } else { 100 };
                for step in 0..steps {
                    let base = if rng.below(2) == 0 { last } else { log.end };
                    let seq = match rng.below(100) {
                        0..=54 => base.wrapping_add(1),
                        55..=69 => base.wrapping_add(2 + rng.below(6) as u16),
                        // Reordered or duplicate (offset 0).
                        70..=81 => base.wrapping_sub(rng.below(24) as u16),
                        // A jump of about one window: size - 1, size or size + 1.
                        82..=87 => base.wrapping_add(size - 1 + rng.below(3) as u16),
                        88..=91 => base.wrapping_add(rng.below(0x8000) as u16),
                        92..=95 => base.wrapping_sub(rng.below(size as u64) as u16),
                        _ => rng.next() as u16,
                    };
                    last = seq;
                    log.add(seq);
                    reference.add(seq);
                    let context = format!("size {size}, run {run}, step {step}, seq {seq}");
                    assert_same(&log, &reference, &context);
                    for skip_last_n in [0, 1 + rng.below(8) as u16, rng.next() as u16] {
                        assert_eq!(
                            log.missing_seq_numbers(skip_last_n),
                            reference.missing_seq_numbers(skip_last_n),
                            "missing, skip_last_n {skip_last_n}, {context}"
                        );
                    }
                }
            }
        }
    }

    /// `missing_seq_numbers`, `fix_last_consecutive` and `add` match the reference from
    /// arbitrary states, not only those a random walk happens to reach: any bitmap, any `end`
    /// and `last_consecutive` — including `last_consecutive` exactly a window behind `end`,
    /// spans many times the window, which re-read the bitmap cyclically, and
    /// `last_consecutive` ahead of `end` — followed by one arrival at every kind of distance.
    #[test]
    fn test_receive_log_scans_match_reference_from_any_state() {
        let mut rng = XorShift(0xd1b5_4a32_d192_ed03);
        for size in SIZES {
            for scenario in 0..40 {
                let packets: Vec<u64> = (0..size / 64)
                    .map(|_| match scenario % 5 {
                        0 => 0,
                        1 => u64::MAX,
                        2 => rng.next(),
                        3 => rng.next() | rng.next() | rng.next(),
                        _ => !(1 << rng.below(64)),
                    })
                    .collect();
                let end = rng.next() as u16;
                let last_consecutive = match rng.below(6) {
                    0 => end.wrapping_sub(size),
                    1 => end.wrapping_sub(size - 1),
                    2 => end.wrapping_sub(rng.below(size as u64 + 1) as u16),
                    3 => end.wrapping_sub(rng.below(0x8000) as u16),
                    4 => end,
                    _ => rng.next() as u16,
                };
                let mut log = ReceiveLog::new(size).unwrap();
                let mut reference = ReferenceLog::new(size);
                log.packets = packets.clone();
                reference.packets = packets;
                log.end = end;
                reference.end = end;
                log.started = true;
                reference.started = true;
                log.last_consecutive = last_consecutive;
                reference.last_consecutive = last_consecutive;

                let context =
                    format!("size {size}, end {end}, last_consecutive {last_consecutive}");
                for skip_last_n in [0, 1, 2, 5, size - 1, size, rng.next() as u16] {
                    assert_eq!(
                        log.missing_seq_numbers(skip_last_n),
                        reference.missing_seq_numbers(skip_last_n),
                        "missing, skip_last_n {skip_last_n}, {context}"
                    );
                }
                let arrivals = [
                    end,
                    end.wrapping_add(1),
                    end.wrapping_add(2),
                    end.wrapping_add(1 + rng.below(size as u64) as u16),
                    end.wrapping_add(size - 1),
                    end.wrapping_add(size),
                    end.wrapping_add(size + 1),
                    end.wrapping_add(rng.below(0x8000) as u16),
                    end.wrapping_sub(1 + rng.below(size as u64) as u16),
                    last_consecutive.wrapping_add(1),
                    rng.next() as u16,
                ];
                for seq in arrivals {
                    let mut log = ReceiveLog {
                        packets: log.packets.clone(),
                        ..log
                    };
                    let mut reference = ReferenceLog {
                        packets: reference.packets.clone(),
                        ..reference
                    };
                    log.add(seq);
                    reference.add(seq);
                    assert_same(&log, &reference, &format!("add {seq}, {context}"));
                }

                log.fix_last_consecutive();
                reference.fix_last_consecutive();
                assert_same(&log, &reference, &context);
            }
        }
    }
}
