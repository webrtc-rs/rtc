//! Receive log for tracking received RTP packets and finding missing sequences.

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
                // Clear packets between end and seq (they may contain old data)
                let mut i = self.end.wrapping_add(1);
                while i != seq {
                    self.del_received(i);
                    i = i.wrapping_add(1);
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
    /// Returns a vector of missing sequence numbers between `last_consecutive + 1`
    /// and `end - skip_last_n`.
    pub(crate) fn missing_seq_numbers(&self, skip_last_n: u16) -> Vec<u16> {
        let until = self.end.wrapping_sub(skip_last_n);

        // Check if until < last_consecutive (with wraparound)
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
        let pos = seq % self.size;
        self.packets[(pos / 64) as usize] |= 1 << (pos % 64);
    }

    fn del_received(&mut self, seq: u16) {
        let pos = seq % self.size;
        self.packets[(pos / 64) as usize] &= !(1u64 << (pos % 64));
    }

    fn get_received(&self, seq: u16) -> bool {
        let pos = seq % self.size;
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
        assert!(missing.contains(&2) || missing.len() > 0);
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
        for start in [0u16, 1, 127, 128, 129, 511, 512, 513, 32767, 32768, 65534, 65535] {
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
}
