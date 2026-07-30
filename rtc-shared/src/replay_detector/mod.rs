mod fixed_big_int;
#[cfg(test)]
mod replay_detector_test;

use fixed_big_int::*;

// ReplayDetector is the interface of sequence replay detector.
/// Tracks which sequence numbers have already been seen, so replayed packets can be dropped.
///
/// Both DTLS and SRTP require this: an attacker who captures a packet must not be able to
/// have it accepted a second time.
pub trait ReplayDetector: Send + Sync {
    /// Returns `true` if `seq` has not been seen before and is inside the window.
    ///
    /// This only tests; call [`Self::accept`] afterwards to record the packet as received.
    fn check(&mut self, seq: u64) -> bool;
    /// Commits the sequence number from the preceding [`Self::check`] call as received.
    ///
    /// Split from `check` so a caller can validate a packet's authenticity first and only then
    /// record it — a forged packet must not advance the window.
    fn accept(&mut self);
}

/// A replay detector over a monotonically increasing sequence number that never wraps.
///
/// Handles the full 64-bit range, which is what DTLS needs. See
/// [`WrappedSlidingWindowDetector`] for sequence numbers that do wrap.
pub struct SlidingWindowDetector {
    accepted: bool,
    seq: u64,
    latest_seq: u64,
    max_seq: u64,
    window_size: usize,
    mask: FixedBigInt,
}

impl SlidingWindowDetector {
    /// Creates a detector with a `window_size`-wide window over sequence numbers up to
    /// `max_seq`.
    ///
    /// Does not allow wrapping: it handles monotonically increasing sequence numbers across
    /// the full 64-bit range, which is what DTLS replay protection needs.
    pub fn new(window_size: usize, max_seq: u64) -> Self {
        SlidingWindowDetector {
            accepted: false,
            seq: 0,
            latest_seq: 0,
            max_seq,
            window_size,
            mask: FixedBigInt::new(window_size),
        }
    }
}

impl ReplayDetector for SlidingWindowDetector {
    fn check(&mut self, seq: u64) -> bool {
        self.accepted = false;

        if seq > self.max_seq {
            // Exceeded upper limit.
            return false;
        }

        if seq <= self.latest_seq {
            if self.latest_seq >= self.window_size as u64 + seq {
                return false;
            }
            if self.mask.bit((self.latest_seq - seq) as usize) != 0 {
                // The sequence number is duplicated.
                return false;
            }
        }

        self.accepted = true;
        self.seq = seq;
        true
    }

    fn accept(&mut self) {
        if !self.accepted {
            return;
        }

        if self.seq > self.latest_seq {
            // Update the head of the window.
            self.mask.lsh((self.seq - self.latest_seq) as usize);
            self.latest_seq = self.seq;
        }
        let diff = (self.latest_seq - self.seq) % self.max_seq;
        self.mask.set_bit(diff as usize);
    }
}

/// A replay detector for a sequence number that wraps at a known maximum.
///
/// SRTP's 16-bit sequence numbers wrap, so the window has to interpret a large backwards
/// jump as a rollover rather than a replay.
pub struct WrappedSlidingWindowDetector {
    accepted: bool,
    seq: u64,
    latest_seq: u64,
    max_seq: u64,
    window_size: usize,
    mask: FixedBigInt,
    init: bool,
}

impl WrappedSlidingWindowDetector {
    /// Creates a detector with a `window_size`-wide window that allows the sequence number to
    /// wrap at `max_seq`.
    ///
    /// Suitable for the short counters used by SRTP and SRTCP.
    pub fn new(window_size: usize, max_seq: u64) -> Self {
        WrappedSlidingWindowDetector {
            accepted: false,
            seq: 0,
            latest_seq: 0,
            max_seq,
            window_size,
            mask: FixedBigInt::new(window_size),
            init: false,
        }
    }
}

impl ReplayDetector for WrappedSlidingWindowDetector {
    fn check(&mut self, seq: u64) -> bool {
        self.accepted = false;

        if seq > self.max_seq {
            // Exceeded upper limit.
            return false;
        }
        if !self.init {
            if seq != 0 {
                self.latest_seq = seq - 1;
            } else {
                self.latest_seq = self.max_seq;
            }
            self.init = true;
        }

        let mut diff = self.latest_seq as i64 - seq as i64;
        // Wrap the number.
        if diff > self.max_seq as i64 / 2 {
            diff -= (self.max_seq + 1) as i64;
        } else if diff <= -(self.max_seq as i64 / 2) {
            diff += (self.max_seq + 1) as i64;
        }

        if diff >= self.window_size as i64 {
            // Too old.
            return false;
        }
        if diff >= 0 && self.mask.bit(diff as usize) != 0 {
            // The sequence number is duplicated.
            return false;
        }

        self.accepted = true;
        self.seq = seq;
        true
    }

    fn accept(&mut self) {
        if !self.accepted {
            return;
        }

        let mut diff = self.latest_seq as i64 - self.seq as i64;
        // Wrap the number.
        if diff > self.max_seq as i64 / 2 {
            diff -= (self.max_seq + 1) as i64;
        } else if diff <= -(self.max_seq as i64 / 2) {
            diff += (self.max_seq + 1) as i64;
        }

        assert!(diff < self.window_size as i64);

        if diff < 0 {
            // Update the head of the window.
            self.mask.lsh((-diff) as usize);
            self.latest_seq = self.seq;
            self.mask.set_bit(0);
        } else {
            self.mask.set_bit(diff as usize);
        }
    }
}

#[derive(Default)]
/// A detector that accepts everything.
///
/// For contexts where replay protection is disabled or handled elsewhere.
pub struct NoOpReplayDetector;

impl ReplayDetector for NoOpReplayDetector {
    fn check(&mut self, _: u64) -> bool {
        true
    }
    fn accept(&mut self) {}
}
