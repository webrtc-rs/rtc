use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Sequencer generates sequential sequence numbers for building RTP packets
pub trait Sequencer: Send + Sync + fmt::Debug {
    /// Returns the next sequence number, wrapping at `u16::MAX` and counting the rollover.
    fn next_sequence_number(&self) -> u16;
    /// How many times the sequence number has wrapped.
    ///
    /// SRTP needs this: the rollover counter is part of the packet index it encrypts with.
    fn roll_over_count(&self) -> u64;
    /// Clones this sequencer behind a trait object.
    fn clone_to(&self) -> Box<dyn Sequencer>;
}

impl Clone for Box<dyn Sequencer> {
    fn clone(&self) -> Box<dyn Sequencer> {
        self.clone_to()
    }
}

/// NewRandomSequencer returns a new sequencer starting from a random sequence
/// number
///
/// The initial value is drawn from only half the sequence-number space (below
/// `1 << 15 - 1`, pion's `maxInitialRandomSequenceNumber`): starting near the
/// rollover with packet loss breaks SRTP decryption, because the receiver
/// cannot tell which side of the wrap the first packets belong to.
pub fn new_random_sequencer() -> impl Sequencer {
    let c = Counters {
        sequence_number: Arc::new(AtomicU16::new(rand::random_range(0..(1 << 15) - 1))),
        roll_over_count: Arc::new(AtomicU64::new(0)),
    };
    SequencerImpl(c)
}

/// NewFixedSequencer returns a new sequencer starting from a specific
/// sequence number
pub fn new_fixed_sequencer(s: u16) -> impl Sequencer {
    let sequence_number = if s == 0 { u16::MAX } else { s - 1 };

    let c = Counters {
        sequence_number: Arc::new(AtomicU16::new(sequence_number)),
        roll_over_count: Arc::new(AtomicU64::new(0)),
    };

    SequencerImpl(c)
}

#[derive(Debug, Clone)]
struct SequencerImpl(Counters);

#[derive(Debug, Clone)]
struct Counters {
    sequence_number: Arc<AtomicU16>,
    roll_over_count: Arc<AtomicU64>,
}

impl Sequencer for SequencerImpl {
    /// NextSequenceNumber increment and returns a new sequence number for
    /// building RTP packets
    fn next_sequence_number(&self) -> u16 {
        if self.0.sequence_number.load(Ordering::SeqCst) == u16::MAX {
            self.0.roll_over_count.fetch_add(1, Ordering::SeqCst);
            self.0.sequence_number.store(0, Ordering::SeqCst);
            0
        } else {
            self.0.sequence_number.fetch_add(1, Ordering::SeqCst) + 1
        }
    }

    /// RollOverCount returns the amount of times the 16bit sequence number
    /// has wrapped
    fn roll_over_count(&self) -> u64 {
        self.0.roll_over_count.load(Ordering::SeqCst)
    }

    fn clone_to(&self) -> Box<dyn Sequencer> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod sequencer_test {
    use super::*;
    use std::collections::HashSet;

    // pion TestSequencerBasic.
    #[test]
    fn test_sequencer_basic() {
        let sequencer = new_fixed_sequencer(1);
        assert_eq!(1, sequencer.next_sequence_number());
        assert_eq!(0, sequencer.roll_over_count());
    }

    // pion TestSequencerWrapAround.
    #[test]
    fn test_sequencer_wrap_around() {
        let sequencer = new_fixed_sequencer(65535);
        assert_eq!(65535, sequencer.next_sequence_number());
        assert_eq!(0, sequencer.next_sequence_number());
        assert_eq!(1, sequencer.roll_over_count());
        assert_eq!(1, sequencer.next_sequence_number());
    }

    // pion TestSequencerMultipleRollovers.
    #[test]
    fn test_sequencer_multiple_rollovers() {
        let sequencer = new_fixed_sequencer(65535);
        sequencer.next_sequence_number();
        sequencer.next_sequence_number();
        assert_eq!(1, sequencer.roll_over_count());

        for _ in 0..65536 {
            sequencer.next_sequence_number();
        }

        assert_eq!(2, sequencer.roll_over_count());
    }

    // pion TestRandomSequencer: the random start stays in the lower half of
    // the sequence-number space (pion asserts < 1<<15-1; the intent — half the
    // space — is that the first number stays below 1<<15).
    #[test]
    fn test_random_sequencer() {
        let sequencer1 = new_random_sequencer();
        let sequencer2 = new_random_sequencer();
        assert!((1 << 15) > sequencer1.next_sequence_number());
        assert!((1 << 15) > sequencer2.next_sequence_number());
    }

    // pion TestSequencerConcurrent: 100 threads drawing 100 numbers each see
    // every number exactly once (pion uses 100 goroutines).
    #[test]
    fn test_sequencer_concurrent() {
        use std::sync::Arc as Shared;

        let sequencer = Shared::new(new_fixed_sequencer(1));
        const THREADS: usize = 16;
        const ITERATIONS: usize = 1000;

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let sequencer = Shared::clone(&sequencer);
                std::thread::spawn(move || {
                    (0..ITERATIONS)
                        .map(|_| sequencer.next_sequence_number())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut seen = HashSet::new();
        for handle in handles {
            for sequence_number in handle.join().expect("thread panics") {
                assert!(seen.insert(sequence_number), "duplicate {sequence_number}");
            }
        }
        assert_eq!(THREADS * ITERATIONS, seen.len());
    }

    // pion TestSequencerRollOverCountDuringWrap.
    #[test]
    fn test_sequencer_roll_over_count_during_wrap() {
        let sequencer = new_fixed_sequencer(65535);
        sequencer.next_sequence_number();
        assert_eq!(0, sequencer.roll_over_count());
        sequencer.next_sequence_number();
        assert_eq!(1, sequencer.roll_over_count());
    }
}
