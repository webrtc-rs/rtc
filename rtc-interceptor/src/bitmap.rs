//! Word-at-a-time operations on circular receipt bitmaps.
//!
//! The NACK receive log and the receiver-report stream each keep one bit per RTP sequence
//! number in a `[u64]` whose bit capacity is a power of two, with `seq` at bit
//! `seq & (capacity - 1)`. A run of sequence numbers is therefore a *circular* range of bits:
//! it starts anywhere, may wrap past the end of the buffer, and — when it is longer than the
//! capacity — comes round again and re-reads bits it has already visited.
//!
//! These helpers take such a range as a start bit (any value; it is reduced modulo the
//! capacity) and a length in bits. They split it at the wrap into linear segments and process
//! each segment a word at a time: the partial first and last words are masked, and the full
//! words in between are handled whole — `count_zeros` for counting, `trailing_zeros` plus
//! `w &= w - 1` for enumerating, `fill(0)` for clearing. The results are exactly what walking
//! the range one bit at a time gives, cyclic re-reads included, because that is what the
//! callers' per-bit loops did and what their tests compare against.
//!
//! This is portable scalar code, not explicit SIMD. The full-word popcount sum is the one loop
//! worth vectorizing, and LLVM does that on its own (NEON `cnt.16b` plus a vector reduction on
//! AArch64); the enumeration is dominated by skipping words with no missing packet, which is
//! one compare per 64 sequence numbers.

use std::ops::ControlFlow;

/// Bits per bitmap word.
const WORD_BITS: usize = u64::BITS as usize;

/// Splits the circular range of `len` bits starting at bit `start` into linear segments and
/// calls `f(segment_start, segment_len, offset)` for each, in range order, where `offset` is
/// the segment's distance from the start of the range. Stops early on `Break`.
///
/// A range longer than the capacity yields more than two segments, the later ones re-covering
/// bits already visited. `words` must be non-empty with a power-of-two bit count.
#[inline]
fn for_each_segment<B>(
    words: usize,
    start: usize,
    len: usize,
    mut f: impl FnMut(usize, usize, usize) -> ControlFlow<B>,
) -> ControlFlow<B> {
    let capacity = words * WORD_BITS;
    debug_assert!(capacity.is_power_of_two());
    let mut bit = start & (capacity - 1);
    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(capacity - bit);
        f(bit, n, offset)?;
        offset += n;
        bit = 0;
    }
    ControlFlow::Continue(())
}

/// Calls `f(word_index, mask)` for each word overlapping the linear bit range
/// `start..start + len` (`len >= 1`), with `mask` selecting the range's bits in that word.
#[inline]
fn for_each_word<B>(
    start: usize,
    len: usize,
    mut f: impl FnMut(usize, u64) -> ControlFlow<B>,
) -> ControlFlow<B> {
    debug_assert!(len >= 1);
    let end = start + len;
    let first = start / WORD_BITS;
    let last = (end - 1) / WORD_BITS;
    let head = u64::MAX << (start % WORD_BITS);
    let tail = u64::MAX >> (WORD_BITS - 1 - (end - 1) % WORD_BITS);
    if first == last {
        return f(first, head & tail);
    }
    f(first, head)?;
    for word in first + 1..last {
        f(word, u64::MAX)?;
    }
    f(last, tail)
}

/// Number of clear bits in the circular range of `len` bits starting at bit `start`.
///
/// Bits are counted once per visit, so a range longer than the capacity counts the bits it
/// re-reads again, as a per-bit walk would.
pub(crate) fn count_zeros(words: &[u64], start: usize, len: usize) -> u32 {
    let mut zeros = 0;
    let _ = for_each_segment::<()>(words.len(), start, len, |start, len, _| {
        zeros += count_zeros_linear(words, start, len);
        ControlFlow::Continue(())
    });
    zeros
}

/// [`count_zeros`] for a range that does not wrap, `len >= 1`.
#[inline]
fn count_zeros_linear(words: &[u64], start: usize, len: usize) -> u32 {
    let end = start + len;
    let first = start / WORD_BITS;
    let last = (end - 1) / WORD_BITS;
    let head = u64::MAX << (start % WORD_BITS);
    let tail = u64::MAX >> (WORD_BITS - 1 - (end - 1) % WORD_BITS);
    if first == last {
        return (!words[first] & head & tail).count_ones();
    }
    // The full words are a plain reduction, which LLVM vectorizes.
    (!words[first] & head).count_ones()
        + words[first + 1..last]
            .iter()
            .map(|word| word.count_zeros())
            .sum::<u32>()
        + (!words[last] & tail).count_ones()
}

/// Calls `f(offset)` for each clear bit in the circular range of `len` bits starting at bit
/// `start`, in range order, where `offset` is the bit's distance from the start of the range.
///
/// A range longer than the capacity reports the bits it re-reads again, at their later offsets.
pub(crate) fn for_each_zero(words: &[u64], start: usize, len: usize, mut f: impl FnMut(usize)) {
    let _ = for_each_segment::<()>(words.len(), start, len, |start, len, offset| {
        for_each_word::<()>(start, len, |word, mask| {
            let mut zeros = !words[word] & mask;
            while zeros != 0 {
                let bit = word * WORD_BITS + zeros.trailing_zeros() as usize;
                f(offset + (bit - start));
                zeros &= zeros - 1;
            }
            ControlFlow::Continue(())
        })
    });
}

/// The offset of the first clear bit in the circular range of `len` bits starting at bit
/// `start`, if there is one.
///
/// A range longer than the capacity is searched only once round: if a full pass finds no clear
/// bit, re-reading the same bits will not find one either.
pub(crate) fn first_zero(words: &[u64], start: usize, len: usize) -> Option<usize> {
    let len = len.min(words.len() * WORD_BITS);
    let found = for_each_segment(words.len(), start, len, |start, len, offset| {
        for_each_word(start, len, |word, mask| {
            let zeros = !words[word] & mask;
            if zeros == 0 {
                return ControlFlow::Continue(());
            }
            let bit = word * WORD_BITS + zeros.trailing_zeros() as usize;
            ControlFlow::Break(offset + (bit - start))
        })
    });
    match found {
        ControlFlow::Break(offset) => Some(offset),
        ControlFlow::Continue(()) => None,
    }
}

/// Clears the circular range of `len` bits starting at bit `start`.
///
/// A range at least as long as the capacity covers every bit, so the whole bitmap is cleared.
pub(crate) fn clear(words: &mut [u64], start: usize, len: usize) {
    if len >= words.len() * WORD_BITS {
        words.fill(0);
        return;
    }
    let _ = for_each_segment::<()>(words.len(), start, len, |start, len, _| {
        clear_linear(words, start, len);
        ControlFlow::Continue(())
    });
}

/// [`clear`] for a range that does not wrap, `len >= 1`.
#[inline]
fn clear_linear(words: &mut [u64], start: usize, len: usize) {
    let end = start + len;
    let first = start / WORD_BITS;
    let last = (end - 1) / WORD_BITS;
    let head = u64::MAX << (start % WORD_BITS);
    let tail = u64::MAX >> (WORD_BITS - 1 - (end - 1) % WORD_BITS);
    if first == last {
        words[first] &= !(head & tail);
        return;
    }
    words[first] &= !head;
    words[first + 1..last].fill(0);
    words[last] &= !tail;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-bit walks the word versions replace.
    fn bit(words: &[u64], seq: usize) -> bool {
        let pos = seq & (words.len() * WORD_BITS - 1);
        words[pos / WORD_BITS] & (1 << (pos % WORD_BITS)) != 0
    }

    fn zeros_per_bit(words: &[u64], start: usize, len: usize) -> Vec<usize> {
        (0..len).filter(|&i| !bit(words, start + i)).collect()
    }

    fn clear_per_bit(words: &mut [u64], start: usize, len: usize) {
        let mask = words.len() * WORD_BITS - 1;
        for i in 0..len {
            let pos = (start + i) & mask;
            words[pos / WORD_BITS] &= !(1 << (pos % WORD_BITS));
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
    }

    /// Every helper matches the per-bit walk for zero, full, mixed and sparse words; ranges that
    /// start and end inside words, on word boundaries and at the wrap; empty ranges; and ranges
    /// longer than the bitmap, which re-read it cyclically.
    #[test]
    fn word_helpers_match_per_bit_walk() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        for words in [1usize, 2, 4, 16, 128, 512] {
            let capacity = words * WORD_BITS;
            for scenario in 0..4 {
                let bitmap: Vec<u64> = (0..words)
                    .map(|_| match scenario % 4 {
                        0 => 0,
                        1 => u64::MAX,
                        2 => rng.next(),
                        // Mostly received, a few losses.
                        _ => rng.next() | rng.next() | rng.next(),
                    })
                    .collect();
                let mut starts = vec![0, 1, 31, 63, 64, 65, capacity - 1, capacity, 65_535];
                starts.extend((0..3).map(|_| rng.next() as usize % 65_536));
                let mut lens = vec![0, 1, 2, 63, 64, 65, 127, 128, 129, capacity - 1, capacity];
                lens.extend([capacity + 1, 3 * capacity + 7, 32_767, 65_535]);
                lens.extend((0..6).map(|_| rng.next() as usize % (2 * capacity)));
                for &start in &starts {
                    for &len in &lens {
                        let expected = zeros_per_bit(&bitmap, start, len);
                        assert_eq!(
                            count_zeros(&bitmap, start, len) as usize,
                            expected.len(),
                            "count, {words} words, start {start}, len {len}"
                        );
                        let mut found = Vec::new();
                        for_each_zero(&bitmap, start, len, |offset| found.push(offset));
                        assert_eq!(found, expected, "enumerate, {words} words, {start}+{len}");
                        assert_eq!(
                            first_zero(&bitmap, start, len),
                            expected.first().copied(),
                            "first, {words} words, start {start}, len {len}"
                        );
                        let mut cleared = bitmap.clone();
                        clear(&mut cleared, start, len);
                        let mut reference = bitmap.clone();
                        clear_per_bit(&mut reference, start, len.min(2 * capacity));
                        assert_eq!(cleared, reference, "clear, {words} words, {start}+{len}");
                    }
                }
            }
        }
    }
}
