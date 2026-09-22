//! Exploratory receiver-report loss-counting probe; no production code is changed.
//!
//! The per-bit kernel models ReceiverStream::generate_report's bitmap walk. Its caller
//! must pass the exact range: last_report_seq_num + 1, with wrapping distance minus one;
//! the existing report excludes last_seq_num. This file isolates counting from reporting.
//! Word counting preserves cyclic bitmap reads even beyond one retained window; this is
//! behavioral equivalence, not a claim that overwritten history is historically accurate.
//!
//! Tests cover partial words, wraps, empty ranges and ranges exceeding bitmap capacity.
//! Timings use hot buffers, six rotated-order samples, upper medians, non-inlined kernels,
//! and black_box. They exclude jitter/statistics updates, report allocation and serialization.
//! See ../../SIMD.md. Build on any supported target; reported assembly/timings were ARM64.

use std::hint::black_box;
use std::time::Instant;

#[unsafe(no_mangle)]
#[inline(never)]
pub fn loss_per_bit(bits: &[u64], start: u16, count: u16) -> u32 {
    let index_mask = bits.len() * 64 - 1;
    let mut lost = 0;
    let mut seq = start;
    for _ in 0..count {
        let pos = seq as usize & index_mask;
        if bits[pos / 64] & (1 << (pos % 64)) == 0 {
            lost += 1;
        }
        seq = seq.wrapping_add(1);
    }
    lost
}

#[inline]
fn count_linear(bits: &[u64], mut start: usize, mut count: usize) -> u32 {
    let mut lost = 0;
    if start % 64 != 0 && count != 0 {
        let n = count.min(64 - start % 64);
        let mask = (u64::MAX >> (64 - n)) << (start % 64);
        lost += (!bits[start / 64] & mask).count_ones();
        start += n;
        count -= n;
    }
    let full = count / 64;
    lost += bits[start / 64..start / 64 + full]
        .iter()
        .map(|word| (!word).count_ones())
        .sum::<u32>();
    start += full * 64;
    count %= 64;
    if count != 0 {
        lost += (!bits[start / 64] & (u64::MAX >> (64 - count))).count_ones();
    }
    lost
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn loss_by_word(bits: &[u64], start: u16, count: u16) -> u32 {
    let capacity = bits.len() * 64;
    assert!(capacity.is_power_of_two() && capacity <= 32768);
    let mut start = start as usize & (capacity - 1);
    let mut left = count as usize;
    let mut lost = 0;
    while left != 0 {
        let n = left.min(capacity - start);
        lost += count_linear(bits, start, n);
        left -= n;
        start = 0;
    }
    lost
}

#[test]
fn counts_match() {
    let mut rng = 0x1234facebeefu64;
    for words in [1, 2, 4, 16, 128, 512] {
        for scenario in 0..32 {
            let bits: Vec<u64> = (0..words)
                .map(|_| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    match scenario % 3 {
                        0 => 0,
                        1 => u64::MAX,
                        _ => rng,
                    }
                })
                .collect();
            for start in [0, 1, 31, 63, 64, 65, 8190, 65500, u16::MAX] {
                for count in [0, 1, 2, 63, 64, 65, 1000, 8191, 8192, 8193, 32768, u16::MAX] {
                    assert_eq!(
                        loss_per_bit(&bits, start, count),
                        loss_by_word(&bits, start, count)
                    );
                }
            }
        }
    }
}

fn main() {
    let bits: Vec<u64> = (0..128u64)
        .map(|n| n.wrapping_mul(0xfacefeedfacefeed))
        .collect();
    for count in [32, 256, 1024, 8191] {
        assert_eq!(
            loss_per_bit(&bits, 65499, count),
            loss_by_word(&bits, 65499, count)
        );
        let iterations = (8_000_000 / count as usize).max(1000);
        let mut times = [Vec::new(), Vec::new()];
        for round in 0..6 {
            for variant in [round % 2, 1 - round % 2] {
                let begin = Instant::now();
                for _ in 0..iterations {
                    let value = if variant == 0 {
                        loss_per_bit(black_box(&bits), black_box(65499), black_box(count))
                    } else {
                        loss_by_word(black_box(&bits), black_box(65499), black_box(count))
                    };
                    black_box(value);
                }
                times[variant].push(begin.elapsed().as_secs_f64() * 1e9 / iterations as f64);
            }
        }
        for t in &mut times {
            t.sort_by(f64::total_cmp);
        }
        println!(
            "count={count}: per-bit={:.1} ns, word={:.1} ns, ratio={:.2}x",
            times[0][3],
            times[1][3],
            times[0][3] / times[1][3]
        );
    }
}
