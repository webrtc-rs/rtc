//! Exploratory Annex B start-code scanner comparisons.
//!
//! `scalar` copies H264Payloader::next_ind's body, replacing &Bytes with &[u8].
//! Both candidates preserve its offset, prefix-length, and long-zero-run semantics.
//! This is not a streaming reader: cross-buffer state and complete packetization remain
//! separate integration work. memchr is pinned by this directory's standalone manifest.
//!
//! Tests exhaust short inputs over {0, 1, 7} at every start offset and long zero prefixes.
//! Synthetic timings use hot buffers and six rotated-order samples (upper median), with
//! non-inlined kernels and black_box. No allocation or packetization is timed.
//! See ../../SIMD.md for interpretation, especially the dense-0x01 negative result.

use std::hint::black_box;
use std::time::Instant;

#[inline(never)]
pub fn scalar(nalu: &[u8], start: usize) -> (isize, isize) {
    let mut zero_count = 0;

    for (i, &b) in nalu[start..].iter().enumerate() {
        if b == 0 {
            zero_count += 1;
            continue;
        } else if b == 1 && zero_count >= 2 {
            return ((start + i - zero_count) as isize, zero_count as isize + 1);
        }
        zero_count = 0
    }
    (-1, -1)
}

#[inline(never)]
pub fn byte_search(nalu: &[u8], start: usize) -> (isize, isize) {
    for relative in memchr::memchr_iter(1, &nalu[start..]) {
        let one = start + relative;
        if relative < 2 || nalu[one - 1] != 0 || nalu[one - 2] != 0 {
            continue;
        }
        let mut first = one - 2;
        while first > start && nalu[first - 1] == 0 {
            first -= 1;
        }
        return (first as isize, (one - first + 1) as isize);
    }
    (-1, -1)
}

#[inline(never)]
pub fn substring_search(nalu: &[u8], start: usize) -> (isize, isize) {
    let Some(relative) = memchr::memmem::find(&nalu[start..], b"\0\0\x01") else {
        return (-1, -1);
    };
    let last = start + relative + 3;
    let mut first = start + relative;
    while first > start && nalu[first - 1] == 0 {
        first -= 1;
    }
    (first as isize, (last - first) as isize)
}

#[test]
fn equivalent_short_inputs_and_offsets() {
    for length in 0..=9 {
        for value in 0..3usize.pow(length) {
            let mut value = value;
            let data: Vec<u8> = (0..length)
                .map(|_| {
                    let b = [0, 1, 7][value % 3];
                    value /= 3;
                    b
                })
                .collect();
            for start in 0..=data.len() {
                assert_eq!(scalar(&data, start), byte_search(&data, start));
                assert_eq!(scalar(&data, start), substring_search(&data, start));
            }
        }
    }
    for zero_count in [2, 3, 4, 15, 16, 31, 32, 255, 4096] {
        let mut data = vec![0; zero_count];
        data.extend_from_slice(&[1, 7]);
        for start in 0..=data.len() {
            assert_eq!(scalar(&data, start), byte_search(&data, start));
            assert_eq!(scalar(&data, start), substring_search(&data, start));
        }
    }
}

fn main() {
    for len in [64, 1200, 16384] {
        for pattern in ["mixed-tail", "ones", "zeros"] {
            let mut rng = 0xfacebeefu64;
            let mut input: Vec<u8> = (0..len)
                .map(|_| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    match pattern {
                        "ones" => 1,
                        "zeros" => 0,
                        _ => rng as u8,
                    }
                })
                .collect();
            if pattern == "mixed-tail" {
                input[len - 4..].copy_from_slice(&[0, 0, 0, 1]);
            }
            assert_eq!(scalar(&input, 0), byte_search(&input, 0));
            assert_eq!(scalar(&input, 0), substring_search(&input, 0));
            let iterations = (2_000_000 / len).max(1000);
            let mut times = [Vec::new(), Vec::new(), Vec::new()];
            for round in 0..6 {
                for variant in [round % 3, (round + 1) % 3, (round + 2) % 3] {
                    let begin = Instant::now();
                    for _ in 0..iterations {
                        let result = match variant {
                            0 => scalar(black_box(&input), black_box(0)),
                            1 => byte_search(black_box(&input), black_box(0)),
                            _ => substring_search(black_box(&input), black_box(0)),
                        };
                        black_box(result);
                    }
                    times[variant].push(begin.elapsed().as_secs_f64() * 1e9 / iterations as f64);
                }
            }
            for t in &mut times {
                t.sort_by(f64::total_cmp);
            }
            println!(
                "{len}/{pattern}: scalar={:.1}ns memchr={:.1}ns memmem={:.1}ns",
                times[0][3], times[1][3], times[2][3]
            );
        }
    }
}
