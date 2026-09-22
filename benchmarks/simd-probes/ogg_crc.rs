//! Exploratory ARM64 Ogg CRC probe; not a production checksum implementation.
//!
//! Run the differential tests before timing; see ../../SIMD.md for commands and limits.
//! This standalone file is intentionally outside the Cargo workspace benchmark suite.
//! All timed variants exclude runtime dispatch, table generation, page construction and I/O.
//! They use identical input buffers, opt-level=3, black_box, and non-inlined kernel calls.
//! The driver takes six samples per variant in rotated order and reports the upper median.
//! Results are hot-buffer kernel timings, not end-to-end throughput or confidence intervals.
//!
//! The byte-wise table recurrence matches rtc-media's Ogg reader/writer. Ogg uses a
//! non-reflected 0x04c11db7 CRC, initial state zero and no final XOR. ARM's reflected
//! IEEE CRC instructions can reproduce it by reversing each input byte's bits and the
//! accumulator at entry/exit. Both accelerated functions require runtime CRC support.
//!
//! Compile and run on aarch64 only. Production integration needs a portable fallback,
//! feature dispatch outside the byte loop, and page-level fixture/conformance testing.

use std::arch::aarch64::*;

const fn checksum_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            r = if r & 0x80000000 != 0 {
                (r << 1) ^ 0x04c11db7
            } else {
                r << 1
            };
            bit += 1;
        }
        table[i] = r;
        i += 1;
    }
    table
}
static TABLE: [u32; 256] = checksum_table();

#[unsafe(no_mangle)]
#[inline(never)]
pub fn ogg_table(mut sum: u32, data: &[u8]) -> u32 {
    for &v in data {
        sum = (sum << 8) ^ TABLE[(((sum >> 24) as u8) ^ v) as usize];
    }
    sum
}

#[unsafe(no_mangle)]
#[inline(never)]
#[target_feature(enable = "crc,neon")]
pub unsafe fn ogg_neon_crc(initial: u32, data: &[u8]) -> u32 {
    let mut crc = initial.reverse_bits();
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        let bits = unsafe { vrbitq_u8(vld1q_u8(chunk.as_ptr())) };
        let words = vreinterpretq_u64_u8(bits);
        crc = __crc32d(crc, vgetq_lane_u64::<0>(words));
        crc = __crc32d(crc, vgetq_lane_u64::<1>(words));
    }
    for &byte in chunks.remainder() {
        crc = __crc32b(crc, byte.reverse_bits());
    }
    crc.reverse_bits()
}

#[unsafe(no_mangle)]
#[inline(never)]
#[target_feature(enable = "crc")]
pub unsafe fn ogg_crc_words(initial: u32, data: &[u8]) -> u32 {
    let mut crc = initial.reverse_bits();
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        crc = __crc32d(crc, word.reverse_bits().swap_bytes());
    }
    for &byte in chunks.remainder() {
        crc = __crc32b(crc, byte.reverse_bits());
    }
    crc.reverse_bits()
}

#[test]
fn ogg_crc_matches_table() {
    if !std::arch::is_aarch64_feature_detected!("crc") {
        return;
    }
    let mut rng = 0xfacefeed12345678u64;
    let data: Vec<u8> = (0..65536)
        .map(|_| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng as u8
        })
        .collect();
    for initial in [0, 1, 0x12345678, u32::MAX] {
        for offset in 0..16 {
            for len in (0..=256).chain([511, 512, 1200, 4096, 16384, 65307]) {
                let input = &data[offset..offset + len];
                assert_eq!(ogg_table(initial, input), unsafe {
                    ogg_neon_crc(initial, input)
                });
                assert_eq!(ogg_table(initial, input), unsafe {
                    ogg_crc_words(initial, input)
                });
            }
        }
    }
    for split in 0..=256 {
        let a = unsafe { ogg_neon_crc(0, &data[..split]) };
        assert_eq!(
            unsafe { ogg_neon_crc(a, &data[split..4096]) },
            ogg_table(0, &data[..4096])
        );
    }
}

fn main() {
    if !std::arch::is_aarch64_feature_detected!("crc") {
        return;
    }
    use std::hint::black_box;
    use std::time::Instant;
    let data: Vec<u8> = (0..65536).map(|x| (x * 71 + x / 7) as u8).collect();
    for len in [80, 1200, 8192, 65307] {
        let input = &data[..len];
        assert_eq!(ogg_table(0, input), unsafe { ogg_neon_crc(0, input) });
        let iterations = (16_000_000 / len).max(1000);
        let mut times = [Vec::new(), Vec::new(), Vec::new()];
        for round in 0..6 {
            for variant in [round % 3, (round + 1) % 3, (round + 2) % 3] {
                let begin = Instant::now();
                for _ in 0..iterations {
                    let value = match variant {
                        0 => ogg_table(black_box(0), black_box(input)),
                        1 => unsafe { ogg_neon_crc(black_box(0), black_box(input)) },
                        _ => unsafe { ogg_crc_words(black_box(0), black_box(input)) },
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
            "len={len}: table={:.1} ns, neon+crc={:.1} ns, scalar+crc={:.1} ns, table/neon={:.2}x",
            times[0][3],
            times[1][3],
            times[2][3],
            times[0][3] / times[1][3]
        );
    }
}
