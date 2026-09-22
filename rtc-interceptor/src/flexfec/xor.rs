//! The XOR at the heart of FlexFEC: folding one serialised packet into a repair buffer.
//!
//! A repair payload is the byte-wise XOR of the packets it protects, and recovery XORs the
//! survivors back out of it. Both directions are [`xor_into`] over buffers of unequal length.

use wide::{u8x16, u8x32};

/// Bytes per vector in the main loop.
const LANES: usize = 32;

/// XOR `src` into `dst` over the shorter of the two; bytes of `dst` beyond that are left alone.
///
/// Leaving the tail alone is what makes packets of unequal length work: XORing a short packet into
/// a repair buffer sized for the longest is the same as XORing it zero-padded, because XOR with
/// zero is the identity.
///
/// # Implementation
///
/// Portable SIMD through [`wide`], which picks its backend when compiling: NEON on AArch64,
/// SSE2/AVX2 on x86-64, `simd128` on WebAssembly, and plain arrays elsewhere. The main loop XORs
/// 32 bytes at a time. The last 32 bytes are computed from the *original* values before that
/// loop runs and stored after it, overlapping whatever the loop already wrote with the same
/// result — sound because `dst` and `src` cannot alias — so there is no byte-at-a-time
/// remainder for any length from 32 up. Shorter inputs use the same trick with 16- and 8-byte
/// words.
///
/// The byte-wise `zip` loop this replaced already auto-vectorised (four 128-bit XORs per
/// iteration on AArch64), so the gain is in the remainder, not the main loop. Measured on an
/// Apple M1 Max against that loop, kernel alone (a shared machine, so treat these as rough):
/// 1,188 bytes 23.5 against 24.0 ns; 200 bytes 7.0 against 6.4 ns; 33 and 63 bytes 3.6 against
/// about 8 ns; every length from 0 to 1,500 summed, 23.9 against 26.8 µs. In complete FlexFEC
/// encoding and recovery the two were indistinguishable.
pub(crate) fn xor_into(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    let (dst, src) = (&mut dst[..len], &src[..len]);
    if len < LANES {
        xor_short(dst, src);
        return;
    }

    // The final vector, from the original bytes: stored last, it overwrites the overlap with
    // the main loop with the same values the loop computed.
    let tail = load32(&dst[len - LANES..]) ^ load32(&src[len - LANES..]);

    let (dst_chunks, _) = dst.as_chunks_mut::<LANES>();
    let (src_chunks, _) = src.as_chunks::<LANES>();
    for (target, source) in dst_chunks.iter_mut().zip(src_chunks) {
        *target = (u8x32::new(*target) ^ u8x32::new(*source)).to_array();
    }

    dst[len - LANES..].copy_from_slice(tail.as_array());
}

/// [`xor_into`] for equal-length inputs shorter than one vector.
fn xor_short(dst: &mut [u8], src: &[u8]) {
    let len = dst.len();
    if len >= 16 {
        // Two overlapping halves, both computed before either is stored.
        let head = load16(&dst[..16]) ^ load16(&src[..16]);
        let tail = load16(&dst[len - 16..]) ^ load16(&src[len - 16..]);
        dst[..16].copy_from_slice(head.as_array());
        dst[len - 16..].copy_from_slice(tail.as_array());
    } else if len >= 8 {
        let head = load8(&dst[..8]) ^ load8(&src[..8]);
        let tail = load8(&dst[len - 8..]) ^ load8(&src[len - 8..]);
        dst[..8].copy_from_slice(&head.to_ne_bytes());
        dst[len - 8..].copy_from_slice(&tail.to_ne_bytes());
    } else {
        for (target, source) in dst.iter_mut().zip(src) {
            *target ^= *source;
        }
    }
}

fn load32(bytes: &[u8]) -> u8x32 {
    u8x32::new(bytes.try_into().expect("32 bytes"))
}

fn load16(bytes: &[u8]) -> u8x16 {
    u8x16::new(bytes.try_into().expect("16 bytes"))
}

fn load8(bytes: &[u8]) -> u64 {
    u64::from_ne_bytes(bytes.try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loop this replaced, kept as the definition of the result.
    fn reference(dst: &mut [u8], src: &[u8]) {
        for (target, source) in dst.iter_mut().zip(src) {
            *target ^= *source;
        }
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(seed) ^ (index >> 8) as u8)
            .collect()
    }

    /// Every pairing of lengths around the 8-, 16-, 32- and 64-byte boundaries, and some MTU-sized
    /// ones, in both orders — the shorter side decides how much is XORed.
    #[test]
    fn matches_the_bytewise_loop_for_every_length_pairing() {
        let mut lengths: Vec<usize> = (0..=130).collect();
        lengths.extend([
            255, 256, 257, 1023, 1024, 1025, 1100, 1187, 1188, 1199, 1200, 1499, 1500,
        ]);

        for &dst_len in &lengths {
            for &src_len in &lengths {
                let src = pattern(src_len, 0x5A);
                let mut expected = pattern(dst_len, 0xC3);
                let mut actual = expected.clone();

                reference(&mut expected, &src);
                xor_into(&mut actual, &src);

                assert_eq!(expected, actual, "dst {dst_len} bytes, src {src_len} bytes");
            }
        }
    }

    /// Slices that do not start on any particular alignment, as a packet's payload after its
    /// header does not.
    #[test]
    fn matches_the_bytewise_loop_at_every_offset() {
        let src_storage = pattern(1600, 0x11);
        let dst_storage = pattern(1600, 0x77);
        for offset in 0..64 {
            for len in [0, 1, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 97, 1188] {
                let src = &src_storage[offset..offset + len];
                let mut expected = dst_storage.clone();
                let mut actual = dst_storage.clone();

                reference(&mut expected[64 - offset..64 - offset + len], src);
                xor_into(&mut actual[64 - offset..64 - offset + len], src);

                assert_eq!(expected, actual, "offset {offset}, {len} bytes");
            }
        }
    }

    #[test]
    fn xor_twice_is_the_identity() {
        let original = pattern(1188, 3);
        let key = pattern(1500, 9);
        let mut buffer = original.clone();
        xor_into(&mut buffer, &key);
        assert_ne!(original, buffer);
        xor_into(&mut buffer, &key);
        assert_eq!(original, buffer);
    }
}
