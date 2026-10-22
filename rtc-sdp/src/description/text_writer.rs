//! The text sink `SessionDescription::marshal` writes into.
//!
//! An SDP from a browser is several hundred short lines, and copying each piece through the
//! allocator-style `memcpy` call costs more than everything else marshalling does. `TextWriter`
//! copies short pieces inline with a few overlapping loads and stores, and skips the UTF-8
//! validation a `Vec<u8>` → `String` conversion would repeat over text that was assembled from
//! `&str`s and is valid by construction.
//!
//! All of the `unsafe` in the crate is in this file.

use std::fmt;

/// A growable UTF-8 buffer that only ever receives whole `&str`s.
pub(crate) struct TextWriter {
    // Invariant: `buf` holds valid UTF-8, because the only way bytes enter it is `push_str`.
    buf: Vec<u8>,
}

impl TextWriter {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub(crate) fn push_str(&mut self, s: &str) {
        let n = s.len();
        let len = self.buf.len();
        if self.buf.capacity() - len < n {
            self.buf.reserve(n);
        }
        // SAFETY: the reservation above leaves at least `n` writable bytes at `len`, and
        // `copy_short` writes exactly `n` bytes there, from `s`, which cannot overlap the
        // destination (it is spare capacity of a different allocation). Every byte of
        // `len..len + n` is initialised before `set_len` exposes it.
        unsafe {
            copy_short(self.buf.as_mut_ptr().add(len), s.as_bytes());
            self.buf.set_len(len + n);
        }
    }

    pub(crate) fn into_string(self) -> String {
        // SAFETY: see the invariant on `buf`: it is a concatenation of `&str`s.
        unsafe { String::from_utf8_unchecked(self.buf) }
    }
}

impl fmt::Write for TextWriter {
    #[inline(always)]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

/// Copies `src` to `dst`, touching exactly `src.len()` bytes of `dst`.
///
/// Pieces up to 32 bytes are copied as two overlapping fixed-size moves, which the compiler
/// turns into plain loads and stores; the branch on the length ladder is cheaper than the
/// function call a variable-length `copy_nonoverlapping` becomes.
///
/// # Safety
///
/// `dst` must be valid for writes of `src.len()` bytes and must not overlap `src`.
#[inline(always)]
unsafe fn copy_short(dst: *mut u8, src: &[u8]) {
    let n = src.len();
    let s = src.as_ptr();
    // SAFETY: every access below lies within `0..n` of both pointers, which the caller
    // guarantees valid and disjoint; the overlapping halves write identical bytes.
    unsafe {
        if n >= 16 {
            if n <= 32 {
                std::ptr::copy_nonoverlapping(s, dst, 16);
                std::ptr::copy_nonoverlapping(s.add(n - 16), dst.add(n - 16), 16);
            } else {
                std::ptr::copy_nonoverlapping(s, dst, n);
            }
        } else if n >= 8 {
            std::ptr::copy_nonoverlapping(s, dst, 8);
            std::ptr::copy_nonoverlapping(s.add(n - 8), dst.add(n - 8), 8);
        } else if n >= 4 {
            std::ptr::copy_nonoverlapping(s, dst, 4);
            std::ptr::copy_nonoverlapping(s.add(n - 4), dst.add(n - 4), 4);
        } else if n >= 1 {
            *dst = *s;
            *dst.add(n / 2) = *s.add(n / 2);
            *dst.add(n - 1) = *s.add(n - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn copy_short_writes_exactly_the_source_for_every_length() {
        for n in 0..=100usize {
            let src: Vec<u8> = (0..n)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(1))
                .collect();
            // Guard bytes on both sides must survive.
            let mut dst = vec![0xEEu8; n + 16];
            unsafe { copy_short(dst.as_mut_ptr().add(8), &src) };
            assert!(
                dst[..8].iter().all(|&b| b == 0xEE),
                "n={n}: wrote before dst"
            );
            assert_eq!(&dst[8..8 + n], &src[..], "n={n}");
            assert!(
                dst[8 + n..].iter().all(|&b| b == 0xEE),
                "n={n}: wrote past the end"
            );
        }
    }

    #[test]
    fn pieces_concatenate_across_growth() {
        let mut writer = TextWriter::with_capacity(4);
        let mut expected = String::new();
        for i in 0..500 {
            let piece = "ab€çd".repeat(i % 9);
            writer.push_str(&piece);
            writer.push_str("\r\n");
            expected.push_str(&piece);
            expected.push_str("\r\n");
        }
        write!(writer, "{} {}", 12345u64, "tail").unwrap();
        expected.push_str("12345 tail");
        assert_eq!(writer.into_string(), expected);
    }

    #[test]
    fn empty_writer_is_an_empty_string() {
        assert_eq!(TextWriter::with_capacity(0).into_string(), "");
    }
}
