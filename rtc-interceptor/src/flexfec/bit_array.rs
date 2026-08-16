//! The 128-bit packet mask that says which media packets a repair packet covers.

/// A 128-bit mask, indexed from the **most** significant bit.
///
/// Bit 0 is the most significant bit, matching how FlexFEC packet masks are laid out on the wire:
/// the first media packet after the base sequence number is the leftmost bit. Upstream keeps this
/// as a `Lo`/`Hi` pair of `u64`s; a single `u128` is the same bits with the seam removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BitArray {
    bits: u128,
}

/// Bit indices at or above this do not exist in a 128-bit mask.
const WIDTH: u32 = 128;

impl BitArray {
    /// An empty mask.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bit at `index`, counting from the most significant.
    ///
    /// Out-of-range indices are ignored rather than panicking: coverage is computed from packet
    /// counts that are already bounded, so a stray index means a caller bug, not a packet the
    /// mask should silently mis-cover.
    pub fn set_bit(&mut self, index: u32) {
        if index < WIDTH {
            self.bits |= 1u128 << (WIDTH - 1 - index);
        }
    }

    /// Whether the bit at `index` is set.
    pub fn bit(&self, index: u32) -> bool {
        index < WIDTH && (self.bits >> (WIDTH - 1 - index)) & 1 == 1
    }

    /// Clear every bit.
    pub fn reset(&mut self) {
        self.bits = 0;
    }

    /// Whether no bits are set.
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// The 15-bit mask covering media packets 0..=14 — the one always present on the wire.
    pub fn mask1(&self) -> u16 {
        (self.bits >> (WIDTH - 15)) as u16
    }

    /// The 31-bit mask covering media packets 15..=45, present when the first k-bit is clear.
    pub fn mask2(&self) -> u32 {
        ((self.bits >> (WIDTH - 46)) & 0x7FFF_FFFF) as u32
    }

    /// The 64-bit mask covering media packets 46..=109, as RFC 8627 lays it out.
    pub fn mask3(&self) -> u64 {
        (self.bits >> (WIDTH - 110)) as u64
    }

    /// The draft-03 variant of [`mask3`](Self::mask3): 63 bits rather than 64.
    ///
    /// Draft-03 spends one more bit on the k-flag than the published RFC does, so the third mask
    /// is one bit narrower and the whole field shifts down by one. This is the single most
    /// consequential difference between the two formats at the bit level, and the reason a
    /// draft-03 round trip proves nothing about RFC 8627 conformance.
    pub fn mask3_draft03(&self) -> u64 {
        self.mask3() >> 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_of(set_bits: &[u32]) -> BitArray {
        let mut mask = BitArray::new();
        for &bit in set_bits {
            mask.set_bit(bit);
        }
        mask
    }

    #[test]
    fn bits_are_indexed_from_the_most_significant() {
        let mask = mask_of(&[0]);
        assert!(mask.bit(0), "bit 0 is the leftmost");
        assert!(!mask.bit(1));
        assert_eq!(
            0x4000,
            mask.mask1(),
            "and lands at the top of the 15-bit mask"
        );
    }

    #[test]
    fn setting_and_reading_round_trips_across_the_whole_width() {
        let mut mask = BitArray::new();
        for index in 0..WIDTH {
            assert!(!mask.bit(index));
            mask.set_bit(index);
            assert!(mask.bit(index), "bit {index}");
        }
        for index in 0..WIDTH {
            assert!(mask.bit(index), "bit {index} still set");
        }
    }

    #[test]
    fn an_out_of_range_index_is_ignored() {
        let mut mask = BitArray::new();
        mask.set_bit(WIDTH);
        mask.set_bit(u32::MAX);
        assert!(mask.is_empty(), "no bit was set, and nothing panicked");
        assert!(!mask.bit(WIDTH));
    }

    #[test]
    fn reset_clears_everything() {
        let mut mask = mask_of(&[0, 64, 127]);
        assert!(!mask.is_empty());
        mask.reset();
        assert!(mask.is_empty());
        assert_eq!(0, mask.mask1());
        assert_eq!(0, mask.mask3());
    }

    /// Vectors from `pion/interceptor`'s `flexfec_coverage_test.go`.
    ///
    /// These are the bit-exact part of the format: which media packet each mask bit stands for,
    /// and where the three masks sit relative to one another. Taken from an independent
    /// implementation rather than derived here, so agreeing with them is evidence.
    #[test]
    fn mask_extraction_matches_upstream_vectors() {
        struct Case {
            name: &'static str,
            set_bits: &'static [u32],
            mask1: u16,
            mask2: u32,
            mask3: u64,
            mask3_draft03: u64,
        }

        let cases = [
            Case {
                name: "empty",
                set_bits: &[],
                mask1: 0,
                mask2: 0,
                mask3: 0,
                mask3_draft03: 0,
            },
            Case {
                name: "one bit in each mask",
                set_bits: &[5, 20, 50],
                mask1: 0x200,
                mask2: 0x2000000,
                mask3: 0x800000000000000,
                mask3_draft03: 0x400000000000000,
            },
            Case {
                name: "several bits in each mask",
                set_bits: &[0, 7, 14, 15, 30, 45, 46, 80, 108, 109],
                mask1: 0x4081,
                mask2: 0x40008001,
                mask3: 0x8000000020000003,
                mask3_draft03: 0x4000000010000001,
            },
            Case {
                name: "the boundaries of each mask",
                set_bits: &[0, 14, 15, 45, 46, 108, 109],
                mask1: 0x4001,
                mask2: 0x40000001,
                mask3: 0x8000000000000003,
                mask3_draft03: 0x4000000000000001,
            },
        ];

        for case in cases {
            let mask = mask_of(case.set_bits);
            assert_eq!(case.mask1, mask.mask1(), "mask1, {}", case.name);
            assert_eq!(case.mask2, mask.mask2(), "mask2, {}", case.name);
            assert_eq!(case.mask3, mask.mask3(), "mask3, {}", case.name);
            assert_eq!(
                case.mask3_draft03,
                mask.mask3_draft03(),
                "draft-03 mask3, {}",
                case.name
            );
        }
    }

    /// The three masks partition media packets 0..=109 without overlapping, which is what makes
    /// "which mask is a packet in" a question with one answer.
    #[test]
    fn the_three_masks_partition_the_covered_range() {
        for index in 0..15 {
            let mask = mask_of(&[index]);
            assert_ne!(0, mask.mask1(), "bit {index} belongs to mask1");
            assert_eq!(0, mask.mask2());
            assert_eq!(0, mask.mask3());
        }
        for index in 15..46 {
            let mask = mask_of(&[index]);
            assert_eq!(0, mask.mask1(), "bit {index} is not in mask1");
            assert_ne!(0, mask.mask2(), "bit {index} belongs to mask2");
            assert_eq!(0, mask.mask3());
        }
        for index in 46..110 {
            let mask = mask_of(&[index]);
            assert_eq!(0, mask.mask1());
            assert_eq!(0, mask.mask2(), "bit {index} is not in mask2");
            assert_ne!(0, mask.mask3(), "bit {index} belongs to mask3");
        }
    }

    /// Bit 109 is the last packet the RFC's mask3 can describe, and the one draft-03's narrower
    /// mask3 drops.
    #[test]
    fn draft03_loses_the_last_bit_the_rfc_mask_carries() {
        let mask = mask_of(&[109]);
        assert_eq!(1, mask.mask3(), "the RFC mask carries it");
        assert_eq!(
            0,
            mask.mask3_draft03(),
            "draft-03's mask is one bit narrower, so it falls off the end"
        );
    }
}
