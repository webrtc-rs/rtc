//! Which media packets each repair packet protects.

use super::bit_array::BitArray;

/// The most media packets one FEC block can protect.
///
/// The three packet masks describe 110 positions between them, so this is a property of the wire
/// format rather than a tuning choice.
pub const MAX_MEDIA_PACKETS: u32 = 110;

/// The most repair packets one block can produce.
pub const MAX_FEC_PACKETS: u32 = MAX_MEDIA_PACKETS;

/// The assignment of media packets to repair packets.
///
/// Repair packets are **interleaved**: with two of them, the first covers media packets 0, 2,
/// 4, … and the second covers 1, 3, 5, …. Interleaving is what makes the scheme tolerate a burst —
/// consecutive losses land in different repair packets, and each can be recovered independently,
/// whereas contiguous blocks would put a burst entirely inside one and recover none of it.
#[derive(Debug, Clone)]
pub struct ProtectionCoverage {
    masks: Vec<BitArray>,
    num_fec_packets: u32,
    num_media_packets: u32,
}

impl ProtectionCoverage {
    /// Assign `num_media_packets` media packets across `num_fec_packets` repair packets.
    ///
    /// Returns `None` when the media count is zero or beyond what the masks can describe.
    pub fn new(num_media_packets: u32, num_fec_packets: u32) -> Option<Self> {
        if num_media_packets == 0 || num_media_packets > MAX_MEDIA_PACKETS {
            return None;
        }

        let mut coverage = Self {
            masks: vec![BitArray::new(); MAX_FEC_PACKETS as usize],
            num_fec_packets: 0,
            num_media_packets: 0,
        };
        coverage.update(num_media_packets, num_fec_packets);
        Some(coverage)
    }

    /// Recompute the assignment for a new block shape.
    ///
    /// A no-op when the shape has not changed, which is the common case: a sender protecting a
    /// steady stream keeps the same counts block after block.
    pub fn update(&mut self, num_media_packets: u32, num_fec_packets: u32) {
        if num_media_packets == 0 || num_media_packets > MAX_MEDIA_PACKETS {
            return;
        }
        if num_media_packets == self.num_media_packets && num_fec_packets == self.num_fec_packets {
            return;
        }

        self.num_media_packets = num_media_packets;
        self.num_fec_packets = num_fec_packets.min(MAX_FEC_PACKETS);
        for mask in &mut self.masks {
            mask.reset();
        }

        for fec_index in 0..self.num_fec_packets {
            let mut media_index = fec_index;
            while media_index < num_media_packets {
                self.masks[fec_index as usize].set_bit(media_index);
                media_index += self.num_fec_packets;
            }
        }
    }

    /// How many repair packets this covers.
    pub fn num_fec_packets(&self) -> u32 {
        self.num_fec_packets
    }

    /// How many media packets this covers.
    pub fn num_media_packets(&self) -> u32 {
        self.num_media_packets
    }

    /// The packet mask of one repair packet.
    pub fn mask(&self, fec_index: u32) -> Option<&BitArray> {
        (fec_index < self.num_fec_packets).then(|| &self.masks[fec_index as usize])
    }

    /// The media packet indices that `fec_index` protects, in order.
    ///
    /// Upstream returns a stateful iterator with `Reset`/`First`/`HasNext`, because its encoder
    /// walks the same coverage three times. A plain `Vec` of indices says the same thing without
    /// the cursor, and the caller can walk it as often as it likes.
    pub fn covered_by(&self, fec_index: u32) -> Vec<u32> {
        let Some(mask) = self.mask(fec_index) else {
            return Vec::new();
        };
        (0..self.num_media_packets)
            .filter(|&media_index| mask.bit(media_index))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Coverage as a grid, for readable assertions: one row per repair packet, one column per
    /// media packet.
    fn grid(coverage: &ProtectionCoverage) -> Vec<Vec<u32>> {
        (0..coverage.num_fec_packets())
            .map(|fec_index| coverage.covered_by(fec_index))
            .collect()
    }

    #[test]
    fn one_repair_packet_covers_everything() {
        let coverage = ProtectionCoverage::new(5, 1).expect("valid shape");
        assert_eq!(vec![vec![0, 1, 2, 3, 4]], grid(&coverage));
    }

    /// The property that makes FEC useful against bursts: consecutive media packets are covered
    /// by *different* repair packets, so losing two in a row is still recoverable.
    #[test]
    fn repair_packets_interleave_rather_than_taking_contiguous_blocks() {
        let coverage = ProtectionCoverage::new(6, 2).expect("valid shape");
        assert_eq!(vec![vec![0, 2, 4], vec![1, 3, 5]], grid(&coverage));

        let coverage = ProtectionCoverage::new(7, 3).expect("valid shape");
        assert_eq!(vec![vec![0, 3, 6], vec![1, 4], vec![2, 5]], grid(&coverage));
    }

    #[test]
    fn every_media_packet_is_covered_exactly_once() {
        for num_media in 1..=20u32 {
            for num_fec in 1..=5u32 {
                let coverage = ProtectionCoverage::new(num_media, num_fec).expect("valid shape");
                let mut covered: Vec<u32> = grid(&coverage).into_iter().flatten().collect();
                covered.sort_unstable();

                assert_eq!(
                    (0..num_media).collect::<Vec<_>>(),
                    covered,
                    "{num_media} media packets across {num_fec} repair packets"
                );
            }
        }
    }

    /// More repair packets than media packets leaves the surplus covering nothing — they carry no
    /// information, and the encoder skips them rather than emitting empty repair packets.
    #[test]
    fn surplus_repair_packets_cover_nothing() {
        let coverage = ProtectionCoverage::new(2, 4).expect("valid shape");
        assert_eq!(vec![vec![0], vec![1], vec![], vec![]], grid(&coverage));
    }

    #[test]
    fn an_impossible_shape_is_rejected() {
        assert!(
            ProtectionCoverage::new(0, 1).is_none(),
            "nothing to protect"
        );
        assert!(
            ProtectionCoverage::new(MAX_MEDIA_PACKETS + 1, 1).is_none(),
            "beyond what the packet masks can describe"
        );
        assert!(ProtectionCoverage::new(MAX_MEDIA_PACKETS, 1).is_some());
    }

    #[test]
    fn the_full_range_reaches_the_last_mask() {
        let coverage = ProtectionCoverage::new(MAX_MEDIA_PACKETS, 1).expect("valid shape");
        let mask = coverage.mask(0).expect("one repair packet");

        assert!(mask.bit(0), "the first media packet");
        assert!(mask.bit(MAX_MEDIA_PACKETS - 1), "and the 110th");
        assert_ne!(0, mask.mask3(), "which only the third mask can describe");
    }

    #[test]
    fn updating_to_the_same_shape_changes_nothing() {
        let mut coverage = ProtectionCoverage::new(6, 2).expect("valid shape");
        let before = grid(&coverage);

        coverage.update(6, 2);
        assert_eq!(before, grid(&coverage));

        coverage.update(4, 2);
        assert_eq!(
            vec![vec![0, 2], vec![1, 3]],
            grid(&coverage),
            "a different shape does recompute"
        );
    }

    #[test]
    fn an_impossible_update_leaves_the_previous_coverage_intact() {
        let mut coverage = ProtectionCoverage::new(6, 2).expect("valid shape");
        let before = grid(&coverage);

        coverage.update(0, 2);
        coverage.update(MAX_MEDIA_PACKETS + 1, 2);

        assert_eq!(before, grid(&coverage));
    }

    #[test]
    fn asking_about_a_repair_packet_that_does_not_exist_yields_nothing() {
        let coverage = ProtectionCoverage::new(5, 2).expect("valid shape");
        assert!(coverage.mask(2).is_none());
        assert!(coverage.covered_by(2).is_empty());
        assert!(coverage.covered_by(u32::MAX).is_empty());
    }
}
