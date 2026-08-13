//! Extending 16-bit RTP sequence numbers to a monotonic 64-bit ordering key.
//!
//! A jitter buffer's whole job is to put packets back in order, so the key it orders by has to be
//! one where "later" is genuinely greater. Raw `u16` sequence numbers are not: 0 follows 65535,
//! and any comparison that does not account for that puts a wrapped packet 65535 places too early.
//!
//! Extending the sequence number — counting the wraps and carrying them in the high bits — makes
//! ordering ordinary integer comparison again.

/// Extends `u16` RTP sequence numbers into a monotonically increasing 64-bit space.
///
/// Each sequence number is placed in the wrap cycle *nearest the last one seen*, using the signed
/// 16-bit distance between them. That handles both directions with one rule: a packet a little
/// ahead extends forward, and a packet a little behind — a reordered or retransmitted one —
/// extends backward into the previous cycle rather than being flung a whole cycle into the future.
#[derive(Debug, Default, Clone)]
pub(crate) struct SequenceExtender {
    /// The highest extended value produced so far, and the anchor for the next one.
    highest: Option<u64>,
}

impl SequenceExtender {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Extend `sequence_number` relative to the highest one seen.
    ///
    /// The first call establishes the origin. Later calls return values that may be lower than
    /// previous ones — that is the point, since a reordered packet must sort before the packets
    /// that overtook it.
    pub(crate) fn extend(&mut self, sequence_number: u16) -> u64 {
        let Some(highest) = self.highest else {
            let extended = u64::from(sequence_number);
            self.highest = Some(extended);
            return extended;
        };

        // The signed 16-bit distance is the shortest path between the two sequence numbers in
        // either direction, which is exactly the "nearest cycle" rule.
        let previous = (highest & 0xFFFF) as u16;
        let distance = i32::from(sequence_number.wrapping_sub(previous) as i16);

        // A packet reordered below the origin has no earlier cycle to fall into; clamp rather
        // than wrap around the bottom of the space.
        let extended = (highest as i64 + i64::from(distance)).max(0) as u64;

        if extended > highest {
            self.highest = Some(extended);
        }
        extended
    }

    /// The highest extended sequence number seen, if any.
    pub(crate) fn highest(&self) -> Option<u64> {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_packet_establishes_the_origin() {
        let mut extender = SequenceExtender::new();
        assert_eq!(1000, extender.extend(1000));
        assert_eq!(Some(1000), extender.highest());
    }

    #[test]
    fn consecutive_packets_increase_by_one() {
        let mut extender = SequenceExtender::new();
        let extended: Vec<u64> = (10..15).map(|n| extender.extend(n)).collect();
        assert_eq!(vec![10, 11, 12, 13, 14], extended);
    }

    /// The property the raw `u16` ordering gets wrong: after 65535 comes 0, and it must sort
    /// *after*, not 65535 places before.
    #[test]
    fn wrapping_past_65535_keeps_increasing() {
        let mut extender = SequenceExtender::new();
        assert_eq!(65534, extender.extend(65534));
        assert_eq!(65535, extender.extend(65535));
        assert_eq!(65536, extender.extend(0), "0 follows 65535");
        assert_eq!(65537, extender.extend(1));
    }

    #[test]
    fn several_wraps_keep_increasing() {
        let mut extender = SequenceExtender::new();
        let mut expected = 0u64;
        let mut sequence_number = 0u16;
        for _ in 0..(3 * 65536 + 100) {
            assert_eq!(expected, extender.extend(sequence_number));
            expected += 1;
            sequence_number = sequence_number.wrapping_add(1);
        }
        assert!(expected > 3 * 65536, "covered three wrap-arounds");
    }

    /// A reordered packet must extend *backwards*, or it sorts after the packets that overtook it
    /// and the buffer emits it out of order.
    #[test]
    fn a_reordered_packet_extends_backwards() {
        let mut extender = SequenceExtender::new();
        extender.extend(100);
        extender.extend(103);
        assert_eq!(
            101,
            extender.extend(101),
            "the straggler belongs before 103"
        );
        assert_eq!(102, extender.extend(102));
        assert_eq!(
            Some(103),
            extender.highest(),
            "a late packet does not lower the anchor"
        );
    }

    /// The hard case: a packet from before the wrap arriving after it. It must land in the
    /// *previous* cycle, not be extended a full cycle forward.
    #[test]
    fn a_packet_reordered_across_a_wrap_lands_in_the_previous_cycle() {
        let mut extender = SequenceExtender::new();
        extender.extend(65534);
        extender.extend(65535);
        assert_eq!(65536, extender.extend(0));

        assert_eq!(
            65535 - 2,
            extender.extend(65533),
            "a straggler from before the wrap sorts before it, not a cycle later"
        );
        assert_eq!(Some(65536), extender.highest());
    }

    /// A packet reordered below the very first one seen has no earlier cycle to fall into.
    #[test]
    fn reordering_below_the_origin_clamps_at_zero() {
        let mut extender = SequenceExtender::new();
        extender.extend(2);
        assert_eq!(1, extender.extend(1));
        assert_eq!(0, extender.extend(0));
        // 65535 is "one before 0" — there is no cycle below the origin to put it in.
        assert_eq!(0, extender.extend(65535), "clamped rather than wrapped");
    }

    /// A jump larger than half the sequence space is indistinguishable from reordering in the
    /// other direction; the nearest-cycle rule resolves it as the smaller move, which is what
    /// every RTP implementation does.
    #[test]
    fn a_jump_of_more_than_half_the_space_is_read_as_reordering() {
        let mut extender = SequenceExtender::new();
        extender.extend(0);
        assert_eq!(
            0u64.wrapping_sub(0),
            extender.extend(0),
            "sanity: the same number is the same value"
        );
        // 40000 is 40000 forward, or 25536 backward. Backward is nearer, and the clamp applies.
        assert_eq!(0, extender.extend(40000));
    }
}
