//! Send buffer for storing RTP packets for NACK retransmission.

/// Half of u16 max value, used for sequence number wraparound detection.
const UINT16_SIZE_HALF: u16 = 1 << 15;

/// Buffer for storing sent RTP packets to enable NACK-based retransmission.
///
/// The buffer uses a circular array indexed by sequence number to store
/// packets. When a NACK is received, packets can be retrieved by sequence
/// number for retransmission.
///
/// The array grows with the stream instead of being allocated whole: a slot is over 100 bytes, so
/// a window of 1024 packets is over 100 KiB, which a stream that has sent a few hundred packets
/// (or sends few, like a screen share) has no use for. Slots are counted from the first sequence
/// number seen, so they fill from the start.
pub(crate) struct SendBuffer {
    /// Circular buffer of packets, as long as the highest slot used so far.
    packets: Vec<Option<rtp::Packet>>,
    /// The sequence number of slot 0.
    origin: u16,
    /// Size of the buffer (must be power of 2).
    size: u16,
    /// `size - 1`, used to index the circular buffer with `& mask` instead of
    /// `% size`. Since `size` is a runtime value the compiler can't prove is a
    /// power of two, `% size` would emit a real integer division per lookup.
    mask: u16,
    /// Highest sequence number added.
    highest_added: u16,
    /// Whether any packet has been added yet.
    started: bool,
}

/// Whether `size` is one the send buffer can hold: 1, 2, 4, ..., 32768.
pub(crate) fn is_valid_size(size: u16) -> bool {
    (0..=15).any(|i| size == 1 << i)
}

impl SendBuffer {
    /// Create a new send buffer with the specified size.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Returns `None` if the size is invalid.
    pub(crate) fn new(size: u16) -> Option<Self> {
        // Valid sizes: 1, 2, 4, 8, 16, 32, 64, 128, ..., 32768
        if !is_valid_size(size) {
            return None;
        }

        Some(Self {
            packets: Vec::new(),
            origin: 0,
            size,
            mask: size - 1,
            highest_added: 0,
            started: false,
        })
    }

    /// The slot of `seq`. Every window size divides 65536, so counting from `origin` maps
    /// sequence numbers to slots as a bijection within a window, wrap-around included.
    fn slot(&self, seq: u16) -> usize {
        (seq.wrapping_sub(self.origin) & self.mask) as usize
    }

    /// Makes room for slot `idx`, growing the array by doubling up to the window size.
    fn reserve_slot(&mut self, idx: usize) {
        if idx < self.packets.len() {
            return;
        }
        let capacity = self.packets.capacity();
        if idx >= capacity {
            let wanted = (capacity * 2).max(16).max(idx + 1).min(self.size as usize);
            self.packets.reserve_exact(wanted - self.packets.len());
        }
        self.packets.resize_with(idx + 1, || None);
    }

    /// Add an RTP packet to the buffer.
    pub(crate) fn add(&mut self, packet: rtp::Packet) {
        let seq = packet.header.sequence_number;

        if !self.started {
            self.origin = seq;
            self.reserve_slot(0);
            self.packets[0] = Some(packet);
            self.highest_added = seq;
            self.started = true;
            return;
        }

        let diff = seq.wrapping_sub(self.highest_added);
        if diff == 0 {
            // Duplicate, ignore
            return;
        } else if diff < UINT16_SIZE_HALF {
            // Positive diff: seq > highest_added
            // Clear packets between highest_added and seq
            let mut i = self.highest_added.wrapping_add(1);
            while i != seq {
                // A slot past the end was never used, so there is nothing in it to clear.
                let idx = self.slot(i);
                if let Some(old) = self.packets.get_mut(idx) {
                    *old = None;
                }
                i = i.wrapping_add(1);
            }
            self.highest_added = seq;
        }
        // For negative diff (out of order), we still store but don't update highest_added

        let idx = self.slot(seq);
        self.reserve_slot(idx);
        self.packets[idx] = Some(packet);
    }

    /// Get a packet by sequence number.
    ///
    /// Returns `None` if the packet is not in the buffer (either too old,
    /// never received, or was cleared).
    pub(crate) fn get(&self, seq: u16) -> Option<&rtp::Packet> {
        if !self.started {
            return None;
        }

        let diff = self.highest_added.wrapping_sub(seq);
        if diff >= UINT16_SIZE_HALF {
            // seq is ahead of highest_added (invalid)
            return None;
        }
        if diff >= self.size {
            // Too old, outside buffer range
            return None;
        }

        let packet = self.packets.get(self.slot(seq))?.as_ref()?;

        // Verify the sequence number matches (handle wraparound collisions)
        if packet.header.sequence_number != seq {
            return None;
        }

        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(seq: u16) -> rtp::Packet {
        rtp::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                ..Default::default()
            },
            payload: vec![seq as u8].into(),
        }
    }

    #[test]
    fn test_send_buffer_invalid_size() {
        assert!(SendBuffer::new(0).is_none());
        assert!(SendBuffer::new(3).is_none());
        assert!(SendBuffer::new(5).is_none());
        assert!(SendBuffer::new(100).is_none());
    }

    #[test]
    fn test_send_buffer_valid_sizes() {
        assert!(SendBuffer::new(1).is_some());
        assert!(SendBuffer::new(2).is_some());
        assert!(SendBuffer::new(8).is_some());
        assert!(SendBuffer::new(1024).is_some());
        assert!(SendBuffer::new(32768).is_some());
    }

    #[test]
    fn test_send_buffer_basic() {
        let mut buf = SendBuffer::new(8).unwrap();

        // Add packet
        buf.add(make_packet(0));
        assert!(buf.get(0).is_some());
        assert_eq!(buf.get(0).unwrap().header.sequence_number, 0);

        // Get non-existent packet
        assert!(buf.get(1).is_none());
    }

    #[test]
    fn test_send_buffer_overwrite() {
        let mut buf = SendBuffer::new(8).unwrap();

        // Fill buffer
        for i in 0..8 {
            buf.add(make_packet(i));
        }

        // All packets should be retrievable
        for i in 0..8 {
            assert!(buf.get(i).is_some());
        }

        // Add packet that wraps (seq 8 overwrites seq 0's slot)
        buf.add(make_packet(8));
        assert!(buf.get(8).is_some());
        assert!(buf.get(0).is_none()); // Should be gone (different seq in same slot)
    }

    #[test]
    fn test_send_buffer_gap_clears_packets() {
        let mut buf = SendBuffer::new(8).unwrap();

        buf.add(make_packet(0));
        buf.add(make_packet(1));
        buf.add(make_packet(2));

        // Jump ahead, packets 3-4 should be cleared
        buf.add(make_packet(5));

        assert!(buf.get(0).is_some());
        assert!(buf.get(1).is_some());
        assert!(buf.get(2).is_some());
        assert!(buf.get(3).is_none()); // Cleared
        assert!(buf.get(4).is_none()); // Cleared
        assert!(buf.get(5).is_some());
    }

    #[test]
    fn test_send_buffer_out_of_range() {
        let mut buf = SendBuffer::new(8).unwrap();

        for i in 0..8 {
            buf.add(make_packet(i));
        }

        // Add more packets to push old ones out of range
        for i in 8..16 {
            buf.add(make_packet(i));
        }

        // Old packets should be out of range
        for i in 0..8 {
            assert!(buf.get(i).is_none());
        }

        // New packets should be available
        for i in 8..16 {
            assert!(buf.get(i).is_some());
        }
    }

    #[test]
    fn test_send_buffer_wraparound() {
        let mut buf = SendBuffer::new(8).unwrap();

        // Start near wraparound
        buf.add(make_packet(65534));
        buf.add(make_packet(65535));
        buf.add(make_packet(0));
        buf.add(make_packet(1));

        assert!(buf.get(65534).is_some());
        assert!(buf.get(65535).is_some());
        assert!(buf.get(0).is_some());
        assert!(buf.get(1).is_some());
    }

    #[test]
    fn test_send_buffer_out_of_order() {
        let mut buf = SendBuffer::new(8).unwrap();

        buf.add(make_packet(0));
        buf.add(make_packet(2)); // Skip 1
        buf.add(make_packet(1)); // Out of order

        assert!(buf.get(0).is_some());
        assert!(buf.get(1).is_some());
        assert!(buf.get(2).is_some());
    }

    /// The buffer as it was before it grew with the stream: every slot allocated up front and
    /// indexed by the sequence number itself. The new one has to answer every question the same way.
    struct Reference {
        packets: Vec<Option<rtp::Packet>>,
        size: u16,
        highest_added: u16,
        started: bool,
    }

    impl Reference {
        fn new(size: u16) -> Self {
            Self {
                packets: vec![None; size as usize],
                size,
                highest_added: 0,
                started: false,
            }
        }

        fn add(&mut self, packet: rtp::Packet) {
            let mask = self.size - 1;
            let seq = packet.header.sequence_number;
            if !self.started {
                self.packets[(seq & mask) as usize] = Some(packet);
                self.highest_added = seq;
                self.started = true;
                return;
            }
            let diff = seq.wrapping_sub(self.highest_added);
            if diff == 0 {
                return;
            } else if diff < UINT16_SIZE_HALF {
                let mut i = self.highest_added.wrapping_add(1);
                while i != seq {
                    self.packets[(i & mask) as usize] = None;
                    i = i.wrapping_add(1);
                }
                self.highest_added = seq;
            }
            self.packets[(seq & mask) as usize] = Some(packet);
        }

        fn get(&self, seq: u16) -> Option<u16> {
            if !self.started {
                return None;
            }
            let diff = self.highest_added.wrapping_sub(seq);
            if diff >= UINT16_SIZE_HALF || diff >= self.size {
                return None;
            }
            let packet = self.packets[(seq & (self.size - 1)) as usize].as_ref()?;
            (packet.header.sequence_number == seq).then_some(seq)
        }
    }

    #[test]
    fn test_send_buffer_answers_as_the_preallocated_one_did() {
        // A xorshift generator: the sequences are arbitrary but the same on every run.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for &size in &[1u16, 2, 8, 64, 1024] {
            for round in 0..40 {
                let mut buf = SendBuffer::new(size).unwrap();
                let mut reference = Reference::new(size);
                let mut seq = (next() & 0xFFFF) as u16;
                // Some rounds start just short of the wrap, where slots and sequence numbers part ways.
                if round % 4 == 0 {
                    seq = 65535 - (next() % 40) as u16;
                }
                for _ in 0..3000 {
                    match next() % 10 {
                        // A gap (packets lost before the buffer saw them).
                        0 => seq = seq.wrapping_add((next() % 50) as u16 + 2),
                        // A late packet, from behind the highest and possibly behind the first.
                        1 | 2 => seq = seq.wrapping_sub((next() % 30) as u16),
                        // The sender moves on by one.
                        _ => seq = seq.wrapping_add(1),
                    }
                    buf.add(make_packet(seq));
                    reference.add(make_packet(seq));
                    for _ in 0..4 {
                        let probe = seq.wrapping_sub((next() % (2 * u64::from(size) + 40)) as u16);
                        assert_eq!(
                            buf.get(probe).map(|p| p.header.sequence_number),
                            reference.get(probe),
                            "size {size}, probe {probe}, last added {seq}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_send_buffer_holds_only_what_the_stream_has_sent() {
        let mut buf = SendBuffer::new(1024).unwrap();
        // A stream starts anywhere in the sequence space; its first packets must not cost a window.
        for seq in 40_000..40_100u16 {
            buf.add(make_packet(seq));
        }
        assert!(
            buf.packets.capacity() <= 128,
            "a hundred packets took {} slots",
            buf.packets.capacity()
        );
        // And it still fills to the window and no further.
        for seq in 40_100..45_000u16 {
            buf.add(make_packet(seq));
        }
        assert_eq!(buf.packets.capacity(), 1024);
        assert!(buf.get(44_999).is_some());
        assert!(buf.get(44_999 - 1023).is_some());
        assert!(buf.get(44_999 - 1024).is_none());
    }
}
