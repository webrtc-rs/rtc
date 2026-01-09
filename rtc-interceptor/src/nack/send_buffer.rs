//! Send buffer for storing RTP packets for NACK retransmission.

/// Half of u16 max value, used for sequence number wraparound detection.
const UINT16_SIZE_HALF: u16 = 1 << 15;

/// Buffer for storing sent RTP packets to enable NACK-based retransmission.
///
/// The buffer uses a circular array indexed by sequence number to store
/// packets. When a NACK is received, packets can be retrieved by sequence
/// number for retransmission.
pub(crate) struct SendBuffer {
    /// Circular buffer of packets.
    packets: Vec<Option<rtp::Packet>>,
    /// Size of the buffer (must be power of 2).
    size: u16,
    /// Highest sequence number added.
    highest_added: u16,
    /// Whether any packet has been added yet.
    started: bool,
}

impl SendBuffer {
    /// Create a new send buffer with the specified size.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Returns `None` if the size is invalid.
    pub(crate) fn new(size: u16) -> Option<Self> {
        // Valid sizes: 1, 2, 4, 8, 16, 32, 64, 128, ..., 32768
        let is_valid = (0..=15).any(|i| size == 1 << i);
        if !is_valid {
            return None;
        }

        Some(Self {
            packets: vec![None; size as usize],
            size,
            highest_added: 0,
            started: false,
        })
    }

    /// Add an RTP packet to the buffer.
    pub(crate) fn add(&mut self, packet: rtp::Packet) {
        let seq = packet.header.sequence_number;

        if !self.started {
            self.packets[(seq % self.size) as usize] = Some(packet);
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
                let idx = (i % self.size) as usize;
                self.packets[idx] = None;
                i = i.wrapping_add(1);
            }
            self.highest_added = seq;
        }
        // For negative diff (out of order), we still store but don't update highest_added

        let idx = (seq % self.size) as usize;
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

        let idx = (seq % self.size) as usize;
        let packet = self.packets[idx].as_ref()?;

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
            ..Default::default()
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
}
