//! Packet arrival time map for TWCC feedback generation.
//!
//! Adapted from Chrome's implementation:
//! <https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/webrtc/modules/remote_bitrate_estimator/packet_arrival_map.h>

const MIN_CAPACITY: usize = 128;
const MAX_NUMBER_OF_PACKETS: i64 = 1 << 15;

/// A map tracking packet arrival times, indexed by unwrapped sequence number.
///
/// Uses a circular buffer where packets are stored at index `seq % capacity`.
/// Automatically grows/shrinks as needed.
pub(crate) struct PacketArrivalTimeMap {
    /// Circular buffer of arrival times. -1 indicates not received.
    arrival_times: Vec<i64>,
    /// First valid sequence number (inclusive).
    begin_sequence_number: i64,
    /// First sequence number after the valid range (exclusive).
    end_sequence_number: i64,
}

impl PacketArrivalTimeMap {
    pub(crate) fn new() -> Self {
        Self {
            arrival_times: Vec::new(),
            begin_sequence_number: 0,
            end_sequence_number: 0,
        }
    }

    /// Record that a packet with the given sequence number arrived at the given time.
    pub(crate) fn add_packet(&mut self, sequence_number: i64, arrival_time: i64) {
        if self.arrival_times.is_empty() {
            // First packet
            self.reallocate(MIN_CAPACITY);
            self.begin_sequence_number = sequence_number;
            self.end_sequence_number = sequence_number + 1;
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if sequence_number >= self.begin_sequence_number
            && sequence_number < self.end_sequence_number
        {
            // The packet is within the buffer, no need to resize.
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if sequence_number < self.begin_sequence_number {
            // The packet goes before the current buffer. Expand to add packet,
            // but only if it fits within the maximum number of packets.
            let new_size = (self.end_sequence_number - sequence_number) as usize;
            if new_size > MAX_NUMBER_OF_PACKETS as usize {
                // Don't expand the buffer back for this packet, as it would remove newer received
                // packets.
                return;
            }
            self.adjust_to_size(new_size);
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            let begin = self.begin_sequence_number;
            self.set_not_received(sequence_number + 1, begin);
            self.begin_sequence_number = sequence_number;
            return;
        }

        // The packet goes after the buffer.
        let new_end_sequence_number = sequence_number + 1;

        if new_end_sequence_number >= self.end_sequence_number + MAX_NUMBER_OF_PACKETS {
            // All old packets have to be removed.
            self.begin_sequence_number = sequence_number;
            self.end_sequence_number = new_end_sequence_number;
            let idx = self.index(sequence_number);
            self.arrival_times[idx] = arrival_time;
            return;
        }

        if self.begin_sequence_number < new_end_sequence_number - MAX_NUMBER_OF_PACKETS {
            // Remove oldest entries.
            self.begin_sequence_number = new_end_sequence_number - MAX_NUMBER_OF_PACKETS;
        }

        self.adjust_to_size((new_end_sequence_number - self.begin_sequence_number) as usize);

        // Packets can be received out of order. If this isn't the next expected packet,
        // add enough placeholders to fill the gap.
        let end = self.end_sequence_number;
        self.set_not_received(end, sequence_number);
        self.end_sequence_number = new_end_sequence_number;
        let idx = self.index(sequence_number);
        self.arrival_times[idx] = arrival_time;
    }

    fn set_not_received(&mut self, start_inclusive: i64, end_exclusive: i64) {
        for sn in start_inclusive..end_exclusive {
            let idx = self.index(sn);
            self.arrival_times[idx] = -1;
        }
    }

    /// Returns the first valid sequence number in the map.
    pub(crate) fn begin_sequence_number(&self) -> i64 {
        self.begin_sequence_number
    }

    /// Returns the first sequence number after the last valid sequence number.
    pub(crate) fn end_sequence_number(&self) -> i64 {
        self.end_sequence_number
    }

    /// Find the next received packet at or after the given sequence number.
    /// Returns (sequence_number, arrival_time) if found.
    pub(crate) fn find_next_at_or_after(&self, sequence_number: i64) -> Option<(i64, i64)> {
        let mut seq = self.clamp(sequence_number);
        while seq < self.end_sequence_number {
            let arrival_time = self.get(seq);
            if arrival_time >= 0 {
                return Some((seq, arrival_time));
            }
            seq += 1;
        }
        None
    }

    /// Erase all elements from the beginning of the map until sequence_number.
    #[allow(dead_code)]
    pub(crate) fn erase_to(&mut self, sequence_number: i64) {
        if sequence_number < self.begin_sequence_number {
            return;
        }
        if sequence_number >= self.end_sequence_number {
            // Erase all.
            self.begin_sequence_number = self.end_sequence_number;
            return;
        }
        // Remove some
        self.begin_sequence_number = sequence_number;
        self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
    }

    /// Remove packets from the beginning as long as they are before sequence_number
    /// and older than arrival_time_limit.
    pub(crate) fn remove_old_packets(&mut self, sequence_number: i64, arrival_time_limit: i64) {
        let check_to = sequence_number.min(self.end_sequence_number);
        while self.begin_sequence_number < check_to
            && self.get(self.begin_sequence_number) <= arrival_time_limit
        {
            self.begin_sequence_number += 1;
        }
        self.adjust_to_size((self.end_sequence_number - self.begin_sequence_number) as usize);
    }

    /// Check if a packet with the given sequence number has been received.
    pub(crate) fn has_received(&self, sequence_number: i64) -> bool {
        self.get(sequence_number) >= 0
    }

    /// Clamp sequence_number to [begin_sequence_number, end_sequence_number].
    pub(crate) fn clamp(&self, sequence_number: i64) -> i64 {
        sequence_number.clamp(self.begin_sequence_number, self.end_sequence_number)
    }

    fn get(&self, sequence_number: i64) -> i64 {
        if sequence_number < self.begin_sequence_number
            || sequence_number >= self.end_sequence_number
        {
            return -1;
        }
        self.arrival_times[self.index(sequence_number)]
    }

    fn index(&self, sequence_number: i64) -> usize {
        // Sequence number might be negative, and we always guarantee that arrival_times
        // length is a power of 2, so it's easier to use "&" instead of "%"
        (sequence_number & (self.capacity() as i64 - 1)) as usize
    }

    fn adjust_to_size(&mut self, new_size: usize) {
        if new_size > self.capacity() {
            let mut new_capacity = self.capacity();
            while new_capacity < new_size {
                new_capacity *= 2;
            }
            self.reallocate(new_capacity);
        }
        if self.capacity() > MIN_CAPACITY.max(new_size * 4) {
            let mut new_capacity = self.capacity();
            while new_capacity >= 2 * new_size.max(MIN_CAPACITY) {
                new_capacity /= 2;
            }
            self.reallocate(new_capacity);
        }
    }

    fn capacity(&self) -> usize {
        self.arrival_times.len()
    }

    fn reallocate(&mut self, new_capacity: usize) {
        let mut new_buffer = vec![-1i64; new_capacity];
        for sn in self.begin_sequence_number..self.end_sequence_number {
            let old_val = self.get(sn);
            new_buffer[(sn & (new_capacity as i64 - 1)) as usize] = old_val;
        }
        self.arrival_times = new_buffer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arrival_time_map_basic() {
        let mut map = PacketArrivalTimeMap::new();

        // Add first packet
        map.add_packet(0, 1000);
        assert!(map.has_received(0));
        assert!(!map.has_received(1));
        assert_eq!(map.begin_sequence_number(), 0);
        assert_eq!(map.end_sequence_number(), 1);
    }

    #[test]
    fn test_arrival_time_map_sequential() {
        let mut map = PacketArrivalTimeMap::new();

        for i in 0..10 {
            map.add_packet(i, i * 1000);
        }

        for i in 0..10 {
            assert!(map.has_received(i));
        }
        assert_eq!(map.begin_sequence_number(), 0);
        assert_eq!(map.end_sequence_number(), 10);
    }

    #[test]
    fn test_arrival_time_map_with_gaps() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(0, 1000);
        map.add_packet(5, 5000);

        assert!(map.has_received(0));
        assert!(!map.has_received(1));
        assert!(!map.has_received(2));
        assert!(!map.has_received(3));
        assert!(!map.has_received(4));
        assert!(map.has_received(5));
    }

    #[test]
    fn test_arrival_time_map_find_next() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(0, 1000);
        map.add_packet(5, 5000);
        map.add_packet(10, 10000);

        assert_eq!(map.find_next_at_or_after(0), Some((0, 1000)));
        assert_eq!(map.find_next_at_or_after(1), Some((5, 5000)));
        assert_eq!(map.find_next_at_or_after(5), Some((5, 5000)));
        assert_eq!(map.find_next_at_or_after(6), Some((10, 10000)));
        assert_eq!(map.find_next_at_or_after(11), None);
    }

    #[test]
    fn test_arrival_time_map_out_of_order() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(5, 5000);
        map.add_packet(3, 3000);
        map.add_packet(7, 7000);

        assert!(map.has_received(3));
        assert!(!map.has_received(4));
        assert!(map.has_received(5));
        assert!(!map.has_received(6));
        assert!(map.has_received(7));
    }

    #[test]
    fn test_arrival_time_map_remove_old() {
        let mut map = PacketArrivalTimeMap::new();

        for i in 0..10 {
            map.add_packet(i, i * 1000);
        }

        // Remove packets older than 5000 up to seq 7
        map.remove_old_packets(7, 5000);

        // Packets 0-5 should be removed (arrival time <= 5000)
        assert!(!map.has_received(0));
        assert!(!map.has_received(5));
        assert!(map.has_received(6));
        assert!(map.has_received(9));
    }

    #[test]
    fn test_arrival_time_map_clamp() {
        let mut map = PacketArrivalTimeMap::new();

        map.add_packet(5, 5000);
        map.add_packet(10, 10000);

        assert_eq!(map.clamp(0), 5);
        assert_eq!(map.clamp(7), 7);
        assert_eq!(map.clamp(100), 11);
    }
}
