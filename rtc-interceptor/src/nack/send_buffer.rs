//! Send buffer for storing RTP packets for NACK retransmission.

use std::time::{Duration, Instant};

/// Half of u16 max value, used for sequence number wraparound detection.
const UINT16_SIZE_HALF: u16 = 1 << 15;

/// A stored packet and when it was sent.
struct Entry {
    packet: rtp::Packet,
    /// Nanoseconds after the buffer's `epoch`. An `Instant` is twice the size on some
    /// platforms, and every slot of a buffer pays for it whether or not it holds a packet.
    sent_at: u64,
}

/// How much retransmission history a [`SendBuffer`] keeps, beyond its packet count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HistoryLimits {
    /// Payload bytes the stored packets may reference. The most recent packet is always kept,
    /// even if it alone exceeds this.
    pub(crate) max_bytes: usize,
    /// How long a packet stays retransmittable after it was sent. `None` keeps it until the
    /// packet count or byte limit displaces it.
    pub(crate) max_age: Option<Duration>,
}

impl HistoryLimits {
    /// Bounded by packet count alone.
    pub(crate) const UNLIMITED: Self = Self {
        max_bytes: usize::MAX,
        max_age: None,
    };
}

/// Buffer for storing sent RTP packets to enable NACK-based retransmission.
///
/// The buffer uses a circular array indexed by sequence number to store
/// packets. When a NACK is received, packets can be retrieved by sequence
/// number for retransmission.
///
/// Bounded three ways: by packet count (the array), and optionally by the payload bytes the
/// stored packets reference and by their age. RTP payloads are shared `Bytes`, so storing a
/// packet copies no payload — but it keeps the payload's allocation alive, which is what the
/// byte and age limits bound.
pub(crate) struct SendBuffer {
    /// Circular buffer of packets.
    packets: Vec<Option<Entry>>,
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
    /// The oldest sequence number that may still be stored: where eviction by bytes or age
    /// resumes. Everything before it, back to the start of the window, is empty.
    oldest: u16,
    /// Payload bytes referenced by the stored packets.
    bytes: usize,
    /// When the most recent packet was added. Once it has aged out, everything has.
    newest_sent_at: Option<Instant>,
    /// What `Entry::sent_at` counts from: the first packet's send time.
    epoch: Option<Instant>,
    limits: HistoryLimits,
}

impl SendBuffer {
    /// Create a new send buffer with the specified size.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Returns `None` if the size is invalid.
    #[cfg(test)]
    pub(crate) fn new(size: u16) -> Option<Self> {
        Self::with_limits(size, HistoryLimits::UNLIMITED)
    }

    /// A send buffer of `size` packets that also enforces `limits`.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Returns `None` if the size is invalid.
    pub(crate) fn with_limits(size: u16, limits: HistoryLimits) -> Option<Self> {
        // Valid sizes: 1, 2, 4, 8, 16, 32, 64, 128, ..., 32768
        let is_valid = (0..=15).any(|i| size == 1 << i);
        if !is_valid {
            return None;
        }

        Some(Self {
            packets: (0..size).map(|_| None).collect(),
            size,
            mask: size - 1,
            highest_added: 0,
            started: false,
            oldest: 0,
            bytes: 0,
            newest_sent_at: None,
            epoch: None,
            limits,
        })
    }

    /// Add an RTP packet, sent at `now`, to the buffer.
    pub(crate) fn add(&mut self, packet: rtp::Packet, now: Instant) {
        let seq = packet.header.sequence_number;

        if !self.started {
            self.highest_added = seq;
            self.oldest = seq;
            self.started = true;
        } else {
            let diff = seq.wrapping_sub(self.highest_added);
            if diff == 0 {
                // Duplicate, ignore
                return;
            } else if diff < UINT16_SIZE_HALF {
                // Positive diff: seq > highest_added
                // Clear packets between highest_added and seq. A jump of a whole buffer or more
                // leaves nothing inside the new window, so clear everything at once rather than
                // visiting each skipped sequence number — a jump can skip up to 32,767 of them,
                // and one loop over them revisited every slot many times.
                if diff >= self.size {
                    self.packets.iter_mut().for_each(|slot| *slot = None);
                    self.bytes = 0;
                    self.oldest = seq;
                } else {
                    let mut i = self.highest_added.wrapping_add(1);
                    while i != seq {
                        self.clear(i);
                        i = i.wrapping_add(1);
                    }
                    // The window now starts `size - 1` behind `seq`.
                    let window_start = seq.wrapping_sub(self.size - 1);
                    if window_start.wrapping_sub(self.oldest) < UINT16_SIZE_HALF {
                        self.oldest = window_start;
                    }
                }
                self.highest_added = seq;
            } else if self.highest_added.wrapping_sub(seq) >= self.size {
                // Out of order and older than the whole window: its slot belongs to a newer
                // packet, which storing it would displace. Nothing could retrieve it anyway.
                return;
            } else if self.oldest.wrapping_sub(seq) < UINT16_SIZE_HALF {
                // Out of order, before where eviction resumes: move that back so the eviction
                // below still reaches it.
                self.oldest = seq;
            }
            // For negative diff (out of order), we still store but don't update highest_added
        }

        // Whatever held this slot is displaced: an older packet a full window back, or a
        // duplicate of this one.
        self.clear(seq);
        self.bytes += packet.payload.len();
        let sent_at = self.stamp(now);
        self.packets[(seq & self.mask) as usize] = Some(Entry { packet, sent_at });
        if self.newest_sent_at.is_none_or(|newest| newest < now) {
            self.newest_sent_at = Some(now);
        }

        self.evict(now);
    }

    /// Get a packet by sequence number, as of `now`.
    ///
    /// Returns `None` if the packet is not in the buffer (either too old,
    /// never received, or was cleared) or has outlived the age limit.
    pub(crate) fn get(&self, seq: u16, now: Instant) -> Option<&rtp::Packet> {
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

        let idx = (seq & self.mask) as usize;
        let entry = self.packets[idx].as_ref()?;

        // Verify the sequence number matches (handle wraparound collisions)
        if entry.packet.header.sequence_number != seq || self.expired(entry, now) {
            return None;
        }

        Some(&entry.packet)
    }

    /// When the whole history will have aged out, if it is not empty and has an age limit.
    ///
    /// The *newest* packet's expiry rather than the oldest's: while packets keep being added,
    /// `add` evicts what has aged, so a timer is needed only once the stream goes idle — and a
    /// per-packet deadline would ask for a wake-up every packet interval.
    pub(crate) fn expires_at(&self) -> Option<Instant> {
        Some(self.newest_sent_at? + self.limits.max_age?)
    }

    /// Drop every packet that has aged out as of `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.evict(now);
    }

    /// Payload bytes referenced by the stored packets.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// `now` as nanoseconds after the epoch, which the first call sets.
    fn stamp(&mut self, now: Instant) -> u64 {
        let epoch = *self.epoch.get_or_insert(now);
        now.saturating_duration_since(epoch).as_nanos() as u64
    }

    fn expired(&self, entry: &Entry, now: Instant) -> bool {
        let (Some(max_age), Some(epoch)) = (self.limits.max_age, self.epoch) else {
            return false;
        };
        let now = now.saturating_duration_since(epoch).as_nanos() as u64;
        now.saturating_sub(entry.sent_at) >= max_age.as_nanos() as u64
    }

    /// Empty the slot `seq` maps to, whichever packet is in it.
    fn clear(&mut self, seq: u16) {
        if let Some(entry) = self.packets[(seq & self.mask) as usize].take() {
            self.bytes -= entry.packet.payload.len();
        }
    }

    /// Evict from the oldest end while over the byte limit or aged out.
    ///
    /// Amortised constant time per packet added: `oldest` only moves forward past what it
    /// evicts or finds empty, and stops at the first packet it keeps.
    fn evict(&mut self, now: Instant) {
        if !self.started {
            return;
        }
        let end = self.highest_added.wrapping_add(1);
        while self.oldest != end {
            let idx = (self.oldest & self.mask) as usize;
            if let Some(entry) = &self.packets[idx]
                && entry.packet.header.sequence_number == self.oldest
            {
                let is_newest = self.oldest == self.highest_added;
                let over_budget = self.bytes > self.limits.max_bytes && !is_newest;
                if !(over_budget || self.expired(entry, now)) {
                    return;
                }
                self.clear(self.oldest);
            }
            self.oldest = self.oldest.wrapping_add(1);
        }
        // Everything has gone: nothing left to age out.
        self.oldest = self.highest_added;
        self.newest_sent_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// For the tests of an unlimited buffer, where no packet ever ages out.
    fn now() -> Instant {
        Instant::now()
    }

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
        buf.add(make_packet(0), now());
        assert!(buf.get(0, now()).is_some());
        assert_eq!(buf.get(0, now()).unwrap().header.sequence_number, 0);

        // Get non-existent packet
        assert!(buf.get(1, now()).is_none());
    }

    #[test]
    fn test_send_buffer_overwrite() {
        let mut buf = SendBuffer::new(8).unwrap();

        // Fill buffer
        for i in 0..8 {
            buf.add(make_packet(i), now());
        }

        // All packets should be retrievable
        for i in 0..8 {
            assert!(buf.get(i, now()).is_some());
        }

        // Add packet that wraps (seq 8 overwrites seq 0's slot)
        buf.add(make_packet(8), now());
        assert!(buf.get(8, now()).is_some());
        assert!(buf.get(0, now()).is_none()); // Should be gone (different seq in same slot)
    }

    #[test]
    fn test_send_buffer_gap_clears_packets() {
        let mut buf = SendBuffer::new(8).unwrap();

        buf.add(make_packet(0), now());
        buf.add(make_packet(1), now());
        buf.add(make_packet(2), now());

        // Jump ahead, packets 3-4 should be cleared
        buf.add(make_packet(5), now());

        assert!(buf.get(0, now()).is_some());
        assert!(buf.get(1, now()).is_some());
        assert!(buf.get(2, now()).is_some());
        assert!(buf.get(3, now()).is_none()); // Cleared
        assert!(buf.get(4, now()).is_none()); // Cleared
        assert!(buf.get(5, now()).is_some());
    }

    #[test]
    fn test_send_buffer_out_of_range() {
        let mut buf = SendBuffer::new(8).unwrap();

        for i in 0..8 {
            buf.add(make_packet(i), now());
        }

        // Add more packets to push old ones out of range
        for i in 8..16 {
            buf.add(make_packet(i), now());
        }

        // Old packets should be out of range
        for i in 0..8 {
            assert!(buf.get(i, now()).is_none());
        }

        // New packets should be available
        for i in 8..16 {
            assert!(buf.get(i, now()).is_some());
        }
    }

    #[test]
    fn test_send_buffer_wraparound() {
        let mut buf = SendBuffer::new(8).unwrap();

        // Start near wraparound
        buf.add(make_packet(65534), now());
        buf.add(make_packet(65535), now());
        buf.add(make_packet(0), now());
        buf.add(make_packet(1), now());

        assert!(buf.get(65534, now()).is_some());
        assert!(buf.get(65535, now()).is_some());
        assert!(buf.get(0, now()).is_some());
        assert!(buf.get(1, now()).is_some());
    }

    #[test]
    fn test_send_buffer_out_of_order() {
        let mut buf = SendBuffer::new(8).unwrap();

        buf.add(make_packet(0), now());
        buf.add(make_packet(2), now()); // Skip 1
        buf.add(make_packet(1), now()); // Out of order

        assert!(buf.get(0, now()).is_some());
        assert!(buf.get(1, now()).is_some());
        assert!(buf.get(2, now()).is_some());
    }

    fn sized_packet(seq: u16, len: usize) -> rtp::Packet {
        rtp::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                ..Default::default()
            },
            payload: vec![0u8; len].into(),
        }
    }

    /// A forward jump of a whole buffer or more clears everything at once, and the result is
    /// exactly what clearing each skipped sequence number would have left: nothing but the new
    /// packet.
    #[test]
    fn test_send_buffer_jump_past_the_window_clears_everything() {
        let mut buf = SendBuffer::new(8).unwrap();
        for i in 0..8 {
            buf.add(make_packet(i), now());
        }

        buf.add(make_packet(30_000), now());

        for i in 0..8 {
            assert!(buf.get(i, now()).is_none());
        }
        assert!(buf.get(30_000, now()).is_some());
        assert_eq!(buf.bytes(), 1);

        // And it keeps working from there, jumping again and then across the wrap.
        buf.add(make_packet(60_000), now());
        assert!(buf.get(30_000, now()).is_none());
        buf.add(make_packet(65_535), now());
        buf.add(make_packet(0), now());
        assert!(buf.get(65_535, now()).is_some());
        assert!(buf.get(0, now()).is_some());
        assert_eq!(buf.bytes(), 2);
    }

    /// A late packet older than the whole window must not displace the newer one that owns its
    /// slot.
    #[test]
    fn test_send_buffer_out_of_window_late_packet_is_ignored() {
        let mut buf = SendBuffer::new(8).unwrap();
        for i in 10..=20 {
            buf.add(make_packet(i), now());
        }

        // 12 and 20 share a slot (both are 4 mod 8), and 12 is a whole window behind.
        buf.add(make_packet(12), now());

        assert!(
            buf.get(20, now()).is_some(),
            "the newer packet was displaced"
        );
        assert!(buf.get(12, now()).is_none());
    }

    /// Byte accounting follows every way a packet leaves: displacement by the window, a gap,
    /// and a duplicate replacing itself.
    #[test]
    fn test_send_buffer_tracks_bytes() {
        let mut buf = SendBuffer::new(4).unwrap();
        buf.add(sized_packet(0, 100), now());
        buf.add(sized_packet(1, 10), now());
        assert_eq!(buf.bytes(), 110);

        buf.add(sized_packet(1, 10), now()); // duplicate, ignored
        assert_eq!(buf.bytes(), 110);

        buf.add(sized_packet(4, 1), now()); // displaces 0; clears the gap 2..=3
        assert_eq!(buf.bytes(), 11);

        buf.add(sized_packet(3, 5), now()); // late, inside the window
        assert_eq!(buf.bytes(), 16);
    }

    /// Over the byte limit, the oldest packets go first — and the newest always stays.
    #[test]
    fn test_send_buffer_byte_limit_evicts_oldest_first() {
        let limits = HistoryLimits {
            max_bytes: 250,
            max_age: None,
        };
        let mut buf = SendBuffer::with_limits(16, limits).unwrap();
        for i in 0..5 {
            buf.add(sized_packet(i, 100), now());
        }

        assert!(buf.bytes() <= 250);
        assert!(buf.get(0, now()).is_none());
        assert!(buf.get(2, now()).is_none());
        assert!(buf.get(3, now()).is_some());
        assert!(buf.get(4, now()).is_some());

        buf.add(sized_packet(5, 1_000), now());
        assert!(
            buf.get(5, now()).is_some(),
            "the newest packet is kept even alone over the limit"
        );
        assert_eq!(buf.bytes(), 1_000);
    }

    /// Packets older than the age limit are neither returned nor kept: evicted as newer ones
    /// arrive, and all at once when the stream goes quiet.
    #[test]
    fn test_send_buffer_age_limit() {
        let max_age = Duration::from_secs(1);
        let limits = HistoryLimits {
            max_bytes: usize::MAX,
            max_age: Some(max_age),
        };
        let mut buf = SendBuffer::with_limits(1024, limits).unwrap();
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);

        for i in 0..10u16 {
            buf.add(sized_packet(i, 100), at(i as u64 * 200));
        }
        // At 1.8 s, packets sent before 0.8 s have aged out as later ones were added.
        assert!(buf.get(3, at(1_800)).is_none());
        assert!(
            buf.get(4, at(1_800)).is_none(),
            "exactly max_age old is expired"
        );
        assert!(buf.get(5, at(1_800)).is_some());
        assert_eq!(buf.bytes(), 500);

        // The stream goes quiet. Its history expires with its newest packet.
        assert_eq!(buf.expires_at(), Some(at(1_800) + max_age));
        assert!(buf.get(9, at(2_799)).is_some());
        assert!(
            buf.get(9, at(2_800)).is_none(),
            "an unexpired lookup must still check age"
        );
        buf.expire(at(2_800));
        assert_eq!(buf.bytes(), 0);
        assert_eq!(buf.expires_at(), None, "nothing left to wake up for");

        // And it takes new packets afterwards.
        buf.add(sized_packet(10, 100), at(5_000));
        assert!(buf.get(10, at(5_000)).is_some());
        assert_eq!(buf.expires_at(), Some(at(5_000) + max_age));
    }
}
