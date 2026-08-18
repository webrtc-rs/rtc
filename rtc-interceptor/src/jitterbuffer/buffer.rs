//! The per-stream packet store: ordered, deduplicating and bounded.
//!
//! This is the data structure only. Deciding *when* a packet is due — the playout policy — is the
//! interceptor's job, and lives above this.

use super::sequence::SequenceExtender;
use crate::{Packet, TaggedPacket};
use std::collections::BTreeMap;

/// Counters describing what a buffer has had to cope with.
///
/// Upstream reports these through a listener callback. There is no natural sans-I/O analogue for
/// a callback, and these are diagnostics rather than control signals, so they are plain counters
/// on the buffer instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JitterBufferStats {
    /// Packets that arrived after a higher sequence number had already been seen.
    pub out_of_order: u64,
    /// Packets discarded because the same sequence number was already held.
    pub duplicates: u64,
    /// Packets dropped because the buffer was full.
    pub overflow: u64,
    /// Packets discarded because they arrived after the buffer had already released that
    /// position — too late to be played out in order.
    pub late: u64,
    /// Packets rejected because they carried a different SSRC than this buffer's stream.
    pub foreign_ssrc: u64,
    /// Times playout asked for a packet and the buffer had none to give.
    pub underflow: u64,
}

/// Whether the buffer is still filling or is handing packets out.
///
/// The *trigger* for the transition is not here: upstream moves to `Emitting` once
/// `minStartCount` packets have accumulated, whereas the policy this port is built for is
/// time-based (a depth in milliseconds). So the buffer owns the state and the playout policy above
/// it decides when to call [`JitterBuffer::begin_emitting`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Filling; playout has not started, so nothing is handed out yet.
    #[default]
    Buffering,
    /// Handing packets out as they come due.
    Emitting,
}

/// Why a packet was not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// The same sequence number is already buffered.
    Duplicate,
    /// The buffer is full and this packet did not displace anything.
    Overflow,
    /// The position has already been released; emitting it now would be out of order.
    Late,
    /// The packet belongs to a different stream.
    ForeignSsrc,
}

/// A single stream's packets, ordered by extended sequence number.
///
/// **One buffer per SSRC.** The buffer records the SSRC of the first packet it accepts and
/// rejects any other, so two streams cannot interleave into one sequence-number ordering. That is
/// a deliberate correction: pion's `ReceiverInterceptor` holds a single buffer for every remote
/// stream and its `BindRemoteStream` ignores `info.SSRC`, so two streams' sequence numbers sort
/// against each other.
///
/// Ordering is by *extended* sequence number — the 16-bit value plus its wrap count — so a packet
/// that arrives
/// after a wrap still sorts into its true position; and because the map is keyed by that value,
/// duplicates collapse rather than being inserted twice as they are upstream.
pub struct JitterBuffer {
    /// The stream this buffer belongs to; `None` until the first packet arrives.
    ssrc: Option<u32>,
    /// Packets keyed by extended sequence number — ordering and deduplication in one structure.
    packets: BTreeMap<u64, TaggedPacket>,
    extender: SequenceExtender,
    /// Highest extended sequence number already released; nothing at or below it may be stored.
    released_through: Option<u64>,
    /// Maximum packets held before the oldest is dropped.
    capacity: usize,
    state: State,
    stats: JitterBufferStats,
}

/// Summarises the buffer rather than dumping its contents: `TaggedPacket` is not `Debug`, and a
/// list of buffered packets is not what anyone wants from a debug print anyway.
impl std::fmt::Debug for JitterBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JitterBuffer")
            .field("ssrc", &self.ssrc)
            .field("held", &self.packets.len())
            .field("capacity", &self.capacity)
            .field("next_due", &self.front_sequence())
            .field("released_through", &self.released_through)
            .field("state", &self.state)
            .field("stats", &self.stats)
            .finish()
    }
}

impl JitterBuffer {
    /// Create an empty buffer holding at most `capacity` packets.
    pub fn new(capacity: usize) -> Self {
        Self {
            ssrc: None,
            packets: BTreeMap::new(),
            extender: SequenceExtender::new(),
            released_through: None,
            capacity: capacity.max(1),
            state: State::Buffering,
            stats: JitterBufferStats::default(),
        }
    }

    /// The SSRC this buffer is bound to, once a packet has established it.
    pub fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// How many packets are currently held.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether the buffer holds nothing.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Counters describing what this buffer has coped with.
    pub fn stats(&self) -> JitterBufferStats {
        self.stats
    }

    /// Store a packet, returning its extended sequence number, or why it was not stored.
    ///
    /// A non-RTP packet is rejected as foreign: this buffer orders by sequence number, and RTCP
    /// has none.
    pub fn push(&mut self, packet: TaggedPacket) -> Result<u64, Rejected> {
        let Packet::Rtp(rtp) = &packet.message.packet else {
            self.stats.foreign_ssrc += 1;
            return Err(Rejected::ForeignSsrc);
        };

        let ssrc = rtp.header.ssrc;
        match self.ssrc {
            None => self.ssrc = Some(ssrc),
            Some(bound) if bound != ssrc => {
                self.stats.foreign_ssrc += 1;
                return Err(Rejected::ForeignSsrc);
            }
            Some(_) => {}
        }

        let sequence_number = rtp.header.sequence_number;
        let previous_highest = self.extender.highest();
        let extended = self.extender.extend(sequence_number);

        if previous_highest.is_some_and(|highest| extended < highest) {
            self.stats.out_of_order += 1;
        }

        // Already played out: storing it would either emit out of order or emit twice.
        if self
            .released_through
            .is_some_and(|released| extended <= released)
        {
            self.stats.late += 1;
            return Err(Rejected::Late);
        }

        if self.packets.contains_key(&extended) {
            self.stats.duplicates += 1;
            return Err(Rejected::Duplicate);
        }

        if self.packets.len() >= self.capacity {
            // Full: the oldest packet is the one closest to being played out, so dropping the
            // *new* packet when it is even older keeps the buffer's contents contiguous.
            let oldest = self
                .packets
                .keys()
                .next()
                .copied()
                .expect("capacity is at least 1, so a full buffer is non-empty");
            if extended < oldest {
                self.stats.overflow += 1;
                return Err(Rejected::Overflow);
            }
            self.packets.remove(&oldest);
            self.stats.overflow += 1;
        }

        self.packets.insert(extended, packet);
        Ok(extended)
    }

    /// The extended sequence number of the packet nearest playout, if any.
    pub fn front_sequence(&self) -> Option<u64> {
        self.packets.keys().next().copied()
    }

    /// Look at the packet nearest playout without removing it.
    pub fn peek(&self) -> Option<&TaggedPacket> {
        self.packets.values().next()
    }

    /// Whether the buffer is filling or emitting.
    pub fn state(&self) -> State {
        self.state
    }

    /// Start handing packets out.
    ///
    /// Called by the playout policy when its start condition is met — a buffered depth here,
    /// where upstream uses a packet count.
    pub fn begin_emitting(&mut self) {
        self.state = State::Emitting;
    }

    /// Stop handing packets out and fill again.
    ///
    /// A stream that has run dry, or restarted across a discontinuity, has to re-accumulate
    /// before playout is smooth again.
    pub fn begin_buffering(&mut self) {
        self.state = State::Buffering;
    }

    /// Remove and return the packet nearest playout.
    ///
    /// Yields nothing while [`State::Buffering`] — upstream returns `ErrPopWhileBuffering` here,
    /// a sentinel its synchronous reader needs; in sans-I/O "nothing yet" is just `None`.
    ///
    /// Releasing a packet also marks its position played out, so a later-arriving copy or an
    /// even older straggler is rejected rather than emitted behind it.
    ///
    /// **Gaps are skipped, not waited for.** Upstream pops strictly at its playout head and
    /// counts an underflow when that exact sequence number is missing, which stalls a stream on
    /// any un-recovered loss. Whether a gap is worth waiting for is a question about deadlines,
    /// so it belongs to the playout policy above this: it decides when a packet is due, and this
    /// hands over whatever is due now.
    pub fn pop(&mut self) -> Option<TaggedPacket> {
        if self.state == State::Buffering {
            return None;
        }
        let Some((&extended, _)) = self.packets.iter().next() else {
            self.stats.underflow += 1;
            return None;
        };
        let packet = self.packets.remove(&extended)?;
        self.mark_released(extended);
        Some(packet)
    }

    /// Remove and return the packet with this wire sequence number, if it is held.
    ///
    /// Takes the 16-bit number off the wire, as a caller naturally holds; the extension to the
    /// internal ordering key happens here.
    pub fn pop_at_sequence(&mut self, sequence_number: u16) -> Option<TaggedPacket> {
        self.pop_at(self.extended_of(sequence_number)?)
    }

    /// Borrow the packet with this wire sequence number without removing it.
    pub fn peek_at_sequence(&self, sequence_number: u16) -> Option<&TaggedPacket> {
        self.find(self.extended_of(sequence_number)?)
    }

    /// Remove and return the first held packet carrying this RTP timestamp.
    ///
    /// One packet, not a whole frame: a video frame spans several packets sharing a timestamp, so
    /// releasing the frame means calling this until it yields `None`. That matches upstream's
    /// `PopAtTimestamp`, and keeps the "how much of a frame is releasable" decision in the
    /// playout policy where the deadline lives.
    pub fn pop_at_timestamp(&mut self, timestamp: u32) -> Option<TaggedPacket> {
        let extended =
            self.packets
                .iter()
                .find_map(|(&extended, packet)| match &packet.message.packet {
                    Packet::Rtp(rtp) if rtp.header.timestamp == timestamp => Some(extended),
                    _ => None,
                })?;
        self.pop_at(extended)
    }

    /// Remove and return the packet at `extended`, if it is held.
    ///
    /// The extended key is the buffer's own ordering space; [`pop_at_sequence`](Self::pop_at_sequence)
    /// is the one to reach for from outside.
    pub fn pop_at(&mut self, extended: u64) -> Option<TaggedPacket> {
        let packet = self.packets.remove(&extended)?;
        self.mark_released(extended);
        Some(packet)
    }

    /// Borrow the packet at `extended` without removing it.
    pub fn find(&self, extended: u64) -> Option<&TaggedPacket> {
        self.packets.get(&extended)
    }

    /// The extended key of a held packet with this wire sequence number.
    ///
    /// Searches rather than extending arithmetically: extending would need to mutate the
    /// extender's anchor, and a lookup must not move the ordering origin. At most one held packet
    /// can carry a given wire number in a buffer this shallow, so the first match is the packet.
    fn extended_of(&self, sequence_number: u16) -> Option<u64> {
        self.packets
            .iter()
            .find_map(|(&extended, packet)| match &packet.message.packet {
                Packet::Rtp(rtp) if rtp.header.sequence_number == sequence_number => Some(extended),
                _ => None,
            })
    }

    /// The RTP timestamp of the packet nearest playout.
    pub fn front_timestamp(&self) -> Option<u32> {
        match &self.peek()?.message.packet {
            Packet::Rtp(rtp) => Some(rtp.header.timestamp),
            _ => None,
        }
    }

    /// Drop everything, keeping the SSRC binding and stats.
    ///
    /// Used when a stream restarts: the ordering anchors are meaningless across a discontinuity,
    /// but what the buffer has coped with so far is still worth reporting.
    pub fn reset(&mut self) {
        self.packets.clear();
        self.extender = SequenceExtender::new();
        self.released_through = None;
        self.state = State::Buffering;
    }

    fn mark_released(&mut self, extended: u64) {
        self.released_through = Some(match self.released_through {
            Some(previous) => previous.max(extended),
            None => extended,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use shared::TransportContext;
    use std::time::Instant;

    fn packet(ssrc: u32, sequence_number: u16, timestamp: u32) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number,
                    timestamp,
                    ..Default::default()
                },
                ..Default::default()
            })),
        }
    }

    fn sequence_of(packet: &TaggedPacket) -> u16 {
        match &packet.message.packet {
            Packet::Rtp(rtp) => rtp.header.sequence_number,
            _ => panic!("not RTP"),
        }
    }

    /// Drains everything held. Starts playout first: `pop` yields nothing while buffering, which
    /// is the state a fresh buffer is in.
    fn drain(buffer: &mut JitterBuffer) -> Vec<u16> {
        buffer.begin_emitting();
        let mut out = Vec::new();
        while let Some(packet) = buffer.pop() {
            out.push(sequence_of(&packet));
        }
        out
    }

    #[test]
    fn packets_come_out_in_sequence_order_however_they_went_in() {
        let mut buffer = JitterBuffer::new(64);
        for sequence_number in [3u16, 1, 4, 2, 0] {
            buffer.push(packet(1, sequence_number, 0)).expect("push");
        }
        assert_eq!(vec![0, 1, 2, 3, 4], drain(&mut buffer));
    }

    #[test]
    fn reordering_is_counted() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 0, 0)).expect("push");
        buffer.push(packet(1, 2, 0)).expect("push");
        assert_eq!(0, buffer.stats().out_of_order);
        buffer.push(packet(1, 1, 0)).expect("push");
        assert_eq!(1, buffer.stats().out_of_order);
    }

    /// Upstream's queue inserts equal priorities, so a retransmission that races its original
    /// leaves two copies of the same packet in the ordering.
    #[test]
    fn a_duplicate_is_rejected_rather_than_stored_twice() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 7, 0)).expect("push");
        assert_eq!(Err(Rejected::Duplicate), buffer.push(packet(1, 7, 0)));
        assert_eq!(1, buffer.len());
        assert_eq!(1, buffer.stats().duplicates);
        assert_eq!(vec![7], drain(&mut buffer));
    }

    /// The wrap case, which raw `u16` ordering gets wrong by a whole cycle.
    #[test]
    fn ordering_survives_a_wrap_around() {
        let mut buffer = JitterBuffer::new(64);
        for sequence_number in [65534u16, 65535, 0, 1] {
            buffer.push(packet(1, sequence_number, 0)).expect("push");
        }
        assert_eq!(vec![65534, 65535, 0, 1], drain(&mut buffer));
    }

    #[test]
    fn ordering_survives_two_wrap_arounds_with_reordering() {
        let mut buffer = JitterBuffer::new(4096);

        // Two full cycles, each pair swapped on the way in.
        let mut expected = Vec::new();
        let mut sequence_number = 65000u16;
        let mut pushed = Vec::new();
        for _ in 0..(2 * 65536 / 2) {
            let a = sequence_number;
            let b = sequence_number.wrapping_add(1);
            pushed.push((b, a)); // swapped
            expected.push(a);
            expected.push(b);
            sequence_number = sequence_number.wrapping_add(2);
        }

        // Push and drain incrementally so the buffer stays within capacity.
        let mut emitted = Vec::new();
        buffer.begin_emitting();
        for (b, a) in pushed {
            let _ = buffer.push(packet(1, b, 0));
            let _ = buffer.push(packet(1, a, 0));
            while buffer.len() > 2 {
                emitted.push(sequence_of(&buffer.pop().expect("non-empty")));
            }
        }
        emitted.extend(drain(&mut buffer));

        assert_eq!(
            expected.len(),
            emitted.len(),
            "every packet came out exactly once across two wraps"
        );
        assert_eq!(expected, emitted, "and in sequence order throughout");
    }

    /// The test pion's shared-buffer design cannot pass: one buffer belongs to one stream.
    #[test]
    fn a_second_ssrc_cannot_interleave_into_this_buffer() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 10, 0)).expect("push");

        assert_eq!(
            Err(Rejected::ForeignSsrc),
            buffer.push(packet(2, 5, 0)),
            "a different stream's packet must not sort against this stream's sequence numbers"
        );
        assert_eq!(1, buffer.stats().foreign_ssrc);
        assert_eq!(Some(1), buffer.ssrc());
        assert_eq!(vec![10], drain(&mut buffer));
    }

    #[test]
    fn rtcp_is_not_stored() {
        let mut buffer = JitterBuffer::new(64);
        let rtcp = TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        assert_eq!(Err(Rejected::ForeignSsrc), buffer.push(rtcp));
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_packet_arriving_after_its_position_was_released_is_rejected() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 5, 0)).expect("push");
        buffer.begin_emitting();
        buffer.pop().expect("release 5");

        assert_eq!(
            Err(Rejected::Late),
            buffer.push(packet(1, 5, 0)),
            "the same packet again would be emitted twice"
        );
        assert_eq!(
            Err(Rejected::Late),
            buffer.push(packet(1, 4, 0)),
            "an older straggler would be emitted out of order"
        );
        assert_eq!(2, buffer.stats().late);
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_full_buffer_drops_its_oldest_packet() {
        let mut buffer = JitterBuffer::new(3);
        for sequence_number in 0..3u16 {
            buffer.push(packet(1, sequence_number, 0)).expect("push");
        }
        buffer.push(packet(1, 3, 0)).expect("push displaces");

        assert_eq!(3, buffer.len(), "capacity is respected");
        assert_eq!(1, buffer.stats().overflow);
        assert_eq!(vec![1, 2, 3], drain(&mut buffer), "the oldest gave way");
    }

    /// When the buffer is full and the arrival is older than everything in it, dropping the
    /// arrival keeps the held run contiguous — evicting the oldest to make room for something
    /// even older would leave a hole at both ends.
    #[test]
    fn a_full_buffer_drops_an_arrival_older_than_everything_held() {
        let mut buffer = JitterBuffer::new(3);
        for sequence_number in [10u16, 11, 12] {
            buffer.push(packet(1, sequence_number, 0)).expect("push");
        }

        assert_eq!(Err(Rejected::Overflow), buffer.push(packet(1, 9, 0)));
        assert_eq!(vec![10, 11, 12], drain(&mut buffer));
    }

    #[test]
    fn pop_at_and_find_address_packets_by_extended_sequence_number() {
        let mut buffer = JitterBuffer::new(64);
        let first = buffer.push(packet(1, 100, 0)).expect("push");
        let second = buffer.push(packet(1, 101, 0)).expect("push");

        assert!(buffer.find(second).is_some());
        assert!(buffer.find(second + 10).is_none());

        assert_eq!(101, sequence_of(&buffer.pop_at(second).expect("pop_at")));
        assert!(buffer.find(second).is_none());
        assert_eq!(100, sequence_of(&buffer.pop_at(first).expect("pop_at")));
        assert!(buffer.is_empty());
    }

    #[test]
    fn the_front_reports_the_next_packet_due() {
        let mut buffer = JitterBuffer::new(64);
        assert_eq!(None, buffer.front_sequence());
        assert_eq!(None, buffer.front_timestamp());

        buffer.push(packet(1, 8, 9000)).expect("push");
        buffer.push(packet(1, 7, 3000)).expect("push");

        assert_eq!(Some(7), buffer.front_sequence());
        assert_eq!(Some(3000), buffer.front_timestamp());
        assert_eq!(7, sequence_of(buffer.peek().expect("peek")));
        assert_eq!(2, buffer.len(), "peeking does not remove");
    }

    /// Upstream returns `ErrPopWhileBuffering` from `Pop` — a "try again later" sentinel its
    /// synchronous reader needs. Sans-I/O has no use for it: not being ready yet is `None`.
    #[test]
    fn nothing_is_handed_out_while_buffering() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 1, 0)).expect("push");

        assert_eq!(
            State::Buffering,
            buffer.state(),
            "a fresh buffer fills first"
        );
        assert!(buffer.pop().is_none(), "no packets while buffering");
        assert_eq!(1, buffer.len(), "and the packet is still held, not dropped");
        assert_eq!(
            0,
            buffer.stats().underflow,
            "declining to emit while buffering is not an underflow"
        );

        buffer.begin_emitting();
        assert_eq!(1, sequence_of(&buffer.pop().expect("now emitting")));
    }

    #[test]
    fn asking_an_empty_emitting_buffer_for_a_packet_is_an_underflow() {
        let mut buffer = JitterBuffer::new(64);
        buffer.begin_emitting();

        assert!(buffer.pop().is_none());
        assert_eq!(1, buffer.stats().underflow, "playout asked and got nothing");

        buffer.begin_buffering();
        assert!(buffer.pop().is_none());
        assert_eq!(
            1,
            buffer.stats().underflow,
            "but a buffering stream is not underflowing — it has not started"
        );
    }

    /// A gap does not stall the stream. Upstream pops strictly at its playout head and underflows
    /// on any missing sequence number; here the deadline above decides whether a gap is worth
    /// waiting for, and this hands over what is due.
    #[test]
    fn a_gap_does_not_stall_playout() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 1, 0)).expect("push");
        buffer.push(packet(1, 3, 0)).expect("push"); // 2 never arrives

        assert_eq!(vec![1, 3], drain(&mut buffer));
    }

    #[test]
    fn packets_are_addressable_by_their_wire_sequence_number() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 100, 0)).expect("push");
        buffer.push(packet(1, 101, 0)).expect("push");

        assert_eq!(
            101,
            sequence_of(buffer.peek_at_sequence(101).expect("peek"))
        );
        assert!(buffer.peek_at_sequence(999).is_none());
        assert_eq!(2, buffer.len(), "peeking does not remove");

        assert_eq!(101, sequence_of(&buffer.pop_at_sequence(101).expect("pop")));
        assert!(buffer.peek_at_sequence(101).is_none());
        assert!(buffer.pop_at_sequence(101).is_none(), "already taken");
        assert_eq!(1, buffer.len());
    }

    /// Addressing by wire number has to keep working across a wrap, where two held packets differ
    /// by a cycle in the ordering but are ordinary neighbours on the wire.
    #[test]
    fn addressing_by_wire_sequence_number_works_across_a_wrap() {
        let mut buffer = JitterBuffer::new(64);
        for sequence_number in [65534u16, 65535, 0, 1] {
            buffer.push(packet(1, sequence_number, 0)).expect("push");
        }

        assert_eq!(
            0,
            sequence_of(buffer.peek_at_sequence(0).expect("post-wrap"))
        );
        assert_eq!(
            65535,
            sequence_of(buffer.peek_at_sequence(65535).expect("pre-wrap"))
        );
        assert_eq!(0, sequence_of(&buffer.pop_at_sequence(0).expect("pop 0")));
        assert_eq!(vec![65534, 65535, 1], drain(&mut buffer));
    }

    /// One packet per call, matching upstream's `PopAtTimestamp`: a video frame spans several
    /// packets sharing a timestamp, and releasing the frame means calling until it yields `None`.
    #[test]
    fn packets_are_addressable_by_rtp_timestamp() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 10, 9000)).expect("push");
        buffer.push(packet(1, 11, 9000)).expect("push"); // same frame
        buffer.push(packet(1, 12, 12000)).expect("push"); // next frame

        assert_eq!(
            10,
            sequence_of(&buffer.pop_at_timestamp(9000).expect("first of the frame")),
            "the lowest sequence number of that timestamp comes out first"
        );
        assert_eq!(
            11,
            sequence_of(&buffer.pop_at_timestamp(9000).expect("second of the frame"))
        );
        assert!(
            buffer.pop_at_timestamp(9000).is_none(),
            "the frame is fully released"
        );
        assert!(buffer.pop_at_timestamp(4242).is_none(), "no such timestamp");

        assert_eq!(1, buffer.len(), "the next frame is untouched");
        assert_eq!(vec![12], drain(&mut buffer));
    }

    /// Taking a packet out by sequence number or timestamp still marks that position played out,
    /// or a straggler could be emitted behind it.
    #[test]
    fn addressed_removal_also_marks_the_position_released() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 5, 0)).expect("push");
        buffer.push(packet(1, 6, 0)).expect("push");

        buffer.pop_at_sequence(6).expect("pop 6");
        assert_eq!(
            Err(Rejected::Late),
            buffer.push(packet(1, 6, 0)),
            "6 has been played out"
        );
        assert_eq!(
            Err(Rejected::Late),
            buffer.push(packet(1, 5, 0)),
            "and so has everything before it"
        );
    }

    #[test]
    fn reset_clears_the_contents_but_keeps_the_stream_and_counters() {
        let mut buffer = JitterBuffer::new(64);
        buffer.push(packet(1, 5, 0)).expect("push");
        buffer.begin_emitting();
        buffer.pop().expect("release");
        buffer.push(packet(1, 5, 0)).ok(); // counted late

        buffer.reset();

        assert!(buffer.is_empty());
        assert_eq!(Some(1), buffer.ssrc(), "still this stream's buffer");
        assert_eq!(1, buffer.stats().late, "history is not erased");
        assert_eq!(
            State::Buffering,
            buffer.state(),
            "a restarted stream re-accumulates before playout resumes"
        );
        // The release anchor is gone, so the stream may restart at any sequence number.
        assert!(buffer.push(packet(1, 5, 0)).is_ok());
    }
}
