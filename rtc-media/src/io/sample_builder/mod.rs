#[cfg(test)]
mod sample_builder_test;
#[cfg(test)]
mod sample_sequence_location_test;

/// Tracks where a sample sits within the RTP sequence-number space.
pub mod sample_sequence_location;

use self::sample_sequence_location::{Comparison, SampleSequenceLocation, SequenceLookup};
use crate::Sample;
use bytes::Bytes;
use rtp::Packet;
use rtp::packetizer::Depacketizer;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Packet slots allocated by the first push. The ring doubles from here only when the
/// packets being held span more sequence numbers than it has slots.
const MIN_PACKET_SLOTS: usize = 16;

/// Default for [`SampleBuilder::with_max_prepared_samples`], matching what the fixed
/// sequence-indexed table this queue replaced could hold. The queue grows on demand, so the
/// limit costs nothing until a caller lets samples pile up.
const DEFAULT_MAX_PREPARED_SAMPLES: usize = u16::MAX as usize;

/// Capacity the prepared-sample queue keeps once a backlog has been drained.
const RETAINED_PREPARED_CAPACITY: usize = 64;

/// SampleBuilder buffers packets until media frames are complete.
pub struct SampleBuilder<T: Depacketizer> {
    /// how many packets to wait until we get a valid Sample
    max_late: u16,
    /// max timestamp between old and new timestamps before dropping packets
    max_late_timestamp: u32,
    /// packets inserted but not yet released, looked up by sequence number
    buffer: PacketRing,
    /// prepared contains the samples that have been processed to date
    prepared: PreparedSamples,
    last_sample_timestamp: Option<u32>,

    /// Interface that allows us to take RTP packets to samples
    depacketizer: T,

    /// sample_rate allows us to compute duration of media.SamplecA
    sample_rate: u32,

    /// filled contains the head/tail of the packets inserted into the buffer
    filled: SampleSequenceLocation,

    /// active contains the active head/tail of the timestamp being actively processed
    active: SampleSequenceLocation,

    /// number of packets forced to be dropped
    dropped_packets: u16,

    /// number of padding packets detected and dropped. This number will be a subset of
    /// `dropped_packets`
    padding_packets: u16,
}

impl<T: Depacketizer> SampleBuilder<T> {
    /// Constructs a new SampleBuilder.
    /// `max_late` is how long to wait until we can construct a completed [`Sample`].
    /// `max_late` is measured in RTP packet sequence numbers.
    /// A large max_late will result in less packet loss but higher latency.
    /// The depacketizer extracts media samples from RTP packets.
    ///
    /// Nothing is allocated until the first packet is pushed. Packet storage then grows
    /// with the span of sequence numbers being held, which `max_late` bounds.
    pub fn new(max_late: u16, depacketizer: T, sample_rate: u32) -> Self {
        Self {
            max_late,
            max_late_timestamp: 0,
            buffer: PacketRing::new(max_late),
            prepared: PreparedSamples::new(DEFAULT_MAX_PREPARED_SAMPLES),
            last_sample_timestamp: None,
            depacketizer,
            sample_rate,
            filled: SampleSequenceLocation::new(),
            active: SampleSequenceLocation::new(),
            dropped_packets: 0,
            padding_packets: 0,
        }
    }

    /// Sets how long to wait for a missing packet before giving up on the sample it belongs to.
    ///
    /// Bounds head-of-line blocking: without it a single lost packet would stall reassembly
    /// indefinitely.
    pub fn with_max_time_delay(mut self, max_late_duration: Duration) -> Self {
        self.max_late_timestamp =
            (self.sample_rate as u128 * max_late_duration.as_millis() / 1000) as u32;
        self
    }

    /// Sets how many completed samples may wait to be popped. Defaults to 65,535; storage
    /// grows only as samples actually wait.
    ///
    /// [`push`](Self::push) completes samples too when `max_late` or the maximum time delay
    /// forces the oldest packets out, so a caller that pushes without popping builds up a
    /// backlog. Once it is full, each newly completed sample discards the oldest waiting one,
    /// and the discarded sample's packets are added to the next returned sample's
    /// [`prev_dropped_packets`](Sample::prev_dropped_packets).
    ///
    /// One push can complete up to `max_late + 1` samples, so a limit below that can discard
    /// samples even when the caller pops after every push. Values below 1 are treated as 1.
    pub fn with_max_prepared_samples(mut self, max_prepared_samples: usize) -> Self {
        self.prepared.max_len = max_prepared_samples.max(1);
        self
    }

    fn too_old(&self, location: &SampleSequenceLocation) -> bool {
        if self.max_late_timestamp == 0 {
            return false;
        }

        let mut found_head: Option<u32> = None;
        let mut found_tail: Option<u32> = None;

        let mut i = location.head;
        while i != location.tail {
            if let Some(packet) = self.buffer.get(i) {
                found_head = Some(packet.header.timestamp);
                break;
            }
            i = i.wrapping_add(1);
        }

        if found_head.is_none() {
            return false;
        }

        let mut i = location.tail.wrapping_sub(1);
        while i != location.head {
            if let Some(packet) = self.buffer.get(i) {
                found_tail = Some(packet.header.timestamp);
                break;
            }
            i = i.wrapping_sub(1);
        }

        if found_tail.is_none() {
            return false;
        }

        found_tail.unwrap().wrapping_sub(found_head.unwrap()) > self.max_late_timestamp
    }

    /// Returns the timestamp associated with a given sample location
    fn fetch_timestamp(&self, location: &SampleSequenceLocation) -> Option<u32> {
        if location.empty() {
            None
        } else {
            Some(self.buffer.get(location.head)?.header.timestamp)
        }
    }

    fn release_packet(&mut self, i: u16) {
        self.buffer.release(i);
    }

    /// Clears all buffers that have already been consumed by
    /// popping.
    fn purge_consumed_buffers(&mut self) {
        let active = self.active;
        self.purge_consumed_location(&active, false);
    }

    /// Clears all buffers that have already been consumed
    /// during a sample building method.
    fn purge_consumed_location(&mut self, consume: &SampleSequenceLocation, force_consume: bool) {
        if !self.filled.has_data() {
            return;
        }
        match consume.compare(self.filled.head) {
            Comparison::Inside if force_consume => {
                self.release_packet(self.filled.head);
                self.filled.head = self.filled.head.wrapping_add(1);
            }
            Comparison::Before => {
                self.release_packet(self.filled.head);
                self.filled.head = self.filled.head.wrapping_add(1);
            }
            _ => {}
        }
    }

    /// Flushes all buffers that are already consumed or those buffers
    /// that are too late to consume.
    fn purge_buffers(&mut self, now: Instant) {
        self.purge_consumed_buffers();

        while (self.too_old(&self.filled) || (self.filled.count() > self.max_late))
            && self.filled.has_data()
        {
            if self.active.empty() {
                // refill the active based on the filled packets
                self.active = self.filled;
            }

            if self.active.has_data() && (self.active.head == self.filled.head) {
                // attempt to force the active packet to be consumed even though
                // outstanding data may be pending arrival
                let err = match self.build_sample(now, true) {
                    Ok(_) => continue,
                    Err(e) => e,
                };

                if !matches!(err, BuildError::InvalidPartition(_)) {
                    // In the InvalidPartition case `build_sample` will have already adjusted `dropped_packets`.
                    self.dropped_packets += 1;
                }

                // could not build the sample so drop it
                self.active.head = self.active.head.wrapping_add(1);
            }

            self.release_packet(self.filled.head);
            self.filled.head = self.filled.head.wrapping_add(1);
        }
    }

    /// Adds an RTP Packet to self's buffer.
    ///
    /// Push does not copy the input. If you wish to reuse
    /// this memory make sure to copy before calling push
    pub fn push(&mut self, now: Instant, p: Packet) {
        let sequence_number = p.header.sequence_number;
        match self.filled.compare(sequence_number) {
            Comparison::Void => {
                self.filled.head = sequence_number;
                self.filled.tail = sequence_number.wrapping_add(1);
            }
            Comparison::Before => {
                self.filled.head = sequence_number;
            }
            Comparison::After => {
                self.filled.tail = sequence_number.wrapping_add(1);
            }
            _ => {}
        }
        self.buffer.insert(p, &self.filled);
        self.purge_buffers(now);
        self.buffer.settle(&self.filled);
    }

    /// Creates a sample from a valid collection of RTP Packets by
    /// walking forwards building a sample if everything looks good clear and
    /// update buffer+values
    fn build_sample(
        &mut self,
        now: Instant,
        purging_buffers: bool,
    ) -> Result<SampleSequenceLocation, BuildError> {
        if self.active.empty() {
            self.active = self.filled;
        }

        if self.active.empty() {
            return Err(BuildError::NoActiveSegment);
        }

        if self.filled.compare(self.active.tail) == Comparison::Inside {
            self.active.tail = self.filled.tail;
        }

        let mut consume = SampleSequenceLocation::new();

        let mut i = self.active.head;
        // `self.active` isn't modified in the loop, fetch the timestamp once and cache it.
        let head_timestamp = self.fetch_timestamp(&self.active);
        while let Some(packet) = self.buffer.get(i) {
            if self.active.compare(i) == Comparison::After {
                break;
            }
            let is_same_timestamp = head_timestamp.map(|t| packet.header.timestamp == t);
            let is_different_timestamp = is_same_timestamp.map(std::ops::Not::not);
            let is_partition_tail = self
                .depacketizer
                .is_partition_tail(packet.header.marker, &packet.payload);

            // If the timestamp is not the same it might be because the next packet is both a start
            // and end of the next partition in which case a sample should be generated now. This
            // can happen when padding packets are used .e.g:
            //
            // p1(t=1), p2(t=1), p3(t=1), p4(t=2, marker=true, start=true)
            //
            // In thic case the generated sample should be p1 through p3, but excluding p4 which is
            // its own sample.
            if is_partition_tail && is_same_timestamp.unwrap_or(true) {
                consume.head = self.active.head;
                consume.tail = i.wrapping_add(1);
                break;
            }

            if is_different_timestamp.unwrap_or(false) {
                consume.head = self.active.head;
                consume.tail = i;
                break;
            }
            i = i.wrapping_add(1);
        }

        if consume.empty() {
            return Err(BuildError::NothingToConsume);
        }

        if !purging_buffers && self.buffer.get(consume.tail).is_none() {
            // wait for the next packet after this set of packets to arrive
            // to ensure at least one post sample timestamp is known
            // (unless we have to release right now)
            return Err(BuildError::PendingTimestampPacket);
        }

        let sample_timestamp = self.fetch_timestamp(&self.active).unwrap_or(0);
        let mut after_timestamp = sample_timestamp;

        // scan for any packet after the current and use that time stamp as the diff point
        for i in consume.tail..self.active.tail {
            if let Some(packet) = self.buffer.get(i) {
                after_timestamp = packet.header.timestamp;
                break;
            }
        }

        // prior to decoding all the packets, check if this packet
        // would end being disposed anyway
        let head_payload = self
            .buffer
            .get(consume.head)
            .map(|p| &p.payload)
            .ok_or(BuildError::GapInSegment)?;
        if !self.depacketizer.is_partition_head(head_payload) {
            // libWebRTC will sometimes send several empty padding packets to smooth out send
            // rate. These packets don't carry any media payloads.
            let is_padding = consume.range(&self.buffer).all(|p| {
                p.map(|p| {
                    self.last_sample_timestamp == Some(p.header.timestamp) && p.payload.is_empty()
                })
                .unwrap_or(false)
            });

            self.dropped_packets += consume.count();
            if is_padding {
                self.padding_packets += consume.count();
            }
            self.purge_consumed_location(&consume, true);
            self.purge_consumed_buffers();

            self.active.head = consume.tail;
            return Err(BuildError::InvalidPartition(consume));
        }

        // the head set of packets is now fully consumed
        self.active.head = consume.tail;

        // Assemble the sample payload from the consumed packets. For the common
        // single-packet sample (all audio, and any frame that fits one RTP
        // packet) hand back the depacketized `Bytes` directly — it is
        // refcounted, so no copy is needed. Only multi-packet samples require
        // concatenation, and even then `Bytes::from(data)` reuses the `Vec`'s
        // buffer instead of copying it a second time.
        let sample_data: Bytes = if consume.count() == 1 {
            let payload = self
                .buffer
                .get(consume.head)
                .map(|p| &p.payload)
                .ok_or(BuildError::GapInSegment)?;
            self.depacketizer
                .depacketize(payload)
                .map_err(|_| BuildError::DepacketizerFailed)?
        } else {
            let mut data: Vec<u8> = Vec::new();
            let mut i = consume.head;
            while i != consume.tail {
                let payload = self
                    .buffer
                    .get(i)
                    .map(|p| &p.payload)
                    .ok_or(BuildError::GapInSegment)?;

                let p = self
                    .depacketizer
                    .depacketize(payload)
                    .map_err(|_| BuildError::DepacketizerFailed)?;

                data.extend_from_slice(&p);
                i = i.wrapping_add(1);
            }
            Bytes::from(data)
        };
        let samples = after_timestamp.wrapping_sub(sample_timestamp);

        let sample = Sample {
            data: sample_data,
            timestamp: now,
            duration: Duration::from_secs_f64((samples as f64) / (self.sample_rate as f64)),
            packet_timestamp: sample_timestamp,
            prev_dropped_packets: self.dropped_packets,
            prev_padding_packets: self.padding_packets,
        };

        self.dropped_packets = 0;
        self.padding_packets = 0;
        self.last_sample_timestamp = Some(sample_timestamp);

        self.prepared.push(sample, consume.count());

        self.purge_consumed_location(&consume, true);
        self.purge_consumed_buffers();

        Ok(consume)
    }

    /// Compiles pushed RTP packets into media samples and then
    /// returns the next valid sample (or None if no sample is compiled).
    pub fn pop(&mut self, now: Instant) -> Option<Sample> {
        // Building into a full backlog would discard its oldest sample, the one about to be
        // returned; hand that out first.
        if !self.prepared.is_full() {
            let _ = self.build_sample(now, false);
        }

        self.prepared.pop()
    }

    /// Compiles pushed RTP packets into media samples and then
    /// returns the next valid sample with its associated RTP timestamp (or `None` if
    /// no sample is compiled).
    pub fn pop_with_timestamp(&mut self, now: Instant) -> Option<(Sample, u32)> {
        if let Some(sample) = self.pop(now) {
            let timestamp = sample.packet_timestamp;
            Some((sample, timestamp))
        } else {
            None
        }
    }
}

/// Packets awaiting assembly, in a ring indexed by sequence number.
///
/// The ring is allocated by the first push and doubles only when the packets held span
/// more sequence numbers than it has slots, so it follows the reorder window in use, which
/// `max_late` bounds, rather than covering the whole `u16` sequence space. A slot is
/// matched on its packet's own sequence number, so a slot reused for a later sequence
/// number never answers for an earlier one.
struct PacketRing {
    /// Length is zero or a power of two.
    slots: Vec<Option<Packet>>,
    /// The packet being pushed, when its slot holds another packet still held (one a
    /// multiple of the ring's length away), until the purge that follows the push has run.
    /// Growing the ring for such a jump instead would keep it large after the purge.
    parked: Option<Packet>,
    /// Slots allocated by the first push.
    initial_slots: usize,
}

impl PacketRing {
    fn new(max_late: u16) -> Self {
        Self {
            slots: Vec::new(),
            parked: None,
            initial_slots: (max_late as usize + 1)
                .next_power_of_two()
                .min(MIN_PACKET_SLOTS),
        }
    }

    /// The slot `seq` maps to; out of bounds only before the first push.
    #[inline]
    fn index(&self, seq: u16) -> usize {
        seq as usize & self.slots.len().wrapping_sub(1)
    }

    #[inline]
    fn get(&self, seq: u16) -> Option<&Packet> {
        match self.slots.get(self.index(seq)) {
            Some(Some(p)) if p.header.sequence_number == seq => Some(p),
            _ => self
                .parked
                .as_ref()
                .filter(|p| p.header.sequence_number == seq),
        }
    }

    #[inline]
    fn release(&mut self, seq: u16) {
        let is_seq = |p: &Packet| p.header.sequence_number == seq;
        let i = self.index(seq);
        if let Some(slot) = self.slots.get_mut(i)
            && slot.as_ref().is_some_and(is_seq)
        {
            *slot = None;
        } else if self.parked.as_ref().is_some_and(is_seq) {
            self.parked = None;
        }
    }

    /// Stores `p`, replacing an earlier packet with the same sequence number (a duplicate)
    /// or one left outside `held`. If its slot holds another packet inside `held`, `p` is
    /// parked until [`settle`](Self::settle).
    // Always inlined: an out-of-line call copies the packet through it on every push.
    #[inline(always)]
    fn insert(&mut self, p: Packet, held: &SampleSequenceLocation) {
        if self.slots.is_empty() {
            self.slots = vec![None; self.initial_slots];
        }
        let seq = p.header.sequence_number;
        let i = self.index(seq);
        if is_held_elsewhere(&self.slots[i], seq, held) {
            debug_assert!(self.parked.is_none());
            self.parked = Some(p);
        } else {
            self.slots[i] = Some(p);
        }
    }

    /// Moves a parked packet that survived the purge into the ring, growing the ring until
    /// its slot is free. The purge has brought what is held within `max_late` sequence
    /// numbers, which bounds the growth.
    #[inline]
    fn settle(&mut self, held: &SampleSequenceLocation) {
        if self.parked.is_some() {
            self.settle_parked(held);
        }
    }

    #[cold]
    fn settle_parked(&mut self, held: &SampleSequenceLocation) {
        let Some(p) = self.parked.take() else {
            return;
        };
        let seq = p.header.sequence_number;
        while is_held_elsewhere(&self.slots[self.index(seq)], seq, held) {
            self.grow();
        }
        let i = self.index(seq);
        self.slots[i] = Some(p);
    }

    /// Doubles the ring, moving each packet to the slot its sequence number now maps to.
    fn grow(&mut self) {
        let len = self.slots.len() * 2;
        let mut slots = vec![None; len];
        for p in self.slots.drain(..).flatten() {
            let i = p.header.sequence_number as usize & (len - 1);
            slots[i] = Some(p);
        }
        self.slots = slots;
    }
}

impl SequenceLookup for PacketRing {
    type Item = Packet;

    #[inline]
    fn lookup(&self, seq: u16) -> Option<&Packet> {
        self.get(seq)
    }
}

/// Whether `slot`, the slot `seq` maps to, holds a different packet that is still inside
/// `held`. Never true once the ring covers the whole sequence space.
#[inline]
fn is_held_elsewhere(slot: &Option<Packet>, seq: u16, held: &SampleSequenceLocation) -> bool {
    slot.as_ref().is_some_and(|p| {
        let other = p.header.sequence_number;
        other != seq && held.compare(other) == Comparison::Inside
    })
}

/// Completed samples waiting to be popped, oldest first.
struct PreparedSamples {
    samples: VecDeque<PreparedSample>,
    /// At least 1.
    max_len: usize,
}

struct PreparedSample {
    sample: Sample,
    /// RTP packets the sample was built from.
    packets: u16,
}

impl PreparedSamples {
    fn new(max_len: usize) -> Self {
        Self {
            samples: VecDeque::new(),
            max_len,
        }
    }

    #[cfg(test)]
    fn empty(&self) -> bool {
        self.samples.is_empty()
    }

    #[cfg(test)]
    fn count(&self) -> usize {
        self.samples.len()
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.samples.len() >= self.max_len
    }

    /// Queues `sample`, first discarding the oldest waiting samples if the queue is full.
    /// Their packets, and the drops they reported, carry over to the sample that becomes
    /// the oldest.
    // Always inlined for the same reason as `PacketRing::insert`.
    #[inline(always)]
    fn push(&mut self, mut sample: Sample, packets: u16) {
        if self.is_full() {
            self.make_room(&mut sample);
        }
        self.samples.push_back(PreparedSample { sample, packets });
    }

    #[cold]
    fn make_room(&mut self, incoming: &mut Sample) {
        while self.is_full() {
            let Some(discarded) = self.samples.pop_front() else {
                break;
            };
            let next = match self.samples.front_mut() {
                Some(next) => &mut next.sample,
                None => &mut *incoming,
            };
            next.prev_dropped_packets = next
                .prev_dropped_packets
                .saturating_add(discarded.sample.prev_dropped_packets)
                .saturating_add(discarded.packets);
            next.prev_padding_packets = next
                .prev_padding_packets
                .saturating_add(discarded.sample.prev_padding_packets);
        }
    }

    #[inline]
    fn pop(&mut self) -> Option<Sample> {
        let prepared = self.samples.pop_front()?;
        if self.samples.is_empty() && self.samples.capacity() > RETAINED_PREPARED_CAPACITY {
            // the caller has caught up with a backlog; don't keep its storage
            self.samples.shrink_to(RETAINED_PREPARED_CAPACITY);
        }
        Some(prepared.sample)
    }
}

// Computes the distance between two sequence numbers
/*pub(crate) fn seqnum_distance(head: u16, tail: u16) -> u16 {
    if head > tail {
        head.wrapping_add(tail)
    } else {
        tail - head
    }
}*/

pub(crate) fn seqnum_distance(x: u16, y: u16) -> u16 {
    let diff = x.wrapping_sub(y);
    if diff > 0xFFFF / 2 {
        0xFFFF - diff + 1
    } else {
        diff
    }
}

#[derive(Debug)]
enum BuildError {
    /// There's no active segment of RTP packets to consider yet.
    NoActiveSegment,

    /// No sample partition could be found in the active segment.
    NothingToConsume,

    /// A segment to consume was identified, but a subsequent packet is needed to determine the
    /// duration of the sample.
    PendingTimestampPacket,

    /// The active segment's head was not aligned with a sample partition head. Some packets were
    /// dropped.
    InvalidPartition(SampleSequenceLocation),

    /// There was a gap in the active segment because of one or more missing RTP packets.
    GapInSegment,

    /// We failed to depacketize an RTP packet.
    DepacketizerFailed,
}
