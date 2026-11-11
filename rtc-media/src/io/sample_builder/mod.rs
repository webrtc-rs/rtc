#[cfg(test)]
mod metadata_test;
#[cfg(test)]
mod sample_builder_test;
#[cfg(test)]
mod sample_sequence_location_test;

/// Tracks where a sample sits within the RTP sequence-number space.
pub mod sample_sequence_location;

use self::sample_sequence_location::{Comparison, SampleSequenceLocation};
use crate::Sample;
use bytes::Bytes;
use rtp::Packet;
use rtp::packetizer::Depacketizer;
use std::time::{Duration, Instant};

fn is_padding(packet: &Packet) -> bool {
    packet.header.padding && packet.payload.is_empty()
}

/// SampleBuilder buffers packets until media frames are complete.
pub struct SampleBuilder<T: Depacketizer, M = ()> {
    /// how many packets to wait until we get a valid Sample
    max_late: u16,
    /// max timestamp between old and new timestamps before dropping packets
    max_late_timestamp: u32,
    /// Require the depacketizer's partition tail on every assembly path.
    require_tail: bool,
    buffer: Vec<Option<Packet>>,
    prepared_samples: Vec<Option<(Sample, Option<M>)>>,
    last_sample_timestamp: Option<u32>,

    /// Interface that allows us to take RTP packets to samples
    depacketizer: T,
    packet_head_handler: fn(&T, &Packet) -> M,

    /// sample_rate allows us to compute duration of media.SamplecA
    sample_rate: u32,

    /// filled contains the head/tail of the packets inserted into the buffer
    filled: SampleSequenceLocation,

    /// active contains the active head/tail of the timestamp being actively processed
    active: SampleSequenceLocation,

    /// prepared contains the samples that have been processed to date
    prepared: SampleSequenceLocation,

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
    pub fn new(max_late: u16, depacketizer: T, sample_rate: u32) -> Self {
        Self::new_with_packet_head_handler(max_late, depacketizer, sample_rate, |_, _| ())
    }
}

impl<T: Depacketizer, M> SampleBuilder<T, M> {
    /// Constructs a builder with owned metadata for each assembled sample.
    ///
    /// The handler runs after the first media packet is successfully depacketized,
    /// before later packets can change the depacketizer. Its result is kept
    /// with the sample only if the entire assembly succeeds; otherwise it is
    /// dropped. A sample containing only skipped padding has no metadata.
    /// Use [`Self::pop_with_metadata`] to retrieve the pair.
    pub fn new_with_packet_head_handler(
        max_late: u16,
        depacketizer: T,
        sample_rate: u32,
        packet_head_handler: fn(&T, &Packet) -> M,
    ) -> Self {
        Self {
            max_late,
            max_late_timestamp: 0,
            require_tail: false,
            buffer: vec![None; u16::MAX as usize + 1],
            prepared_samples: (0..=u16::MAX as usize).map(|_| None).collect(),
            last_sample_timestamp: None,
            depacketizer,
            packet_head_handler,
            sample_rate,
            filled: SampleSequenceLocation::new(),
            active: SampleSequenceLocation::new(),
            prepared: SampleSequenceLocation::new(),
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

    /// Emit only complete partitions, without waiting for a later timestamp.
    ///
    /// The depacketizer's tail check must identify a complete partition (for
    /// example H264's RTP marker). This policy also applies during expiry:
    /// incomplete partitions are discarded, never emitted as partial samples.
    /// `duration` is zero when no following timestamp is available.
    pub fn with_complete_samples(mut self) -> Self {
        self.require_tail = true;
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
            if let Some(packet) = self.buffer[i as usize].as_ref().filter(|p| !is_padding(p)) {
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
            if let Some(packet) = self.buffer[i as usize].as_ref().filter(|p| !is_padding(p)) {
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
            Some(
                (self.buffer[location.head as usize])
                    .as_ref()?
                    .header
                    .timestamp,
            )
        }
    }

    fn release_packet(&mut self, i: u16) {
        self.buffer[i as usize] = None;
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

        // Once timestamps expire, retire head holes until a packet can be aged again.
        let mut purging_expired_timestamp = false;
        while self.filled.has_data()
            && (self.too_old(&self.filled)
                || self.filled.count() > self.max_late
                || (purging_expired_timestamp && self.buffer[self.filled.head as usize].is_none()))
        {
            purging_expired_timestamp |= self.too_old(&self.filled);
            if self.active.empty() {
                // refill the active based on the filled packets
                self.active = self.filled;
            }

            if self.active.has_data() && (self.active.head == self.filled.head) {
                // attempt to force the active packet to be consumed even though
                // outstanding data may be pending arrival
                let head = self.filled.head;
                let err = match self.build_sample(now, true) {
                    Ok(_) => continue,
                    Err(e) => e,
                };
                // Padding retirement may already have satisfied the bound.
                if self.require_tail && self.filled.head != head {
                    continue;
                }

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
        self.buffer[sequence_number as usize] = Some(p);
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
        self.purge_buffers(now);
    }

    /// Creates a sample from a valid collection of RTP Packets by
    /// walking forwards building a sample if everything looks good clear and
    /// update buffer+values
    fn build_sample(
        &mut self,
        now: Instant,
        purging_buffers: bool,
    ) -> Result<SampleSequenceLocation, BuildError> {
        if self.active.has_data() && self.filled.compare(self.active.tail) == Comparison::Inside {
            self.active.tail = self.filled.tail;
        }
        if self.require_tail {
            let window = if self.active.empty() {
                self.filled
            } else {
                self.active
            };
            let mut head = window.head;
            while window.compare(head) == Comparison::Inside
                && self.buffer[head as usize].as_ref().is_some_and(is_padding)
            {
                head = head.wrapping_add(1);
            }
            // An isolated padding packet may precede an out-of-order FU start.
            // Retire the prefix only once the next media partition has a head.
            if head != window.head
                && window.compare(head) == Comparison::Inside
                && self.buffer[head as usize]
                    .as_ref()
                    .is_some_and(|packet| self.depacketizer.is_partition_head(&packet.payload))
            {
                let mut i = window.head;
                while i != head {
                    self.release_packet(i);
                    if self.filled.head == i {
                        self.filled.head = i.wrapping_add(1);
                    }
                    i = i.wrapping_add(1);
                }
                if self.active.has_data() {
                    self.active.head = head;
                }
            }
        }
        if self.active.empty() {
            // A marker may arrive before its partition head. Do not commit the
            // initial read position until reordering supplies that head.
            if self.require_tail
                && self.buffer[self.filled.head as usize]
                    .as_ref()
                    .is_some_and(|packet| !self.depacketizer.is_partition_head(&packet.payload))
            {
                return Err(BuildError::GapInSegment);
            }
            self.active = self.filled;
        }

        if self.active.empty() {
            return Err(BuildError::NoActiveSegment);
        }

        let mut consume = SampleSequenceLocation::new();
        let mut complete = false;

        let mut i = self.active.head;
        // `self.active` isn't modified in the loop, fetch the timestamp once and cache it.
        let head_timestamp = self.fetch_timestamp(&self.active);
        while let Some(ref packet) = self.buffer[i as usize] {
            if self.active.compare(i) == Comparison::After {
                break;
            }
            if is_padding(packet) {
                i = i.wrapping_add(1);
                continue;
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
                complete = true;
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

        if self.require_tail && !complete {
            return Err(BuildError::PendingTimestampPacket);
        }

        if !purging_buffers && self.buffer[consume.tail as usize].is_none() {
            // wait for the next packet after this set of packets to arrive
            // to ensure at least one post sample timestamp is known
            // (unless we have to release right now)
            return Err(BuildError::PendingTimestampPacket);
        }

        let sample_timestamp = self.fetch_timestamp(&self.active).unwrap_or(0);
        let mut after_timestamp = sample_timestamp;

        // scan for any packet after the current and use that time stamp as the diff point
        for i in consume.tail..self.active.tail {
            if let Some(packet) = self.buffer[i as usize].as_ref().filter(|p| !is_padding(p)) {
                after_timestamp = packet.header.timestamp;
                break;
            }
        }

        // prior to decoding all the packets, check if this packet
        // would end being disposed anyway
        let head_payload = self.buffer[consume.head as usize]
            .as_ref()
            .map(|p| &p.payload)
            .ok_or(BuildError::GapInSegment)?;
        if !self.depacketizer.is_partition_head(head_payload) {
            if self.require_tail {
                return Err(BuildError::GapInSegment);
            }
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
        let mut metadata = None;
        let sample_data: Bytes = if consume.count() == 1 {
            let packet = self.buffer[consume.head as usize]
                .as_ref()
                .ok_or(BuildError::GapInSegment)?;
            let data = self
                .depacketizer
                .depacketize(&packet.payload)
                .map_err(|_| BuildError::DepacketizerFailed)?;
            metadata = Some((self.packet_head_handler)(&self.depacketizer, packet));
            data
        } else {
            let mut data: Vec<u8> = Vec::new();
            let mut i = consume.head;
            while i != consume.tail {
                let packet = self.buffer[i as usize]
                    .as_ref()
                    .ok_or(BuildError::GapInSegment)?;
                // RTP padding occupies a sequence number but has no codec data.
                if is_padding(packet) {
                    i = i.wrapping_add(1);
                    continue;
                }

                let p = self
                    .depacketizer
                    .depacketize(&packet.payload)
                    .map_err(|_| BuildError::DepacketizerFailed)?;

                if metadata.is_none() {
                    metadata = Some((self.packet_head_handler)(&self.depacketizer, packet));
                }

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

        self.prepared_samples[self.prepared.tail as usize] = Some((sample, metadata));
        self.prepared.tail = self.prepared.tail.wrapping_add(1);

        self.purge_consumed_location(&consume, true);
        self.purge_consumed_buffers();

        // Unlike duration-oriented pop, a complete partition can consume the
        // entire active window. Do not refill it from already consumed packets.
        if self.require_tail {
            while self.filled.has_data()
                && matches!(
                    consume.compare(self.filled.head),
                    Comparison::Before | Comparison::Inside
                )
            {
                self.purge_consumed_location(&consume, true);
            }
        }

        Ok(consume)
    }

    /// Compiles pushed RTP packets into media samples and then
    /// returns the next valid sample (or None if no sample is compiled).
    pub fn pop(&mut self, now: Instant) -> Option<Sample> {
        self.pop_with_metadata(now).map(|(sample, _)| sample)
    }

    /// Returns the next valid sample and its owned first-packet metadata.
    ///
    /// Samples prepared during [`Self::push`] retain their own metadata even
    /// if later samples are assembled before this call returns them.
    pub fn pop_with_metadata(&mut self, now: Instant) -> Option<(Sample, Option<M>)> {
        let _ = self.build_sample(now, self.require_tail);

        if self.prepared.empty() {
            return None;
        }
        let result = self.prepared_samples[self.prepared.head as usize].take();
        self.prepared.head = self.prepared.head.wrapping_add(1);
        result
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
