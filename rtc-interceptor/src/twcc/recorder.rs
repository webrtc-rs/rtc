//! TWCC Recorder - tracks packet arrival times and builds feedback packets.

use super::arrival_time_map::PacketArrivalTimeMap;
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, StatusVectorChunk,
    SymbolSizeTypeTcc, SymbolTypeTcc, TransportLayerCc,
};

/// Window for packet timestamps in microseconds (500ms).
const PACKET_WINDOW_MICROSECONDS: i64 = 500_000;

/// Maximum number of missing sequence numbers to include in feedback.
const MAX_MISSING_SEQUENCE_NUMBERS: i64 = 0x7FFE;

/// Scale factor for TWCC deltas (250 microseconds).
const TYPE_TCC_DELTA_SCALE_FACTOR: i64 = 250;

/// Chunk capacity limits.
const MAX_RUN_LENGTH_CAP: usize = 0x1fff; // 13 bits
const MAX_ONE_BIT_CAP: usize = 14;
const MAX_TWO_BIT_CAP: usize = 7;

/// Sequence number unwrapper to handle 16-bit wraparound.
struct SequenceUnwrapper {
    last_unwrapped: Option<i64>,
}

impl SequenceUnwrapper {
    fn new() -> Self {
        Self { last_unwrapped: None }
    }

    fn unwrap(&mut self, seq: u16) -> i64 {
        match self.last_unwrapped {
            None => {
                self.last_unwrapped = Some(seq as i64);
                seq as i64
            }
            Some(last) => {
                // Calculate the difference, handling wraparound
                let seq_i64 = seq as i64;
                let last_seq = (last & 0xFFFF) as i64;
                let mut diff = seq_i64 - last_seq;

                // Handle wraparound
                if diff > 0x8000 {
                    diff -= 0x10000;
                } else if diff < -0x8000 {
                    diff += 0x10000;
                }

                let unwrapped = last + diff;
                self.last_unwrapped = Some(unwrapped);
                unwrapped
            }
        }
    }
}

/// Records incoming RTP packets and their arrival times, building TWCC feedback.
pub(crate) struct Recorder {
    arrival_time_map: PacketArrivalTimeMap,
    sequence_unwrapper: SequenceUnwrapper,
    /// The first sequence number that will be included in the next feedback packet.
    start_sequence_number: Option<i64>,
    sender_ssrc: u32,
    media_ssrc: u32,
    fb_pkt_cnt: u8,
    packets_held: usize,
}

impl Recorder {
    /// Create a new Recorder with the given sender SSRC.
    pub(crate) fn new(sender_ssrc: u32) -> Self {
        Self {
            arrival_time_map: PacketArrivalTimeMap::new(),
            sequence_unwrapper: SequenceUnwrapper::new(),
            start_sequence_number: None,
            sender_ssrc,
            media_ssrc: 0,
            fb_pkt_cnt: 0,
            packets_held: 0,
        }
    }

    /// Record a packet arrival.
    pub(crate) fn record(&mut self, media_ssrc: u32, sequence_number: u16, arrival_time: i64) {
        self.media_ssrc = media_ssrc;

        // Unwrap the sequence number to get a monotonically increasing value.
        let unwrapped_sn = self.sequence_unwrapper.unwrap(sequence_number);
        self.maybe_cull_old_packets(unwrapped_sn, arrival_time);

        if self.start_sequence_number.is_none()
            || unwrapped_sn < self.start_sequence_number.unwrap()
        {
            self.start_sequence_number = Some(unwrapped_sn);
        }

        // We are only interested in the first time a packet is received.
        if self.arrival_time_map.has_received(unwrapped_sn) {
            return;
        }

        self.arrival_time_map.add_packet(unwrapped_sn, arrival_time);
        self.packets_held += 1;

        // Limit the range of sequence numbers to send feedback for.
        if let Some(start) = self.start_sequence_number {
            if start < self.arrival_time_map.begin_sequence_number() {
                self.start_sequence_number = Some(self.arrival_time_map.begin_sequence_number());
            }
        }
    }

    fn maybe_cull_old_packets(&mut self, sequence_number: i64, arrival_time: i64) {
        if let Some(start) = self.start_sequence_number {
            if start >= self.arrival_time_map.end_sequence_number()
                && arrival_time >= PACKET_WINDOW_MICROSECONDS
            {
                self.arrival_time_map.remove_old_packets(
                    sequence_number,
                    arrival_time - PACKET_WINDOW_MICROSECONDS,
                );
            }
        }
    }

    /// Returns the number of received packets currently held.
    #[allow(dead_code)]
    pub(crate) fn packets_held(&self) -> usize {
        self.packets_held
    }

    /// Build TWCC feedback packets for all recorded arrivals.
    pub(crate) fn build_feedback_packet(&mut self) -> Vec<Box<dyn rtcp::Packet>> {
        let Some(mut start_sn) = self.start_sequence_number else {
            return Vec::new();
        };

        let end_sn = self.arrival_time_map.end_sequence_number();
        let mut feedbacks: Vec<Box<dyn rtcp::Packet>> = Vec::new();

        while start_sn < end_sn {
            let Some(feedback) = self.maybe_build_feedback_packet(start_sn, end_sn) else {
                break;
            };
            start_sn = self.start_sequence_number.unwrap_or(end_sn);
            feedbacks.push(Box::new(feedback.get_rtcp()));
        }
        self.packets_held = 0;

        feedbacks
    }

    fn maybe_build_feedback_packet(
        &mut self,
        begin_seq_inclusive: i64,
        end_seq_exclusive: i64,
    ) -> Option<Feedback> {
        let start_sn_inclusive = self.arrival_time_map.clamp(begin_seq_inclusive);
        let end_sn_exclusive = self.arrival_time_map.clamp(end_seq_exclusive);

        let mut fb: Option<Feedback> = None;
        let mut next_sequence_number = begin_seq_inclusive;

        let mut seq = start_sn_inclusive;
        while seq < end_sn_exclusive {
            let Some((found_seq, arrival_time)) = self.arrival_time_map.find_next_at_or_after(seq)
            else {
                break;
            };
            seq = found_seq;
            if seq >= end_sn_exclusive {
                break;
            }

            if fb.is_none() {
                let mut new_fb = Feedback::new(self.sender_ssrc, self.media_ssrc, self.fb_pkt_cnt);
                self.fb_pkt_cnt = self.fb_pkt_cnt.wrapping_add(1);

                // Calculate base sequence number, limiting how far back we report missing packets.
                let base_sequence_number =
                    begin_seq_inclusive.max(seq - MAX_MISSING_SEQUENCE_NUMBERS);

                new_fb.set_base(base_sequence_number as u16, arrival_time);

                if !new_fb.add_received(seq as u16, arrival_time) {
                    // Could not add a single received packet.
                    self.start_sequence_number = Some(seq);
                    return None;
                }
                fb = Some(new_fb);
            } else if !fb.as_mut().unwrap().add_received(seq as u16, arrival_time) {
                // Could not add timestamp. Packet may be full.
                break;
            }

            next_sequence_number = seq + 1;
            seq += 1;
        }

        self.start_sequence_number = Some(next_sequence_number);
        fb
    }
}

/// Helper struct to build a single TransportLayerCC feedback packet.
struct Feedback {
    sender_ssrc: u32,
    media_ssrc: u32,
    fb_pkt_cnt: u8,
    base_sequence_number: u16,
    ref_timestamp_64ms: i64,
    last_timestamp_us: i64,
    next_sequence_number: u16,
    sequence_number_count: u16,
    len: usize,
    last_chunk: Chunk,
    chunks: Vec<PacketStatusChunk>,
    deltas: Vec<RecvDelta>,
}

impl Feedback {
    fn new(sender_ssrc: u32, media_ssrc: u32, fb_pkt_cnt: u8) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
            fb_pkt_cnt,
            base_sequence_number: 0,
            ref_timestamp_64ms: 0,
            last_timestamp_us: 0,
            next_sequence_number: 0,
            sequence_number_count: 0,
            len: 0,
            last_chunk: Chunk::new(),
            chunks: Vec::new(),
            deltas: Vec::new(),
        }
    }

    fn set_base(&mut self, sequence_number: u16, time_us: i64) {
        self.base_sequence_number = sequence_number;
        self.next_sequence_number = sequence_number;
        self.ref_timestamp_64ms = time_us / 64_000;
        self.last_timestamp_us = self.ref_timestamp_64ms * 64_000;
    }

    fn get_rtcp(mut self) -> TransportLayerCc {
        // Flush remaining chunk
        while !self.last_chunk.deltas.is_empty() {
            self.chunks.push(self.last_chunk.encode());
        }

        TransportLayerCc {
            sender_ssrc: self.sender_ssrc,
            media_ssrc: self.media_ssrc,
            base_sequence_number: self.base_sequence_number,
            packet_status_count: self.sequence_number_count,
            reference_time: self.ref_timestamp_64ms as u32,
            fb_pkt_count: self.fb_pkt_cnt,
            packet_chunks: self.chunks,
            recv_deltas: self.deltas,
        }
    }

    fn add_received(&mut self, sequence_number: u16, timestamp_us: i64) -> bool {
        let delta_us = timestamp_us - self.last_timestamp_us;
        let delta_250us = if delta_us >= 0 {
            (delta_us + TYPE_TCC_DELTA_SCALE_FACTOR / 2) / TYPE_TCC_DELTA_SCALE_FACTOR
        } else {
            (delta_us - TYPE_TCC_DELTA_SCALE_FACTOR / 2) / TYPE_TCC_DELTA_SCALE_FACTOR
        };

        // delta doesn't fit into 16 bit, need to create new packet
        if delta_250us < i16::MIN as i64 || delta_250us > i16::MAX as i64 {
            return false;
        }
        let delta_us_rounded = delta_250us * TYPE_TCC_DELTA_SCALE_FACTOR;

        // Add "not received" entries for missing packets
        while self.next_sequence_number != sequence_number {
            if !self.last_chunk.can_add(SymbolTypeTcc::PacketNotReceived) {
                self.chunks.push(self.last_chunk.encode());
            }
            self.last_chunk.add(SymbolTypeTcc::PacketNotReceived);
            self.sequence_number_count += 1;
            self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        }

        let recv_delta = if delta_250us >= 0 && delta_250us <= 0xff {
            self.len += 1;
            SymbolTypeTcc::PacketReceivedSmallDelta
        } else {
            self.len += 2;
            SymbolTypeTcc::PacketReceivedLargeDelta
        };

        if !self.last_chunk.can_add(recv_delta) {
            self.chunks.push(self.last_chunk.encode());
        }
        self.last_chunk.add(recv_delta);
        self.deltas.push(RecvDelta {
            type_tcc_packet: recv_delta,
            delta: delta_us_rounded,
        });
        self.last_timestamp_us += delta_us_rounded;
        self.sequence_number_count += 1;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);

        true
    }
}

/// Helper struct for building status chunks.
struct Chunk {
    has_large_delta: bool,
    has_different_types: bool,
    deltas: Vec<SymbolTypeTcc>,
}

impl Chunk {
    fn new() -> Self {
        Self {
            has_large_delta: false,
            has_different_types: false,
            deltas: Vec::new(),
        }
    }

    fn can_add(&self, delta: SymbolTypeTcc) -> bool {
        if self.deltas.len() < MAX_TWO_BIT_CAP {
            return true;
        }
        if self.deltas.len() < MAX_ONE_BIT_CAP
            && !self.has_large_delta
            && delta != SymbolTypeTcc::PacketReceivedLargeDelta
        {
            return true;
        }
        if self.deltas.len() < MAX_RUN_LENGTH_CAP && !self.has_different_types && delta == self.deltas[0]
        {
            return true;
        }
        false
    }

    fn add(&mut self, delta: SymbolTypeTcc) {
        if !self.deltas.is_empty() && delta != self.deltas[0] {
            self.has_different_types = true;
        }
        self.has_large_delta =
            self.has_large_delta || delta == SymbolTypeTcc::PacketReceivedLargeDelta;
        self.deltas.push(delta);
    }

    fn encode(&mut self) -> PacketStatusChunk {
        if !self.has_different_types {
            let chunk = PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: self.deltas[0],
                run_length: self.deltas.len() as u16,
            });
            self.reset();
            return chunk;
        }

        if self.deltas.len() == MAX_ONE_BIT_CAP {
            let chunk = PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
                type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
                symbol_size: SymbolSizeTypeTcc::OneBit,
                symbol_list: self.deltas.clone(),
            });
            self.reset();
            return chunk;
        }

        let min_cap = MAX_TWO_BIT_CAP.min(self.deltas.len());
        let chunk = PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
            type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
            symbol_size: SymbolSizeTypeTcc::TwoBit,
            symbol_list: self.deltas[..min_cap].to_vec(),
        });
        self.deltas = self.deltas[min_cap..].to_vec();
        self.has_different_types = false;
        self.has_large_delta = false;

        if !self.deltas.is_empty() {
            let first = self.deltas[0];
            for &d in &self.deltas {
                if d != first {
                    self.has_different_types = true;
                }
                if d == SymbolTypeTcc::PacketReceivedLargeDelta {
                    self.has_large_delta = true;
                }
            }
        }

        chunk
    }

    fn reset(&mut self) {
        self.deltas.clear();
        self.has_large_delta = false;
        self.has_different_types = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_unwrapper() {
        let mut unwrapper = SequenceUnwrapper::new();

        assert_eq!(unwrapper.unwrap(0), 0);
        assert_eq!(unwrapper.unwrap(1), 1);
        assert_eq!(unwrapper.unwrap(100), 100);

        // Test wraparound
        let mut unwrapper = SequenceUnwrapper::new();
        assert_eq!(unwrapper.unwrap(65534), 65534);
        assert_eq!(unwrapper.unwrap(65535), 65535);
        assert_eq!(unwrapper.unwrap(0), 65536);
        assert_eq!(unwrapper.unwrap(1), 65537);
    }

    #[test]
    fn test_recorder_basic() {
        let mut recorder = Recorder::new(5000);

        recorder.record(1234, 0, 64000);
        recorder.record(1234, 1, 64250);
        recorder.record(1234, 2, 64500);

        let packets = recorder.build_feedback_packet();
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn test_recorder_with_gaps() {
        let mut recorder = Recorder::new(5000);

        recorder.record(1234, 0, 64000);
        recorder.record(1234, 5, 65000); // Gap: 1-4 missing

        let packets = recorder.build_feedback_packet();
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn test_chunk_run_length() {
        let mut chunk = Chunk::new();

        // Fill with same type
        for _ in 0..10 {
            assert!(chunk.can_add(SymbolTypeTcc::PacketReceivedSmallDelta));
            chunk.add(SymbolTypeTcc::PacketReceivedSmallDelta);
        }

        assert!(!chunk.has_different_types);

        let encoded = chunk.encode();
        match encoded {
            PacketStatusChunk::RunLengthChunk(rlc) => {
                assert_eq!(rlc.packet_status_symbol, SymbolTypeTcc::PacketReceivedSmallDelta);
                assert_eq!(rlc.run_length, 10);
            }
            _ => panic!("Expected RunLengthChunk"),
        }
    }

    #[test]
    fn test_chunk_status_vector() {
        let mut chunk = Chunk::new();

        // Mix of types
        chunk.add(SymbolTypeTcc::PacketReceivedSmallDelta);
        chunk.add(SymbolTypeTcc::PacketNotReceived);
        chunk.add(SymbolTypeTcc::PacketReceivedLargeDelta);

        assert!(chunk.has_different_types);
        assert!(chunk.has_large_delta);
    }

    #[test]
    fn test_feedback_add_received() {
        let mut fb = Feedback::new(5000, 1234, 0);
        fb.set_base(0, 64000);

        // Add packet 0
        assert!(fb.add_received(0, 64000));
        assert_eq!(fb.sequence_number_count, 1);
        assert_eq!(fb.next_sequence_number, 1);

        // Add packet 2 (skip 1)
        assert!(fb.add_received(2, 64500));
        assert_eq!(fb.sequence_number_count, 3); // 0, 1 (not received), 2
        assert_eq!(fb.next_sequence_number, 3);
    }
}
