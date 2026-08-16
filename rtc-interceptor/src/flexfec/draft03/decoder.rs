//! FlexFEC draft-03 recovery: rebuilding a lost media packet from a repair packet.

use super::encoder::BASE_RTP_HEADER_SIZE;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// Recovered media packets kept for matching against later repair packets.
const MAX_MEDIA_PACKETS: usize = 100;

/// Repair packets held while waiting for the media they protect.
const MAX_FEC_PACKETS: usize = 100;

/// Recovered packets retained after pruning.
const RETAINED_RECOVERED_PACKETS: usize = 192;

/// Sequence distance beyond which a held repair packet is considered stale.
const STALE_SEQUENCE_DISTANCE: u16 = 0x3FFF;

/// Why a repair packet could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than the fields it claims to carry.
    Truncated,
    /// The retransmission bit is set; this scheme does not carry retransmissions.
    RetransmissionBitSet,
    /// The F bit selects the inflexible generator matrix, which draft-03 does not define here.
    InflexibleGeneratorMatrix,
    /// Draft-03 protects exactly one stream per repair packet.
    MultipleSsrcProtection,
    /// The last packet mask did not set its k-bit, so the header never terminates.
    UnterminatedPacketMask,
}

/// A repair packet's header, parsed.
#[derive(Debug, Clone)]
struct RepairHeader {
    protected_ssrc: u32,
    sequence_number_base: u16,
    /// Sequence numbers this repair packet protects, derived from the packet masks.
    protected_sequence_numbers: Vec<u16>,
    /// Offset of the repair payload within the packet payload.
    payload_offset: usize,
}

/// A media packet a repair packet protects, and the copy of it we hold, if any.
#[derive(Debug, Clone)]
struct ProtectedPacket {
    sequence_number: u16,
    packet: Option<rtp::Packet>,
}

/// A repair packet and what it is waiting for.
#[derive(Debug, Clone)]
struct RepairState {
    packet: rtp::Packet,
    header: RepairHeader,
    protected: Vec<ProtectedPacket>,
}

impl RepairState {
    fn missing(&self) -> usize {
        self.protected
            .iter()
            .filter(|protected| protected.packet.is_none())
            .count()
    }
}

/// Recovers media packets lost from a stream protected by FlexFEC draft-03.
///
/// Feed it every packet of both streams — media and repair — and it returns whatever it was able
/// to rebuild. A repair packet recovers exactly one loss among the packets it covers, which is why
/// the encoder interleaves: consecutive losses land under different repair packets.
///
/// # Difference from upstream
///
/// `pion/interceptor` stores each protected packet as a pointer into the recovered-packet slice,
/// then `append`s to and sorts that same slice. Appending can reallocate and sorting reorders, so
/// those pointers can dangle or come to refer to a different packet. Copies are held here instead:
/// the borrow checker would not permit the upstream shape, and the bug it prevents is real.
#[derive(Debug)]
pub struct FlexFec03Decoder {
    repair_ssrc: u32,
    media_ssrc: u32,
    /// Media packets seen or recovered, ordered oldest first.
    recovered: Vec<rtp::Packet>,
    repair_packets: Vec<RepairState>,
}

impl FlexFec03Decoder {
    /// A decoder for `media_ssrc`, protected by the repair stream on `repair_ssrc`.
    pub fn new(repair_ssrc: u32, media_ssrc: u32) -> Self {
        Self {
            repair_ssrc,
            media_ssrc,
            recovered: Vec::new(),
            repair_packets: Vec::new(),
        }
    }

    /// Offer a packet from either stream, returning any media packets it made recoverable.
    ///
    /// Recovery can cascade: rebuilding one packet may complete another repair packet that was
    /// waiting on two losses, so this repeats until nothing further can be recovered.
    pub fn decode(&mut self, packet: rtp::Packet) -> Vec<rtp::Packet> {
        self.reset_on_large_discontinuity(&packet);
        self.insert(packet);
        self.attempt_recovery()
    }

    /// Media packets currently held, whether received or recovered.
    pub fn recovered_len(&self) -> usize {
        self.recovered.len()
    }

    /// Repair packets currently held while waiting for the media they protect.
    pub fn pending_repair_packets(&self) -> usize {
        self.repair_packets.len()
    }

    /// A jump far beyond the window means the stream moved on; holding the old state would match
    /// new packets against repair packets that can never complete.
    fn reset_on_large_discontinuity(&mut self, packet: &rtp::Packet) {
        if self.recovered.len() < MAX_MEDIA_PACKETS {
            return;
        }
        let Some(newest) = self.recovered.last() else {
            return;
        };
        if newest.header.ssrc != packet.header.ssrc {
            return;
        }
        if sequence_distance(packet.header.sequence_number, newest.header.sequence_number)
            > MAX_MEDIA_PACKETS as u16
        {
            self.recovered.clear();
            self.repair_packets.clear();
        }
    }

    fn insert(&mut self, packet: rtp::Packet) {
        if packet.header.ssrc == self.repair_ssrc {
            self.prune_stale_repair_packets(packet.header.sequence_number);
            self.insert_repair_packet(packet);
        } else if packet.header.ssrc == self.media_ssrc {
            self.insert_media_packet(packet);
        }
        self.discard_old_recovered_packets();
    }

    /// Drop repair packets whose sequence numbers are far from what is arriving now: they protect
    /// media that will never be offered again.
    fn prune_stale_repair_packets(&mut self, sequence_number: u16) {
        let repair_ssrc_distance = |state: &RepairState| {
            sequence_distance(sequence_number, state.packet.header.sequence_number)
        };
        self.repair_packets
            .retain(|state| repair_ssrc_distance(state) <= STALE_SEQUENCE_DISTANCE);
    }

    fn insert_media_packet(&mut self, packet: rtp::Packet) {
        if self
            .recovered
            .iter()
            .any(|held| held.header.sequence_number == packet.header.sequence_number)
        {
            return;
        }
        self.record_recovered(packet);
    }

    fn insert_repair_packet(&mut self, packet: rtp::Packet) {
        if self
            .repair_packets
            .iter()
            .any(|state| state.packet.header.sequence_number == packet.header.sequence_number)
        {
            return;
        }

        let Ok(header) = parse_repair_header(&packet.payload) else {
            return;
        };
        if header.protected_ssrc != self.media_ssrc {
            // Protecting a stream this decoder knows nothing about.
            return;
        }
        if header.protected_sequence_numbers.is_empty() {
            return;
        }

        let protected = header
            .protected_sequence_numbers
            .iter()
            .map(|&sequence_number| ProtectedPacket {
                sequence_number,
                packet: self
                    .recovered
                    .iter()
                    .find(|held| held.header.sequence_number == sequence_number)
                    .cloned(),
            })
            .collect();

        self.repair_packets.push(RepairState {
            packet,
            header,
            protected,
        });
        self.repair_packets.sort_by(|a, b| {
            sequence_order(
                a.packet.header.sequence_number,
                b.packet.header.sequence_number,
            )
        });
        if self.repair_packets.len() > MAX_FEC_PACKETS {
            self.repair_packets.remove(0);
        }
    }

    /// Record a media packet and tell every repair packet waiting for it.
    fn record_recovered(&mut self, packet: rtp::Packet) {
        for state in &mut self.repair_packets {
            for protected in &mut state.protected {
                if protected.sequence_number == packet.header.sequence_number {
                    protected.packet = Some(packet.clone());
                }
            }
        }
        self.recovered.push(packet);
        self.recovered
            .sort_by(|a, b| sequence_order(a.header.sequence_number, b.header.sequence_number));
    }

    fn attempt_recovery(&mut self) -> Vec<rtp::Packet> {
        let mut recovered_now = Vec::new();

        while let Some(index) = self
            .repair_packets
            .iter()
            .position(|state| state.missing() == 1)
        {
            let state = self.repair_packets[index].clone();
            let Some(packet) = self.recover(&state) else {
                // Unusable — drop it rather than retrying it forever.
                self.repair_packets.remove(index);
                continue;
            };

            recovered_now.push(packet.clone());
            self.record_recovered(packet);
            self.repair_packets.remove(index);
            self.discard_old_recovered_packets();
        }

        recovered_now
    }

    /// Rebuild the one missing packet of `state` by XORing the others back out of the repair data.
    fn recover(&self, state: &RepairState) -> Option<rtp::Packet> {
        let repair_payload = state.packet.payload.get(state.header.payload_offset..)?;

        // The recovery fields occupy the first 8 bytes; the RTP header is 12.
        let mut header = vec![0u8; BASE_RTP_HEADER_SIZE];
        header[..8].copy_from_slice(state.packet.payload.get(..8)?);

        let mut missing_sequence_number = 0u16;
        for protected in &state.protected {
            let Some(packet) = &protected.packet else {
                missing_sequence_number = protected.sequence_number;
                continue;
            };

            let mut marshalled = vec![0u8; packet.header.marshal_size()];
            packet.header.marshal_to(&mut marshalled).ok()?;
            // Bytes 2..4 of a media header are its sequence number; in the recovery fields that
            // position carries the payload length instead, so substitute before XORing.
            let payload_length = (packet.marshal_size() - BASE_RTP_HEADER_SIZE) as u16;
            marshalled[2..4].copy_from_slice(&payload_length.to_be_bytes());

            for index in 0..8 {
                header[index] ^= marshalled[index];
            }
        }

        // Version 2, and no padding: neither is recovered, both are known.
        header[0] |= 0x80;
        header[0] &= 0xBF;

        let payload_length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if repair_payload.len() < payload_length {
            return None;
        }
        header[2..4].copy_from_slice(&missing_sequence_number.to_be_bytes());
        header[8..12].copy_from_slice(&self.media_ssrc.to_be_bytes());

        let mut payload = repair_payload[..payload_length].to_vec();
        for protected in &state.protected {
            let Some(packet) = &protected.packet else {
                continue;
            };
            let mut marshalled = vec![0u8; packet.marshal_size()];
            packet.marshal_to(&mut marshalled).ok()?;
            for (target, &source) in payload.iter_mut().zip(&marshalled[BASE_RTP_HEADER_SIZE..]) {
                *target ^= source;
            }
        }

        header.extend_from_slice(&payload);
        let mut buffer = header.as_slice();
        rtp::Packet::unmarshal(&mut buffer).ok()
    }

    fn discard_old_recovered_packets(&mut self) {
        if self.recovered.len() > RETAINED_RECOVERED_PACKETS {
            let excess = self.recovered.len() - RETAINED_RECOVERED_PACKETS;
            self.recovered.drain(..excess);
        }
    }
}

/// Read the packet masks and the fields needed to recover from a repair payload.
fn parse_repair_header(data: &[u8]) -> Result<RepairHeader, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated);
    }
    if data[0] & 0x80 != 0 {
        return Err(ParseError::RetransmissionBitSet);
    }
    if data[0] & 0x40 != 0 {
        return Err(ParseError::InflexibleGeneratorMatrix);
    }
    if data[8] != 1 {
        return Err(ParseError::MultipleSsrcProtection);
    }

    let protected_ssrc = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let sequence_number_base = u16::from_be_bytes([data[16], data[17]]);

    let mut protected_sequence_numbers = Vec::new();
    let mask0 = u16::from_be_bytes([data[18], data[19]]) & 0x7FFF;
    append_mask(
        &mut protected_sequence_numbers,
        u64::from(mask0),
        15,
        sequence_number_base,
    );

    if data[18] & 0x80 != 0 {
        return Ok(RepairHeader {
            protected_ssrc,
            sequence_number_base,
            protected_sequence_numbers,
            payload_offset: 20,
        });
    }

    if data.len() < 24 {
        return Err(ParseError::Truncated);
    }
    let mask1 = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) & 0x7FFF_FFFF;
    append_mask(
        &mut protected_sequence_numbers,
        u64::from(mask1),
        31,
        sequence_number_base.wrapping_add(15),
    );

    if data[20] & 0x80 != 0 {
        return Ok(RepairHeader {
            protected_ssrc,
            sequence_number_base,
            protected_sequence_numbers,
            payload_offset: 24,
        });
    }

    if data.len() < 32 {
        return Err(ParseError::Truncated);
    }
    let mut mask2_bytes = [0u8; 8];
    mask2_bytes.copy_from_slice(&data[24..32]);
    let mask2 = u64::from_be_bytes(mask2_bytes) & 0x7FFF_FFFF_FFFF_FFFF;
    append_mask(
        &mut protected_sequence_numbers,
        mask2,
        63,
        sequence_number_base.wrapping_add(46),
    );

    if data[24] & 0x80 == 0 {
        // Nothing marks the end of the mask list, so the payload offset is unknown.
        return Err(ParseError::UnterminatedPacketMask);
    }

    Ok(RepairHeader {
        protected_ssrc,
        sequence_number_base,
        protected_sequence_numbers,
        payload_offset: 32,
    })
}

/// Expand one packet mask into the sequence numbers it names, most significant bit first.
fn append_mask(out: &mut Vec<u16>, mask: u64, bit_count: u16, base: u16) {
    for bit in 0..bit_count {
        if (mask >> (bit_count - 1 - bit)) & 1 == 1 {
            out.push(base.wrapping_add(bit));
        }
    }
}

/// Whether `value` is later than `previous` in the wrapping 16-bit sequence space.
fn is_newer(previous: u16, value: u16) -> bool {
    const HALF: u16 = 0x8000;
    let forward = value.wrapping_sub(previous);
    if forward == HALF {
        return value > previous;
    }
    value != previous && forward < HALF
}

/// Order two sequence numbers oldest first, respecting the wrap.
fn sequence_order(a: u16, b: u16) -> std::cmp::Ordering {
    if a == b {
        std::cmp::Ordering::Equal
    } else if is_newer(a, b) {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// The shorter distance between two sequence numbers in either direction.
fn sequence_distance(a: u16, b: u16) -> u16 {
    a.wrapping_sub(b).min(b.wrapping_sub(a))
}
