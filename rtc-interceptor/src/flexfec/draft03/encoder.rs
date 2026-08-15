//! FlexFEC draft-03 repair packet construction.

use crate::flexfec::bit_array::BitArray;
use crate::flexfec::coverage::ProtectionCoverage;
use shared::marshal::{Marshal, MarshalSize};

/// Bytes of RTP header a repair packet recovers from, and the offset its payload starts at.
pub(crate) const BASE_RTP_HEADER_SIZE: usize = 12;

/// The fixed part of a draft-03 repair payload: recovery fields, SSRC count, the protected SSRC,
/// the base sequence number and the first packet mask.
pub(crate) const BASE_HEADER_SIZE: usize = 20;

/// Bytes added when the second packet mask is present.
const MASK2_SIZE: usize = 4;

/// Bytes added when the third packet mask is present.
const MASK3_SIZE: usize = 8;

/// Builds FlexFEC **draft-03** repair packets.
///
/// Draft-03 rather than [RFC 8627] because draft-03 is what browsers negotiate as
/// `video/flexfec-03`. The RFC states its payload formats are not backward compatible with the
/// earlier drafts, so the two are separate implementations with separate vectors — a draft-03
/// round trip is evidence about browsers, not about the RFC.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|0| P|X|  CC  |M| PT recovery |         length recovery       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          TS recovery                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   SSRCCount   |                    reserved                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             SSRC_i                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           SN base_i           |k|          Mask [0-14]        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |k|                   Mask [15-45] (optional)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |k|                                                             |
/// +-+                   Mask [46-108] (optional)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [RFC 8627]: https://www.rfc-editor.org/rfc/rfc8627
#[derive(Debug)]
pub struct FlexFec03Encoder {
    payload_type: u8,
    ssrc: u32,
    next_sequence_number: u16,
    coverage: Option<ProtectionCoverage>,
}

impl FlexFec03Encoder {
    /// A repair-stream encoder sending `payload_type` on `ssrc`.
    ///
    /// The repair stream has its own SSRC and its own sequence-number space, both negotiated
    /// separately from the media it protects.
    pub fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            next_sequence_number: 0,
            coverage: None,
        }
    }

    /// Start the repair stream's sequence numbers at `sequence_number`.
    pub fn with_base_sequence_number(mut self, sequence_number: u16) -> Self {
        self.next_sequence_number = sequence_number;
        self
    }

    /// The sequence number the next repair packet will carry.
    pub fn next_sequence_number(&self) -> u16 {
        self.next_sequence_number
    }

    /// Build up to `num_fec_packets` repair packets protecting `media_packets`.
    ///
    /// Returns nothing when the media packets are not a **consecutive** run: a packet mask
    /// describes positions relative to one base sequence number, so a gap would silently shift
    /// every position after it and protect the wrong packets. A caller that has lost a packet
    /// should start a new block rather than encode across the hole.
    pub fn encode(
        &mut self,
        media_packets: &[rtp::Packet],
        num_fec_packets: u32,
    ) -> Vec<rtp::Packet> {
        if media_packets.is_empty() || num_fec_packets == 0 {
            return Vec::new();
        }

        let consecutive = media_packets.windows(2).all(|pair| {
            pair[1].header.sequence_number == pair[0].header.sequence_number.wrapping_add(1)
        });
        if !consecutive {
            return Vec::new();
        }

        let num_media_packets = media_packets.len() as u32;
        match &mut self.coverage {
            Some(coverage) => coverage.update(num_media_packets, num_fec_packets),
            None => match ProtectionCoverage::new(num_media_packets, num_fec_packets) {
                Some(coverage) => self.coverage = Some(coverage),
                None => return Vec::new(),
            },
        }
        let Some(coverage) = &self.coverage else {
            return Vec::new();
        };
        if coverage.num_media_packets() != num_media_packets {
            // The block is longer than the masks can describe; the caller must split it.
            return Vec::new();
        }

        let base_sequence_number = media_packets[0].header.sequence_number;
        let mut repair_packets = Vec::with_capacity(num_fec_packets as usize);
        for fec_index in 0..num_fec_packets {
            if let Some(packet) = self.encode_one(fec_index, base_sequence_number, media_packets) {
                repair_packets.push(packet);
            }
        }
        repair_packets
    }

    fn encode_one(
        &mut self,
        fec_index: u32,
        base_sequence_number: u16,
        media_packets: &[rtp::Packet],
    ) -> Option<rtp::Packet> {
        let coverage = self.coverage.as_ref()?;
        let covered = coverage.covered_by(fec_index);
        if covered.is_empty() {
            // A repair packet protecting nothing carries no information.
            return None;
        }
        let mask = *coverage.mask(fec_index)?;

        let mask2 = mask.mask2();
        let mask3 = mask.mask3_draft03();
        let header_size = BASE_HEADER_SIZE
            + if mask2 != 0 || mask3 != 0 {
                MASK2_SIZE
            } else {
                0
            }
            + if mask3 != 0 { MASK3_SIZE } else { 0 };

        // The repair payload must be long enough for the largest packet it protects: recovering a
        // lost packet means XORing this back out, so anything shorter would truncate it.
        let max_payload = covered
            .iter()
            .map(|&index| media_packets[index as usize].marshal_size() - BASE_RTP_HEADER_SIZE)
            .max()?;

        let mut payload = vec![0u8; header_size + max_payload];
        let (header, repair) = payload.split_at_mut(header_size);

        let mut protected_ssrc = None;
        for &index in &covered {
            let media_packet = &media_packets[index as usize];
            let size = media_packet.marshal_size();
            let mut buffer = vec![0u8; size];
            media_packet.marshal_to(&mut buffer).ok()?;

            protected_ssrc.get_or_insert(media_packet.header.ssrc);

            // Recovery fields are the XOR of the corresponding media header bytes, so a receiver
            // holding every packet but one can XOR the rest back out and be left with it.
            header[0] ^= buffer[0];
            header[1] ^= buffer[1];
            // The first two bits are the RTP version, which is not recovered — it is always 2.
            header[0] &= 0b0011_1111;

            let length_recovery = (size - BASE_RTP_HEADER_SIZE) as u16;
            header[2] ^= (length_recovery >> 8) as u8;
            header[3] ^= length_recovery as u8;

            // Timestamp recovery. The sequence number at bytes 2..4 of the media header is *not*
            // recovered this way — its position is taken by length recovery, and a lost packet's
            // sequence number is implied by its position in the mask.
            for byte in 4..8 {
                header[byte] ^= buffer[byte];
            }

            for (target, &source) in repair.iter_mut().zip(&buffer[BASE_RTP_HEADER_SIZE..]) {
                *target ^= source;
            }
        }

        header[8] = 1; // SSRCCount: draft-03 protects a single stream per repair packet.
        header[9..12].fill(0); // reserved
        header[12..16].copy_from_slice(&protected_ssrc?.to_be_bytes());
        header[16..18].copy_from_slice(&base_sequence_number.to_be_bytes());
        header[18..20].copy_from_slice(&mask.mask1().to_be_bytes());

        // The k-bit marks the last mask present. It is the top bit of each mask word, which is
        // why mask1 is 15 bits rather than 16 and mask3 is 63 rather than 64.
        if mask2 == 0 && mask3 == 0 {
            header[18] |= 0b1000_0000;
        } else {
            header[20..24].copy_from_slice(&mask2.to_be_bytes());
            if mask3 == 0 {
                header[20] |= 0b1000_0000;
            } else {
                header[24..32].copy_from_slice(&mask3.to_be_bytes());
                header[24] |= 0b1000_0000;
            }
        }

        let sequence_number = self.next_sequence_number;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);

        Some(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: self.payload_type,
                sequence_number,
                // Upstream hardcodes a constant here. The repair stream is a stream in its own
                // right, so it carries the media timestamp it was built from — which is at least
                // monotonic with the media, rather than frozen for the life of the process.
                timestamp: media_packets[covered[0] as usize].header.timestamp,
                ssrc: self.ssrc,
                csrc: Vec::new(),
                ..Default::default()
            },
            payload: payload.into(),
        })
    }
}

/// The packet mask a repair packet declares, read back off the wire.
///
/// Used by the tests here and by the decoder; kept beside the encoder so the two cannot drift.
pub(crate) fn parse_packet_mask(header: &[u8]) -> Option<(BitArray, usize)> {
    if header.len() < BASE_HEADER_SIZE {
        return None;
    }

    let mut mask = BitArray::new();
    let mask1 = u16::from_be_bytes([header[18] & 0b0111_1111, header[19]]);
    for bit in 0..15 {
        if mask1 & (1 << (14 - bit)) != 0 {
            mask.set_bit(bit);
        }
    }
    if header[18] & 0b1000_0000 != 0 {
        return Some((mask, BASE_HEADER_SIZE));
    }

    if header.len() < BASE_HEADER_SIZE + MASK2_SIZE {
        return None;
    }
    let mask2 = u32::from_be_bytes([header[20] & 0b0111_1111, header[21], header[22], header[23]]);
    for bit in 0..31 {
        if mask2 & (1 << (30 - bit)) != 0 {
            mask.set_bit(15 + bit);
        }
    }
    if header[20] & 0b1000_0000 != 0 {
        return Some((mask, BASE_HEADER_SIZE + MASK2_SIZE));
    }

    if header.len() < BASE_HEADER_SIZE + MASK2_SIZE + MASK3_SIZE {
        return None;
    }
    let mut mask3_bytes = [0u8; 8];
    mask3_bytes.copy_from_slice(&header[24..32]);
    mask3_bytes[0] &= 0b0111_1111;
    let mask3 = u64::from_be_bytes(mask3_bytes);
    for bit in 0..63 {
        if mask3 & (1 << (62 - bit)) != 0 {
            mask.set_bit(46 + bit);
        }
    }
    Some((mask, BASE_HEADER_SIZE + MASK2_SIZE + MASK3_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEDIA_SSRC: u32 = 476_325_762;
    const REPAIR_SSRC: u32 = 867_589_674;
    const REPAIR_PT: u8 = 49;

    fn media_packet(sequence_number: u16, payload: &[u8]) -> rtp::Packet {
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: true,
                payload_type: 96,
                sequence_number,
                timestamp: 3_653_407_706,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            },
            payload: payload.to_vec().into(),
        }
    }

    fn run(count: u16) -> Vec<rtp::Packet> {
        (0..count)
            .map(|i| media_packet(100 + i, &[1, 2, 3, 4, 5, i as u8]))
            .collect()
    }

    fn encoder() -> FlexFec03Encoder {
        FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC)
    }

    /// The repair packet is a stream of its own: its own SSRC, payload type and sequence numbers,
    /// which is what distinguishes FlexFEC from RED-carried schemes.
    #[test]
    fn repair_packets_form_their_own_stream() {
        let mut encoder = encoder().with_base_sequence_number(1000);
        let repair = encoder.encode(&run(4), 2);

        assert_eq!(2, repair.len());
        for (offset, packet) in repair.iter().enumerate() {
            assert_eq!(REPAIR_SSRC, packet.header.ssrc, "not the media SSRC");
            assert_eq!(REPAIR_PT, packet.header.payload_type);
            assert_eq!(1000 + offset as u16, packet.header.sequence_number);
            assert_eq!(2, packet.header.version);
        }
        assert_eq!(1002, encoder.next_sequence_number());
    }

    /// The block is described relative to one base sequence number, so a gap would shift every
    /// position after it and protect the wrong packets. Encoding across a hole is refused rather
    /// than done wrongly.
    #[test]
    fn a_block_with_a_gap_is_refused() {
        let mut packets = run(3);
        packets[2].header.sequence_number = 105; // 100, 101, 105

        assert!(encoder().encode(&packets, 1).is_empty());
    }

    #[test]
    fn an_out_of_order_block_is_refused() {
        let mut packets = run(2);
        packets.swap(0, 1);

        assert!(encoder().encode(&packets, 1).is_empty());
    }

    #[test]
    fn a_block_that_wraps_the_sequence_space_is_accepted() {
        let packets = vec![
            media_packet(65534, &[1]),
            media_packet(65535, &[2]),
            media_packet(0, &[3]),
        ];
        assert_eq!(
            1,
            encoder().encode(&packets, 1).len(),
            "0 follows 65535: consecutive, not a gap"
        );
    }

    #[test]
    fn nothing_to_protect_produces_nothing() {
        assert!(encoder().encode(&[], 1).is_empty());
        assert!(encoder().encode(&run(3), 0).is_empty());
    }

    /// A repair packet covering no media packet carries no information, so the surplus is dropped
    /// rather than emitted as an empty packet.
    #[test]
    fn surplus_repair_packets_are_not_emitted() {
        let repair = encoder().encode(&run(2), 4);
        assert_eq!(
            2,
            repair.len(),
            "two media packets can back two repair packets"
        );
    }

    #[test]
    fn a_block_longer_than_the_masks_can_describe_is_refused() {
        let packets = run(crate::flexfec::coverage::MAX_MEDIA_PACKETS as u16 + 1);
        assert!(
            encoder().encode(&packets, 1).is_empty(),
            "the caller must split the block"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Header layout
    // ---------------------------------------------------------------------------------------

    #[test]
    fn the_header_names_the_stream_and_block_it_protects() {
        let repair = encoder().encode(&run(4), 1);
        let payload = &repair[0].payload;

        assert_eq!(1, payload[8], "SSRCCount: draft-03 protects one stream");
        assert_eq!(&[0, 0, 0], &payload[9..12], "reserved");
        assert_eq!(
            MEDIA_SSRC.to_be_bytes(),
            payload[12..16],
            "the protected stream"
        );
        assert_eq!(
            100u16.to_be_bytes(),
            payload[16..18],
            "the block's base sequence number"
        );
    }

    /// The k-bit marks the last mask present, which is why mask1 is 15 bits and not 16.
    #[test]
    fn a_short_block_carries_one_mask_with_the_k_bit_set() {
        let repair = encoder().encode(&run(4), 1);
        let payload = &repair[0].payload;

        assert_eq!(
            BASE_HEADER_SIZE + 6,
            payload.len(),
            "20-byte header plus the longest protected payload"
        );
        assert_ne!(0, payload[18] & 0b1000_0000, "k-bit set: no further masks");

        let (mask, header_size) = parse_packet_mask(payload).expect("parses");
        assert_eq!(BASE_HEADER_SIZE, header_size);
        assert_eq!(
            vec![true, true, true, true],
            (0..4).map(|bit| mask.bit(bit)).collect::<Vec<_>>(),
            "all four media packets covered"
        );
    }

    #[test]
    fn a_longer_block_adds_the_second_mask() {
        let repair = encoder().encode(&run(20), 1);
        let payload = &repair[0].payload;

        assert_eq!(
            0,
            payload[18] & 0b1000_0000,
            "k-bit clear: another mask follows"
        );
        assert_ne!(0, payload[20] & 0b1000_0000, "and that one is the last");

        let (mask, header_size) = parse_packet_mask(payload).expect("parses");
        assert_eq!(BASE_HEADER_SIZE + MASK2_SIZE, header_size);
        for bit in 0..20 {
            assert!(mask.bit(bit), "media packet {bit} covered");
        }
        assert!(!mask.bit(20), "and nothing beyond the block");
    }

    #[test]
    fn a_block_beyond_46_packets_adds_the_third_mask() {
        let repair = encoder().encode(&run(60), 1);
        let payload = &repair[0].payload;

        assert_eq!(0, payload[18] & 0b1000_0000);
        assert_eq!(0, payload[20] & 0b1000_0000);
        assert_ne!(0, payload[24] & 0b1000_0000, "the third mask is the last");

        let (mask, header_size) = parse_packet_mask(payload).expect("parses");
        assert_eq!(BASE_HEADER_SIZE + MASK2_SIZE + MASK3_SIZE, header_size);
        for bit in 0..60 {
            assert!(mask.bit(bit), "media packet {bit} covered");
        }
    }

    /// The mask on the wire has to name exactly the packets the coverage assigned, or a receiver
    /// XORs the wrong set back out and "recovers" corruption.
    #[test]
    fn the_declared_mask_matches_the_interleaved_coverage() {
        let repair = encoder().encode(&run(6), 2);
        assert_eq!(2, repair.len());

        let (first, _) = parse_packet_mask(&repair[0].payload).expect("parses");
        let (second, _) = parse_packet_mask(&repair[1].payload).expect("parses");

        assert_eq!(
            vec![0, 2, 4],
            (0..6).filter(|&bit| first.bit(bit)).collect::<Vec<_>>()
        );
        assert_eq!(
            vec![1, 3, 5],
            (0..6).filter(|&bit| second.bit(bit)).collect::<Vec<_>>()
        );
    }

    // ---------------------------------------------------------------------------------------
    // Recovery arithmetic
    // ---------------------------------------------------------------------------------------

    /// The recovery fields must be the XOR of the media bytes they stand for. Computing that XOR
    /// here independently is what makes this a check on the encoder rather than a restatement of
    /// it — and it is the property the decoder will rely on, before the decoder exists.
    #[test]
    fn recovery_fields_are_the_xor_of_the_protected_packets() {
        let media = run(4);
        let repair = encoder().encode(&media, 1);
        let payload = &repair[0].payload;

        let mut expected = [0u8; 8];
        let mut expected_length = 0u16;
        for packet in &media {
            let mut buffer = vec![0u8; packet.marshal_size()];
            packet.marshal_to(&mut buffer).expect("marshal");
            expected[0] ^= buffer[0];
            expected[1] ^= buffer[1];
            for byte in 4..8 {
                expected[byte] ^= buffer[byte];
            }
            expected_length ^= (packet.marshal_size() - BASE_RTP_HEADER_SIZE) as u16;
        }
        expected[0] &= 0b0011_1111;

        assert_eq!(expected[0], payload[0], "flags and CC recovery");
        assert_eq!(expected[1], payload[1], "marker and payload type recovery");
        assert_eq!(
            expected_length.to_be_bytes(),
            payload[2..4],
            "length recovery"
        );
        assert_eq!(expected[4..8], payload[4..8], "timestamp recovery");
    }

    #[test]
    fn the_repair_payload_is_the_xor_of_the_protected_payloads() {
        let media = run(4);
        let repair = encoder().encode(&media, 1);
        let header_size = parse_packet_mask(&repair[0].payload).expect("parses").1;
        let repair_payload = &repair[0].payload[header_size..];

        let mut expected = vec![0u8; media.iter().map(|p| p.payload.len()).max().unwrap()];
        for packet in &media {
            for (target, &source) in expected.iter_mut().zip(packet.payload.iter()) {
                *target ^= source;
            }
        }

        assert_eq!(expected.as_slice(), repair_payload);
    }

    /// Recovery XORs the repair payload back out, so it has to be as long as the largest packet
    /// it protects — a shorter one would truncate whatever it recovers.
    #[test]
    fn the_repair_payload_is_as_long_as_the_largest_protected_packet() {
        let media = vec![
            media_packet(1, &[1, 2, 3]),
            media_packet(2, &[1, 2, 3, 4, 5, 6, 7, 8]),
            media_packet(3, &[9]),
        ];
        let repair = encoder().encode(&media, 1);
        let header_size = parse_packet_mask(&repair[0].payload).expect("parses").1;

        assert_eq!(8, repair[0].payload.len() - header_size);
    }

    /// The RTP version is fixed at 2 and never recovered, so the top two bits of the first
    /// recovery byte are cleared rather than carrying XORed version bits.
    #[test]
    fn the_version_bits_are_not_recovered() {
        let repair = encoder().encode(&run(3), 1);
        assert_eq!(
            0,
            repair[0].payload[0] & 0b1100_0000,
            "the two version bits are zeroed"
        );
    }
}
