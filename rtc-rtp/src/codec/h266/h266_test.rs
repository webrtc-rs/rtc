//! H.266 tests ported from pion/rtp v1.10.6 `codecs/h266_packet_test.go`.

use super::*;
use crate::packetizer::{Depacketizer, Payloader};
use bytes::{Bytes, BytesMut};
use shared::error::{Error, Result};

/// Builds a test NAL header the way pion's `createTestH266Header` does.
fn create_test_h266_header(p_type: u8, layer_id: u8, tid: u8, f: bool, z: bool) -> H266NALUHeader {
    let mut v = u16::from(tid) | (u16::from(p_type) << 3) | (u16::from(layer_id) << 8);
    if f {
        v |= 1 << 15;
    }
    if z {
        v |= 1 << 14;
    }
    H266NALUHeader(v)
}

/// Builds a single NAL unit packet.
fn single(header: H266NALUHeader, donl: Option<u16>, payload: &[u8]) -> SingleNalUnitPacket {
    SingleNalUnitPacket {
        header: header.0,
        donl,
        payload: Bytes::copy_from_slice(payload),
    }
}

/// Builds an aggregation packet.
fn aggregation(header: H266NALUHeader, donl: Option<u16>, payload: &[u8]) -> AggregationPacket {
    AggregationPacket {
        header: header.0,
        donl,
        payload: Bytes::copy_from_slice(payload),
    }
}

fn packetize(packet: &impl Packetize) -> Bytes {
    let mut out = BytesMut::new();
    packet.packetize_into(&mut out);
    out.freeze()
}

/// Serializes in wire form; implemented by the packet types under test.
trait Packetize {
    /// Appends the packet to `out`.
    fn packetize_into(&self, out: &mut BytesMut);
}

impl Packetize for SingleNalUnitPacket {
    fn packetize_into(&self, out: &mut BytesMut) {
        SingleNalUnitPacket::packetize_into(self, out)
    }
}

impl Packetize for AggregationPacket {
    fn packetize_into(&self, out: &mut BytesMut) {
        AggregationPacket::packetize_into(self, out)
    }
}

impl Packetize for FragmentationPacket {
    fn packetize_into(&self, out: &mut BytesMut) {
        FragmentationPacket::packetize_into(self, out)
    }
}

#[test]
fn test_h266_aggregation_roundtrip() -> Result<()> {
    let simple_packet = single(
        create_test_h266_header(0, 0, 1, false, false),
        None,
        &[0x00, 0x01, 0x02, 0x03],
    );
    let diff_packet = single(
        H266NALUHeader::new(0b1000000, 0b00010000),
        None,
        &[0x03, 0x02, 0x01, 0x00, 0x12],
    );

    fn test_aggregation(expected: &[SingleNalUnitPacket]) -> Result<()> {
        let created = new_aggregation_packet(expected)?;
        let wire = packetize(&created);
        let parsed = parse_h266_packet(&wire, false)?;
        let H266Packet::Aggregation(aggr) = parsed else {
            panic!("expected an aggregation packet");
        };
        let split = split_aggregation_packet(&aggr)?;
        assert_eq!(split.len(), expected.len());
        assert!(
            split
                .iter()
                .zip(expected.iter())
                .all(|(a, b)| a.payload == b.payload && a.header == b.header)
        );
        Ok(())
    }
    test_aggregation(&[
        simple_packet.clone(),
        simple_packet.clone(),
        simple_packet.clone(),
    ])?;
    test_aggregation(&[
        diff_packet.clone(),
        simple_packet.clone(),
        simple_packet.clone(),
    ])?;
    test_aggregation(&[
        diff_packet.clone(),
        diff_packet.clone(),
        simple_packet.clone(),
    ])?;
    Ok(())
}

#[test]
fn test_h266_aggregation_header() -> Result<()> {
    let simple_packet = single(
        create_test_h266_header(0, 0, 0, false, false),
        None,
        &[0x00, 0x01, 0x02, 0x03],
    );
    // Packet with the F bit set.
    let f_packet = single(
        create_test_h266_header(0, 0, 0, true, false),
        None,
        &[0x03, 0x02, 0x01, 0x00, 0x12],
    );
    // Packet with the Z bit set.
    let z_packet = single(
        create_test_h266_header(0, 0, 0, false, true),
        None,
        &[0x03, 0x02, 0x01, 0x00, 0x12],
    );
    // Packet with layer id 1.
    let layer_one_packet = single(
        create_test_h266_header(0, 1, 0, false, false),
        None,
        &[0x03, 0x02, 0x01, 0x00, 0x12],
    );
    // Packet with TID 1.
    let tid_one_packet = single(
        create_test_h266_header(0, 0, 1, false, false),
        None,
        &[0x03, 0x02, 0x01, 0x00, 0x12],
    );

    fn test_aggregation(
        to_aggregate: &[SingleNalUnitPacket],
        expected_header: H266NALUHeader,
        message: &str,
    ) -> Result<()> {
        let created = new_aggregation_packet(to_aggregate)?;
        assert_eq!(created.header, expected_header.0, "{message}");
        Ok(())
    }

    test_aggregation(
        &[
            simple_packet.clone(),
            simple_packet.clone(),
            simple_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        "expected all fields to match",
    )?;
    test_aggregation(
        &[
            simple_packet.clone(),
            simple_packet.clone(),
            f_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, true, false),
        "expected the F bit to be set if any of the packets has it",
    )?;
    // The Z bit is ignored.
    test_aggregation(
        &[
            simple_packet.clone(),
            simple_packet.clone(),
            z_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        "expected the Z bit to be ignored",
    )?;
    test_aggregation(
        &[z_packet.clone(), z_packet.clone(), z_packet.clone()],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        "expected the Z bit to be ignored",
    )?;
    test_aggregation(
        &[
            layer_one_packet.clone(),
            layer_one_packet.clone(),
            layer_one_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 1, 0, false, false),
        "expected the layer id to be 1",
    )?;
    test_aggregation(
        &[
            layer_one_packet.clone(),
            simple_packet.clone(),
            layer_one_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        "expected the layer id to be the lowest of the aggregated packets",
    )?;
    test_aggregation(
        &[
            tid_one_packet.clone(),
            tid_one_packet.clone(),
            tid_one_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 1, false, false),
        "expected the TID to be 1",
    )?;
    test_aggregation(
        &[
            tid_one_packet.clone(),
            tid_one_packet.clone(),
            simple_packet.clone(),
        ],
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        "expected the TID to be the lowest of the aggregated packets",
    )?;
    Ok(())
}

#[test]
fn test_h266_aggregation_malformed() {
    let header = create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false);

    let no_packets = aggregation(header, None, &[]);
    assert!(matches!(
        split_aggregation_packet(&no_packets),
        Err(Error::ErrH266NotEnoughPackets)
    ));

    let only_one_packet = aggregation(header, None, &[0x00, 0x03, 0x00, 0x00, 0x01]);
    assert!(matches!(
        split_aggregation_packet(&only_one_packet),
        Err(Error::ErrH266NotEnoughPackets)
    ));

    // Length field (0x00ff) too large for the payload size.
    let too_short_packet = aggregation(header, None, &[0x00, 0xff, 0x00, 0x00, 0xff]);
    assert!(matches!(
        split_aggregation_packet(&too_short_packet),
        Err(Error::ErrShortPacket)
    ));

    // Contains an aggregation packet.
    let contains_aggregation = aggregation(header, None, &[0x00, 0x03, 0x00, 0xe0, 0xff]);
    assert!(matches!(
        split_aggregation_packet(&contains_aggregation),
        Err(Error::ErrInvalidH266PacketType)
    ));

    // Contains a fragmentation packet.
    let contains_fragmentation =
        aggregation(header, None, &[0x00, 0x04, 0x00, 0xe8, 0xff, 0xff, 0xff]);
    assert!(matches!(
        split_aggregation_packet(&contains_fragmentation),
        Err(Error::ErrInvalidH266PacketType)
    ));
}

#[test]
fn test_h266_aggregation_donl() -> Result<()> {
    let initial_donl = 100u16;
    // Packet with three inner packets.
    let test_packet = aggregation(
        create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
        Some(initial_donl),
        &[
            0x00, 0x03, 0xff, 0xff, 0xff, 0x00, 0x03, 0xff, 0xff, 0xff, 0x00, 0x03, 0xff, 0xff,
            0xff,
        ],
    );
    let packets = split_aggregation_packet(&test_packet)?;
    for (i, p) in packets.iter().enumerate() {
        assert_eq!(p.donl, Some(initial_donl + i as u16));
    }
    Ok(())
}

#[test]
fn test_h266_fragmentation_roundtrip() -> Result<()> {
    fn test_fragmentation(packet: &SingleNalUnitPacket) -> Result<()> {
        let fragments = new_fragmentation_packets(100, packet)?;
        let rebuilt = rebuild_fragmentation_packets(&fragments)?;
        assert_eq!(
            packetize(packet),
            packetize(&rebuilt),
            "expected packets to match after fragmentation"
        );
        Ok(())
    }

    let payload: Vec<u8> = (0..200u16).map(|i| i as u8).collect();

    let simple_packet = single(
        create_test_h266_header(0, 0, 0, false, false),
        None,
        &payload,
    );
    test_fragmentation(&simple_packet)?;

    let packet_with_donl = single(
        create_test_h266_header(0, 0, 0, false, false),
        Some(100),
        &payload,
    );
    test_fragmentation(&packet_with_donl)?;

    let every_flag_set = single(
        create_test_h266_header(1, 1, 1, true, true),
        Some(100),
        &payload,
    );
    test_fragmentation(&every_flag_set)?;

    Ok(())
}

#[test]
fn test_h266_fragmentation_header() -> Result<()> {
    let payload: Vec<u8> = (0..100u16).map(|i| i as u8).collect();
    let simple_packet = single(
        create_test_h266_header(0, 0, 1, false, false),
        None,
        &payload,
    );

    let fragments = new_fragmentation_packets(100, &simple_packet)?;

    assert!(
        fu_start(fragments[0].fu_header),
        "first fragmentation packet should have the S flag"
    );
    assert!(
        fu_end(fragments[fragments.len() - 1].fu_header),
        "last fragmentation packet should have the E flag"
    );

    for fragment in &fragments {
        assert_eq!(
            H266NALUHeader(simple_packet.header).nalu_type(),
            fu_type(fragment.fu_header),
            "each fragment should have the same type as the contained packet"
        );
    }
    Ok(())
}

#[test]
fn test_h266_fragmentation_edge_case() -> Result<()> {
    // Exactly large enough to fill two full FUs.
    let payload: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
    let simple_packet = single(
        create_test_h266_header(1, 1, 1, false, false),
        None,
        &payload,
    );

    // (payload length / 2) + payload header length + FU header length
    let fragments = new_fragmentation_packets(103, &simple_packet)?;
    assert_eq!(
        fragments.len(),
        2,
        "expected exactly two, completely full packets"
    );

    // Exactly large enough to fill one FU.
    let payload: Vec<u8> = (0..100u16).map(|i| i as u8).collect();
    let simple_packet = single(
        create_test_h266_header(1, 1, 1, false, false),
        None,
        &payload,
    );

    // payload length + payload header length + FU header length
    let fragments = new_fragmentation_packets(103, &simple_packet);
    assert!(fragments.is_err());

    Ok(())
}

#[test]
fn test_h266_packet_parsing() -> Result<()> {
    // Nothingburger packet.
    let parsed = parse_h266_packet(&Bytes::from_static(&[0x00, 0x00, 1, 2, 3]), false)?;
    assert_eq!(
        parsed,
        H266Packet::Single(single(
            create_test_h266_header(0, 0, 0, false, false),
            None,
            &[1, 2, 3]
        ))
    );

    // Nothingburger packet with DONL.
    let parsed = parse_h266_packet(&Bytes::from_static(&[0x00, 0x00, 0, 123, 1, 2, 3]), true)?;
    assert_eq!(
        parsed,
        H266Packet::Single(single(
            create_test_h266_header(0, 0, 0, false, false),
            Some(123),
            &[1, 2, 3]
        ))
    );

    // Aggregation packet, with two one-byte-long packets.
    let parsed = parse_h266_packet(
        &Bytes::from_static(&[0x00, 0xe0, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42]),
        false,
    )?;
    assert_eq!(
        parsed,
        H266Packet::Aggregation(aggregation(
            create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
            None,
            &[0x00, 0x01, 0x42, 0x00, 0x01, 0x42]
        ))
    );

    // Aggregation packet, with two one-byte-long packets, with DONL.
    let parsed = parse_h266_packet(
        &Bytes::from_static(&[0x00, 0xe0, 0x00, 123, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42]),
        true,
    )?;
    assert_eq!(
        parsed,
        H266Packet::Aggregation(aggregation(
            create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
            Some(123),
            &[0x00, 0x01, 0x42, 0x00, 0x01, 0x42]
        ))
    );

    // Fragmentation packet.
    let parsed = parse_h266_packet(
        &Bytes::from_static(&[0x00, 0xe8, 0x00, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42]),
        false,
    )?;
    assert_eq!(
        parsed,
        H266Packet::Fragmentation(FragmentationPacket {
            header: create_test_h266_header(FRAGMENTATION_UNIT_TYPE, 0, 0, false, false).0,
            // pion builds this from newH266NALUHeader(0x00, 0x01): type 0, no flags.
            fu_header: 0x00,
            donl: None,
            payload: Bytes::from_static(&[0x00, 0x01, 0x42, 0x00, 0x01, 0x42]),
        })
    );
    Ok(())
}

#[test]
fn test_h266_packet_roundtrip() -> Result<()> {
    fn test_roundtrip(packet: &H266Packet, has_donl: bool) -> Result<()> {
        let wire = match packet {
            H266Packet::Single(p) => packetize(p),
            H266Packet::Aggregation(p) => packetize(p),
            H266Packet::Fragmentation(p) => packetize(p),
        };
        let parsed = parse_h266_packet(&wire, has_donl)?;
        assert_eq!(&parsed, packet);
        Ok(())
    }

    // Nothingburger packet.
    test_roundtrip(
        &H266Packet::Single(single(
            create_test_h266_header(0, 0, 0, false, false),
            None,
            &[1, 2, 3],
        )),
        false,
    )?;

    // Nothingburger packet with DONL.
    test_roundtrip(
        &H266Packet::Single(single(
            create_test_h266_header(0, 0, 0, false, false),
            Some(123),
            &[1, 2, 3],
        )),
        true,
    )?;

    // Aggregation packet, with two one-byte-long packets.
    let ap = |donl| {
        H266Packet::Aggregation(aggregation(
            create_test_h266_header(AGGREGATION_PACKET_TYPE, 0, 0, false, false),
            donl,
            &[0x00, 0x01, 0x42, 0x00, 0x01, 0x42],
        ))
    };
    test_roundtrip(&ap(None), false)?;
    test_roundtrip(&ap(Some(123)), true)?;

    // pion's file repeats the aggregation cases for the fragmentation section; ported as-is.
    test_roundtrip(&ap(None), false)?;
    test_roundtrip(&ap(Some(123)), true)?;

    Ok(())
}

#[test]
fn test_h266_packetizer_single() -> Result<()> {
    let mut packetizer = H266Payloader::default();

    // Type 1, 8-byte payload NALU.
    let header = create_test_h266_header(1, 0, 0, false, false);
    let payload = [0xffu8; 8];
    let mut basic_packet = Vec::new();
    basic_packet.extend_from_slice(&ANNEXB_START_CODE);
    basic_packet.extend_from_slice(&header.0.to_be_bytes());
    basic_packet.extend_from_slice(&payload);

    let packets = packetizer.payload(100, &Bytes::from(basic_packet))?;
    assert_eq!(packets.len(), 1, "expected only one NALU to be generated");
    assert_eq!(
        u16::from_be_bytes([packets[0][0], packets[0][1]]),
        header.0,
        "expected headers to match"
    );
    assert_eq!(&packets[0][2..], &payload, "expected payloads to match");
    Ok(())
}

#[test]
fn test_h266_packetizer_aggregated() -> Result<()> {
    let mut packetizer = H266Payloader::default();

    // Type 1, 8-byte payload.
    let header = create_test_h266_header(1, 0, 0, false, false);
    let payload = [0xffu8; 8];
    let mut basic_packet = Vec::new();
    basic_packet.extend_from_slice(&ANNEXB_START_CODE);
    basic_packet.extend_from_slice(&header.0.to_be_bytes());
    basic_packet.extend_from_slice(&payload);
    let two = [basic_packet.clone(), basic_packet].concat();

    let packets = packetizer.payload(100, &Bytes::from(two))?;
    assert_eq!(packets.len(), 1, "expected only one NALU to be generated");
    let aggregated = &packets[0];
    let parsed_header = H266NALUHeader(u16::from_be_bytes([aggregated[0], aggregated[1]]));
    assert_eq!(
        parsed_header.nalu_type(),
        AGGREGATION_PACKET_TYPE,
        "NALU header should be type 28"
    );

    assert_eq!(
        u16::from_be_bytes([aggregated[2], aggregated[3]]) as usize,
        NAL_HEADER_SIZE + payload.len(),
        "expected length to match"
    );
    assert_eq!(
        u16::from_be_bytes([aggregated[4], aggregated[5]]),
        header.0,
        "expected headers to match"
    );
    assert_eq!(&aggregated[6..14], &payload, "expected payloads to match");

    assert_eq!(
        u16::from_be_bytes([aggregated[14], aggregated[15]]) as usize,
        NAL_HEADER_SIZE + payload.len(),
        "expected length to match"
    );
    assert_eq!(
        u16::from_be_bytes([aggregated[16], aggregated[17]]),
        header.0,
        "expected headers to match"
    );
    assert_eq!(&aggregated[18..], &payload, "expected payloads to match");
    Ok(())
}

#[test]
fn test_h266_packetizer_fragmented() -> Result<()> {
    let mut packetizer = H266Payloader::default();

    // Type 1, 50-byte payload.
    let header = create_test_h266_header(1, 0, 0, false, false);
    let mut big_packet = Vec::new();
    big_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00]);
    big_packet.extend_from_slice(&header.0.to_be_bytes());
    big_packet.extend_from_slice(&[0xffu8; 50]);

    let packets = packetizer.payload(50, &Bytes::from(big_packet))?;
    assert_eq!(packets.len(), 2, "expected two NALUs to be generated");
    let parsed_header = H266NALUHeader(u16::from_be_bytes([packets[0][0], packets[0][1]]));
    assert_eq!(
        parsed_header.nalu_type(),
        FRAGMENTATION_UNIT_TYPE,
        "NALU header should be type 29"
    );
    assert!(packets[0][2] & 0x80 != 0, "first FU header should be S");
    assert!(packets[1][2] & 0x40 != 0, "second FU header should be E");
    Ok(())
}

#[test]
fn test_h266_depacketizer_roundtrip() -> Result<()> {
    fn test_depacketizer(
        packets: &[Bytes],
        expected: Vec<SingleNalUnitPacket>,
        with_donl: bool,
    ) -> Result<()> {
        let mut depacketizer = H266Depacketizer::new().with_donl(with_donl);
        let mut output = vec![];
        for packet in packets {
            let out = depacketizer.depacketize(packet)?;
            // Middle fragments of a fragmented NAL unit return nothing.
            if out.is_empty() {
                continue;
            }
            emit_h266_nalus(&out, |b| {
                output.push(parse_h266_packet(&b, false).expect("depacketized NALUs parse"));
            });
        }
        let singles: Vec<SingleNalUnitPacket> = output
            .into_iter()
            .map(|p| match p {
                H266Packet::Single(s) => s,
                _ => panic!("expected single NAL unit packets"),
            })
            .collect();
        assert_eq!(singles, expected);
        Ok(())
    }

    let test_donl = 100u16;
    let test_donl2 = 101u16;

    // Single NAL.
    let basic_packet = single(
        create_test_h266_header(0, 0, 0, false, false),
        None,
        &[0xff, 0xff, 0xff],
    );
    test_depacketizer(
        &[packetize(&basic_packet)],
        vec![basic_packet.clone()],
        false,
    )?;

    // With DONL.
    let mut donl_packet = basic_packet.clone();
    donl_packet.donl = Some(test_donl);
    let wire = packetize(&donl_packet);
    test_depacketizer(&[wire], vec![basic_packet.clone()], true)?;

    // Multiple NALs aggregated.
    let first_packet = single(
        create_test_h266_header(0, 0, 0, false, false),
        None,
        &[0xff, 0xff, 0xff],
    );
    let second_packet = single(
        create_test_h266_header(1, 2, 3, true, true),
        None,
        &[0x67, 0x67, 0x67],
    );

    let aggregated = new_aggregation_packet(&[first_packet.clone(), second_packet.clone()])?;
    let wire = packetize(&aggregated);
    test_depacketizer(
        &[wire],
        vec![first_packet.clone(), second_packet.clone()],
        false,
    )?;

    // With DONL.
    let mut first_donl = first_packet.clone();
    first_donl.donl = Some(test_donl);
    let mut second_donl = second_packet.clone();
    second_donl.donl = Some(test_donl2);

    let donl_aggregated = new_aggregation_packet(&[first_donl, second_donl])?;
    let wire = packetize(&donl_aggregated);
    test_depacketizer(
        &[wire],
        vec![first_packet.clone(), second_packet.clone()],
        true,
    )?;

    // A large NAL that gets fragmented.
    let large_payload: Vec<u8> = (0..512u16).map(|i| i as u8).collect();
    let large_packet = single(
        create_test_h266_header(1, 1, 1, false, false),
        None,
        &large_payload,
    );

    let fragments = new_fragmentation_packets(100, &large_packet)?;
    let wires: Vec<Bytes> = fragments.iter().map(packetize).collect();
    test_depacketizer(&wires, vec![large_packet.clone()], false)?;

    // With DONL.
    let mut donl_large = large_packet.clone();
    donl_large.donl = Some(test_donl);

    let donl_fragments = new_fragmentation_packets(100, &donl_large)?;
    let wires: Vec<Bytes> = donl_fragments.iter().map(packetize).collect();
    test_depacketizer(&wires, vec![large_packet], true)?;

    Ok(())
}

#[test]
fn test_h266_payload_never_loops_or_panics_on_tiny_mtu() -> Result<()> {
    // pion's packetizer hangs at an MTU of 3; every MTU must terminate here.
    for mtu in 0..8 {
        let mut pck = H266Payloader::default();
        let frame = Bytes::from_static(&[0, 0, 1, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let out = pck.payload(mtu, &frame)?;
        assert!(
            out.iter().all(|p| p.len() <= mtu.max(2)),
            "mtu {mtu}: {out:?}"
        );
    }
    Ok(())
}
