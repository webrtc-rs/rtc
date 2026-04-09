// Silence warning on `for i in 0..vec.len() { … }`:
#![allow(clippy::needless_range_loop)]

use super::*;

#[test]
fn test_h264_payload() -> Result<()> {
    let empty = Bytes::from_static(&[]);
    let small_payload = Bytes::from_static(&[0x90, 0x90, 0x90]);
    let multiple_payload = Bytes::from_static(&[0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x01, 0x90]);
    let large_payload = Bytes::from_static(&[
        0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15,
    ]);
    let large_payload_packetized = vec![
        Bytes::from_static(&[0x1c, 0x80, 0x01, 0x02, 0x03]),
        Bytes::from_static(&[0x1c, 0x00, 0x04, 0x05, 0x06]),
        Bytes::from_static(&[0x1c, 0x00, 0x07, 0x08, 0x09]),
        Bytes::from_static(&[0x1c, 0x00, 0x10, 0x11, 0x12]),
        Bytes::from_static(&[0x1c, 0x40, 0x13, 0x14, 0x15]),
    ];

    let mut pck = H264Payloader::default();

    // Positive MTU, empty payload
    let result = pck.payload(1, &empty)?;
    assert!(result.is_empty(), "Generated payload should be empty");

    // 0 MTU, small payload
    let result = pck.payload(0, &small_payload)?;
    assert_eq!(result.len(), 0, "Generated payload should be empty");

    // Positive MTU, small payload
    let result = pck.payload(1, &small_payload)?;
    assert_eq!(result.len(), 0, "Generated payload should be empty");

    // Positive MTU, small payload
    let result = pck.payload(5, &small_payload)?;
    assert_eq!(result.len(), 1, "Generated payload should be the 1");
    assert_eq!(
        result[0].len(),
        small_payload.len(),
        "Generated payload should be the same size as original payload size"
    );

    // Multiple NALU in a single payload
    let result = pck.payload(5, &multiple_payload)?;
    assert_eq!(result.len(), 2, "2 nal units should be broken out");
    for i in 0..2 {
        assert_eq!(
            result[i].len(),
            1,
            "Payload {} of 2 is packed incorrectly",
            i + 1,
        );
    }

    // Large Payload split across multiple RTP Packets
    let result = pck.payload(5, &large_payload)?;
    assert_eq!(
        result, large_payload_packetized,
        "FU-A packetization failed"
    );

    // Nalu type 9 or 12
    let small_payload2 = Bytes::from_static(&[0x09, 0x00, 0x00]);
    let result = pck.payload(5, &small_payload2)?;
    assert_eq!(result.len(), 0, "Generated payload should be empty");

    Ok(())
}

#[test]
fn test_h264_packet_unmarshal() -> Result<()> {
    let single_payload = Bytes::from_static(&[0x90, 0x90, 0x90]);
    let single_payload_unmarshaled =
        Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x90, 0x90, 0x90]);
    let single_payload_unmarshaled_avc =
        Bytes::from_static(&[0x00, 0x00, 0x00, 0x03, 0x90, 0x90, 0x90]);

    let large_payload = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15,
    ]);
    let large_payload_avc = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15,
    ]);
    let large_payload_packetized = vec![
        Bytes::from_static(&[0x1c, 0x80, 0x01, 0x02, 0x03]),
        Bytes::from_static(&[0x1c, 0x00, 0x04, 0x05, 0x06]),
        Bytes::from_static(&[0x1c, 0x00, 0x07, 0x08, 0x09]),
        Bytes::from_static(&[0x1c, 0x00, 0x10, 0x11, 0x12]),
        Bytes::from_static(&[0x1c, 0x40, 0x13, 0x14, 0x15]),
    ];

    let single_payload_multi_nalu = Bytes::from_static(&[
        0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40, 0x3c,
        0x22, 0x11, 0xa8, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
    ]);
    let single_payload_multi_nalu_unmarshaled = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
        0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
    ]);
    let single_payload_multi_nalu_unmarshaled_avc = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
        0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
    ]);

    let incomplete_single_payload_multi_nalu = Bytes::from_static(&[
        0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40, 0x3c,
        0x22, 0x11,
    ]);

    let mut pkt = H264Packet::default();
    let mut avc_pkt = H264Packet {
        is_avc: true,
        ..Default::default()
    };

    let data = Bytes::from_static(&[]);
    let result = pkt.depacketize(&data);
    assert!(result.is_err(), "Unmarshal did not fail on nil payload");

    let data = Bytes::from_static(&[0x00, 0x00]);
    let result = pkt.depacketize(&data);
    assert!(
        result.is_err(),
        "Unmarshal accepted a packet that is too small for a payload and header"
    );

    let data = Bytes::from_static(&[0xFF, 0x00, 0x00]);
    let result = pkt.depacketize(&data);
    assert!(
        result.is_err(),
        "Unmarshal accepted a packet with a NALU Type we don't handle"
    );

    let result = pkt.depacketize(&incomplete_single_payload_multi_nalu);
    assert!(
        result.is_err(),
        "Unmarshal accepted a STAP-A packet with insufficient data"
    );

    let payload = pkt.depacketize(&single_payload)?;
    assert_eq!(
        payload, single_payload_unmarshaled,
        "Unmarshalling a single payload shouldn't modify the payload"
    );

    let payload = avc_pkt.depacketize(&single_payload)?;
    assert_eq!(
        payload, single_payload_unmarshaled_avc,
        "Unmarshalling a single payload into avc stream shouldn't modify the payload"
    );

    let mut large_payload_result = BytesMut::new();
    for p in &large_payload_packetized {
        let payload = pkt.depacketize(p)?;
        large_payload_result.put(&*payload.clone());
    }
    assert_eq!(
        large_payload_result.freeze(),
        large_payload,
        "Failed to unmarshal a large payload"
    );

    let mut large_payload_result_avc = BytesMut::new();
    for p in &large_payload_packetized {
        let payload = avc_pkt.depacketize(p)?;
        large_payload_result_avc.put(&*payload.clone());
    }
    assert_eq!(
        large_payload_result_avc.freeze(),
        large_payload_avc,
        "Failed to unmarshal a large payload into avc stream"
    );

    let payload = pkt.depacketize(&single_payload_multi_nalu)?;
    assert_eq!(
        payload, single_payload_multi_nalu_unmarshaled,
        "Failed to unmarshal a single packet with multiple NALUs"
    );

    let payload = avc_pkt.depacketize(&single_payload_multi_nalu)?;
    assert_eq!(
        payload, single_payload_multi_nalu_unmarshaled_avc,
        "Failed to unmarshal a single packet with multiple NALUs into avc stream"
    );

    Ok(())
}

#[test]
fn test_h264_partition_head_checker_is_partition_head() -> Result<()> {
    let h264 = H264Packet::default();
    let empty_nalu = Bytes::from_static(&[]);
    assert!(
        !h264.is_partition_head(&empty_nalu),
        "empty nalu must not be a partition head"
    );

    let single_nalu = Bytes::from_static(&[1, 0]);
    assert!(
        h264.is_partition_head(&single_nalu),
        "single nalu must be a partition head"
    );

    let stapa_nalu = Bytes::from_static(&[STAPA_NALU_TYPE, 0]);
    assert!(
        h264.is_partition_head(&stapa_nalu),
        "stapa nalu must be a partition head"
    );

    let fua_start_nalu = Bytes::from_static(&[FUA_NALU_TYPE, FU_START_BITMASK]);
    assert!(
        h264.is_partition_head(&fua_start_nalu),
        "fua start nalu must be a partition head"
    );

    let fua_end_nalu = Bytes::from_static(&[FUA_NALU_TYPE, FU_END_BITMASK]);
    assert!(
        !h264.is_partition_head(&fua_end_nalu),
        "fua end nalu must not be a partition head"
    );

    let fub_start_nalu = Bytes::from_static(&[FUB_NALU_TYPE, FU_START_BITMASK]);
    assert!(
        h264.is_partition_head(&fub_start_nalu),
        "fub start nalu must be a partition head"
    );

    let fub_end_nalu = Bytes::from_static(&[FUB_NALU_TYPE, FU_END_BITMASK]);
    assert!(
        !h264.is_partition_head(&fub_end_nalu),
        "fub end nalu must not be a partition head"
    );

    Ok(())
}

#[test]
fn test_h264_payloader_payload_sps_and_pps_handling() -> Result<()> {
    let mut pck = H264Payloader::default();
    let expected = vec![
        Bytes::from_static(&[
            0x78, 0x00, 0x03, 0x07, 0x00, 0x01, 0x00, 0x03, 0x08, 0x02, 0x03,
        ]),
        Bytes::from_static(&[0x05, 0x04, 0x05]),
    ];

    // When packetizing SPS and PPS are emitted with following NALU
    let res = pck.payload(1500, &Bytes::from_static(&[0x07, 0x00, 0x01]))?;
    assert!(res.is_empty(), "Generated payload should be empty");

    let res = pck.payload(1500, &Bytes::from_static(&[0x08, 0x02, 0x03]))?;
    assert!(res.is_empty(), "Generated payload should be empty");

    let actual = pck.payload(1500, &Bytes::from_static(&[0x05, 0x04, 0x05]))?;
    assert_eq!(actual, expected, "SPS and PPS aren't packed together");

    Ok(())
}

/// When the combined STAP-A of SPS + PPS exceeds the MTU, both should still
/// be emitted as individual (possibly FU-A fragmented) packets instead of
/// being silently dropped.
#[test]
fn test_h264_stap_a_exceeds_mtu_emits_individually() -> Result<()> {
    let mut pck = H264Payloader::default();

    // SPS: 3 bytes (NALU type 7)
    let sps = Bytes::from_static(&[0x07, 0xAA, 0xBB]);
    // PPS: 3 bytes (NALU type 8)
    let pps = Bytes::from_static(&[0x08, 0xCC, 0xDD]);

    let res = pck.payload(1500, &sps)?;
    assert!(res.is_empty(), "SPS alone should be stashed, not emitted");

    let res = pck.payload(1500, &pps)?;
    assert!(res.is_empty(), "PPS alone should be stashed, not emitted");

    // Use a tiny MTU so the STAP-A (1 + 2+3 + 2+3 = 11 bytes) exceeds it.
    // SPS and PPS individually are 3 bytes each, which fits in MTU=5.
    let result = pck.payload(5, &Bytes::from_static(&[0x05, 0x01, 0x02]))?;

    // Expect: SPS (3 bytes, fits), PPS (3 bytes, fits), then the IDR NALU (3 bytes, fits)
    assert_eq!(result.len(), 3, "expected SPS + PPS + IDR = 3 packets");
    assert_eq!(result[0], sps, "first packet should be the SPS NALU");
    assert_eq!(result[1], pps, "second packet should be the PPS NALU");
    assert_eq!(
        result[2],
        Bytes::from_static(&[0x05, 0x01, 0x02]),
        "third packet should be the IDR NALU"
    );

    Ok(())
}

/// When SPS or PPS are too large for a u16 length field (>65535 bytes), they
/// should be emitted via FU-A fragmentation using emit_single_or_fragment
/// rather than being packed into a STAP-A.
#[test]
fn test_h264_oversized_sps_uses_fua_fragmentation() -> Result<()> {
    let mut pck = H264Payloader::default();

    // Build a large SPS that genuinely exceeds u16::MAX (65535 bytes).
    // This ensures we actually hit the `sps_nalu.len() > u16::MAX` branch.
    let mut sps_data = vec![0x67]; // NALU type 7, with ref_idc bits set
    sps_data.extend(vec![0xAA; 70_000]);
    let sps = Bytes::from(sps_data); // 70001 bytes, well above u16::MAX threshold

    let pps = Bytes::from_static(&[0x68, 0xCC, 0xDD]); // NALU type 8, with ref_idc bits

    let res = pck.payload(1500, &sps)?;
    assert!(res.is_empty(), "SPS alone should be stashed");

    let res = pck.payload(1500, &pps)?;
    assert!(res.is_empty(), "PPS alone should be stashed");

    // Trigger emission with a small non-SPS/PPS NALU
    let result = pck.payload(1500, &Bytes::from_static(&[0x65, 0x01, 0x02]))?;

    // SPS (70001 bytes) exceeds u16::MAX, so it should be FU-A fragmented.
    // PPS (3 bytes) fits in a single packet.
    // IDR (3 bytes) fits in a single packet.
    assert!(
        result.len() >= 3,
        "expected at least 3 packets (fragmented SPS + PPS + IDR), got {}",
        result.len()
    );

    // Verify the first packet is a FU-A start fragment of the SPS
    assert_eq!(
        result[0][0] & NALU_TYPE_BITMASK,
        FUA_NALU_TYPE,
        "first packet should be a FU-A fragment"
    );
    assert_ne!(
        result[0][1] & FU_START_BITMASK,
        0,
        "first FU-A fragment should have start bit set"
    );

    Ok(())
}

/// The emit_single_or_fragment helper should pass through small NALUs directly
/// and fragment large ones via FU-A.
#[test]
fn test_h264_emit_single_or_fragment_small_nalu() {
    let nalu = Bytes::from_static(&[0x65, 0x01, 0x02, 0x03]);
    let mut payloads = vec![];
    H264Payloader::emit_single_or_fragment(&nalu, 10, &mut payloads);
    assert_eq!(payloads.len(), 1, "small NALU should emit as single packet");
    assert_eq!(payloads[0], nalu);
}

#[test]
fn test_h264_emit_single_or_fragment_large_nalu() {
    let mut data = vec![0x65]; // IDR NALU type
    data.extend(vec![0xBB; 20]);
    let nalu = Bytes::from(data);
    let mut payloads = vec![];
    H264Payloader::emit_single_or_fragment(&nalu, 10, &mut payloads);
    assert!(
        payloads.len() > 1,
        "large NALU should be FU-A fragmented into multiple packets"
    );
    // First fragment should have FU-A type and start bit
    assert_eq!(payloads[0][0] & NALU_TYPE_BITMASK, FUA_NALU_TYPE);
    assert_ne!(payloads[0][1] & FU_START_BITMASK, 0);
    // Last fragment should have end bit
    let last = payloads.last().unwrap();
    assert_ne!(last[1] & FU_END_BITMASK, 0);
}

#[test]
fn test_h264_emit_single_or_fragment_empty_nalu() {
    let nalu = Bytes::new();
    let mut payloads = vec![];
    H264Payloader::emit_single_or_fragment(&nalu, 10, &mut payloads);
    assert!(payloads.is_empty(), "empty NALU should produce no packets");
}
