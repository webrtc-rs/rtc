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

/// The byte-at-a-time scanner `next_ind` used before the `memmem` search, kept as the reference
/// the replacement must match.
fn byte_loop_next_ind(nalu: &Bytes, start: usize) -> (isize, isize) {
    let mut zero_count = 0;

    for (i, &b) in nalu[start..].iter().enumerate() {
        if b == 0 {
            zero_count += 1;
            continue;
        } else if b == 1 && zero_count >= 2 {
            return ((start + i - zero_count) as isize, zero_count as isize + 1);
        }
        zero_count = 0
    }
    (-1, -1)
}

/// `Payloader::payload` with the byte-loop scanner; everything else is the payloader's own.
fn byte_loop_payload(pck: &mut H264Payloader, mtu: usize, payload: &Bytes) -> Vec<Bytes> {
    if payload.is_empty() || mtu == 0 {
        return vec![];
    }

    let mut payloads = vec![];

    let (mut next_ind_start, mut next_ind_len) = byte_loop_next_ind(payload, 0);
    if next_ind_start == -1 {
        pck.emit(payload, mtu, &mut payloads);
    } else {
        while next_ind_start != -1 {
            let prev_start = (next_ind_start + next_ind_len) as usize;
            let (next_ind_start2, next_ind_len2) = byte_loop_next_ind(payload, prev_start);
            next_ind_start = next_ind_start2;
            next_ind_len = next_ind_len2;
            if next_ind_start != -1 {
                pck.emit(
                    &payload.slice(prev_start..next_ind_start as usize),
                    mtu,
                    &mut payloads,
                );
            } else {
                pck.emit(&payload.slice(prev_start..), mtu, &mut payloads);
            }
        }
    }

    payloads
}

/// xorshift64: deterministic test data without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// A byte biased towards the values start codes are made of.
    fn biased_byte(&mut self) -> u8 {
        match self.below(8) {
            0..=2 => 0,
            3 => 1,
            _ => self.next() as u8,
        }
    }
}

fn assert_next_ind_matches(data: &[u8]) {
    let data = Bytes::copy_from_slice(data);
    for start in 0..=data.len() {
        assert_eq!(
            H264Payloader::next_ind(&data, start),
            byte_loop_next_ind(&data, start),
            "data {data:?}, start {start}"
        );
    }
}

#[test]
fn test_h264_next_ind_matches_byte_loop_on_short_inputs() {
    for length in 0..=9u32 {
        for value in 0..3usize.pow(length) {
            let mut value = value;
            let data: Vec<u8> = (0..length)
                .map(|_| {
                    let b = [0, 1, 7][value % 3];
                    value /= 3;
                    b
                })
                .collect();
            assert_next_ind_matches(&data);
        }
    }
}

#[test]
fn test_h264_next_ind_matches_byte_loop_on_long_zero_runs() {
    for zero_count in [
        0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 4096,
    ] {
        let zeros = vec![0u8; zero_count];
        for (before, after) in [
            (&[][..], &[1u8, 7][..]),
            (&[7], &[1, 7]),
            (&[0x65, 1], &[1]),
            (&[], &[7, 1]),
            (&[9, 9, 9], &[]),
            (&[], &[1, 0, 0, 1]),
        ] {
            let mut data = before.to_vec();
            data.extend_from_slice(&zeros);
            data.extend_from_slice(after);
            assert_next_ind_matches(&data);
        }
    }
}

#[test]
fn test_h264_next_ind_matches_byte_loop_on_random_inputs() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2_000 {
        let len = rng.below(300);
        let data: Vec<u8> = (0..len).map(|_| rng.biased_byte()).collect();
        assert_next_ind_matches(&data);
    }
}

/// An Annex B access unit: NAL units of random type and size, each behind a start code of two
/// to six zeros and a `01`, with bodies drawn from `byte`.
fn random_access_unit(rng: &mut Rng, byte: fn(&mut Rng) -> u8) -> Vec<u8> {
    const TYPES: [u8; 10] = [0x67, 0x68, 0x65, 0x41, 0x06, 0x09, 0x0c, 0x00, 0x1c, 0x78];
    let mut au = Vec::new();
    if rng.below(4) == 0 {
        // Leading bytes before the first start code.
        let n = rng.below(5);
        au.extend((0..n).map(|_| byte(rng)));
    }
    for _ in 0..1 + rng.below(5) {
        au.extend(std::iter::repeat_n(0, 2 + rng.below(5)));
        au.push(1);
        if rng.below(8) != 0 {
            au.push(TYPES[rng.below(TYPES.len())]);
        }
        let n = match rng.below(4) {
            0 => rng.below(4),
            1 | 2 => rng.below(64),
            _ => rng.below(3000),
        };
        au.extend((0..n).map(|_| byte(rng)));
    }
    au
}

#[test]
fn test_h264_payload_matches_byte_loop_scanner() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let byte_sources: [fn(&mut Rng) -> u8; 3] = [
        Rng::biased_byte,
        |rng| rng.next() as u8,
        |rng| [0, 1, 7, 0x67, 0x68][rng.below(5)],
    ];
    for round in 0..600 {
        let mtu = match round % 5 {
            0 => 1 + rng.below(8),
            1 => 1 + rng.below(40),
            2 => 100,
            _ => 1200,
        };
        // Payloaders carry SPS/PPS between calls, so feed each pair a sequence of payloads.
        let mut pck = H264Payloader::default();
        let mut reference = H264Payloader::default();
        for _ in 0..4 {
            let byte = byte_sources[rng.below(byte_sources.len())];
            let data = if rng.below(4) == 0 {
                let n = rng.below(40);
                (0..n).map(|_| byte(&mut rng)).collect()
            } else {
                random_access_unit(&mut rng, byte)
            };
            let data = Bytes::from(data);

            let actual = pck.payload(mtu, &data).unwrap();
            let expected = byte_loop_payload(&mut reference, mtu, &data);
            assert_eq!(actual, expected, "mtu {mtu}, payload {data:?}");
            assert_eq!(pck.sps_nalu, reference.sps_nalu);
            assert_eq!(pck.pps_nalu, reference.pps_nalu);
        }
    }
}

#[test]
fn test_h264_payload_long_zero_run_prefix() -> Result<()> {
    // A start code takes every zero before its `01`, so runs longer than `00 00 00 01` leave no
    // trailing zeros on the previous unit.
    let mut pck = H264Payloader::default();
    let data = Bytes::from_static(&[0, 0, 0, 0, 0, 1, 0x65, 0xaa, 0, 0, 0, 0, 1, 0x41, 0xbb]);
    let actual = pck.payload(1200, &data)?;
    assert_eq!(
        actual,
        vec![
            Bytes::from_static(&[0x65, 0xaa]),
            Bytes::from_static(&[0x41, 0xbb]),
        ]
    );
    Ok(())
}
