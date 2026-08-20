use super::*;

#[test]
fn test_smpte336m_payload_fragments_and_reassembles() -> Result<()> {
    let mut pck = Smpte336mPayloader::default();

    const TEST_LEN: usize = 10000;
    const TEST_MTU: usize = 1400;

    let unit: Vec<u8> = (0..TEST_LEN).map(|i| (i % 256) as u8).collect();
    let unit = Bytes::copy_from_slice(&unit);

    let payloads = pck.payload(TEST_MTU, &unit)?;
    let expected_count = TEST_LEN.div_ceil(TEST_MTU);
    assert_eq!(expected_count, payloads.len());
    for payload in &payloads[..payloads.len() - 1] {
        assert_eq!(payload.len(), TEST_MTU);
    }

    let mut depkt = Smpte336mDepacketizer::default();
    let mut reassembled = Vec::new();
    for payload in &payloads {
        reassembled.extend_from_slice(&depkt.depacketize(payload)?);
    }
    assert_eq!(Bytes::from(reassembled), unit);

    Ok(())
}

#[test]
fn test_smpte336m_payload_empty_or_zero_mtu() -> Result<()> {
    let mut pck = Smpte336mPayloader::default();

    let empty = Bytes::from_static(&[]);
    assert!(pck.payload(1400, &empty)?.is_empty());

    let unit = Bytes::from_static(&[0x06, 0x0e, 0x2b, 0x34]);
    assert!(pck.payload(0, &unit)?.is_empty());

    Ok(())
}

#[test]
fn test_smpte336m_partition_boundaries_follow_marker_bit() {
    let depkt = Smpte336mDepacketizer::default();
    let payload = Bytes::from_static(&[0xab]);

    // No structural head marker exists in this payload format, so every packet is
    // accepted as a possible partition head.
    assert!(depkt.is_partition_head(&payload));

    // The marker bit is the only signal that an SMPTE ST 336 (KLV) unit is complete.
    assert!(!depkt.is_partition_tail(false, &payload));
    assert!(depkt.is_partition_tail(true, &payload));
}
