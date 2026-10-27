use super::*;

fn roundtrip(size_length_bits: u8, index_length_bits: u8, mtu: usize, au: &[u8]) -> Result<Bytes> {
    let mut payloader = Mpeg4GenericPayloader::new(size_length_bits, index_length_bits)?;
    let mut depacketizer = Mpeg4GenericDepacketizer::new(size_length_bits, index_length_bits)?;

    let au = Bytes::copy_from_slice(au);
    let packets = payloader.payload(mtu, &au)?;

    let mut out = BytesMut::new();
    for packet in &packets {
        out.put_slice(&depacketizer.depacketize(packet)?);
    }

    Ok(out.freeze())
}

#[test]
fn test_single_packet_roundtrip() -> Result<()> {
    let au = [0x11, 0x12, 0x13, 0x14, 0x15];

    let mut payloader = Mpeg4GenericPayloader::default();
    let packets = payloader.payload(1500, &Bytes::copy_from_slice(&au))?;
    assert_eq!(packets.len(), 1, "a small AU must fit in one packet");

    // AU-headers-length = 16 bits, AU-header = size(5) << 3 | index(0).
    assert_eq!(&packets[0][..4], &[0x00, 0x10, 0x00, 0x28]);
    assert_eq!(&packets[0][4..], &au);

    assert_eq!(
        roundtrip(
            DEFAULT_SIZE_LENGTH_BITS,
            DEFAULT_INDEX_LENGTH_BITS,
            1500,
            &au
        )?,
        Bytes::copy_from_slice(&au)
    );

    Ok(())
}

/// Per RFC 3640 §3.2.1.1, every fragment of an Access Unit — not just the first — carries an
/// AU-header, and its AU-size field always states the size of the *entire* Access Unit, not the
/// fragment's own size.
#[test]
fn test_fragmented_roundtrip() -> Result<()> {
    let au: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();

    let mut payloader = Mpeg4GenericPayloader::default();
    let packets = payloader.payload(1000, &Bytes::copy_from_slice(&au))?;
    assert!(packets.len() > 1, "a large AU must be fragmented");

    for packet in &packets {
        assert_eq!(
            u16::from_be_bytes([packet[0], packet[1]]),
            16,
            "every fragment carries an AU-headers-length of 16 bits"
        );
        // AU-size = au.len() (3000) << 3 | index(0) = 24000, packed into 2 bytes.
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 24000);
    }

    assert_eq!(
        roundtrip(
            DEFAULT_SIZE_LENGTH_BITS,
            DEFAULT_INDEX_LENGTH_BITS,
            1000,
            &au
        )?,
        Bytes::copy_from_slice(&au)
    );

    Ok(())
}

#[test]
fn test_multiple_access_units() -> Result<()> {
    let first = [0xAAu8; 10];
    let second = [0xBBu8; 20];

    let mut payloader = Mpeg4GenericPayloader::default();
    let mut depacketizer = Mpeg4GenericDepacketizer::default();

    let first_packets = payloader.payload(1500, &Bytes::copy_from_slice(&first))?;
    let second_packets = payloader.payload(1500, &Bytes::copy_from_slice(&second))?;

    let out_first = depacketizer.depacketize(&first_packets[0])?;
    let out_second = depacketizer.depacketize(&second_packets[0])?;

    assert_eq!(out_first, Bytes::copy_from_slice(&first));
    assert_eq!(out_second, Bytes::copy_from_slice(&second));

    Ok(())
}

/// Known limitation, documented rather than silently left as a surprise: RFC 3640 gives no bit
/// marking a fragment as the first one (see the module docs), so if every continuation fragment
/// of an Access Unit is lost, a subsequent, coincidentally same-sized Access Unit's data is
/// appended to the still-open reassembly buffer instead of starting a new one. Real reassembly
/// across loss additionally depends on the RTP timestamp, which this depacketizer never sees
/// (`Depacketizer::depacketize` takes only the payload) — the caller (e.g. a jitter-buffering
/// sample builder keyed on RTP timestamp and `is_partition_tail`/the marker bit) is expected to
/// stop feeding it packets from a dropped Access Unit before this can happen, in practice.
#[test]
fn test_same_size_au_after_packet_loss_is_a_known_limitation() -> Result<()> {
    let lost = vec![0xCCu8; 30];
    let next = vec![0xDDu8; 30];

    let mut payloader = Mpeg4GenericPayloader::new(6, 0)?; // sizeLength=6 caps the AU at 63 bytes.
    let mut depacketizer = Mpeg4GenericDepacketizer::new(6, 0)?;

    let lost_packets = payloader.payload(mtu_for_one_byte_fragments(), &Bytes::copy_from_slice(&lost))?;
    assert!(lost_packets.len() > 1, "test setup: `lost` must fragment");
    // Simulate losing every packet of `lost` except the first, leaving a dangling partial AU.
    depacketizer.depacketize(&lost_packets[0])?;

    // `next` happens to be the same size as `lost`, so its first packet cannot be told apart
    // from a continuation of the abandoned one: its 30 bytes get appended to the 10 bytes
    // already buffered from `lost`, completing (and truncating to) a corrupted 30-byte "AU" —
    // the first 10 bytes of `lost` followed by the first 20 bytes of `next` — instead of
    // starting fresh and eventually emitting `next` intact.
    let next_packets = payloader.payload(1500, &Bytes::copy_from_slice(&next))?;
    let out = depacketizer.depacketize(&next_packets[0])?;
    let mut expected_corrupted = lost[..10].to_vec();
    expected_corrupted.extend_from_slice(&next[..20]);
    assert_eq!(
        out,
        Bytes::copy_from_slice(&expected_corrupted),
        "documents the known limitation above"
    );

    Ok(())
}

fn mtu_for_one_byte_fragments() -> usize {
    // sizeLength=6, indexLength=0 -> a 1-byte AU-header; overhead is AU_HEADERS_LENGTH_SIZE(2) + 1.
    3 + 10
}

#[test]
fn test_payload_empty_or_zero_mtu() -> Result<()> {
    let mut payloader = Mpeg4GenericPayloader::default();

    let empty = Bytes::from_static(&[]);
    let payload = Bytes::from_static(&[0x11, 0x12, 0x13]);

    assert!(payloader.payload(1500, &empty)?.is_empty());
    assert!(payloader.payload(0, &payload)?.is_empty());

    Ok(())
}

#[test]
fn test_payload_au_too_large() {
    let mut payloader = Mpeg4GenericPayloader::default();
    let au = Bytes::copy_from_slice(&vec![0u8; 1 << DEFAULT_SIZE_LENGTH_BITS]);
    assert!(payloader.payload(1500, &au).is_err());
}

#[test]
fn test_depacketize_short_packet() {
    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    let packet = Bytes::from_static(&[0x00]);
    assert!(depacketizer.depacketize(&packet).is_err());
}

#[test]
fn test_depacketize_unsupported_au_headers_length() {
    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    // AU-headers-length = 32 bits, i.e. two AU-headers (bundling two complete Access Units) —
    // valid on the wire (see the `_aus` tests below), but `depacketize` only ever accepts one.
    let packet = Bytes::from_static(&[0x00, 0x20, 0, 0, 0, 0]);
    assert!(depacketizer.depacketize(&packet).is_err());
}

/// A zero `AU-headers-length` (the "configured empty AU Header Section" case, RFC 3640 §3.2.1)
/// isn't supported either: this implementation always expects the AU-header this depacketizer
/// was configured for, on every packet.
#[test]
fn test_depacketize_zero_au_headers_length_unsupported() {
    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    let packet = Bytes::from_static(&[0x00, 0x00, 0x11, 0x12]);
    assert!(depacketizer.depacketize(&packet).is_err());
}

/// RFC 3640 gives no bit distinguishing a fragment's position, so a well-formed continuation
/// fragment is structurally indistinguishable from a well-formed first fragment — both parse the
/// same AU-header and both report `is_partition_head`. See the module docs and
/// [`Mpeg4GenericDepacketizer::is_partition_head`].
#[test]
fn test_is_partition_head_and_tail() {
    let depacketizer = Mpeg4GenericDepacketizer::default();

    let start = Bytes::from_static(&[0x00, 0x10, 0x00, 0x28, 0x11]);
    let continuation = Bytes::from_static(&[0x00, 0x10, 0x00, 0x28, 0x12]);
    let malformed = Bytes::from_static(&[0x00, 0x00, 0x12]);

    assert!(depacketizer.is_partition_head(&start));
    assert!(depacketizer.is_partition_head(&continuation));
    assert!(!depacketizer.is_partition_head(&malformed));

    assert!(depacketizer.is_partition_tail(true, &start));
    assert!(!depacketizer.is_partition_tail(false, &start));
}

#[test]
fn test_invalid_au_header_lengths_rejected() {
    assert!(
        Mpeg4GenericPayloader::new(0, 3).is_err(),
        "sizeLength=0 must be rejected"
    );
    assert!(
        Mpeg4GenericPayloader::new(30, 3).is_err(),
        "sizeLength + indexLength > 32 must be rejected"
    );
    assert!(Mpeg4GenericDepacketizer::new(0, 3).is_err());
    assert!(Mpeg4GenericDepacketizer::new(30, 3).is_err());
}

/// A non-default `sizeLength`/`indexLength` (as negotiated via SDP fmtp, e.g.
/// `sizelength=6;indexlength=2;indexdeltalength=2`) must roundtrip too, with a correspondingly
/// sized (1-byte) AU-header instead of AAC-hbr's 2-byte one.
#[test]
fn test_custom_size_and_index_length_roundtrip() -> Result<()> {
    let au = [0x01, 0x02, 0x03, 0x04];

    let mut payloader = Mpeg4GenericPayloader::new(6, 2)?;
    let packets = payloader.payload(1500, &Bytes::copy_from_slice(&au))?;
    assert_eq!(packets.len(), 1);

    // AU-headers-length = 8 bits, AU-header = size(4) << 2 | index(0), in a single byte.
    assert_eq!(&packets[0][..3], &[0x00, 0x08, 0x04 << 2]);
    assert_eq!(&packets[0][3..], &au);

    assert_eq!(roundtrip(6, 2, 1500, &au)?, Bytes::copy_from_slice(&au));

    // And fragmented, to exercise the non-default header size on every fragment.
    // (sizeLength=6 caps the AU at 63 bytes, so keep this one within range.)
    let big_au: Vec<u8> = (0..50).collect();
    assert_eq!(
        roundtrip(6, 2, 20, &big_au)?,
        Bytes::copy_from_slice(&big_au)
    );

    Ok(())
}

#[test]
fn test_mismatched_size_length_between_peers_errors() -> Result<()> {
    // One side configured for AAC-hbr (13/3, 2-byte header), the other for 6/2 (1-byte header):
    // the depacketizer must reject the mismatched AU-headers-length rather than misparse it.
    let mut payloader = Mpeg4GenericPayloader::new(6, 2)?;
    let mut depacketizer =
        Mpeg4GenericDepacketizer::new(DEFAULT_SIZE_LENGTH_BITS, DEFAULT_INDEX_LENGTH_BITS)?;

    let packets = payloader.payload(1500, &Bytes::from_static(&[0x11, 0x12]))?;
    assert!(depacketizer.depacketize(&packets[0]).is_err());

    Ok(())
}

#[test]
fn test_payload_aus_bundles_several_small_aus_into_one_packet() -> Result<()> {
    let aus = [
        Bytes::from_static(&[0x01, 0x02]),
        Bytes::from_static(&[0x03, 0x04, 0x05]),
        Bytes::from_static(&[0x06]),
    ];

    let mut payloader = Mpeg4GenericPayloader::default();
    let packets = payloader.payload_aus(1500, &aus)?;
    assert_eq!(packets.len(), 1, "all three fit under the MTU together");

    // AU-headers-length = 3 * 16 = 48 bits; 3 AU-headers, each a big-endian u16 of
    // `size << 3 | index(0)`; then the AUs' data concatenated in order.
    assert_eq!(&packets[0][..2], &[0x00, 0x30]);
    assert_eq!(
        &packets[0][2..8],
        &[0x00, 0x02 << 3, 0x00, 0x03 << 3, 0x00, 0x01 << 3]
    );
    assert_eq!(&packets[0][8..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    let out = depacketizer.depacketize_aus(&packets[0])?;
    assert_eq!(out, aus);

    Ok(())
}

#[test]
fn test_payload_aus_flushes_bundle_before_an_au_that_would_overflow_it() -> Result<()> {
    // Each AU plus its header takes AU_HEADERS_LENGTH_SIZE(2) + header(2) + 10 = 14 bytes when
    // bundled; an MTU of 30 fits two bundled but not three (2*10+2+4=26 fits, +10 more won't).
    let aus: Vec<Bytes> = (0..3)
        .map(|i| Bytes::copy_from_slice(&[i as u8; 10]))
        .collect();

    let mut payloader = Mpeg4GenericPayloader::default();
    let packets = payloader.payload_aus(30, &aus)?;
    assert_eq!(
        packets.len(),
        2,
        "the first two AUs bundle together, the third gets its own packet"
    );

    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    let mut out = depacketizer.depacketize_aus(&packets[0])?;
    out.extend(depacketizer.depacketize_aus(&packets[1])?);
    assert_eq!(out, aus);

    Ok(())
}

#[test]
fn test_payload_aus_fragments_an_oversized_au_amid_bundling() -> Result<()> {
    let small_before = Bytes::from_static(&[0xAA; 5]);
    let oversized = Bytes::copy_from_slice(&(0..2000).map(|i| i as u8).collect::<Vec<u8>>());
    let small_after = Bytes::from_static(&[0xBB; 5]);

    let mut payloader = Mpeg4GenericPayloader::default();
    let packets = payloader.payload_aus(1000, &[small_before.clone(), oversized.clone(), small_after.clone()])?;
    assert!(
        packets.len() > 2,
        "the oversized AU alone must span more than one packet"
    );

    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    let mut recovered = Vec::new();
    for packet in &packets {
        recovered.extend(depacketizer.depacketize_aus(packet)?);
    }
    assert_eq!(recovered, vec![small_before, oversized, small_after]);

    Ok(())
}

#[test]
fn test_payload_aus_empty_input() -> Result<()> {
    let mut payloader = Mpeg4GenericPayloader::default();
    assert!(payloader.payload_aus(1500, &[])?.is_empty());
    assert!(payloader.payload_aus(0, &[Bytes::from_static(&[1])])?.is_empty());
    Ok(())
}

#[test]
fn test_depacketize_aus_rejects_short_bundled_packet() {
    let mut depacketizer = Mpeg4GenericDepacketizer::default();
    // AU-headers-length = 32 bits (2 headers) declaring sizes 5 and 5, but only 3 data bytes.
    let packet = Bytes::from_static(&[0x00, 0x20, 0x00, 0x28, 0x00, 0x28, 0x01, 0x02, 0x03]);
    assert!(depacketizer.depacketize_aus(&packet).is_err());
}
