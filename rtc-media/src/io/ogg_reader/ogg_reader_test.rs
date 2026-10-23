use bytes::Bytes;
use std::io::Cursor;

use super::*;

// generates a valid ogg file that can be used for tests
fn build_ogg_container() -> Vec<u8> {
    vec![
        0x4f, 0x67, 0x67, 0x53, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e,
        0x9b, 0x20, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x61, 0xee, 0x61, 0x17, 0x01, 0x13, 0x4f, 0x70,
        0x75, 0x73, 0x48, 0x65, 0x61, 0x64, 0x01, 0x02, 0x00, 0x0f, 0x80, 0xbb, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x4f, 0x67, 0x67, 0x53, 0x00, 0x00, 0xda, 0x93, 0xc2, 0xd9, 0x00, 0x00, 0x00,
        0x00, 0x8e, 0x9b, 0x20, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x49, 0x97, 0x03, 0x37, 0x01, 0x05,
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]
}

// pion buildSurroundOggContainerShort: family 1 with the mapping table missing.
fn build_surround_ogg_container_short() -> Vec<u8> {
    vec![
        0x4f, 0x67, 0x67, 0x53, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58,
        0x49, 0xac, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xc1, 0xa8, 0x7d, 0x4e, 0x01, 0x13, 0x4f, 0x70,
        0x75, 0x73, 0x48, 0x65, 0x61, 0x64, 0x01, 0x06, 0x38, 0x01, 0x80, 0xbb, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ]
}

fn build_opus_head_payload(
    version: u8,
    channels: u8,
    preskip: u16,
    sample_rate: u32,
    output_gain: u16,
    channel_map: u8,
) -> Vec<u8> {
    let mut payload = ID_PAGE_SIGNATURE.to_vec();
    payload.push(version);
    payload.push(channels);
    payload.extend_from_slice(&preskip.to_le_bytes());
    payload.extend_from_slice(&sample_rate.to_le_bytes());
    payload.extend_from_slice(&output_gain.to_le_bytes());
    payload.push(channel_map);
    payload
}

fn build_unknown_mapping_family_container(mapping_family: u8, channels: u8) -> Vec<u8> {
    build_page(
        0,
        0,
        PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
        &build_opus_head_payload(1, channels, 0x0138, 48_000, 0, mapping_family),
    )
}

fn build_channel_mapping_family_container(
    mapping_family: u8,
    channels: u8,
    stream_count: u8,
    coupled_count: u8,
    mapping: &[u8],
) -> Vec<u8> {
    let mut payload = build_opus_head_payload(1, channels, 0x0138, 48_000, 0, mapping_family);
    payload.push(stream_count);
    payload.push(coupled_count);
    payload.extend_from_slice(mapping);
    build_page(0, 0, PAGE_HEADER_TYPE_BEGINNING_OF_STREAM, &payload)
}

/// pion's `buildOggPage` (checksums left zero; tests disable them).
fn build_page(serial: u32, page_index: u32, header_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut page = Vec::with_capacity(PAGE_HEADER_SIZE + 1 + payload.len());
    page.extend_from_slice(PAGE_HEADER_SIGNATURE);
    page.push(0); // version
    page.push(header_type);
    page.extend_from_slice(&0u64.to_le_bytes()); // granule position
    page.extend_from_slice(&serial.to_le_bytes());
    page.extend_from_slice(&page_index.to_le_bytes());
    page.extend_from_slice(&0u32.to_le_bytes()); // checksum
    page.push(1); // one segment
    page.push(payload.len() as u8);
    page.extend_from_slice(payload);
    page
}

// pion TestOggReader_ParseValidHeader.
#[test]
fn test_ogg_reader_parse_valid_header() -> Result<()> {
    let ogg = build_ogg_container();
    let (_reader, header) = OggReader::new(Cursor::new(ogg), true)?;

    assert_eq!(header.channel_map, 0);
    assert_eq!(header.channels, 2);
    assert_eq!(header.output_gain, 0);
    assert_eq!(header.pre_skip, 0xf00);
    assert_eq!(header.sample_rate, 48000);
    assert_eq!(header.version, 1);
    Ok(())
}

// pion TestOggReader_ParseNextPage, including the byte counters
// (`bytesReadSuccesfully`).
#[test]
fn test_ogg_reader_parse_next_page() -> Result<()> {
    let ogg = build_ogg_container();
    let (mut reader, _) = OggReader::new(Cursor::new(ogg), true)?;
    assert_eq!(47, reader.bytes_read);

    let (payload, _) = reader.parse_next_page()?;
    assert_eq!(Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]), payload);
    assert_eq!(80, reader.bytes_read);

    assert!(reader.parse_next_page().is_err(), "EOF after the last page");
    Ok(())
}

// pion TestOggReader_ParseErrors.
#[test]
fn test_ogg_reader_parse_errors() -> Result<()> {
    // Invalid ID Page Header Signature
    {
        let mut ogg = build_ogg_container();
        ogg[0] = 0;
        assert_eq!(
            OggReader::new(Cursor::new(ogg), false).err(),
            Some(Error::ErrBadIDPageSignature)
        );
    }

    // Invalid ID Page Header Type
    {
        let mut ogg = build_ogg_container();
        ogg[5] = 0;
        assert_eq!(
            OggReader::new(Cursor::new(ogg), false).err(),
            Some(Error::ErrBadIDPageType)
        );
    }

    // Invalid ID Page Payload Length (empty payload: the segment size is zeroed)
    {
        let mut ogg = build_ogg_container();
        ogg[27] = 0;
        assert_eq!(
            OggReader::new(Cursor::new(ogg), false).err(),
            Some(Error::ErrBadIDPageLength)
        );
    }

    // Invalid ID Page Payload Signature (the OpusHead magic is corrupted)
    {
        let mut ogg = build_ogg_container();
        ogg[35] = 0;
        assert_eq!(
            OggReader::new(Cursor::new(ogg), false).err(),
            Some(Error::ErrBadIDPagePayloadSignature)
        );
    }

    // Invalid Page Checksum
    {
        let mut ogg = build_ogg_container();
        ogg[22] = 0;
        assert_eq!(
            OggReader::new(Cursor::new(ogg), true).err(),
            Some(Error::ErrChecksumMismatch)
        );
    }

    // Invalid Multichannel ID Page Payload Length
    assert_eq!(
        OggReader::new(Cursor::new(build_surround_ogg_container_short()), false).err(),
        Some(Error::ErrBadIDPageLength)
    );

    // Unsupported Channel Mapping Family
    assert_eq!(
        OggReader::new(
            Cursor::new(build_unknown_mapping_family_container(4, 2)),
            false
        )
        .err(),
        Some(Error::ErrUnsupportedChannelMappingFamily)
    );

    Ok(())
}

// pion TestOggReader_ChannelMappingFamily1: the Vorbis-order surrounds.
#[test]
fn test_ogg_reader_channel_mapping_family_1() -> Result<()> {
    let cases = [
        (1u8, 1u8, 0u8, vec![0u8]),
        (2, 1, 1, vec![0, 1]),
        (3, 2, 1, vec![0, 2, 1]),
        (4, 2, 2, vec![0, 1, 2, 3]),
        (5, 3, 2, vec![0, 1, 2, 3, 4]),
        (6, 4, 2, vec![0, 4, 1, 2, 3, 5]),
        (7, 4, 3, vec![0, 1, 2, 3, 4, 5, 6]),
        (8, 5, 3, vec![0, 1, 2, 3, 4, 5, 6, 7]),
    ];

    for (channels, streams, coupled, channel_map) in cases {
        let data =
            build_channel_mapping_family_container(1, channels, streams, coupled, &channel_map);
        let mut reader = OggReader::new_with_options(Cursor::new(data), false);

        let (payload, page_header) = reader.parse_next_page()?;
        assert_eq!(
            Some(OggHeaderType::OpusHead),
            page_header.opus_header_type(&payload)
        );

        let header = parse_opus_head(&payload)?;
        assert_eq!(1, header.version);
        assert_eq!(channels, header.channels);
        assert_eq!(0x138, header.pre_skip);
        assert_eq!(48_000, header.sample_rate);
        assert_eq!(0, header.output_gain);
        assert_eq!(1, header.channel_map);
        assert_eq!(streams, header.stream_count);
        assert_eq!(coupled, header.coupled_count);
        assert_eq!(channel_map, header.channel_mapping);
    }
    Ok(())
}

// pion TestOggReader_KnownChannelMappingFamilies.
#[test]
fn test_ogg_reader_known_channel_mapping_families() -> Result<()> {
    let cases = [
        (2u8, 2u8, 1u8, 1u8, vec![0u8, 1]),
        (255, 2, 1, 1, vec![0, 1]),
    ];

    for (family, channels, streams, coupled, channel_map) in cases {
        let data = build_channel_mapping_family_container(
            family,
            channels,
            streams,
            coupled,
            &channel_map,
        );
        let mut reader = OggReader::new_with_options(Cursor::new(data), false);

        let (payload, page_header) = reader.parse_next_page()?;
        assert_eq!(
            Some(OggHeaderType::OpusHead),
            page_header.opus_header_type(&payload)
        );

        let header = parse_opus_head(&payload)?;
        assert_eq!(family, header.channel_map);
        assert_eq!(channels, header.channels);
        assert_eq!(0x138, header.pre_skip);
        assert_eq!(48_000, header.sample_rate);
        assert_eq!(0, header.output_gain);
    }
    Ok(())
}

// pion TestOggReader_ParseExtraFieldsForNonZeroMappingFamily.
#[test]
fn test_ogg_reader_parse_extra_fields_for_non_zero_mapping_family() -> Result<()> {
    let cases = [
        (1u8, 2u8, 1u8, 1u8, vec![0u8, 1]),
        (1, 6, 4, 2, vec![0, 4, 1, 2, 3, 5]),
        (1, 8, 5, 3, vec![0, 1, 2, 3, 4, 5, 6, 7]),
        (2, 4, 2, 2, vec![0, 1, 2, 3]),
        (255, 5, 3, 2, vec![0, 1, 2, 3, 4]),
    ];

    for (family, channels, streams, coupled, channel_map) in cases {
        let data = build_channel_mapping_family_container(
            family,
            channels,
            streams,
            coupled,
            &channel_map,
        );
        let mut reader = OggReader::new_with_options(Cursor::new(data), false);

        let (payload, page_header) = reader.parse_next_page()?;
        assert_eq!(
            Some(OggHeaderType::OpusHead),
            page_header.opus_header_type(&payload)
        );

        let header = parse_opus_head(&payload)?;
        assert_eq!(family, header.channel_map);
        assert_eq!(channels, header.channels);
        assert_eq!(streams, header.stream_count);
        assert_eq!(coupled, header.coupled_count);
        assert_eq!(channel_map, header.channel_mapping);
    }
    Ok(())
}

// pion TestOggReader_NewWithOptions. The Rust API takes the checksum flag
// directly (pion's option validates a default), so the default-true arm is the
// plain `new` constructor.
#[test]
fn test_ogg_reader_new_with_options() -> Result<()> {
    // Checksum enabled (pion's default): a corrupted checksum fails the page.
    {
        let mut reader = OggReader::new_with_options(Cursor::new(build_ogg_container()), true);
        let (payload, _) = reader.parse_next_page()?;
        assert_eq!(ID_PAGE_SIGNATURE, &payload[..8]);

        let mut ogg = build_ogg_container();
        ogg[22] = 0;
        let mut reader = OggReader::new_with_options(Cursor::new(ogg), true);
        assert_eq!(
            reader.parse_next_page().err(),
            Some(Error::ErrChecksumMismatch)
        );
    }

    // Checksum disabled: the same corruption is ignored.
    {
        let mut ogg = build_ogg_container();
        ogg[22] = 0;
        let mut reader = OggReader::new_with_options(Cursor::new(ogg), false);
        assert!(reader.parse_next_page().is_ok());
    }
    Ok(())
}

// pion TestOggReader_MultiTrackFile: two Opus ID pages, one per logical stream.
#[test]
fn test_ogg_reader_multi_track_file() -> Result<()> {
    let first_serial = 0xd03e_d35du32;
    let second_serial = 0xfa6e_13f0u32;
    let opus_head = build_opus_head_payload(1, 1, 0x0138, 48_000, 0, 0);

    let mut data = build_page(
        first_serial,
        0,
        PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
        &opus_head,
    );
    data.extend(build_page(
        second_serial,
        0,
        PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
        &opus_head,
    ));

    let mut reader = OggReader::new_with_options(Cursor::new(data), false);
    let mut headers = vec![];
    let mut serials = vec![];
    while let Ok((payload, page_header)) = reader.parse_next_page() {
        assert_eq!(
            Some(OggHeaderType::OpusHead),
            page_header.opus_header_type(&payload)
        );
        headers.push(parse_opus_head(&payload)?);
        serials.push(page_header.serial);
    }

    assert_eq!(2, headers.len(), "both tracks' headers are found");
    assert_eq!(1, headers[0].channels);
    assert_eq!(1, headers[1].channels);
    assert_eq!(48_000, headers[0].sample_rate);
    assert_eq!(48_000, headers[1].sample_rate);
    assert_eq!(vec![first_serial, second_serial], serials);
    Ok(())
}

fn build_opus_tags_payload(vendor: &str, comments: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = COMMENT_PAGE_SIGNATURE.to_vec();
    payload.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    payload.extend_from_slice(vendor.as_bytes());
    payload.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for (comment, value) in comments {
        let len = comment.len() + 1 + value.len();
        payload.extend_from_slice(&(len as u32).to_le_bytes());
        payload.extend_from_slice(comment.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value.as_bytes());
    }
    payload
}

// pion TestOggReader_DetectHeadersAndTags.
#[test]
fn test_ogg_reader_detect_headers_and_tags() -> Result<()> {
    let serial1 = 0xd03e_d35du32;
    let serial2 = 0xfa6e_13f0u32;

    let track1_comments = vec![
        ("title", "never gonna give you up"),
        ("encoder", "test-encoder-v1.0"),
    ];
    let track2_comments = vec![("title", "Noise Track 2"), ("encoder", "test-encoder-v1.0")];
    let opus_head = build_opus_head_payload(1, 2, 0x0138, 48_000, 0, 0);

    let mut data = build_page(serial1, 0, PAGE_HEADER_TYPE_BEGINNING_OF_STREAM, &opus_head);
    data.extend(build_page(
        serial1,
        1,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        &build_opus_tags_payload("TestVendor", &track1_comments),
    ));
    data.extend(build_page(
        serial2,
        0,
        PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
        &opus_head,
    ));
    data.extend(build_page(
        serial2,
        1,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        &build_opus_tags_payload("TestVendor", &track2_comments),
    ));

    let mut reader = OggReader::new_with_options(Cursor::new(data), false);
    let mut opus_id_count = 0;
    let mut opus_tags_count = 0;
    let mut tags = vec![];
    while let Ok((payload, page_header)) = reader.parse_next_page() {
        match page_header.opus_header_type(&payload) {
            Some(OggHeaderType::OpusHead) => opus_id_count += 1,
            Some(OggHeaderType::OpusTags) => {
                opus_tags_count += 1;
                tags.push((page_header.serial, parse_opus_tags(&payload)?));
            }
            None => {}
        }
    }

    assert_eq!(2, opus_id_count, "two OpusHead pages");
    assert_eq!(2, opus_tags_count, "two OpusTags pages");

    let to_map = |tags: &OpusTags| -> std::collections::HashMap<String, String> {
        tags.user_comments
            .iter()
            .map(|c| (c.comment.clone(), c.value.clone()))
            .collect()
    };
    let (_, track1) = &tags[0];
    let (_, track2) = &tags[1];
    assert_eq!("TestVendor", track1.vendor);
    assert_eq!("TestVendor", track2.vendor);
    let track1 = to_map(track1);
    let track2 = to_map(track2);
    assert_eq!(
        Some(&"never gonna give you up".to_owned()),
        track1.get("title")
    );
    assert_eq!(Some(&"test-encoder-v1.0".to_owned()), track1.get("encoder"));
    assert_eq!(Some(&"Noise Track 2".to_owned()), track2.get("title"));
    assert_eq!(Some(&"test-encoder-v1.0".to_owned()), track2.get("encoder"));
    Ok(())
}

// pion TestParseOpusTagsErrors.
#[test]
fn test_parse_opus_tags_errors() {
    let make_header = |length: usize| {
        let mut payload = vec![0u8; length];
        payload[..8].copy_from_slice(COMMENT_PAGE_SIGNATURE);
        payload
    };

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("payload too short", b"short".to_vec()),
        ("bad signature", {
            let mut payload = b"OpusHead".to_vec();
            payload.extend_from_slice(&[0u8; 8]);
            payload
        }),
        ("vendor length longer than payload", {
            let mut payload = make_header(20);
            payload[8..12].copy_from_slice(&10u32.to_le_bytes());
            payload
        }),
        ("unreasonable comment count", {
            let mut payload = make_header(17);
            payload[8..12].copy_from_slice(&1u32.to_le_bytes());
            payload[12] = b'v';
            payload[13..17].copy_from_slice(&3u32.to_le_bytes());
            payload
        }),
        ("payload too short for first comment length", {
            let mut payload = make_header(16);
            payload[8..12].copy_from_slice(&0u32.to_le_bytes());
            payload[12..16].copy_from_slice(&1u32.to_le_bytes());
            payload
        }),
        ("payload too short for comment data", {
            let mut payload = make_header(20);
            payload[8..12].copy_from_slice(&0u32.to_le_bytes());
            payload[12..16].copy_from_slice(&1u32.to_le_bytes());
            payload[16..20].copy_from_slice(&10u32.to_le_bytes());
            payload
        }),
        ("invalid comment format", {
            let comment = b"novalue";
            let mut payload = make_header(20 + comment.len());
            payload[8..12].copy_from_slice(&0u32.to_le_bytes());
            payload[12..16].copy_from_slice(&1u32.to_le_bytes());
            payload[16..20].copy_from_slice(&(comment.len() as u32).to_le_bytes());
            payload[20..].copy_from_slice(comment);
            payload
        }),
    ];

    for (name, payload) in cases {
        assert!(
            matches!(
                parse_opus_tags(&payload),
                Err(Error::ErrBadOpusTagsSignature)
            ),
            "{name}"
        );
    }
}

// pion TestParseOpusHead_EmptyPayload_NoPanic.
#[test]
fn test_parse_opus_head_empty_payload_no_panic() {
    assert!(parse_opus_head(&[]).is_err());
}

// pion TestParseOpusHead_ChannelMappingSliceOverflow_NoPanic: a family-1
// header with the largest channel count parses without slicing out of range.
#[test]
fn test_parse_opus_head_channel_mapping_slice_overflow_no_panic() {
    let channels = 235u8;
    let mut payload = vec![0u8; 21 + channels as usize];
    payload[..8].copy_from_slice(ID_PAGE_SIGNATURE);
    payload[8] = 1;
    payload[9] = channels;
    payload[12..16].copy_from_slice(&48_000u32.to_le_bytes());
    payload[18] = 1; // family 1
    payload[19] = channels;
    payload[20] = 0;
    for (i, entry) in payload[21..].iter_mut().enumerate() {
        *entry = i as u8;
    }

    let header = parse_opus_head(&payload).expect("no panic, valid header");
    assert_eq!(channels as usize, header.channel_mapping.len());
}
