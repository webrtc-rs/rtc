use bytes::Bytes;

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

#[test]
fn test_ogg_reader_parse_valid_header() -> Result<()> {
    let ogg = build_ogg_container();
    let r = Cursor::new(&ogg);
    let (_reader, header) = OggReader::new(r, true)?;

    assert_eq!(header.channel_map, 0);
    assert_eq!(header.channels, 2);
    assert_eq!(header.output_gain, 0);
    assert_eq!(header.pre_skip, 0xf00);
    assert_eq!(header.sample_rate, 48000);
    assert_eq!(header.version, 1);

    Ok(())
}

#[test]
fn test_ogg_reader_parse_next_page() -> Result<()> {
    let ogg = build_ogg_container();
    let r = Cursor::new(&ogg);
    let (mut reader, _header) = OggReader::new(r, true)?;

    let (payload, _) = reader.parse_next_page()?;
    assert_eq!(payload, Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]));

    let result = reader.parse_next_page();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_ogg_reader_parse_errors() -> Result<()> {
    //"Invalid ID Page Header Signature"
    {
        let mut ogg = build_ogg_container();
        ogg[0] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageSignature);
        }
    }

    //"Invalid ID Page Header Type"
    {
        let mut ogg = build_ogg_container();
        ogg[5] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageType);
        }
    }

    //"Invalid ID Page Payload Length"
    {
        let mut ogg = build_ogg_container();
        ogg[27] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageLength);
        }
    }

    //"Invalid ID Page Payload Length"
    {
        let mut ogg = build_ogg_container();
        ogg[35] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPagePayloadSignature);
        }
    }

    //"Invalid Page Checksum"
    {
        let mut ogg = build_ogg_container();
        ogg[22] = 0;

        let result = OggReader::new(Cursor::new(ogg), true);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrChecksumMismatch);
        }
    }

    Ok(())
}

/// The byte-at-a-time table walk the reader and writer used before `PageChecksum`, kept as the
/// reference the accelerated checksum is compared with.
fn reference_page_checksum(mut sum: u32, data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut r = (i as u32) << 24;
        for _ in 0..8 {
            r = if r & 0x8000_0000 != 0 {
                (r << 1) ^ 0x04c1_1db7
            } else {
                r << 1
            };
        }
        *t = r;
    }
    for &v in data {
        sum = (sum << 8) ^ table[(((sum >> 24) as u8) ^ v) as usize];
    }
    sum
}

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state = 0xfeed_face_1234_5678u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn page_checksum_matches_the_check_value() {
    assert_eq!(PageChecksum::of(b"123456789"), 0x89a1_897f);
    assert_eq!(PageChecksum::of(b""), 0);
}

/// Every length through 256 bytes at every alignment of the start within a 16-byte vector, plus
/// sizes up to the largest page (255 segments of 255 bytes plus a 282-byte header).
#[test]
fn page_checksum_matches_the_table_walk() {
    let data = pseudo_random_bytes(65_307 + 16);
    for offset in 0..16 {
        for len in (0..=256).chain([511, 512, 1200, 4096, 16_384, 65_307]) {
            let input = &data[offset..offset + len];
            assert_eq!(
                PageChecksum::of(input),
                reference_page_checksum(0, input),
                "offset {offset}, length {len}"
            );
        }
    }
}

/// The reader feeds the header, segment table and payload separately; splitting the input at any
/// point must not change the result.
#[test]
fn page_checksum_is_incremental() {
    let data = pseudo_random_bytes(4096);
    let whole = reference_page_checksum(0, &data);
    for first in (0..=300).chain([1000, 2047, 4096]) {
        for second in [first, first + 1, first + 27, first + 255, 4096] {
            let second = second.min(data.len());
            let mut sum = PageChecksum::new();
            sum.update(&data[..first]);
            sum.update(&data[first..second]);
            sum.update(&data[second..]);
            assert_eq!(sum.finish(), whole, "split at {first} and {second}");
        }
    }
}

/// Pages the writer produces pass the reader's check, and corrupting any single bit of a page
/// makes the reader reject it (a CRC detects every single-bit error).
#[test]
fn written_pages_verify_and_every_corruption_is_rejected() -> Result<()> {
    use crate::io::Writer;
    use crate::io::ogg_writer::OggWriter;

    let mut file = Vec::new();
    {
        let mut writer = OggWriter::new(&mut file, 48_000, 2)?;
        for (i, len) in [1usize, 254, 255, 256, 1200, 4000].into_iter().enumerate() {
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    sequence_number: i as u16,
                    timestamp: 960 * i as u32,
                    ..Default::default()
                },
                payload: Bytes::from(pseudo_random_bytes(len)),
            };
            writer.write_rtp(&packet)?;
        }
        writer.close()?;
    }

    let mut reader = OggReader::new_with_options(Cursor::new(&file), true);
    let mut page_starts = vec![0];
    while let Ok((payload, header)) = reader.parse_next_page() {
        let start = *page_starts.last().unwrap();
        page_starts.push(start + PAGE_HEADER_SIZE + header.segments_count as usize + payload.len());
    }
    assert_eq!(
        *page_starts.last().unwrap(),
        file.len(),
        "every page verified"
    );
    assert!(page_starts.len() > 6);

    // Corrupt the last audio page, bit by bit, and read it on its own.
    let start = page_starts[page_starts.len() - 2];
    let page = &file[start..];
    for byte in 0..page.len() {
        for bit in 0..8 {
            let mut corrupted = page.to_vec();
            corrupted[byte] ^= 1 << bit;
            let mut reader = OggReader::new_with_options(Cursor::new(corrupted), true);
            assert!(
                reader.parse_next_page().is_err(),
                "flipping bit {bit} of byte {byte} went undetected"
            );
        }
    }

    Ok(())
}
