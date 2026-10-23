use std::io::Cursor;

use super::*;

fn h264_reader(data: &[u8]) -> H26xReader<Cursor<&[u8]>> {
    H26xReader::new(Cursor::new(data), 3, false)
}

fn h265_reader(data: &[u8]) -> H26xReader<Cursor<&[u8]>> {
    H26xReader::new(Cursor::new(data), 3, true)
}

fn h264(nal: H26xNAL) -> H264NAL {
    match nal {
        H26xNAL::H264(nal) => nal,
        H26xNAL::H265(_) => panic!("expected an H.264 NAL"),
    }
}

fn h265(nal: H26xNAL) -> H265NAL {
    match nal {
        H26xNAL::H265(nal) => nal,
        H26xNAL::H264(_) => panic!("expected an H.265 NAL"),
    }
}

/// pion h264reader TestDataDoesNotStartWithH264Header: a stream that ends before a full
/// start code reports EOF; a full-but-wrong word reports "not a H264 bitstream".
#[test]
fn test_h264_reader_data_does_not_start_with_h264_header() {
    let tests: Vec<(&[u8], bool)> = vec![
        (&[2], true),           // EOF: stream ended mid-word
        (&[0, 2], true),        // EOF: stream ended mid-word
        (&[0, 0, 2], true),     // EOF: stream ended mid-word
        (&[0, 0, 2, 0], false), // full word, not a prefix
        (&[0, 0, 0, 2], false), // full word, not a prefix
    ];

    for (input, expect_eof) in tests {
        let mut reader = h264_reader(input);
        match (reader.next_nal(), expect_eof) {
            (Err(Error::ErrIoEOF), true) => {}
            (Err(Error::ErrDataIsNotH264Stream), false) => {}
            (result, _) => panic!(
                "input {input:?}: unexpected result {:?}",
                result.as_ref().map(|_| "()")
            ),
        }
    }
}

/// pion h264reader TestParseHeader: header fields parsed from the first NAL byte.
#[test]
fn test_h264_reader_parse_header() {
    let mut reader = h264_reader(&[0x0, 0x0, 0x1, 0xAB]);
    let nal = h264(reader.next_nal().unwrap());

    assert_eq!(nal.data.len(), 1);
    assert!(nal.forbidden_zero_bit);
    assert_eq!(nal.picture_order_count, 0);
    assert_eq!(nal.ref_idc, 1);
    assert_eq!(nal.unit_type, H264NalUnitType::EndOfStream);
}

/// pion h264reader TestEOF: a start code with nothing after it, at any length, is EOF.
#[test]
fn test_h264_reader_eof() {
    for input in [&[0u8, 0, 0, 1][..], &[0, 0, 1][..], &[][..]] {
        let mut reader = h264_reader(input);
        match reader.next_nal() {
            Err(Error::ErrIoEOF) => {}
            result => panic!(
                "input {input:?}: unexpected result {:?}",
                result.as_ref().map(|_| "()")
            ),
        }
    }
}

/// pion h264reader TestSkipSEI: SEI NAL units are skipped by default.
#[test]
fn test_h264_reader_skip_sei() {
    let h264_bytes: &[u8] = &[
        0x0, 0x0, 0x0, 0x1, 0xAA, //
        0x0, 0x0, 0x0, 0x1, 0x6, // SEI
        0x0, 0x0, 0x0, 0x1, 0xAB,
    ];
    let mut reader = h264_reader(h264_bytes);

    let nal = h264(reader.next_nal().unwrap());
    assert_eq!(nal.data[0], 0xAA);

    let nal = h264(reader.next_nal().unwrap());
    assert_eq!(nal.data[0], 0xAB);
}

/// pion h264reader TestIncludeSEI: with the option set, SEI NAL units are yielded.
#[test]
fn test_h264_reader_include_sei() {
    let h264_bytes: &[u8] = &[
        0x0, 0x0, 0x0, 0x1, 0xAA, //
        0x0, 0x0, 0x0, 0x1, 0x6, // SEI
        0x0, 0x0, 0x0, 0x1, 0xAB,
    ];
    let mut reader = h264_reader(h264_bytes).with_include_sei(true);

    let nal = h264(reader.next_nal().unwrap());
    assert_eq!(nal.data[0], 0xAA);

    let nal = h264(reader.next_nal().unwrap());
    assert_eq!(nal.unit_type, H264NalUnitType::SEI);
    assert_eq!(nal.data[0], 0x6);

    let nal = h264(reader.next_nal().unwrap());
    assert_eq!(nal.data[0], 0xAB);
}

/// pion h264reader TestIssue1734_NextNal: pathological start-code sequences must not crash
/// or loop.
#[test]
fn test_h264_reader_issue1734_next_nal() {
    let streams: Vec<&[u8]> = vec![
        &[0x00, 0x00, 0x01, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01],
        &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01],
    ];

    for stream in streams {
        let mut reader = h264_reader(stream);
        while let Ok(_nal) = reader.next_nal() {
            // Just make sure it doesn't crash.
        }
    }
}

/// pion h264reader TestTrailing01AfterStartCode: a start code followed by 0x01 yields empty
/// NAL data without error.
#[test]
fn test_h264_reader_trailing_01_after_start_code() {
    let mut reader = h264_reader(&[
        0x0, 0x0, 0x0, 0x1, 0x01, //
        0x0, 0x0, 0x0, 0x1, 0x01,
    ]);

    for _ in 0..=1 {
        let _nal = reader.next_nal().unwrap();
    }
}

/// pion h265reader TestH265Reader_NextNAL: invalid data, prefix-only, VPS parsing, multiple
/// NAL units and EOF.
#[test]
fn test_h265_reader_next_nal() {
    // Invalid data.
    let mut reader = h265_reader(&[0xFF, 0xFF, 0xFF, 0xFF]);
    match reader.next_nal() {
        Err(Error::ErrDataIsNotH265Stream) => {}
        result => panic!("unexpected result {:?}", result.as_ref().map(|_| "()")),
    }

    // Valid H265 prefix but no NAL data.
    let mut reader = h265_reader(&[0, 0, 1]);
    match reader.next_nal() {
        Err(Error::ErrIoEOF) => {}
        result => panic!("unexpected result {:?}", result.as_ref().map(|_| "()")),
    }

    // Valid H265 NAL unit (VPS example).
    let mut nal_data: Vec<u8> = vec![
        0x0, 0x0, 0x0, 0x1, 0x40, 0x01, 0x0C, 0x01, 0xFF, 0xFF, 0x01, 0x60, 0x00, 0x0, 0x0, 0x3,
        0x0, 0x90, 0x0, 0x0, 0x3, 0x0, 0x0, 0x3, 0x0, 0x78, 0xAC, 0x09,
    ];
    let mut reader = h265_reader(&nal_data);
    let nal = h265(reader.next_nal().unwrap());
    assert_eq!(nal.unit_type, H265NalUnitType::VPS);
    assert!(!nal.forbidden_zero_bit);

    // Multiple NAL units: VPS then SPS, then EOF.
    nal_data.extend_from_slice(&[
        0x0, 0x0, 0x0, 0x1, 0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x0, 0x3, 0x0, 0x90, 0x0, 0x0, 0x3,
        0x0, 0x0, 0x3, 0x0, 0x78, 0xA0, 0x3, 0xC0, 0x80, 0x10, 0xE5, 0x96, 0x56, 0x69, 0x24, 0xCA,
        0xE0, 0x10, 0x00, 0x0, 0x3, 0x0, 0x10, 0x0, 0x0, 0x3, 0x1, 0xE0, 0x80,
    ]);
    let mut reader = h265_reader(&nal_data);

    let nal1 = h265(reader.next_nal().unwrap());
    assert_eq!(nal1.unit_type, H265NalUnitType::VPS);

    let nal2 = h265(reader.next_nal().unwrap());
    assert_eq!(nal2.unit_type, H265NalUnitType::SPS);

    match reader.next_nal() {
        Err(Error::ErrIoEOF) => {}
        result => panic!("unexpected result {:?}", result.as_ref().map(|_| "()")),
    }
}

/// pion h265reader TestH265Reader_processByte: NAL boundary detection and zero-run counting.
#[test]
fn test_h265_reader_process_byte() {
    let mut reader = h265_reader(&[]);
    reader.nal_buffer = BytesMut::from(&[1, 2, 3, 0, 0][..]);
    reader.count_of_consecutive_zero_bytes = 2;

    // Finding a NAL boundary: the trailing zero-run is trimmed off.
    let nal_found = reader.process_byte(1);
    assert!(nal_found);
    assert_eq!(reader.nal_buffer.len(), 3);

    // Zero byte counting.
    reader.count_of_consecutive_zero_bytes = 0;
    let nal_found = reader.process_byte(0);
    assert!(!nal_found);
    assert_eq!(reader.count_of_consecutive_zero_bytes, 1);

    // A non-zero, non-one byte resets the run.
    reader.count_of_consecutive_zero_bytes = 5;
    let nal_found = reader.process_byte(0xFF);
    assert!(!nal_found);
    assert_eq!(reader.count_of_consecutive_zero_bytes, 0);
}

/// pion h265reader TestH265Reader_SEIPrefixSuffixSkippedByDefault: both SEI flavours are
/// skipped unless requested.
#[test]
fn test_h265_reader_sei_prefix_suffix_skipped_by_default() {
    // VPS (32), PrefixSEI (39), SuffixSEI (40), SPS (33); NAL type is bits 1..6 of byte 0.
    let stream: &[u8] = &[
        0x0, 0x0, 0x0, 0x1, 0x40, 0x01, 0xFF, // VPS
        0x0, 0x0, 0x0, 0x1, 0x4E, 0x01, 0xFF, // PrefixSEI
        0x0, 0x0, 0x0, 0x1, 0x50, 0x01, 0xFF, // SuffixSEI
        0x0, 0x0, 0x0, 0x1, 0x42, 0x01, 0xFF, // SPS
    ];

    let mut reader = h265_reader(stream);

    let nal1 = h265(reader.next_nal().unwrap());
    assert_eq!(nal1.unit_type, H265NalUnitType::VPS);

    // SEI is skipped by default (both prefix and suffix).
    let nal2 = h265(reader.next_nal().unwrap());
    assert_eq!(nal2.unit_type, H265NalUnitType::SPS);

    match reader.next_nal() {
        Err(Error::ErrIoEOF) => {}
        result => panic!("unexpected result {:?}", result.as_ref().map(|_| "()")),
    }
}

/// pion h265reader TestH265Reader_IncludeSEI: with the option set, both SEI flavours are
/// yielded in order.
#[test]
fn test_h265_reader_include_sei() {
    let start = [0x0u8, 0x0, 0x0, 0x1];
    let vps = [0x40u8, 0x01];
    let prefix_sei = [0x4Eu8, 0x01];
    let suffix_sei = [0x50u8, 0x01];
    let sps = [0x42u8, 0x01];

    let mut stream: Vec<u8> = Vec::new();
    for nal in [vps, prefix_sei, suffix_sei, sps] {
        stream.extend_from_slice(&start);
        stream.extend_from_slice(&nal);
    }

    let mut reader = h265_reader(&stream).with_include_sei(true);

    assert_eq!(
        h265(reader.next_nal().unwrap()).unit_type,
        H265NalUnitType::VPS
    );
    assert_eq!(
        h265(reader.next_nal().unwrap()).unit_type,
        H265NalUnitType::PrefixSEI
    );
    assert_eq!(
        h265(reader.next_nal().unwrap()).unit_type,
        H265NalUnitType::SuffixSEI
    );
    assert_eq!(
        h265(reader.next_nal().unwrap()).unit_type,
        H265NalUnitType::SPS
    );
}

/// pion h265reader TestNAL_parseHeader: the two-byte H.265 header fields, including the
/// too-short and forbidden-bit cases.
#[test]
fn test_h265_nal_parse_header() {
    // VPS NAL header.
    let mut nal = H265NAL::new(BytesMut::from(&[0x40, 0x01, 0x0C, 0x01][..]));
    nal.parse_header();
    assert!(!nal.forbidden_zero_bit);
    assert_eq!(nal.unit_type, H265NalUnitType::VPS);
    assert_eq!(nal.nuh_layer_id, 0);
    assert_eq!(nal.nuh_temporal_id_plus1, 1);

    // SPS NAL header.
    let mut nal = H265NAL::new(BytesMut::from(&[0x42, 0x01, 0x01, 0x01][..]));
    nal.parse_header();
    assert!(!nal.forbidden_zero_bit);
    assert_eq!(nal.unit_type, H265NalUnitType::SPS);

    // Insufficient data: must not panic.
    let mut nal = H265NAL::new(BytesMut::from(&[0x40][..]));
    nal.parse_header();

    // Forbidden bit set.
    let mut nal = H265NAL::new(BytesMut::from(&[0x80, 0x01][..]));
    nal.parse_header();
    assert!(nal.forbidden_zero_bit);
}
