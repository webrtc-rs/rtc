use std::io::Cursor;

use super::*;

#[test]
fn test_ivf_writer_add_packet_and_close() -> Result<()> {
    // Construct valid packet
    let raw_valid_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x89, 0x9e,
    ]);

    let mut valid_packet = rtp::Packet {
        header: rtp::Header {
            marker: true,
            extension: true,
            extension_profile: 1,
            version: 2,
            //payloadOffset:    20,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            padding: false,
            extensions: vec![],
            extensions_padding: 0,
            padding_size: 0,
        },
        payload: raw_valid_pkt.slice(20..),
    };
    valid_packet
        .header
        .set_extension(0, Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]))?;

    // Construct mid partition packet
    let raw_mid_part_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x88, 0x36, 0xbe, 0x89, 0x9e,
    ]);

    let mut mid_part_packet = rtp::Packet {
        header: rtp::Header {
            marker: true,
            extension: true,
            extension_profile: 1,
            version: 2,
            //PayloadOffset:    20,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            padding: !raw_mid_part_pkt.len().is_multiple_of(4),
            extensions: vec![],
            extensions_padding: 0,
            padding_size: 0,
        },
        payload: raw_mid_part_pkt.slice(20..),
    };
    mid_part_packet
        .header
        .set_extension(0, Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]))?;

    // Construct keyframe packet
    let raw_keyframe_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);

    let mut keyframe_packet = rtp::Packet {
        header: rtp::Header {
            marker: true,
            extension: true,
            extension_profile: 1,
            version: 2,
            //PayloadOffset:    20,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            padding: !raw_keyframe_pkt.len().is_multiple_of(4),
            extensions: vec![],
            extensions_padding: 0,
            padding_size: 0,
        },
        payload: raw_keyframe_pkt.slice(20..),
    };
    keyframe_packet
        .header
        .set_extension(0, Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]))?;

    // Check valid packet parameters
    let mut vp8packet = rtp::codec::vp8::Vp8Packet::default();
    let payload = vp8packet.depacketize(&valid_packet.payload)?;
    assert_eq!(1, vp8packet.s, "Start packet S value should be 1");
    assert_eq!(
        payload[0] & 0x01,
        1,
        "Non Keyframe packet P value should be 1"
    );

    // Check mid partition packet parameters
    let mut vp8packet = rtp::codec::vp8::Vp8Packet::default();
    let payload = vp8packet.depacketize(&mid_part_packet.payload)?;
    assert_eq!(vp8packet.s, 0, "Mid Partition packet S value should be 0");
    assert_eq!(
        payload[0] & 0x01,
        1,
        "Non Keyframe packet P value should be 1"
    );

    // Check keyframe packet parameters
    let mut vp8packet = rtp::codec::vp8::Vp8Packet::default();
    let payload = vp8packet.depacketize(&keyframe_packet.payload)?;
    assert_eq!(vp8packet.s, 1, "Start packet S value should be 1");
    assert_eq!(payload[0] & 0x01, 0, "Keyframe packet P value should be 0");

    let add_packet_test_case = vec![
        (
            "IVFWriter should be able to skip something an empty packet",
            "IVFWriter should be able to close the file",
            rtp::Packet::default(),
            false,
            1,
        ),
        (
            "IVFWriter should be able to write an IVF packet",
            "IVFWriter should be able to close the file",
            valid_packet.clone(),
            false,
            1,
        ),
        (
            "IVFWriter should be able to write a Keframe IVF packet",
            "IVFWriter should be able to close the file",
            keyframe_packet,
            true,
            2,
        ),
    ];

    let header = IVFFileHeader {
        signature: *b"DKIF",      // DKIF
        version: 0,               // version
        header_size: 32,          // Header size
        four_cc: *b"VP80",        // FOURCC
        width: 640,               // Width in pixels
        height: 480,              // Height in pixels
        timebase_denominator: 30, // Framerate denominator
        timebase_numerator: 1,    // Framerate numerator
        num_frames: 900,          // Frame count, will be updated on first Close() call
        unused: 0,                // Unused
    };

    for (msg1, _msg2, packet, seen_key_frame, count) in add_packet_test_case {
        let mut writer = IVFWriter::new(Cursor::new(Vec::<u8>::new()), &header)?;
        assert!(
            !writer.seen_key_frame,
            "Writer's seenKeyFrame should initialize false"
        );
        assert_eq!(writer.count, 0, "Writer's packet count should initialize 0");
        let result = writer.write_rtp(&packet);

        assert!(result.is_ok(), "{}", msg1);

        assert_eq!(seen_key_frame, writer.seen_key_frame, "{msg1} failed");
        if count == 1 {
            assert_eq!(writer.count, 0);
        } else if count == 2 {
            assert_eq!(writer.count, 1);
        }

        writer.write_rtp(&mid_part_packet)?;
        if count == 1 {
            assert_eq!(writer.count, 0);
        } else if count == 2 {
            assert_eq!(writer.count, 1);

            writer.write_rtp(&valid_packet)?;
            assert_eq!(writer.count, 2);
        }

        writer.close()?;
    }

    Ok(())
}

/// The default header pion's `NewWith` writes: 640x480, 30fps, VP8/VP9/AV1 fourcc, frame
/// count pre-filled with 900 (updated on close).
fn default_header(four_cc: [u8; 4]) -> IVFFileHeader {
    IVFFileHeader {
        signature: *b"DKIF",
        version: 0,
        header_size: 32,
        four_cc,
        width: 640,
        height: 480,
        timebase_denominator: 30,
        timebase_numerator: 1,
        num_frames: 900,
        unused: 0,
    }
}

/// pion TestIVFWriter_EmptyPayload: an empty RTP payload is a no-op.
#[test]
fn test_ivf_writer_empty_payload() -> Result<()> {
    let mut writer = IVFWriter::new(Cursor::new(Vec::new()), &default_header(*b"VP80"))?;
    writer.write_rtp(&rtp::Packet {
        payload: Vec::new().into(),
        ..Default::default()
    })?;
    writer.close()
}

/// pion TestIVFWriter_VP8DescriptorOnlyPayload: a VP8 payload that is only a descriptor
/// depacketizes to nothing and writes no frame.
#[test]
fn test_ivf_writer_vp8_descriptor_only_payload() -> Result<()> {
    let payloads: [&[u8]; 3] = [&[0x10], &[0x90, 0x00], &[0x90, 0x80, 0x05]];

    for payload in payloads {
        let mut writer = IVFWriter::new(Cursor::new(Vec::new()), &default_header(*b"VP80"))?;

        writer.write_rtp(&rtp::Packet {
            header: rtp::Header {
                marker: true,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(payload),
        })?;
        writer.close()?;

        // Header written at construction, 32 bytes, and nothing after it.
        assert_eq!(writer.writer.get_ref().len(), 32, "payload {payload:?}");
    }

    Ok(())
}

/// pion TestIVFWriter_VP9: non-keyframe and non-start packets are ignored; a complete
/// frame (start + marker) is written as one IVF frame.
#[test]
fn test_ivf_writer_vp9() -> Result<()> {
    let vp9_header = [
        0x44, 0x4b, 0x49, 0x46, 0x00, 0x00, 0x20, 0x00, 0x56, 0x50, 0x39, 0x30, 0x80, 0x02, 0xe0,
        0x01, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x84, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let mut writer = IVFWriter::new(Cursor::new(Vec::new()), &default_header(*b"VP90"))?;

    // No keyframe yet: a P packet is ignored.
    writer.write_rtp(&rtp::Packet {
        payload: Bytes::from_static(&[0xD0, 0x02, 0xAA]),
        ..Default::default()
    })?;
    assert_eq!(writer.writer.get_ref(), &vp9_header[..]);

    // No current frame: packets that do not start one (B) are ignored.
    writer.write_rtp(&rtp::Packet {
        payload: Bytes::from_static(&[0x00, 0xAA]),
        ..Default::default()
    })?;
    assert_eq!(writer.writer.get_ref(), &vp9_header[..]);

    // B packet without the marker bit.
    writer.write_rtp(&rtp::Packet {
        payload: Bytes::from_static(&[0x08, 0xAA]),
        ..Default::default()
    })?;
    assert_eq!(writer.writer.get_ref(), &vp9_header[..]);

    // B packet with the marker bit: the frame completes and is written.
    writer.write_rtp(&rtp::Packet {
        header: rtp::Header {
            marker: true,
            ..Default::default()
        },
        payload: Bytes::from_static(&[0x08, 0xAB]),
    })?;
    let mut expected = vp9_header.to_vec();
    expected.extend_from_slice(&[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xab,
    ]);
    assert_eq!(writer.writer.get_ref(), &expected[..]);

    writer.close()?;
    let mut closed = expected;
    closed[24..28].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(writer.writer.get_ref(), &closed[..]);

    Ok(())
}

/// pion TestIVFWriter_AV1: unfragmented and fragmented OBUs, with the byte-exact IVF output.
#[test]
fn test_ivf_writer_av1() -> Result<()> {
    // Unfragmented: N=1, Length=1, OBU_TYPE=4.
    {
        let mut writer = IVFWriter::new(Cursor::new(Vec::new()), &default_header(*b"AV01"))?;

        writer.write_rtp(&rtp::Packet {
            header: rtp::Header {
                marker: true,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0x08, 0x01, 0x20]),
        })?;
        writer.close()?;

        assert_eq!(
            writer.writer.get_ref(),
            &[
                0x44, 0x4b, 0x49, 0x46, 0x0, 0x0, 0x20, 0x0, 0x41, 0x56, 0x30, 0x31, 0x80, 0x2,
                0xe0, 0x1, 0x1e, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x0,
                0x22, 0x0,
            ][..],
            "unfragmented AV1 frame with the count updated on close"
        );
    }

    // Fragmented: four fragments accumulate until the marker bit flushes the OBU set.
    {
        let mut writer = IVFWriter::new(Cursor::new(Vec::new()), &default_header(*b"AV01"))?;

        let fragments: [&[u8]; 4] = [
            &[0x48, 0x02, 0x00, 0x01], // Y=true
            &[0xc0, 0x02, 0x02, 0x03], // Z=true, Y=true
            &[0xc0, 0x02, 0x04, 0x04], // Z=true, Y=true
            &[0x80, 0x01, 0x05],       // Z=true, Y=false
        ];
        for fragment in fragments {
            writer.write_rtp(&rtp::Packet {
                header: rtp::Header {
                    marker: false,
                    ..Default::default()
                },
                payload: Bytes::copy_from_slice(fragment),
            })?;
        }

        writer.write_rtp(&rtp::Packet {
            header: rtp::Header {
                marker: true,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0x08, 0x01, 0x20]),
        })?;
        writer.close()?;

        assert_eq!(
            writer.writer.get_ref(),
            &[
                0x44, 0x4b, 0x49, 0x46, 0x0, 0x0, 0x20, 0x0, 0x41, 0x56, 0x30, 0x31, 0x80, 0x2,
                0xe0, 0x1, 0x1e, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x0,
                0x2, 0x6, 0x1, 0x2, 0x3, 0x4, 0x4, 0x5, 0x22, 0x0,
            ][..],
            "fragmented AV1 frame"
        );
    }

    Ok(())
}
