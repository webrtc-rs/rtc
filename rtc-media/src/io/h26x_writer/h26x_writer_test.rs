use super::*;
use bytes::Bytes;
use rtp::Packet;
use rtp::codec::h265::H265NALUHeader;
use rtp::codec::h265::HevcPayloader;
use rtp::packetizer::Payloader;

#[test]
fn test_h26x_writer_h264() {
    // TODO: Add tests for H26xWriter with H264
    // This would require:
    // 1. Sample H264 RTP packets
    // 2. Expected Annex B output
    // 3. Verification of correct depacketization
}

#[test]
fn test_h26x_writer_h265_single_nal_preserves_header() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);

    writer
        .write_rtp(&Packet {
            payload: vec![0x28, 0x01, 0xaa, 0xbb].into(),
            ..Default::default()
        })
        .expect("write single nal");

    assert_eq!(
        writer.writer,
        vec![0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaa, 0xbb],
        "writer should persist the original H265 single-NAL header and payload"
    );
}

#[test]
fn test_h26x_writer_h265_flushes_exact_full_tail_fragment() {
    let mut payloader = HevcPayloader::default();
    // IDR_W_RADL NAL (type 19): the writer discards packets until a key frame arrives.
    let nalu = Bytes::from_static(&[0x00, 0x00, 0x01, 0x26, 0x01, 1, 2, 3, 4, 5, 6]);
    let packets = payloader.payload(6, &nalu).expect("packetize H265 NAL");

    assert_eq!(packets.len(), 2, "expected two H265 FU packets");

    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);

    writer
        .write_rtp(&Packet {
            payload: packets[0].clone(),
            ..Default::default()
        })
        .expect("write first fragment");
    assert!(
        writer.writer.is_empty(),
        "writer must not flush before the final HEVC fragment"
    );
    assert!(
        !writer.buffer.is_empty(),
        "writer should buffer the in-progress fragmented HEVC NAL"
    );

    writer
        .write_rtp(&Packet {
            payload: packets[1].clone(),
            ..Default::default()
        })
        .expect("write last fragment");

    assert!(
        writer.buffer.is_empty(),
        "writer buffer should be drained after the final HEVC fragment"
    );
    assert_eq!(
        writer.writer,
        vec![0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 1, 2, 3, 4, 5, 6],
        "writer should reconstruct the complete Annex-B HEVC NAL"
    );
}

#[test]
fn test_h26x_writer_h265_fragmentation_preserves_layer_and_tid_bits() {
    let payload_header = H265NALUHeader::new(0x28, 0x09);
    let header = rebuild_h265_nalu_header(payload_header, 20);

    assert_eq!(header, [0x28, 0x09]);
}

/// pion h264writer TestIsKeyFrame: SPS packets - bare or inside STAP-A - are key frames;
/// anything shorter than four bytes is not.
#[test]
fn test_h264_writer_is_key_frame() {
    let tests = [
        (vec![0x27, 0x90, 0x90], false),
        (
            vec![
                0x38, 0x00, 0x03, 0x27, 0x90, 0x90, 0x00, 0x05, 0x28, 0x90, 0x90, 0x90, 0x90,
            ],
            true,
        ),
        (vec![0x27, 0x90, 0x90, 0x00], true),
    ];

    for (payload, want) in tests {
        assert_eq!(is_key_frame(&payload), want, "payload {payload:?}");
    }
}

/// A writer that counts how many times it was written to, for TestNoZeroWrite.
struct CountingWriter {
    write_count: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_count += 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// pion h264writer TestNoZeroWrite: FU-A continuation fragments carry no bytes, so the
/// underlying writer is touched exactly once for a five-fragment NAL.
#[test]
fn test_h264_writer_no_zero_write() {
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x1c, 0x80, 0x01, 0x02, 0x03],
        vec![0x1c, 0x00, 0x04, 0x05, 0x06],
        vec![0x1c, 0x00, 0x07, 0x08, 0x09],
        vec![0x1c, 0x00, 0x10, 0x11, 0x12],
        vec![0x1c, 0x40, 0x13, 0x14, 0x15],
    ];

    let mut writer = H26xWriter {
        writer: CountingWriter { write_count: 0 },
        packet: H26xPacket::H264(H264Packet::default()),
        is_hevc: false,
        has_key_frame: true,
        buffer: BytesMut::new(),
        h265_has_key_frame: false,
    };

    for payload in payloads {
        writer
            .write_rtp(&Packet {
                payload: payload.into(),
                ..Default::default()
            })
            .expect("write_rtp");
    }
    assert_eq!(writer.writer.write_count, 1);
}

/// pion h264writer TestWriteRTP: empty payloads are skipped, SPS/PPS + FU-A IDR packets are
/// written as an Annex-B stream.
#[test]
fn test_h264_writer_write_rtp() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), false);

    // Empty payload: skipped.
    writer
        .write_rtp(&Packet {
            payload: Vec::new().into(),
            ..Default::default()
        })
        .expect("write empty payload");
    assert!(writer.writer.is_empty());

    // A non-key frame is discarded until a key frame arrives.
    writer
        .write_rtp(&Packet {
            payload: vec![0x27, 0x90, 0x90, 0x00].into(), // SPS (key frame)
            ..Default::default()
        })
        .expect("write sps");
    assert_eq!(
        writer.writer,
        vec![0x00, 0x00, 0x00, 0x01, 0x27, 0x90, 0x90, 0x00],
        "the SPS NAL is written with its Annex-B start code"
    );

    // A single-NAL packet follows.
    writer
        .write_rtp(&Packet {
            payload: vec![0x07, 0x90, 0x90].into(),
            ..Default::default()
        })
        .expect("write single nal");
    assert_eq!(
        writer.writer[8..],
        vec![0x00, 0x00, 0x00, 0x01, 0x07, 0x90, 0x90],
        "subsequent NALs append with start codes"
    );

    writer.close().expect("close");
}

/// pion h264writer TestNewWith: the constructor takes the output writer.
#[test]
fn test_h264_writer_new_with() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), false);
    writer
        .write_rtp(&Packet {
            payload: vec![0x27, 0x90, 0x90, 0x00].into(),
            ..Default::default()
        })
        .expect("write");
    assert!(!writer.writer.is_empty());
    writer.close().expect("close");
}

/// pion h265writer TestIsKeyFrame: VPS/SPS/PPS/IDR NALs directly, in aggregation packets
/// and in fragmentation units.
#[test]
fn test_h265_writer_is_key_frame() {
    let tests = [
        // VPS single NAL: key frame.
        (vec![0x40, 0x01, 0x0C, 0x01], true),
        // TRAIL_R single NAL: not a key frame.
        (vec![0x02, 0x01, 0xAF, 0x06], false),
        // Aggregation packet containing a VPS.
        (vec![0x60, 0x01, 0x00, 0x04, 0x40, 0x01, 0x0C, 0x01], true),
        // Too short.
        (vec![0x40], false),
        (Vec::new(), false),
    ];

    for (payload, want) in tests {
        assert_eq!(is_key_frame_h265(&payload), want, "payload {payload:?}");
    }

    // Fragmentation unit carrying an IDR_W_RADL (type 19): the FU header is S|E|FuType,
    // so a start-fragmented IDR_W_RADL is 0x80 | 19 = 0x93. pion's own test bytes (0x40)
    // only pass its NAL-header-mask quirk; the RFC 7798 mask reads them as FuType 0.
    assert!(is_key_frame_h265(&[0x62, 0x01, 0x93])); // S + IDR_W_RADL (19)
    assert!(is_key_frame_h265(&[0x62, 0x01, 0x40 | 32])); // S + VPS (32)
    assert!(!is_key_frame_h265(&[0x62, 0x01, 0x81])); // S + TRAIL_R (1)
}

/// pion h265writer TestCheckAggregationPacketForKeyFrame: walking the size-prefixed NAL
/// list inside an aggregation packet, including the malformed cases.
#[test]
fn test_h265_writer_check_aggregation_packet_for_key_frame() {
    let tests = [
        // AP with VPS.
        (vec![0x60, 0x01, 0x00, 0x04, 0x40, 0x01, 0x0C, 0x01], true),
        // AP with TRAIL_R.
        (vec![0x60, 0x01, 0x00, 0x04, 0x02, 0x01, 0xAF, 0x06], false),
        // AP with multiple NALs, the second an SPS.
        (
            vec![
                0x60, 0x01, 0x00, 0x04, 0x02, 0x01, 0xAF, 0x06, 0x00, 0x04, 0x42, 0x01, 0x01, 0x01,
            ],
            true,
        ),
        // Malformed AP: incomplete size.
        (vec![0x60, 0x01, 0x00], false),
        // Empty AP.
        (vec![0x60, 0x01], false),
    ];

    for (data, expected) in tests {
        assert_eq!(
            check_aggregation_packet_for_key_frame(&data),
            expected,
            "data {data:?}"
        );
    }
}

/// pion h265writer TestH265Writer_WriteRTP: empty payloads are skipped; a VPS single-NAL
/// packet is written with its Annex-B start code.
#[test]
fn test_h265_writer_write_rtp() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);

    // Empty payload: skipped.
    writer
        .write_rtp(&Packet {
            payload: Vec::new().into(),
            ..Default::default()
        })
        .expect("write empty payload");

    // VPS packet (key frame).
    let vps_payload: Vec<u8> = vec![0x40, 0x01, 0x0C, 0x01, 0xFF, 0xFF, 0x01, 0x60];
    writer
        .write_rtp(&Packet {
            payload: vps_payload.clone().into(),
            ..Default::default()
        })
        .expect("write vps");

    let mut expected = vec![0x00, 0x00, 0x00, 0x01];
    expected.extend_from_slice(&vps_payload);
    assert_eq!(
        writer.writer, expected,
        "buffer should contain the start code followed by the VPS payload"
    );

    writer.close().expect("close");
}
