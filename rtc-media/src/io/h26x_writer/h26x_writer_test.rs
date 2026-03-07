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
    let nalu = Bytes::from_static(&[0x00, 0x00, 0x01, 0x02, 0x01, 1, 2, 3, 4, 5, 6]);
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
        vec![0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 1, 2, 3, 4, 5, 6],
        "writer should reconstruct the complete Annex-B HEVC NAL"
    );
}

#[test]
fn test_h26x_writer_h265_fragmentation_preserves_layer_and_tid_bits() {
    let payload_header = H265NALUHeader::new(0x28, 0x09);
    let header = rebuild_h265_nalu_header(payload_header, 20);

    assert_eq!(header, [0x28, 0x09]);
}
