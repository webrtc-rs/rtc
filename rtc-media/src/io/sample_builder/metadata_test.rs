use super::*;
use rtp::{Header, codec::vp8::Vp8Packet};

// Deliberately not Clone: metadata transfers with its sample.
struct HeadMetadata {
    sequence: u16,
    picture: u16,
    start: u8,
}

fn metadata(vp8: &Vp8Packet, packet: &Packet) -> HeadMetadata {
    HeadMetadata {
        sequence: packet.header.sequence_number,
        picture: vp8.picture_id,
        start: vp8.s,
    }
}

fn packet(sequence: u16, timestamp: u32, picture: u8, start: bool, marker: bool) -> Packet {
    Packet {
        header: Header {
            sequence_number: sequence,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::from(vec![
            0x80 | if start { 0x10 } else { 0 },
            0x80,
            picture,
            1,
            2,
            3,
        ]),
    }
}

#[test]
fn head_metadata_stays_with_samples_prepared_by_push_and_pop() {
    let now = Instant::now();
    let mut builder =
        SampleBuilder::new_with_packet_head_handler(16, Vp8Packet::default(), 90_000, metadata)
            .with_complete_samples()
            .with_max_time_delay(Duration::from_millis(100));
    let mut plain = SampleBuilder::new(16, Vp8Packet::default(), 90_000)
        .with_complete_samples()
        .with_max_time_delay(Duration::from_millis(100));
    for packet in [
        packet(1, 1_000, 10, true, false),
        packet(2, 1_000, 10, false, true),
        packet(3, 2_000, 20, true, true),
        packet(4, 3_000, 30, true, true),
        packet(5, 20_000, 40, true, true),
    ] {
        plain.push(now, packet.clone());
        builder.push(now, packet);
    }
    // The final push expires three complete AUs. The first pop also builds
    // the fourth AU before returning the oldest one.
    assert_eq!(builder.prepared.count(), 3);
    for (sequence, picture, timestamp) in [
        (1, 10, 1_000),
        (3, 20, 2_000),
        (4, 30, 3_000),
        (5, 40, 20_000),
    ] {
        let (sample, head) = builder.pop_with_metadata(now).unwrap();
        let head = head.unwrap();
        assert_eq!(sample, plain.pop(now).unwrap());
        assert_eq!(sample.packet_timestamp, timestamp);
        assert_eq!(
            (head.sequence, head.picture, head.start),
            (sequence, picture, 1)
        );
    }
    assert!(builder.pop_with_metadata(now).is_none());
    for sequence in [6, 7] {
        builder.push(
            now,
            packet(sequence, 21_000 + u32::from(sequence), 50, true, true),
        );
    }
    assert_eq!(builder.pop(now).unwrap().packet_timestamp, 21_006);
    assert_eq!(builder.pop_with_timestamp(now).unwrap().1, 21_007);
}

#[test]
fn failed_assembly_does_not_commit_its_head_metadata() {
    let now = Instant::now();
    let mut builder =
        SampleBuilder::new_with_packet_head_handler(16, Vp8Packet::default(), 90_000, metadata)
            .with_complete_samples()
            .with_max_time_delay(Duration::from_millis(100));
    builder.push(now, packet(1, 1_000, 10, true, false));
    let mut malformed_tail = packet(2, 1_000, 10, false, true);
    malformed_tail.payload = Bytes::from_static(&[0]);
    builder.push(now, malformed_tail);
    assert!(builder.pop_with_metadata(now).is_none());
    assert!(builder.prepared.empty());

    builder.push(now, packet(3, 20_000, 30, true, true));
    let (sample, head) = builder.pop_with_metadata(now).unwrap();
    let head = head.unwrap();
    assert_eq!(sample.packet_timestamp, 20_000);
    assert_eq!((head.sequence, head.picture, head.start), (3, 30, 1));
    assert_eq!(sample.data.as_ref(), &[1, 2, 3]);
    assert!(builder.pop_with_metadata(now).is_none());
}
