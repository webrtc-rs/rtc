use bytes::Bytes;
use rtc_media::io::sample_builder::SampleBuilder;
use rtp::{Header, Packet, codec::h264::H264Packet};
use shared::marshal::{Marshal, Unmarshal};
use std::time::{Duration, Instant};

#[test]
fn complete_h264_consumes_padding_between_fragments() {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(16, H264Packet::default(), 90_000).with_complete_samples();
    let packet = |sequence_number, marker, padding, payload: &[u8]| Packet {
        header: Header {
            version: 2,
            payload_type: 96,
            ssrc: 1,
            timestamp: 90_000,
            sequence_number,
            marker,
            padding,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(payload),
    };
    builder.push(now, packet(1, false, false, &[0x7c, 0x85, 0x11]));
    assert!(builder.pop(now).is_none());
    // Use the actual RTP wire codec: padding bytes are stripped, but its
    // sequence number and the P bit remain available to the assembler.
    let mut wire = packet(2, false, true, &[]).marshal().unwrap();
    let padding = Packet::unmarshal(&mut wire).unwrap();
    assert!(padding.header.padding && padding.payload.is_empty());
    builder.push(now, padding);
    assert!(builder.pop(now).is_none());
    builder.push(now, packet(3, true, false, &[0x7c, 0x45, 0x22]));
    let sample = builder
        .pop(now)
        .expect("complete FU with contiguous padding");
    assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x65, 0x11, 0x22]);
    assert_eq!(sample.packet_timestamp, 90_000);
    assert_eq!(sample.prev_dropped_packets, 0);
    assert!(builder.pop(now).is_none());
    // Padding can arrive before the preceding FU start without becoming a gap.
    let mut builder = SampleBuilder::new(16, H264Packet::default(), 90_000).with_complete_samples();
    let mut wire = packet(5, false, true, &[]).marshal().unwrap();
    builder.push(now, Packet::unmarshal(&mut wire).unwrap());
    assert!(builder.pop(now).is_none());
    builder.push(now, packet(4, false, false, &[0x7c, 0x85, 0x11]));
    builder.push(now, packet(6, true, false, &[0x7c, 0x45, 0x22]));
    assert_eq!(
        builder.pop(now).unwrap().data.as_ref(),
        &[0, 0, 0, 1, 0x65, 0x11, 0x22]
    );
}

#[test]
fn complete_h264_consumes_leading_padding_before_each_au() {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(16, H264Packet::default(), 90_000).with_complete_samples();
    for index in 0..2 {
        let timestamp = 90_000 + index * 3_000;
        for (offset, marker, padding, payload) in [
            (0, false, true, &[][..]),
            (1, false, false, &[0x7c, 0x85, 0x11][..]),
            (2, true, false, &[0x7c, 0x45, 0x22][..]),
        ] {
            let packet = Packet {
                header: Header {
                    version: 2,
                    payload_type: 96,
                    ssrc: 1,
                    timestamp: if padding {
                        timestamp - 3_000
                    } else {
                        timestamp
                    },
                    sequence_number: index as u16 * 3 + offset,
                    marker,
                    padding,
                    ..Default::default()
                },
                payload: Bytes::copy_from_slice(payload),
            };
            let mut wire = packet.marshal().unwrap();
            builder.push(now, Packet::unmarshal(&mut wire).unwrap());
        }
    }
    // Buffer both AUs before consuming: the second padding is at the active
    // cursor, rather than only at the initially filled window's head.
    for timestamp in [90_000, 93_000] {
        let sample = builder
            .pop(now)
            .expect("leading padding must not block an AU");
        assert_eq!(sample.packet_timestamp, timestamp);
        assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x65, 0x11, 0x22]);
        assert_eq!(sample.prev_dropped_packets, 0);
        assert_eq!(
            sample.duration,
            if timestamp == 90_000 {
                Duration::from_secs_f64(3_000.0 / 90_000.0)
            } else {
                Duration::ZERO
            }
        );
    }
    assert!(builder.pop(now).is_none());

    let mut builder = SampleBuilder::new(16, H264Packet::default(), 90_000).with_complete_samples();
    let packet = |sequence_number, timestamp, padding: bool| Packet {
        header: Header {
            version: 2,
            payload_type: 96,
            ssrc: 1,
            sequence_number,
            timestamp,
            marker: !padding,
            padding,
            ..Default::default()
        },
        payload: if padding {
            Bytes::new()
        } else {
            Bytes::from_static(&[0x65, 0x11, 0x22])
        },
    };
    for packet in [packet(0, 100, false), packet(1, 100, true)] {
        let mut wire = packet.marshal().unwrap();
        builder.push(now, Packet::unmarshal(&mut wire).unwrap());
    }
    assert_eq!(builder.pop(now).unwrap().packet_timestamp, 100);
    assert!(builder.pop(now).is_none());
    // A later static AU must be released on this pop, not a future wake-up.
    builder.push(now, packet(2, 200, false));
    assert_eq!(
        builder
            .pop(now)
            .expect("new AU extends the padding cursor")
            .packet_timestamp,
        200
    );
    assert!(builder.pop(now).is_none());

    // Prefix retirement can itself bring the window back within max_late.
    let mut builder = SampleBuilder::new(2, H264Packet::default(), 90_000).with_complete_samples();
    for seq in [0, 1] {
        let mut wire = packet(seq, 100, true).marshal().unwrap();
        builder.push(now, Packet::unmarshal(&mut wire).unwrap());
    }
    let mut start = packet(2, 200, false);
    start.header.marker = false;
    start.payload = Bytes::from_static(&[0x7c, 0x85, 0x11]);
    builder.push(now, start);
    let mut end = packet(3, 200, false);
    end.payload = Bytes::from_static(&[0x7c, 0x45, 0x22]);
    builder.push(now, end);
    assert_eq!(
        builder
            .pop(now)
            .expect("prefix removal retains the pending FU")
            .data
            .as_ref(),
        &[0, 0, 0, 1, 0x65, 0x11, 0x22]
    );
}
