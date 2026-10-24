//! Ports of pion/webrtc v4.2.24 `pkg/media/samplebuilder/samplebuilder_test.go`: the same
//! fake depacketizer (a payload is a partition head when its first byte is listed, empty
//! payloads never are) and the same packets. Expected values are pion's except where a case
//! says otherwise.

use super::*;
use rtp::Header;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FakeDepacketizer {
    head_checker: bool,
    head_bytes: Vec<u8>,
    always_head: bool,
}

impl FakeDepacketizer {
    fn new() -> Self {
        Self {
            head_checker: false,
            head_bytes: vec![],
            always_head: false,
        }
    }
}

impl Depacketizer for FakeDepacketizer {
    fn depacketize(&mut self, b: &Bytes) -> shared::error::Result<Bytes> {
        Ok(b.clone())
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if !self.head_checker {
            // simulates a bug in the 3.0 version
            // the tests should be fixed to not assume the bug
            return true;
        }
        // skip padding
        if payload.is_empty() {
            return false;
        }
        if self.always_head {
            return true;
        }
        self.head_bytes.contains(&payload[0])
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

fn pkt(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Packet {
    Packet {
        header: Header {
            sequence_number: seq,
            timestamp: ts,
            marker,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(payload),
    }
}

/// (data, duration in seconds, packet timestamp, prev dropped packets)
type Want = (&'static [u8], u64, u32, u16);

fn check(samples: &[Sample], want: &[Want], message: &str) {
    assert_eq!(samples.len(), want.len(), "{message}: sample count");
    for (s, (data, secs, ts, dropped)) in samples.iter().zip(want) {
        assert_eq!(&s.data[..], *data, "{message}: data");
        assert_eq!(
            s.duration,
            Duration::from_secs(*secs),
            "{message}: duration"
        );
        assert_eq!(s.packet_timestamp, *ts, "{message}: timestamp");
        assert_eq!(s.prev_dropped_packets, *dropped, "{message}: dropped");
    }
}

struct Case {
    message: &'static str,
    packets: Vec<Packet>,
    head_checker: bool,
    head_bytes: Vec<u8>,
    samples: Vec<Want>,
    max_late: u16,
    max_late_timestamp: u32,
}

fn case(message: &'static str, packets: Vec<Packet>, samples: Vec<Want>, max_late: u16) -> Case {
    Case {
        message,
        packets,
        head_checker: false,
        head_bytes: vec![],
        samples,
        max_late,
        max_late_timestamp: 0,
    }
}

/// pion TestSampleBuilder, sub-test "Pop".
#[test]
fn test_pion_sample_builder() {
    let now = Instant::now();
    let seven = |first_marker: bool, second_marker: bool| {
        vec![
            pkt(5000, 5, first_marker, &[0x01]),
            pkt(5002, 7, second_marker, &[0x02]),
            pkt(5004, 9, false, &[0x03]),
            pkt(5006, 11, false, &[0x04]),
            pkt(5008, 13, false, &[0x05]),
            pkt(5010, 15, false, &[0x06]),
            pkt(5012, 17, false, &[0x07]),
        ]
    };
    let mut cases = vec![
        case(
            "SampleBuilder shouldn't emit anything if only one RTP packet has been pushed",
            vec![pkt(5000, 5, false, &[0x01])],
            vec![],
            50,
        ),
        case(
            "SampleBuilder shouldn't emit anything if only one RTP packet has been pushed even if the market bit is set",
            vec![pkt(5000, 5, true, &[0x01])],
            vec![],
            50,
        ),
        case(
            "SampleBuilder should emit two packets, we had three packets with unique timestamps",
            vec![
                pkt(5000, 5, false, &[0x01]),
                pkt(5001, 6, false, &[0x02]),
                pkt(5002, 7, false, &[0x03]),
            ],
            vec![(&[0x01], 1, 5, 0), (&[0x02], 1, 6, 0)],
            50,
        ),
        case(
            "SampleBuilder should emit one packet, we had a packet end of sequence marker and run out of space",
            seven(true, false),
            vec![(&[0x01], 2, 5, 0)],
            5,
        ),
        case(
            "SampleBuilder shouldn't emit any packet, we do not have a valid end of sequence and run out of space",
            seven(false, false),
            vec![],
            5,
        ),
        case(
            "SampleBuilder should emit one packet, we had a packet end of sequence marker and run out of space (2)",
            seven(true, true),
            vec![(&[0x01], 2, 5, 0), (&[0x02], 2, 7, 1)],
            5,
        ),
        case(
            "SampleBuilder should emit one packet, we had two packets but two with duplicate timestamps",
            vec![
                pkt(5000, 5, false, &[0x01]),
                pkt(5001, 6, false, &[0x02]),
                pkt(5002, 6, false, &[0x03]),
                pkt(5003, 7, false, &[0x04]),
            ],
            vec![(&[0x01], 1, 5, 0), (&[0x02, 0x03], 1, 6, 0)],
            50,
        ),
        case(
            "SampleBuilder shouldn't emit a packet because we have a gap before a valid one",
            vec![
                pkt(5000, 5, false, &[0x01]),
                pkt(5007, 6, false, &[0x02]),
                pkt(5008, 7, false, &[0x03]),
            ],
            vec![],
            50,
        ),
        Case {
            head_checker: true,
            head_bytes: vec![0x02],
            ..case(
                "SampleBuilder shouldn't emit a packet after a gap as there are gaps and have not reached maxLate yet",
                vec![
                    pkt(5000, 5, false, &[0x01]),
                    pkt(5007, 6, false, &[0x02]),
                    pkt(5008, 7, false, &[0x03]),
                ],
                vec![],
                50,
            )
        },
        Case {
            head_checker: true,
            head_bytes: vec![],
            ..case(
                "SampleBuilder shouldn't emit a packet after a gap if PartitionHeadChecker doesn't assume it head",
                vec![
                    pkt(5000, 5, false, &[0x01]),
                    pkt(5007, 6, false, &[0x02]),
                    pkt(5008, 7, false, &[0x03]),
                ],
                vec![],
                50,
            )
        },
        case(
            "SampleBuilder should emit multiple valid packets",
            (0..6u16)
                .map(|i| pkt(5000 + i, 1 + i as u32, false, &[1 + i as u8]))
                .collect(),
            vec![
                (&[0x01], 1, 1, 0),
                (&[0x02], 1, 2, 0),
                (&[0x03], 1, 3, 0),
                (&[0x04], 1, 4, 0),
                (&[0x05], 1, 5, 0),
            ],
            50,
        ),
        Case {
            head_checker: true,
            head_bytes: vec![0x04],
            max_late_timestamp: 2000,
            ..case(
                "SampleBuilder should skip time stamps too old",
                vec![
                    pkt(5000, 1, false, &[0x01]),
                    pkt(5001, 2, false, &[0x02]),
                    pkt(5002, 3, false, &[0x03]),
                    pkt(5013, 4000, false, &[0x04]),
                    pkt(5014, 4000, false, &[0x05]),
                    pkt(5015, 4002, false, &[0x06]),
                    pkt(5016, 7000, false, &[0x04]),
                    pkt(5017, 7001, false, &[0x05]),
                ],
                // pion reports 13: its purge loop counts the packets of a rejected partition and then
                // the rejected head again. Rust counts each dropped packet once.
                vec![(&[0x04, 0x05], 2, 4000, 12)],
                50,
            )
        },
    ];
    cases.push(Case {
        head_checker: true,
        head_bytes: vec![1],
        max_late_timestamp: 2000,
        ..case(
            "Sample builder should recognize padding packets",
            vec![
                pkt(5000, 1, false, &[1]),
                pkt(5001, 1, false, &[2]),
                pkt(5002, 1, true, &[3]),
                pkt(5003, 1, false, &[]),
                pkt(5004, 1, false, &[]),
                pkt(5005, 3, false, &[1]),
                pkt(5006, 3, true, &[7]),
                pkt(5007, 4, false, &[1]),
            ],
            vec![(&[1, 2, 3], 0, 1, 0)],
            50,
        )
    });

    for c in cases {
        let d = FakeDepacketizer {
            head_checker: c.head_checker,
            head_bytes: c.head_bytes.clone(),
            always_head: false,
        };
        let mut s = SampleBuilder::new(c.max_late, d, 1);
        if c.max_late_timestamp != 0 {
            s = s.with_max_time_delay(Duration::from_millis(c.max_late_timestamp as u64));
        }
        let mut samples = vec![];
        for p in c.packets {
            s.push(now, p);
        }
        while let Some(sample) = s.pop(now) {
            samples.push(sample);
        }
        check(&samples, &c.samples, c.message);
    }
}

/// pion TestSampleBuilder, case "should emit samples with RTP headers when WithRTPHeaders
/// option is enabled".
#[test]
fn test_pion_sample_builder_rtp_headers() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(50, FakeDepacketizer::new(), 1).with_rtp_headers(true);
    for p in [
        pkt(5000, 5, false, &[0x01]),
        pkt(5001, 6, false, &[0x02]),
        pkt(5002, 6, false, &[0x03]),
        pkt(5003, 7, false, &[0x04]),
    ] {
        s.push(now, p);
    }
    let first = s.pop_detailed(now).unwrap();
    assert_eq!(&first.sample.data[..], &[0x01]);
    assert_eq!(first.sample.duration, Duration::from_secs(1));
    assert_eq!(first.sample.packet_timestamp, 5);
    assert_eq!(
        first
            .rtp_headers
            .iter()
            .map(|h| (h.sequence_number, h.timestamp))
            .collect::<Vec<_>>(),
        vec![(5000, 5)]
    );
    let second = s.pop_detailed(now).unwrap();
    assert_eq!(&second.sample.data[..], &[0x02, 0x03]);
    assert_eq!(
        second
            .rtp_headers
            .iter()
            .map(|h| (h.sequence_number, h.timestamp))
            .collect::<Vec<_>>(),
        vec![(5001, 6), (5002, 6)]
    );
    assert!(s.pop_detailed(now).is_none());
}

/// pion TestSampleBuilderWithPacketReleaseHandler
#[test]
fn test_pion_sample_builder_with_packet_release_handler() {
    let now = Instant::now();
    let released: Arc<Mutex<Vec<u16>>> = Arc::default();
    let r2 = released.clone();
    let pkts = [
        pkt(0, 0, false, &[0x01]),
        pkt(11, 120, false, &[0x02]),
        pkt(12, 121, false, &[0x03]),
        pkt(13, 122, false, &[0x04]),
        pkt(21, 200, false, &[0x05]),
    ];
    let mut fd = SampleBuilder::new(10, FakeDepacketizer::new(), 1)
        .with_packet_release_handler(move |p| r2.lock().unwrap().push(p.header.sequence_number));
    fd.push(now, pkts[0].clone());
    fd.push(now, pkts[1].clone());
    {
        let released = released.lock().unwrap();
        assert!(!released.is_empty(), "Old packet is not released");
        assert_eq!(
            released[0], pkts[0].header.sequence_number,
            "Unexpected packet released by maxLate"
        );
    }
    // Test packets released after samples built.
    fd.push(now, pkts[2].clone());
    fd.push(now, pkts[3].clone());
    fd.push(now, pkts[4].clone());
    assert!(fd.pop(now).is_some(), "Should have some sample here.");
    let released = released.lock().unwrap();
    assert!(
        released.len() >= 3,
        "packet built with sample is not released"
    );
    assert_eq!(
        released[2], pkts[2].header.sequence_number,
        "Unexpected packet released by samples built"
    );
}

/// pion TestSampleBuilderWithPacketHeadHandler
#[test]
fn test_pion_sample_builder_with_packet_head_handler() {
    let now = Instant::now();
    let packets = [
        pkt(5000, 5, false, &[0x01]),
        pkt(5001, 5, false, &[0x02]),
        pkt(5002, 6, false, &[0x01]),
        pkt(5003, 6, false, &[0x02]),
        pkt(5004, 7, false, &[0x01]),
    ];
    let head_count = Arc::new(AtomicUsize::new(0));
    let h2 = head_count.clone();
    let mut s =
        SampleBuilder::new(10, FakeDepacketizer::new(), 1).with_packet_head_handler(move |_| {
            h2.fetch_add(1, Ordering::SeqCst);
            Box::new(true)
        });
    for p in packets {
        s.push(now, p);
    }
    while let Some(popped) = s.pop_detailed(now) {
        let metadata = popped.metadata.expect("sample metadata shouldn't be nil");
        assert_eq!(
            metadata.downcast_ref::<bool>(),
            Some(&true),
            "sample metadata should've been set to true"
        );
    }
    assert_eq!(
        head_count.load(Ordering::SeqCst),
        2,
        "two sample heads should have been inspected"
    );
}

/// pion TestSampleBuilderPacketUnreference: only the last packet stays referenced.
#[test]
fn test_pion_sample_builder_packet_unreference() {
    let now = Instant::now();
    let released = Arc::new(AtomicUsize::new(0));
    let r2 = released.clone();
    let mut fd = SampleBuilder::new(
        10,
        FakeDepacketizer {
            head_checker: true,
            head_bytes: vec![],
            always_head: false,
        },
        1,
    )
    .with_packet_release_handler(move |_| {
        r2.fetch_add(1, Ordering::SeqCst);
    });
    let mut pushed = 0usize;
    for i in 0..0x20000usize {
        pushed += 1;
        fd.push(now, pkt(i as u16, (i + 42) as u32, false, &[i as u8]));
        while fd.pop(now).is_some() {}
    }
    assert_eq!(pushed - released.load(Ordering::SeqCst), 1);
    assert_eq!(fd.buffer.iter().filter(|p| p.is_some()).count(), 1);
}

/// pion TestSampleBuilder_Flush
#[test]
fn test_pion_sample_builder_flush() {
    let now = Instant::now();
    let mut fd = SampleBuilder::new(
        50,
        FakeDepacketizer {
            head_checker: true,
            head_bytes: vec![0x01],
            always_head: false,
        },
        1,
    );
    fd.push(now, pkt(999, 0, false, &[0x00])); // Invalid packet
    // Gap preventing below packets to be processed
    fd.push(now, pkt(1001, 1, true, &[0x01, 0x11])); // Valid packet
    fd.push(now, pkt(1011, 10, true, &[0x01, 0x12])); // Valid packet

    assert!(
        fd.pop(now).is_none(),
        "Unexpected sample is returned. Test precondition may be broken"
    );

    fd.flush(now);

    let mut samples = vec![];
    while let Some(s) = fd.pop(now) {
        samples.push(s);
    }
    check(
        &samples,
        &[(&[0x01, 0x11], 9, 1, 2), (&[0x01, 0x12], 0, 10, 9)],
        "flush",
    );
}
