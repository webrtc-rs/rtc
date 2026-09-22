use rtp::Header;
use rtp::Packet;
use rtp::packetizer::Depacketizer;
use shared::error::Result;

use super::*;

// Turns u8 integers into Bytes Array
macro_rules! bytes {
    ($($item:expr),*) => ({
        static STATIC_SLICE: &'static [u8] = &[$($item), *];
        Bytes::from_static(STATIC_SLICE)
    });
}
#[derive(Default)]
pub struct SampleBuilderTest {
    message: String,
    packets: Vec<Packet>,
    with_head_checker: bool,
    head_bytes: Vec<bytes::Bytes>,
    samples: Vec<Sample>,
    max_late: u16,
    max_late_timestamp: Duration,
    extra_pop_attempts: usize,
}

pub struct FakeDepacketizer {
    head_checker: bool,
    head_bytes: Vec<bytes::Bytes>,
}

impl FakeDepacketizer {
    fn new() -> Self {
        Self {
            head_checker: false,
            head_bytes: vec![],
        }
    }
}

impl Depacketizer for FakeDepacketizer {
    fn depacketize(&mut self, b: &Bytes) -> Result<bytes::Bytes> {
        Ok(b.clone())
    }

    /// Checks if the packet is at the beginning of a partition.  This
    /// should return false if the result could not be determined, in
    /// which case the caller will detect timestamp discontinuities.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if !self.head_checker {
            // from .go: simulates a bug in 3.0 version, the tests should not assume the bug
            return true;
        }

        for b in &self.head_bytes {
            if *payload == b {
                return true;
            }
        }
        false
    }

    /// Checks if the packet is at the end of a partition.  This should
    /// return false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

#[test]
pub fn test_sample_builder() {
    #![allow(clippy::needless_update)]
    let now = Instant::now();
    let test_data: Vec<SampleBuilderTest> = vec![
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit anything if only one RTP packet has been pushed".into(),
            packets: vec![Packet {
                header: Header {
                    sequence_number: 5000,
                    timestamp: 5,
                    ..Default::default()
                },
                payload: bytes!(1),
                ..Default::default()
            }],
            samples: vec![],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit anything if only one RTP packet has been pushed even if the marker bit is set".into(),
            packets: vec![Packet {
                header: Header {
                    sequence_number: 5000,
                    timestamp: 5,
                    marker: true,
                    ..Default::default()
                },
                payload: bytes!(1),
                ..Default::default()
            }],
            samples: vec![],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should emit two packets, we had three packets with unique timestamps".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 6,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1),
                    duration: Duration::from_secs(1), // technically this is the default value, but since it was in .go source....
                    packet_timestamp: 5,
                    ..Sample::new(now)
                },
                Sample {
                    // Second sample
                    data: bytes!(2),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 6,
                    ..Sample::new(now)
                },
            ],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should emit one packet, we had a packet end of sequence marker and run out of space".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 9,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5006,
                        timestamp: 11,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Fifth packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 13,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5010,
                        timestamp: 15,
                        ..Default::default()
                    },
                    payload: bytes!(6),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5012,
                        timestamp: 17,
                        ..Default::default()
                    },
                    payload: bytes!(7),
                    ..Default::default()
                },
            ],
            samples: vec![Sample {
                // First sample
                data: bytes!(1),
                duration: Duration::from_secs(2),
                packet_timestamp: 5,
                ..Sample::new(now)
            }],
            max_late: 5,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit any packet, we do not have a valid end of sequence and run out of space".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 9,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5006,
                        timestamp: 11,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Fifth packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 13,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5010,
                        timestamp: 15,
                        ..Default::default()
                    },
                    payload: bytes!(6),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5012,
                        timestamp: 17,
                        ..Default::default()
                    },
                    payload: bytes!(7),
                    ..Default::default()
                },
            ],
            samples: vec![],
            max_late: 5,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should emit one packet, we had a packet end of sequence marker and run out of space".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 7,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 9,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5006,
                        timestamp: 11,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Fifth packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 13,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5010,
                        timestamp: 15,
                        ..Default::default()
                    },
                    payload: bytes!(6),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5012,
                        timestamp: 17,
                        ..Default::default()
                    },
                    payload: bytes!(7),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First (dropped) sample
                    data: bytes!(1),
                    duration: Duration::from_secs(2),
                    packet_timestamp: 5,
                    ..Sample::new(now)
                },
                Sample {
                    // First correct sample
                    data: bytes!(2),
                    duration: Duration::from_secs(2),
                    packet_timestamp: 7,
                    prev_dropped_packets: 1,
                    ..Sample::new(now)
                },
            ],
            max_late: 5,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should emit one packet, we had two packets but with duplicate timestamps".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 6,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 6,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5003,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 5,
                    ..Sample::new(now)
                },
                Sample {
                    // Second (duplicate) correct sample
                    data: bytes!(2, 3),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 6,
                    ..Sample::new(now)
                },
            ],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit a packet because we have a gap before a valid one".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5007,
                        timestamp: 6,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
            ],
            samples: vec![],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit a packet after a gap as there are gaps and have not reached maxLate yet".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5007,
                        timestamp: 6,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
            ],
            with_head_checker: true,
            head_bytes: vec![bytes!(2)],
            samples: vec![],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder shouldn't emit a packet after a gap if PartitionHeadChecker doesn't assume it head".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 5,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5007,
                        timestamp: 6,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5008,
                        timestamp: 7,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
            ],
            with_head_checker: true,
            head_bytes: vec![],
            samples: vec![],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should emit multiple valid packets".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 2,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 3,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5003,
                        timestamp: 4,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Fifth packet
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 5,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5005,
                        timestamp: 6,
                        ..Default::default()
                    },
                    payload: bytes!(6),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 1,
                    ..Sample::new(now)
                },
                Sample {
                    // Second sample
                    data: bytes!(2),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 2,
                    ..Sample::new(now)
                },
                Sample {
                    // Third sample
                    data: bytes!(3),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 3,
                    ..Sample::new(now)
                },
                Sample {
                    // Fourth sample
                    data: bytes!(4),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 4,
                    ..Sample::new(now)
                },
                Sample {
                    // Fifth sample
                    data: bytes!(5),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 5,
                    ..Sample::new(now)
                },
            ],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(0),
            ..Default::default()
        },
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should skip timestamps too old".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 2,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 3,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Fourth packet
                    header: Header {
                        sequence_number: 5013,
                        timestamp: 4000,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Fifth packet
                    header: Header {
                        sequence_number: 5014,
                        timestamp: 4000,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5015,
                        timestamp: 4002,
                        ..Default::default()
                    },
                    payload: bytes!(6),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5016,
                        timestamp: 7000,
                        ..Default::default()
                    },
                    payload: bytes!(4),
                    ..Default::default()
                },
                Packet {
                    // Eighth packet
                    header: Header {
                        sequence_number: 5017,
                        timestamp: 7001,
                        ..Default::default()
                    },
                    payload: bytes!(5),
                    ..Default::default()
                },
            ],
            samples: vec![Sample {
                // First sample
                data: bytes!(4, 5),
                duration: Duration::from_secs(2),
                packet_timestamp: 4000,
                prev_dropped_packets: 12,
                ..Sample::new(now)
            }],
            with_head_checker: true,
            head_bytes: vec![bytes!(4)],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(2000),
            ..Default::default()
        },
        // This test is based on observed RTP packet streams from Chrome. libWebRTC inserts padding
        // packets to keep send rates steady, these are not important for sample building but we
        // should identify them as padding packets to differentiate them from lost packets.
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should recognise padding packets".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 1,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Padding packet 1
                    header: Header {
                        sequence_number: 5003,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[]),
                    ..Default::default()
                },
                Packet {
                    // Padding packet 2
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[]),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5005,
                        timestamp: 2,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5006,
                        timestamp: 2,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(7),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5007,
                        timestamp: 3,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1, 2, 3),
                    duration: Duration::from_secs(0),
                    packet_timestamp: 1,
                    prev_dropped_packets: 0,
                    ..Sample::new(now)
                },
                Sample {
                    // Second sample
                    data: bytes!(1, 7),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 2,
                    prev_dropped_packets: 2,
                    prev_padding_packets: 2,
                    ..Sample::new(now)
                },
            ],
            with_head_checker: true,
            head_bytes: vec![bytes!(1)],
            max_late: 50,
            max_late_timestamp: Duration::from_secs(2000),
            extra_pop_attempts: 1,
            ..Default::default()
        },
        // This test is based on observed RTP packet streams when screen sharing in Chrome.
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should recognise padding packets when combined with max_late_timestamp".into(),
            packets: vec![
                Packet {
                    // First packet
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Second packet
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                Packet {
                    // Third packet
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 1,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(3),
                    ..Default::default()
                },
                Packet {
                    // Padding packet 1
                    header: Header {
                        sequence_number: 5003,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[]),
                    ..Default::default()
                },
                Packet {
                    // Padding packet 2
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[]),
                    ..Default::default()
                },
                Packet {
                    // Sixth packet
                    header: Header {
                        sequence_number: 5005,
                        timestamp: 3,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5006,
                        timestamp: 3,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(7),
                    ..Default::default()
                },
                Packet {
                    // Seventh packet
                    header: Header {
                        sequence_number: 5007,
                        timestamp: 4,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1, 2, 3),
                    duration: Duration::from_secs(0),
                    packet_timestamp: 1,
                    prev_dropped_packets: 0,
                    ..Sample::new(now)
                },
                Sample {
                    // Second sample
                    data: bytes!(1, 7),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 3,
                    prev_dropped_packets: 2,
                    prev_padding_packets: 2,
                    ..Sample::new(now)
                },
            ],
            with_head_checker: true,
            head_bytes: vec![bytes!(1)],
            max_late: 50,
            max_late_timestamp: Duration::from_millis(1050),
            extra_pop_attempts: 1,
            ..Default::default()
        },
        // This test is based on observed RTP packet streams when screen sharing in Chrome.
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should build a sample out of a packet that's both start and end".into(),
            packets: vec![
                Packet {
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                Packet {
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 2,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
            ],
            samples: vec![Sample {
                // First sample
                data: bytes!(1),
                duration: Duration::from_secs(1),
                packet_timestamp: 1,
                prev_dropped_packets: 0,
                ..Sample::new(now)
            }],
            with_head_checker: true,
            head_bytes: vec![bytes!(1)],
            max_late: 50,
            max_late_timestamp: Duration::from_millis(1050),
            ..Default::default()
        },
        // This test is based on observed RTP packet streams when screen sharing in Chrome. In
        // particular the scenario used involved no movement on screen which causes Chrome to
        // generate padding packets.
        SampleBuilderTest {
            #[rustfmt::skip]
            message: "Sample builder should build a sample out of a packet that's both start and end following a run of padding packets".into(),
            packets: vec![
                // First valid packet
                Packet {
                    header: Header {
                        sequence_number: 5000,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                // Second valid packet
                Packet {
                    header: Header {
                        sequence_number: 5001,
                        timestamp: 1,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(2),
                    ..Default::default()
                },
                // Padding packet 1
                Packet {
                    header: Header {
                        sequence_number: 5002,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::default(),
                    ..Default::default()
                },
                // Padding packet 2
                Packet {
                    header: Header {
                        sequence_number: 5003,
                        timestamp: 1,
                        ..Default::default()
                    },
                    payload: Bytes::default(),
                    ..Default::default()
                },
                // Third valid packet
                Packet {
                    header: Header {
                        sequence_number: 5004,
                        timestamp: 2,
                        marker: true,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
                // Fourth valid packet, start of next sample
                Packet {
                    header: Header {
                        sequence_number: 5005,
                        timestamp: 3,
                        ..Default::default()
                    },
                    payload: bytes!(1),
                    ..Default::default()
                },
            ],
            samples: vec![
                Sample {
                    // First sample
                    data: bytes!(1, 2),
                    duration: Duration::from_secs(0),
                    packet_timestamp: 1,
                    prev_dropped_packets: 0,
                    ..Sample::new(now)
                },
                Sample {
                    // Second sample
                    data: bytes!(1),
                    duration: Duration::from_secs(1),
                    packet_timestamp: 2,
                    prev_dropped_packets: 2,
                    prev_padding_packets: 2,
                    ..Sample::new(now)
                },
            ],
            with_head_checker: true,
            head_bytes: vec![bytes!(1)],
            extra_pop_attempts: 1,
            max_late: 50,
            ..Default::default()
        },
    ];

    for t in test_data {
        let d = FakeDepacketizer {
            head_checker: t.with_head_checker,
            head_bytes: t.head_bytes,
        };

        let mut s = {
            let sample_builder = SampleBuilder::new(t.max_late, d, 1);
            if t.max_late_timestamp != Duration::from_secs(0) {
                sample_builder.with_max_time_delay(t.max_late_timestamp)
            } else {
                sample_builder
            }
        };

        let mut samples = Vec::<Sample>::new();
        for p in t.packets {
            s.push(now, p)
        }

        while let Some(sample) = s.pop(now) {
            samples.push(sample)
        }

        for _ in 0..t.extra_pop_attempts {
            // Pop some more
            while let Some(sample) = s.pop(now) {
                samples.push(sample)
            }
        }

        // Compare samples field-by-field, ignoring timestamp (which varies with wall clock time)
        assert_eq!(
            t.samples.len(),
            samples.len(),
            "{}: Sample count mismatch",
            t.message
        );

        for (i, (expected, actual)) in t.samples.iter().zip(samples.iter()).enumerate() {
            assert_eq!(
                expected.data, actual.data,
                "{}: Sample {} data mismatch",
                t.message, i
            );
            assert_eq!(
                expected.duration, actual.duration,
                "{}: Sample {} duration mismatch",
                t.message, i
            );
            assert_eq!(
                expected.packet_timestamp, actual.packet_timestamp,
                "{}: Sample {} packet_timestamp mismatch",
                t.message, i
            );
            assert_eq!(
                expected.prev_dropped_packets, actual.prev_dropped_packets,
                "{}: Sample {} prev_dropped_packets mismatch",
                t.message, i
            );
            assert_eq!(
                expected.prev_padding_packets, actual.prev_padding_packets,
                "{}: Sample {} prev_padding_packets mismatch",
                t.message, i
            );
            // Note: We skip comparing 'timestamp' field as it contains wall-clock time
            // which varies between test runs, causing flakiness
        }
    }
}

// SampleBuilder should respect maxLate if we popped successfully but then have a gap larger then maxLate
#[test]
fn test_sample_builder_max_late() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(50, FakeDepacketizer::new(), 1);

    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 0,
                timestamp: 1,
                ..Default::default()
            },
            payload: bytes!(0x01),
        },
    );
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 1,
                timestamp: 2,
                ..Default::default()
            },
            payload: bytes!(0x01),
        },
    );
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 2,
                timestamp: 3,
                ..Default::default()
            },
            payload: bytes!(0x01),
        },
    );
    assert_eq!(
        s.pop(now),
        Some(Sample {
            data: bytes!(0x01),
            duration: Duration::from_secs(1),
            packet_timestamp: 1,
            ..Sample::new(now)
        }),
        "Failed to build samples before gap"
    );

    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 5000,
                timestamp: 500,
                ..Default::default()
            },
            payload: bytes!(0x02),
        },
    );
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 5001,
                timestamp: 501,
                ..Default::default()
            },
            payload: bytes!(0x02),
        },
    );
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 5002,
                timestamp: 502,
                ..Default::default()
            },
            payload: bytes!(0x02),
        },
    );

    assert_eq!(
        s.pop(now),
        Some(Sample {
            data: bytes!(0x01),
            duration: Duration::from_secs(1),
            packet_timestamp: 2,
            ..Sample::new(now)
        }),
        "Failed to build samples after large gap"
    );
    assert_eq!(None, s.pop(now), "Failed to build samples after large gap");

    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 6000,
                timestamp: 600,
                ..Default::default()
            },
            payload: bytes!(0x03),
        },
    );
    assert_eq!(
        s.pop(now),
        Some(Sample {
            data: bytes!(0x02),
            duration: Duration::from_secs(1),
            packet_timestamp: 500,
            prev_dropped_packets: 4998,
            ..Sample::new(now)
        }),
        "Failed to build samples after large gap"
    );
    assert_eq!(
        s.pop(now),
        Some(Sample {
            data: bytes!(0x02),
            duration: Duration::from_secs(1),
            packet_timestamp: 501,
            ..Sample::new(now)
        }),
        "Failed to build samples after large gap"
    );
}

#[test]
fn test_seqnum_distance() {
    struct TestData {
        x: u16,
        y: u16,
        d: u16,
    }
    let test_data = vec![
        TestData {
            x: 0x0001,
            y: 0x0003,
            d: 0x0002,
        },
        TestData {
            x: 0x0003,
            y: 0x0001,
            d: 0x0002,
        },
        TestData {
            x: 0xFFF3,
            y: 0xFFF1,
            d: 0x0002,
        },
        TestData {
            x: 0xFFF1,
            y: 0xFFF3,
            d: 0x0002,
        },
        TestData {
            x: 0xFFFF,
            y: 0x0001,
            d: 0x0002,
        },
        TestData {
            x: 0x0001,
            y: 0xFFFF,
            d: 0x0002,
        },
    ];

    for data in test_data {
        assert_eq!(
            seqnum_distance(data.x, data.y),
            data.d,
            "seqnum_distance({}, {}) returned {} which must be {}",
            data.x,
            data.y,
            seqnum_distance(data.x, data.y),
            data.d
        );
    }
}

#[test]
fn test_sample_builder_clean_reference() {
    let now = Instant::now();
    for seq_start in [0_u16, 0xfff8, 0xfffe] {
        let mut s = SampleBuilder::new(10, FakeDepacketizer::new(), 1);
        s.push(
            now,
            Packet {
                header: Header {
                    sequence_number: seq_start,
                    timestamp: 0,
                    ..Default::default()
                },
                payload: bytes!(0x01),
            },
        );
        s.push(
            now,
            Packet {
                header: Header {
                    sequence_number: seq_start.wrapping_add(1),
                    timestamp: 0,
                    ..Default::default()
                },
                payload: bytes!(0x02),
            },
        );
        s.push(
            now,
            Packet {
                header: Header {
                    sequence_number: seq_start.wrapping_add(2),
                    timestamp: 0,
                    ..Default::default()
                },
                payload: bytes!(0x03),
            },
        );
        let pkt4 = Packet {
            header: Header {
                sequence_number: seq_start.wrapping_add(14),
                timestamp: 120,
                ..Default::default()
            },
            payload: bytes!(0x04),
        };
        s.push(now, pkt4.clone());
        let pkt5 = Packet {
            header: Header {
                sequence_number: seq_start.wrapping_add(12),
                timestamp: 120,
                ..Default::default()
            },
            payload: bytes!(0x05),
        };
        s.push(now, pkt5.clone());

        for i in 0..3 {
            assert_eq!(
                s.buffer.get(seq_start.wrapping_add(i)),
                None,
                "Old packet ({i}) is not unreferenced (seq_start: {seq_start}, max_late: 10, pushed: 12)"
            );
        }
        assert_eq!(s.buffer.get(seq_start.wrapping_add(14)), Some(&pkt4));
        assert_eq!(s.buffer.get(seq_start.wrapping_add(12)), Some(&pkt5));
    }
}

#[test]
fn test_sample_builder_push_max_zero() {
    let now = Instant::now();
    let pkt = Packet {
        header: Header {
            sequence_number: 0,
            timestamp: 0,
            marker: true,
            ..Default::default()
        },
        payload: bytes!(0x01),
    };
    let d = FakeDepacketizer {
        head_checker: true,
        head_bytes: vec![bytes!(0x01)],
    };
    let mut s = SampleBuilder::new(0, d, 1);
    s.push(now, pkt);
    assert!(s.pop(now).is_some(), "Should expect a popped sample.")
}

#[test]
fn test_pop_with_timestamp() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(0, FakeDepacketizer::new(), 1);
    assert_eq!(s.pop_with_timestamp(now), None);
}

#[test]
fn test_too_old_timestamp_wrapping() {
    let now = Instant::now();
    // Create a SampleBuilder with 1ms max late duration (sample rate 48000 = 48 samples per 1ms)
    let mut s = SampleBuilder::new(10, FakeDepacketizer::new(), 48000)
        .with_max_time_delay(Duration::from_millis(1));

    // Push packet with very high timestamp that would wrap around
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 1,
                timestamp: u32::MAX - 10, // Very high timestamp
                marker: false,
                ..Default::default()
            },
            payload: bytes!(0x01),
        },
    );

    // Push packet with wrapped timestamp, too_old will say true and we would get a sample with above packet
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 2,
                timestamp: 38, // Very low timestamp but the ts diff will be > 48
                marker: false,
                ..Default::default()
            },
            payload: bytes!(0x02),
        },
    );

    // This test would panic with "attempt to subtract with overflow" if wrapping_sub wasn't used
    // The difference between timestamps should wrap around properly
    assert!(
        s.prepared.count() > 0, // due to ts diff 49 > 48 it will say that an old sample is done
        "Expected packets to be considered too old event with timestamp wrapping"
    );
}

#[test]
fn test_too_old_ok_timestamp_wrapping() {
    let now = Instant::now();
    // Create a SampleBuilder with 1ms max late duration (sample rate 48000 = 48 samples per 1ms)
    let mut s = SampleBuilder::new(10, FakeDepacketizer::new(), 48000)
        .with_max_time_delay(Duration::from_millis(1));

    // Push packet with very high timestamp that would wrap around
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 1,
                timestamp: u32::MAX - 10, // Very high timestamp
                marker: false,
                ..Default::default()
            },
            payload: bytes!(0x01),
        },
    );

    // Push packet with low timestamp
    s.push(
        now,
        Packet {
            header: Header {
                sequence_number: 2,
                timestamp: 10, // Very low timestamp
                marker: false,
                ..Default::default()
            },
            payload: bytes!(0x02),
        },
    );

    // This test would panic with "attempt to subtract with overflow" if wrapping_sub wasn't used
    // The difference between timestamps should wrap around properly
    assert!(
        !s.too_old(&s.filled), // 21 < 48
        "Expected packets to not be considered too old even with timestamp wrapping"
    );
    assert!(s.prepared.empty());
}

#[test]
fn test_sample_builder_data() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(10, FakeDepacketizer::new(), 1);
    let mut j: usize = 0;
    for i in 0..0x20000_usize {
        let p = Packet {
            header: Header {
                sequence_number: i as u16,
                timestamp: (i + 42) as u32,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(&[i as u8]),
        };
        s.push(now, p);
        while let Some((sample, ts)) = s.pop_with_timestamp(now) {
            assert_eq!(ts, (j + 42) as u32, "timestamp");
            assert_eq!(sample.data.len(), 1, "data length");
            assert_eq!(sample.data[0], j as u8, "timestamp");
            j += 1;
        }
    }
    // only the last packet should be dropped
    assert_eq!(j, 0x1FFFF);
}

/// `frames` frames of `per_frame` packets from `seq0`. Frame `f` has timestamp `f * 10`, its
/// last packet carries the marker, and packet `k` of it has payload `[f, f >> 8, k, k >> 8]`.
fn frame_packets(seq0: u16, frames: usize, per_frame: usize) -> Vec<Packet> {
    (0..frames * per_frame)
        .map(|i| {
            let (f, k) = (i / per_frame, i % per_frame);
            Packet {
                header: Header {
                    sequence_number: seq0.wrapping_add(i as u16),
                    timestamp: f as u32 * 10,
                    marker: k == per_frame - 1,
                    ..Default::default()
                },
                payload: Bytes::from(vec![f as u8, (f >> 8) as u8, k as u8, (k >> 8) as u8]),
            }
        })
        .collect()
}

/// The sample data of frame `f` from [`frame_packets`].
fn frame_data(f: usize, per_frame: usize) -> Vec<u8> {
    (0..per_frame)
        .flat_map(|k| [f as u8, (f >> 8) as u8, k as u8, (k >> 8) as u8])
        .collect()
}

/// Pushes `packets` in order, popping after every push.
fn push_and_pop<T: Depacketizer>(
    s: &mut SampleBuilder<T>,
    packets: impl IntoIterator<Item = Packet>,
) -> Vec<Sample> {
    let now = Instant::now();
    let mut samples = vec![];
    for p in packets {
        s.push(now, p);
        while let Some(sample) = s.pop(now) {
            samples.push(sample);
        }
    }
    samples
}

/// Asserts that `samples` are frames `0..frames` of [`frame_packets`], intact and in order.
fn assert_frames(samples: &[Sample], frames: usize, per_frame: usize, context: &str) {
    assert_eq!(samples.len(), frames, "{context}: sample count");
    for (f, sample) in samples.iter().enumerate() {
        assert_eq!(
            sample.data,
            frame_data(f, per_frame),
            "{context}: frame {f} data"
        );
        assert_eq!(
            sample.packet_timestamp,
            f as u32 * 10,
            "{context}: frame {f} timestamp"
        );
        assert_eq!(sample.prev_dropped_packets, 0, "{context}: frame {f} drops");
    }
}

#[test]
fn test_sample_builder_new_allocates_nothing() {
    for max_late in [0, 10, 500, u16::MAX] {
        let s = SampleBuilder::new(max_late, FakeDepacketizer::new(), 1);
        assert_eq!(s.buffer.slots.capacity(), 0, "max_late {max_late}");
        assert!(s.buffer.parked.is_none(), "max_late {max_late}");
        assert_eq!(s.prepared.samples.capacity(), 0, "max_late {max_late}");
    }
}

#[test]
fn test_sample_builder_ring_follows_window() {
    // A caller that pops promptly holds a few packets at a time, so the ring keeps its
    // initial size however large max_late is.
    for max_late in [20, 500, u16::MAX] {
        let mut s = SampleBuilder::new(max_late, FakeDepacketizer::new(), 1);
        let samples = push_and_pop(&mut s, frame_packets(0xff00, 200, 3));
        assert_frames(&samples, 199, 3, &format!("max_late {max_late}"));
        assert_eq!(
            s.buffer.slots.len(),
            MIN_PACKET_SLOTS,
            "max_late {max_late}"
        );
    }

    // One that never pops lets the window fill to max_late; the ring grows to cover it but
    // no further.
    let now = Instant::now();
    for max_late in [0, 1, 10, 15, 16, 17, 100, 500] {
        let mut s = SampleBuilder::new(max_late, FakeDepacketizer::new(), 1);
        for p in frame_packets(0xff00, 400, 2) {
            s.push(now, p);
            assert!(s.buffer.slots.len() >= s.filled.count() as usize);
        }
        let bound = (max_late as usize)
            .next_power_of_two()
            .max(MIN_PACKET_SLOTS);
        assert!(
            s.buffer.slots.len() <= bound,
            "max_late {max_late}: {} slots",
            s.buffer.slots.len()
        );
    }
}

#[test]
fn test_sample_builder_wraparound_frames() {
    for (seq0, per_frame) in [(0xfff0, 1), (0xffe0, 3), (0xff00, 7), (0xfffe, 40)] {
        for max_late in [2 * per_frame as u16 + 2, 100, u16::MAX] {
            let mut s = SampleBuilder::new(max_late, FakeDepacketizer::new(), 1);
            let samples = push_and_pop(&mut s, frame_packets(seq0, 60, per_frame));
            let context =
                format!("seq0 {seq0:#x}, {per_frame} packets per frame, max_late {max_late}");
            // the last frame waits for a packet after it
            assert_frames(&samples, 59, per_frame, &context);
        }
    }
}

#[test]
fn test_sample_builder_reordering() {
    for (seq0, per_frame) in [(0xfff0_u16, 1), (0xffe0, 3), (0xff80, 5)] {
        let in_order = frame_packets(seq0, 60, per_frame);
        // Keep the first packets in order: a packet older than the first one pushed is
        // dropped, as before. After that, reverse runs of 2 (swapped neighbours), 4 and 7.
        for run in [2, 4, 7] {
            let mut packets = in_order.clone();
            for chunk in packets[4..].chunks_mut(run) {
                chunk.reverse();
            }
            let mut s = SampleBuilder::new(20, FakeDepacketizer::new(), 1);
            let samples = push_and_pop(&mut s, packets);
            let context = format!("seq0 {seq0:#x}, {per_frame} packets per frame, run {run}");
            assert_frames(&samples, 59, per_frame, &context);
        }
    }
}

#[test]
fn test_sample_builder_duplicates() {
    for (seq0, per_frame) in [(0xfff0_u16, 1), (0xffe0, 4)] {
        let packets = frame_packets(seq0, 60, per_frame);
        let mut duplicated = vec![];
        for (i, p) in packets.iter().enumerate() {
            duplicated.push(p.clone());
            // immediate duplicates, replays from within the window, and replays of packets
            // consumed long ago
            if i % 3 == 0 {
                duplicated.push(p.clone());
            }
            if i % 5 == 0 && i >= 3 {
                duplicated.push(packets[i - 3].clone());
            }
            if i % 11 == 0 && i >= 40 {
                duplicated.push(packets[i - 40].clone());
            }
        }
        let mut s = SampleBuilder::new(20, FakeDepacketizer::new(), 1);
        let samples = push_and_pop(&mut s, duplicated);
        assert_frames(
            &samples,
            59,
            per_frame,
            &format!("{per_frame} packets per frame"),
        );
    }
}

#[test]
fn test_sample_builder_missing_fragments() {
    // VP8 frames of 4 packets; the S bit marks the first packet of each frame.
    const PER_FRAME: usize = 4;
    let lossy_frames = [5, 9, 12];
    let mut packets = vec![];
    for f in 0..20_usize {
        for k in 0..PER_FRAME {
            // frame 5 loses a middle packet, frame 9 its first and frame 12 its last
            let lost = (f == 5 && k == 1) || (f == 9 && k == 0) || (f == 12 && k == PER_FRAME - 1);
            if lost {
                continue;
            }
            let descriptor = if k == 0 { 0x10 } else { 0x00 };
            packets.push(Packet {
                header: Header {
                    sequence_number: 0xfff0_u16.wrapping_add((f * PER_FRAME + k) as u16),
                    timestamp: f as u32 * 3000,
                    marker: k == PER_FRAME - 1,
                    ..Default::default()
                },
                payload: Bytes::from(vec![descriptor, f as u8, k as u8, 0xaa]),
            });
        }
    }
    let mut s = SampleBuilder::new(12, rtp::codec::vp8::Vp8Packet::default(), 90000);
    let samples = push_and_pop(&mut s, packets);

    let delivered: Vec<u32> = samples.iter().map(|s| s.packet_timestamp / 3000).collect();
    let expected: Vec<u32> = (0..19).filter(|f| !lossy_frames.contains(f)).collect();
    assert_eq!(
        delivered, expected,
        "frames with a missing packet are dropped"
    );
    for sample in &samples {
        let f = sample.packet_timestamp / 3000;
        let data: Vec<u8> = (0..PER_FRAME as u8)
            .flat_map(|k| [f as u8, k, 0xaa])
            .collect();
        assert_eq!(sample.data, data, "frame {f} data");
        assert_eq!(
            sample.prev_dropped_packets > 0,
            f > 0 && lossy_frames.contains(&(f - 1)),
            "frame {f} reports the drops before it"
        );
    }
}

#[test]
fn test_sample_builder_large_frames() {
    const PER_FRAME: usize = 300;
    let in_order = frame_packets(0xff00, 5, PER_FRAME);
    // Frames far larger than the initial ring, in order and with all but the first frame
    // arriving back to front.
    let mut reversed = in_order.clone();
    for frame in reversed[PER_FRAME..4 * PER_FRAME].chunks_mut(PER_FRAME) {
        frame.reverse();
    }
    for (name, packets) in [("in order", in_order), ("reversed", reversed)] {
        let mut s = SampleBuilder::new(700, FakeDepacketizer::new(), 1);
        let samples = push_and_pop(&mut s, packets[..4 * PER_FRAME + 1].to_vec());
        assert_frames(&samples, 4, PER_FRAME, name);
        let slots = s.buffer.slots.len();
        assert!((PER_FRAME..=1024).contains(&slots), "{name}: {slots} slots");
    }
}

#[test]
fn test_sample_builder_jump_into_held_slot() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(10, FakeDepacketizer::new(), 1);
    for p in frame_packets(100, 4, 1) {
        s.push(now, p);
    }
    // 116 maps to the slot 100 is still held in. The purge its arrival forces releases 100
    // first, so the ring keeps its size.
    let jump = Packet {
        header: Header {
            sequence_number: 116,
            timestamp: 1000,
            marker: true,
            ..Default::default()
        },
        payload: bytes!(0xee),
    };
    s.push(now, jump.clone());
    assert_eq!(s.buffer.slots.len(), MIN_PACKET_SLOTS);
    assert!(s.buffer.parked.is_none());
    assert_eq!(s.buffer.get(100), None);
    assert_eq!(s.buffer.get(116), Some(&jump));

    let samples: Vec<Sample> = std::iter::from_fn(|| s.pop(now)).collect();
    assert_frames(&samples, 4, 1, "frames forced out by the jump");
}

fn ring_packet(seq: u16) -> Packet {
    Packet {
        header: Header {
            sequence_number: seq,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(&seq.to_be_bytes()),
    }
}

fn held(head: u16, tail: u16) -> SampleSequenceLocation {
    SampleSequenceLocation { head, tail }
}

#[test]
fn test_packet_ring_slot_reuse_identity() {
    let mut ring = PacketRing::new(10);
    assert_eq!(ring.get(5), None);
    ring.release(5);

    ring.insert(ring_packet(5), &held(5, 6));
    assert_eq!(ring.slots.len(), 16);
    // 21 shares 5's slot: neither a lookup nor a release for 21 may touch 5's packet
    assert_eq!(ring.get(21), None);
    ring.release(21);
    assert_eq!(ring.get(5), Some(&ring_packet(5)));

    // a duplicate replaces the earlier copy
    let mut duplicate = ring_packet(5);
    duplicate.payload = bytes!(0xdd);
    ring.insert(duplicate.clone(), &held(5, 6));
    assert_eq!(ring.get(5), Some(&duplicate));

    // once 5 is no longer held, 21 takes the slot and 5 is gone
    ring.insert(ring_packet(21), &held(21, 22));
    assert_eq!(ring.get(5), None);
    assert_eq!(ring.get(21), Some(&ring_packet(21)));

    // likewise across the sequence-number wrap
    ring.insert(ring_packet(0xfff5), &held(0xfff5, 0xfff6));
    assert_eq!(ring.get(21), None);
    assert_eq!(ring.get(0xfff5), Some(&ring_packet(0xfff5)));
    ring.release(0xfff5);
    assert_eq!(ring.get(0xfff5), None);
    assert!(ring.slots.iter().all(Option::is_none));
}

#[test]
fn test_packet_ring_parks_and_grows() {
    let mut ring = PacketRing::new(10);
    ring.insert(ring_packet(5), &held(5, 6));

    // 21 arrives while 5 is held: it is parked, and both stay visible
    ring.insert(ring_packet(21), &held(5, 22));
    assert!(ring.parked.is_some());
    assert_eq!(ring.get(5), Some(&ring_packet(5)));
    assert_eq!(ring.get(21), Some(&ring_packet(21)));

    // the purge releases 5, so 21 settles into the slot without growing the ring
    ring.release(5);
    ring.settle(&held(6, 22));
    assert!(ring.parked.is_none());
    assert_eq!(ring.slots.len(), 16);
    assert_eq!(ring.get(21), Some(&ring_packet(21)));

    // 37 arrives and 21 stays held: the ring doubles to fit both
    ring.insert(ring_packet(37), &held(21, 38));
    ring.settle(&held(21, 38));
    assert_eq!(ring.slots.len(), 32);
    assert_eq!(ring.get(21), Some(&ring_packet(21)));
    assert_eq!(ring.get(37), Some(&ring_packet(37)));

    // a parked packet the purge releases leaves nothing to settle
    ring.insert(ring_packet(69), &held(21, 70));
    assert_eq!(ring.get(69), Some(&ring_packet(69)));
    ring.release(69);
    ring.settle(&held(21, 38));
    assert_eq!(ring.get(69), None);
    assert_eq!(ring.get(37), Some(&ring_packet(37)));
    assert_eq!(ring.slots.len(), 32);

    // growth stops once the ring covers the whole sequence space
    let mut ring = PacketRing::new(u16::MAX);
    let wide = held(0, 40000);
    ring.insert(ring_packet(0), &wide);
    ring.insert(ring_packet(32768), &wide);
    ring.settle(&wide);
    assert_eq!(ring.slots.len(), u16::MAX as usize + 1);
    assert_eq!(ring.get(0), Some(&ring_packet(0)));
    assert_eq!(ring.get(32768), Some(&ring_packet(32768)));
}

#[test]
fn test_sample_builder_prepared_backlog_limit() {
    let now = Instant::now();
    // With max_late 5 every push past the sixth forces the oldest sample out, so a caller
    // that doesn't pop builds up prepared samples: frames 0..=24 after 30 pushes.
    let frames = frame_packets(0xfff8, 30, 1);

    // The default limit holds all of them.
    let mut s = SampleBuilder::new(5, FakeDepacketizer::new(), 1);
    for p in frames.clone() {
        s.push(now, p);
    }
    assert_eq!(s.prepared.count(), 25);
    let samples: Vec<Sample> = std::iter::from_fn(|| s.pop(now)).collect();
    assert_frames(&samples, 29, 1, "default limit");

    // A limit of 4 keeps frames 21..=24 and reports the 21 discarded ones on frame 21.
    // Popping from the full queue returns the oldest sample without building another, so
    // draining it discards nothing more.
    let mut s = SampleBuilder::new(5, FakeDepacketizer::new(), 1).with_max_prepared_samples(4);
    for p in frames.clone() {
        s.push(now, p);
    }
    assert_eq!(s.prepared.count(), 4);
    let samples: Vec<Sample> = std::iter::from_fn(|| s.pop(now)).collect();
    let delivered: Vec<u32> = samples.iter().map(|s| s.packet_timestamp / 10).collect();
    assert_eq!(delivered, (21..29).collect::<Vec<u32>>());
    assert_eq!(samples[0].prev_dropped_packets, 21);
    assert!(samples[1..].iter().all(|s| s.prev_dropped_packets == 0));

    // A limit of 0 acts as 1.
    let mut s = SampleBuilder::new(5, FakeDepacketizer::new(), 1).with_max_prepared_samples(0);
    for p in frames {
        s.push(now, p);
    }
    let first = s.pop(now).expect("the newest prepared sample");
    assert_eq!(first.packet_timestamp, 240);
    assert_eq!(first.prev_dropped_packets, 24);
}

#[test]
fn test_sample_builder_prepared_backlog_accounting() {
    // Every sequence number up to the last sample returned is either in a returned sample
    // or counted in a `prev_dropped_packets`, including losses reported by samples that
    // were later discarded.
    let now = Instant::now();
    let lost = [3_usize, 4, 11, 30];
    let packets: Vec<Packet> = frame_packets(0xffd0, 80, 1)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !lost.contains(i))
        .map(|(_, p)| p)
        .collect();
    for limit in [1, 2, 7, 100] {
        let mut s =
            SampleBuilder::new(3, FakeDepacketizer::new(), 1).with_max_prepared_samples(limit);
        for p in packets.clone() {
            s.push(now, p);
        }
        let samples: Vec<Sample> = std::iter::from_fn(|| s.pop(now)).collect();
        let last = samples.last().expect("samples").packet_timestamp as usize / 10;
        let accounted: usize = samples
            .iter()
            .map(|s| s.prev_dropped_packets as usize + 1)
            .sum();
        assert_eq!(accounted, last + 1, "limit {limit}");
    }
}

#[test]
fn test_sample_builder_prepared_backlog_released() {
    let now = Instant::now();
    let mut s = SampleBuilder::new(5, FakeDepacketizer::new(), 1);
    for p in frame_packets(0, 1000, 1) {
        s.push(now, p);
    }
    assert_eq!(s.prepared.count(), 995);
    assert!(s.prepared.samples.capacity() >= 995);
    while s.pop(now).is_some() {}
    assert!(s.prepared.samples.capacity() <= RETAINED_PREPARED_CAPACITY);
}

#[test]
fn test_sample_builder_max_late_boundaries() {
    let now = Instant::now();

    // max_late 0 releases every packet on arrival; a frame closed by its own marker is
    // still delivered.
    let mut s = SampleBuilder::new(0, FakeDepacketizer::new(), 1);
    let samples = push_and_pop(&mut s, frame_packets(0xfff0, 40, 1));
    assert_eq!(samples.len(), 40);
    for (f, sample) in samples.iter().enumerate() {
        assert_eq!(sample.data, frame_data(f, 1), "frame {f}");
    }
    assert!(s.buffer.slots.len() <= 1);

    // max_late u16::MAX with a prompt caller across several wraps.
    let mut s = SampleBuilder::new(u16::MAX, FakeDepacketizer::new(), 1);
    let samples = push_and_pop(&mut s, frame_packets(0x8000, 140_000, 1));
    assert_eq!(samples.len(), 139_999);
    for (f, sample) in samples.iter().enumerate() {
        assert_eq!(sample.data, frame_data(f, 1), "frame {f}");
    }
    assert_eq!(s.buffer.slots.len(), MIN_PACKET_SLOTS);

    // max_late u16::MAX holding 40,000 packets before any pop.
    let mut s = SampleBuilder::new(u16::MAX, FakeDepacketizer::new(), 1);
    for p in frame_packets(0xfff0, 40_000, 1) {
        s.push(now, p);
    }
    assert_eq!(s.buffer.slots.len(), u16::MAX as usize + 1);
    let samples: Vec<Sample> = std::iter::from_fn(|| s.pop(now)).collect();
    assert_eq!(samples.len(), 39_999);
    for (f, sample) in samples.iter().enumerate() {
        assert_eq!(sample.data, frame_data(f, 1), "frame {f}");
    }
}
