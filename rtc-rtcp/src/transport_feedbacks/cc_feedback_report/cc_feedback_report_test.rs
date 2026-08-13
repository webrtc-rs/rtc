//! Wire-format tests for [RFC 8888] congestion control feedback.
//!
//! The raw byte vectors are taken from `pion/rtcp@v1.2.17`'s `rfc8888_test.go`, which is an
//! independent implementation of the same RFC. That matters: a round trip through *this* encoder
//! and decoder would agree with itself no matter what it put on the wire, so it is evidence of
//! self-consistency and not of conformance. Every `Data` array below is a byte sequence some
//! other implementation produces and accepts.
//!
//! [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888.html

use super::*;
use crate::packet::unmarshal;
use bytes::{Bytes, BytesMut};

// ---------------------------------------------------------------------------------------
// Metric block — two bytes, the smallest unit
// ---------------------------------------------------------------------------------------

/// Every vector round-trips: bytes → value → the same bytes.
#[test]
fn metric_block_round_trips_every_vector() {
    let cases: &[(&str, u16, CcFeedbackMetricBlock)] = &[
        (
            "not received",
            0x0000,
            CcFeedbackMetricBlock {
                received: false,
                ecn: Ecn::NotEct,
                arrival_time_offset: 0,
            },
        ),
        (
            "received, no offset",
            0x8000,
            CcFeedbackMetricBlock {
                received: true,
                ecn: Ecn::NotEct,
                arrival_time_offset: 0,
            },
        ),
        (
            "received with offset",
            0x9FFD,
            CcFeedbackMetricBlock {
                received: true,
                ecn: Ecn::NotEct,
                arrival_time_offset: 8189,
            },
        ),
        (
            "received, offset near the 13-bit ceiling",
            0x9FFE,
            CcFeedbackMetricBlock {
                received: true,
                ecn: Ecn::NotEct,
                arrival_time_offset: 8190,
            },
        ),
        (
            "received, maximum representable offset",
            0x9FFF,
            CcFeedbackMetricBlock {
                received: true,
                ecn: Ecn::NotEct,
                arrival_time_offset: 8191,
            },
        ),
        (
            "received, congestion encountered",
            0xFFF8,
            CcFeedbackMetricBlock {
                received: true,
                ecn: Ecn::Ce,
                arrival_time_offset: 8184,
            },
        ),
    ];

    for (name, word, expected) in cases {
        assert_eq!(
            *expected,
            CcFeedbackMetricBlock::unmarshal_word(*word),
            "decoding {name}"
        );
        assert_eq!(
            *word,
            expected.marshal_word().expect("encode"),
            "encoding {name}"
        );
    }
}

/// A lost packet reports nothing else, so the other 15 bits are ignored rather than decoded.
///
/// Without this, a peer leaving stale bits in a not-received block would make a lost packet
/// appear to have arrived carrying an ECN marking — feeding congestion control a measurement of
/// a packet that never came.
#[test]
fn a_not_received_block_ignores_the_remaining_bits() {
    for (name, word) in [
        ("ECN bits set", 0x6200u16),
        ("ECT(1) and an offset", 0x2200),
        ("every non-R bit set", 0x7FFF),
    ] {
        assert_eq!(
            CcFeedbackMetricBlock {
                received: false,
                ecn: Ecn::NotEct,
                arrival_time_offset: 0,
            },
            CcFeedbackMetricBlock::unmarshal_word(word),
            "decoding a not-received block with {name}"
        );
    }
}

/// All four ECN codepoints are defined by RFC 3168, so there is no "unknown" value to reject —
/// two bits, four meanings. This pins the mapping instead, because the ECT pair is the easy one
/// to transpose: `ECT(1)` is `01` and `ECT(0)` is `10`.
#[test]
fn ecn_codepoints_match_rfc3168() {
    let cases = [
        (0b00u8, Ecn::NotEct, "Not-ECT (00)"),
        (0b01, Ecn::Ect1, "ECT(1) (01)"),
        (0b10, Ecn::Ect0, "ECT(0) (10)"),
        (0b11, Ecn::Ce, "CE (11)"),
    ];
    for (bits, expected, display) in cases {
        assert_eq!(expected, Ecn::from_bits(bits), "codepoint {bits:#04b}");
        assert_eq!(
            bits as u16, expected as u16,
            "numeric value of {expected:?}"
        );
        assert_eq!(display, expected.to_string());
    }

    // And the codepoint survives a full encode/decode at the block level.
    for (_, ecn, _) in cases {
        let block = CcFeedbackMetricBlock {
            received: true,
            ecn,
            arrival_time_offset: 1,
        };
        assert_eq!(
            block,
            CcFeedbackMetricBlock::unmarshal_word(block.marshal_word().expect("encode"))
        );
    }
}

// ---------------------------------------------------------------------------------------
// Report block
// ---------------------------------------------------------------------------------------

fn marshal_block(block: &CcFeedbackReportBlock) -> Vec<u8> {
    let mut storage = vec![0u8; block.raw_size()];
    let mut buf = storage.as_mut_slice();
    block.marshal_to(&mut buf).expect("marshal block");
    storage
}

fn unmarshal_block(data: &[u8]) -> Result<(CcFeedbackReportBlock, usize)> {
    let mut buf = data;
    CcFeedbackReportBlock::unmarshal_from(&mut buf, data.len())
}

#[test]
fn report_block_round_trips_every_vector() {
    let received = |offset| CcFeedbackMetricBlock {
        received: true,
        ecn: Ecn::NotEct,
        arrival_time_offset: offset,
    };
    let lost = CcFeedbackMetricBlock::default();

    let cases: &[(&str, &[u8], CcFeedbackReportBlock)] = &[
        (
            "no reported packets",
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            CcFeedbackReportBlock {
                media_ssrc: 0,
                begin_sequence: 0,
                metric_blocks: vec![],
            },
        ),
        (
            "two of four received",
            &[
                0x00, 0x00, 0x00, 0x01, // media SSRC
                0x00, 0x02, 0x00, 0x04, // begin_seq=2, num_reports=4
                0x9F, 0xFD, 0x9F, 0xFC, // reports 0..1
                0x00, 0x00, 0x00, 0x00, // reports 2..3
            ],
            CcFeedbackReportBlock {
                media_ssrc: 1,
                begin_sequence: 2,
                metric_blocks: vec![received(8189), received(8188), lost, lost],
            },
        ),
        (
            "odd count, padded to a 32-bit boundary",
            &[
                0x00, 0x00, 0x00, 0x01, // media SSRC
                0x00, 0x02, 0x00, 0x03, // begin_seq=2, num_reports=3
                0x9F, 0xFD, 0x9F, 0xFC, // reports 0..1
                0x00, 0x00, 0x00, 0x00, // report 2, then padding
            ],
            CcFeedbackReportBlock {
                media_ssrc: 1,
                begin_sequence: 2,
                metric_blocks: vec![received(8189), received(8188), lost],
            },
        ),
        (
            "sequence numbers wrapping through zero",
            &[
                0x00, 0x00, 0x00, 0x01, // media SSRC
                0xFF, 0xFE, 0x00, 0x04, // begin_seq=65534, num_reports=4
                0x9F, 0xFD, 0x9F, 0xFC, // reports 0..1
                0x00, 0x00, 0x00, 0x00, // reports 2..3
            ],
            CcFeedbackReportBlock {
                media_ssrc: 1,
                begin_sequence: 65534,
                metric_blocks: vec![received(8189), received(8188), lost, lost],
            },
        ),
    ];

    for (name, data, expected) in cases {
        let (decoded, consumed) = unmarshal_block(data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(*expected, decoded, "decoding {name}");
        assert_eq!(data.len(), consumed, "consumed length for {name}");
        assert_eq!(data.to_vec(), marshal_block(expected), "encoding {name}");
    }
}

/// The padding block is not a reported packet.
///
/// `num_reports` records the true count while the block is padded to an even number of metric
/// blocks, so an odd-length block must not decode as one packet longer than it is — the extra
/// entry would look like a lost packet at `begin_sequence + num_reports`.
#[test]
fn padding_is_not_decoded_as_an_extra_report() {
    let data = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x9F, 0xFD, 0x9F, 0xFC, 0x00, 0x00, 0x00,
        0x00,
    ];
    let (block, consumed) = unmarshal_block(&data).expect("decode");
    assert_eq!(3, block.metric_blocks.len(), "three reports, not four");
    assert_eq!(
        16, consumed,
        "but sixteen bytes consumed, including padding"
    );
}

#[test]
fn truncated_report_blocks_are_rejected_without_panicking() {
    // Shorter than the block header.
    for len in 0..REPORT_BLOCK_HEADER_LENGTH {
        let data = vec![0u8; len];
        assert!(
            unmarshal_block(&data).is_err(),
            "a {len}-byte block must be rejected"
        );
    }

    // `num_reports` claims more metric blocks than the block carries.
    let data = [
        0x00, 0x00, 0x00, 0x01, // media SSRC
        0x00, 0x02, 0x00, 0x05, // begin_seq=2, num_reports=5 — only 4 present
        0x9F, 0xFD, 0x9F, 0xFC, //
        0x00, 0x00, 0x00, 0x00, //
    ];
    assert!(
        unmarshal_block(&data).is_err(),
        "num_reports beyond the block's own length must be rejected"
    );
}

/// `num_reports` is a `u16`, so a block can claim up to 65535 packets; the format's own limit is
/// 16384. A claim within `u16` but backed by real bytes decodes — the limit is enforced when
/// encoding, which is where this implementation controls the outcome.
#[test]
fn a_large_but_backed_report_count_decodes() {
    let count = 0x7FFBusize;
    let mut data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    data.extend_from_slice(&(count as u16).to_be_bytes());
    data.extend(std::iter::repeat_n(0u8, 2 * (count + 1)));

    let (block, _) = unmarshal_block(&data).expect("decode");
    assert_eq!(count, block.metric_blocks.len());
}

#[test]
fn encoding_more_metric_blocks_than_the_format_allows_is_rejected() {
    let block = CcFeedbackReportBlock {
        media_ssrc: 0,
        begin_sequence: 0,
        metric_blocks: vec![CcFeedbackMetricBlock::default(); MAX_METRIC_BLOCKS + 1],
    };
    let mut storage = vec![0u8; block.raw_size()];
    let mut buf = storage.as_mut_slice();
    assert!(matches!(
        block.marshal_to(&mut buf),
        Err(Error::TooManyReports)
    ));
}

// ---------------------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------------------

/// Header `0x8B 0xCD`: V=2, P=0, FMT=11, PT=205.
const EMPTY_REPORT: &[u8] = &[
    0x8B, 0xCD, 0x00, 0x02, // V=2, P=0, FMT=11, PT=205, length=2
    0x00, 0x00, 0x00, 0x01, // sender SSRC=1
    0x00, 0x00, 0x00, 0x01, // report timestamp=1
];

const TWO_BLOCK_REPORT: &[u8] = &[
    0x8B, 0xCD, 0x00, 0x0A, // V=2, P=0, FMT=11, PT=205, length=10
    0x00, 0x00, 0x00, 0x01, // sender SSRC=1
    0x00, 0x00, 0x00, 0x01, // media SSRC=1
    0x00, 0x02, 0x00, 0x04, // begin_seq=2, num_reports=4
    0x9F, 0xFD, 0x9F, 0xFC, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x02, // media SSRC=2
    0x00, 0x02, 0x00, 0x03, // begin_seq=2, num_reports=3
    0x9F, 0xFD, 0x9F, 0xFC, //
    0x00, 0x00, 0x00, 0x00, // report 2, then padding
    0x00, 0x00, 0x00, 0x01, // report timestamp=1
];

fn two_block_report() -> CcFeedbackReport {
    let received = |offset| CcFeedbackMetricBlock {
        received: true,
        ecn: Ecn::NotEct,
        arrival_time_offset: offset,
    };
    let lost = CcFeedbackMetricBlock::default();

    CcFeedbackReport {
        sender_ssrc: 1,
        report_blocks: vec![
            CcFeedbackReportBlock {
                media_ssrc: 1,
                begin_sequence: 2,
                metric_blocks: vec![received(8189), received(8188), lost, lost],
            },
            CcFeedbackReportBlock {
                media_ssrc: 2,
                begin_sequence: 2,
                metric_blocks: vec![received(8189), received(8188), lost],
            },
        ],
        report_timestamp: 1,
    }
}

fn marshal(report: &CcFeedbackReport) -> Vec<u8> {
    let mut storage = vec![0u8; report.marshal_size()];
    report.marshal_to(&mut storage).expect("marshal");
    storage
}

#[test]
fn an_empty_report_round_trips() {
    let expected = CcFeedbackReport {
        sender_ssrc: 1,
        report_blocks: vec![],
        report_timestamp: 1,
    };

    let mut buf = EMPTY_REPORT;
    let decoded = CcFeedbackReport::unmarshal(&mut buf).expect("decode");
    assert_eq!(expected, decoded);
    assert_eq!(EMPTY_REPORT.to_vec(), marshal(&expected));
}

#[test]
fn a_multi_stream_report_round_trips_byte_identically() {
    let expected = two_block_report();

    let mut buf = TWO_BLOCK_REPORT;
    let decoded = CcFeedbackReport::unmarshal(&mut buf).expect("decode");
    assert_eq!(expected, decoded, "decoding an independent vector");
    assert_eq!(
        TWO_BLOCK_REPORT.to_vec(),
        marshal(&decoded),
        "re-encoding must reproduce the same bytes"
    );
}

/// One report covers several streams, so it has several destination SSRCs — unlike most feedback
/// packets. An SFU routes on this, so a missing SSRC means feedback never reaches that sender.
#[test]
fn destination_ssrc_lists_every_reported_media_stream() {
    assert_eq!(vec![1, 2], two_block_report().destination_ssrc());
    assert_eq!(
        Vec::<u32>::new(),
        CcFeedbackReport::default().destination_ssrc()
    );
}

#[test]
fn the_header_declares_ccfb_and_a_consistent_length() {
    let report = two_block_report();
    let header = report.header();

    assert_eq!(PacketType::TransportSpecificFeedback, header.packet_type);
    assert_eq!(FORMAT_CCFB, header.count);
    assert!(!header.padding, "every field is already 32-bit aligned");
    assert_eq!(
        TWO_BLOCK_REPORT.len(),
        4 * (header.length as usize + 1),
        "the declared length must match the encoded size"
    );
    assert_eq!(TWO_BLOCK_REPORT.len(), report.marshal_size());
    assert_eq!(TWO_BLOCK_REPORT.len(), report.raw_size());
}

#[test]
fn truncated_reports_are_rejected_without_panicking() {
    for len in 0..TWO_BLOCK_REPORT.len() {
        let mut buf = &TWO_BLOCK_REPORT[..len];
        // Truncation is detected either by the buffer being short or by the header's declared
        // length exceeding it. Both are errors; neither may panic.
        assert!(
            CcFeedbackReport::unmarshal(&mut buf).is_err(),
            "a {len}-byte report must be rejected"
        );
    }
}

#[test]
fn a_report_with_the_wrong_type_or_format_is_rejected() {
    // PT=200 (Sender Report) rather than 205.
    let mut wrong_type = EMPTY_REPORT.to_vec();
    wrong_type[1] = 0xC8;
    assert!(matches!(
        CcFeedbackReport::unmarshal(&mut wrong_type.as_slice()),
        Err(Error::WrongType)
    ));

    // FMT=15 (transport-wide CC) rather than 11 — the same packet type, a different format.
    let mut wrong_format = EMPTY_REPORT.to_vec();
    wrong_format[0] = 0x8F;
    assert!(matches!(
        CcFeedbackReport::unmarshal(&mut wrong_format.as_slice()),
        Err(Error::WrongType)
    ));
}

#[test]
fn marshalling_into_a_short_buffer_is_rejected() {
    let report = two_block_report();
    let mut storage = vec![0u8; report.marshal_size() - 1];
    assert!(matches!(
        report.marshal_to(&mut storage),
        Err(Error::BufferTooShort)
    ));
}

// ---------------------------------------------------------------------------------------
// Dispatch — the reason this type exists rather than a `RawPacket`
// ---------------------------------------------------------------------------------------

/// Before this packet type existed, a received CCFB report fell through the dispatcher to
/// `RawPacket`. The whole point of registering FMT=11 is that a caller holding `Box<dyn Packet>`
/// can downcast to a decoded report.
#[test]
fn compound_dispatch_yields_a_downcastable_report() {
    let mut raw = BytesMut::from(TWO_BLOCK_REPORT);
    let packets = unmarshal(&mut raw).expect("dispatch");

    assert_eq!(1, packets.len());
    let report = packets[0]
        .as_any()
        .downcast_ref::<CcFeedbackReport>()
        .expect("a CCFB report must not decode as a RawPacket");
    assert_eq!(two_block_report(), *report);
    assert_eq!(vec![1, 2], packets[0].destination_ssrc());
}

/// A CCFB report alongside other RTCP in one datagram, which is how it actually arrives.
#[test]
fn a_ccfb_report_dispatches_correctly_inside_a_compound_packet() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(TWO_BLOCK_REPORT);
    datagram.extend_from_slice(EMPTY_REPORT);

    let mut raw = BytesMut::from(datagram.as_slice());
    let packets = unmarshal(&mut raw).expect("dispatch");

    assert_eq!(2, packets.len());
    assert_eq!(
        two_block_report(),
        *packets[0]
            .as_any()
            .downcast_ref::<CcFeedbackReport>()
            .expect("first")
    );
    assert_eq!(
        1,
        packets[1]
            .as_any()
            .downcast_ref::<CcFeedbackReport>()
            .expect("second")
            .sender_ssrc
    );
}

/// `equal` and `cloned` back `PartialEq`/`Clone` for `dyn Packet`, which the compound-packet
/// paths rely on.
#[test]
fn trait_object_equality_and_cloning_behave() {
    let report = two_block_report();
    let boxed: Box<dyn Packet> = Box::new(report.clone());
    let cloned = boxed.clone();

    assert!(boxed.equal(cloned.as_ref()));
    assert_eq!(&boxed, &cloned);

    let mut different = report;
    different.sender_ssrc = 99;
    assert!(!boxed.equal(&different));
}

/// A report decoded from a longer buffer must consume exactly its own bytes, or the next packet
/// in a compound datagram starts at the wrong offset.
#[test]
fn decoding_consumes_exactly_the_declared_length() {
    let mut datagram = TWO_BLOCK_REPORT.to_vec();
    datagram.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let mut buf = Bytes::from(datagram);
    let decoded = CcFeedbackReport::unmarshal(&mut buf).expect("decode");

    assert_eq!(two_block_report(), decoded);
    assert_eq!(
        4,
        buf.remaining(),
        "the trailing bytes must still be unread for the next packet"
    );
}
