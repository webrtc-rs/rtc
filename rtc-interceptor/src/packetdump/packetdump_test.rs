//! packetdump tests ported from pion/interceptor v0.1.49 `pkg/packetdump`
//! (`receiver_interceptor_test.go`, `sender_interceptor_test.go`, `packet_dumper_test.go`),
//! plus the forwarding, ordering and registry-placement tests the issue asks for.
//!
//! pion splits the dumper into a receiver interceptor (inbound) and a sender interceptor
//! (outbound); the belt has one interceptor that sees both legs, so each pion test is ported
//! against the leg it exercised.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use rtcp::header::PacketType;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;

use super::*;
use crate::Slot;
use crate::packet::Attribute;
use crate::packet::AttributedPacket;

/// A sink that keeps the lines it was written, in order.
#[derive(Clone, Default)]
struct RecordingSink(Arc<Mutex<Vec<String>>>);

impl PacketDumpSink for RecordingSink {
    fn write(&mut self, line: &str) {
        self.0.lock().unwrap().push(line.to_owned());
    }
}

impl RecordingSink {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

fn rtp_packet(sequence_number: u16) -> rtp::Packet {
    let mut packet = rtp::Packet::default();
    packet.header.sequence_number = sequence_number;
    packet
}

fn pli(sender_ssrc: u32, media_ssrc: u32) -> Packet {
    Packet::Rtcp(vec![Box::new(PictureLossIndication {
        sender_ssrc,
        media_ssrc,
    })])
}

fn tagged(message: crate::packet::AttributedPacket) -> TaggedPacket {
    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message,
    }
}

/// Feeds a packet through the read leg and returns what came out the other side.
fn read_one(dump: &mut PacketDump, message: AttributedPacket) -> Option<TaggedPacket> {
    dump.handle_read(tagged(message)).unwrap();
    let out = dump.poll_read();
    assert!(dump.poll_read().is_none(), "one packet in, one packet out");
    out
}

/// Feeds a packet through the write leg and returns what came out the other side.
fn write_one(dump: &mut PacketDump, message: AttributedPacket) -> Option<TaggedPacket> {
    dump.handle_write(tagged(message)).unwrap();
    let out = dump.poll_write();
    assert!(dump.poll_write().is_none(), "one packet in, one packet out");
    out
}

/// pion's `TestReceiverFilterEverythingOut` and `TestSenderFilterEverythingOut`: filters that
/// reject everything leave the output empty, on both legs.
#[test]
fn test_packetdump_receiver_filter_everything_out() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_filter(|_| false)
        .rtcp_filter(|_| false)
        .sink(Box::new(sink.clone()))
        .build();

    read_one(&mut dump, AttributedPacket::new(pli(123, 456)));
    read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(0))));

    assert!(sink.lines().is_empty(), "every packet was filtered out");
}

/// The write leg of `TestReceiverFilterEverythingOut`: pion's `TestSenderFilterEverythingOut`.
#[test]
fn test_packetdump_sender_filter_everything_out() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_filter(|_| false)
        .rtcp_filter(|_| false)
        .sink(Box::new(sink.clone()))
        .build();

    write_one(&mut dump, AttributedPacket::new(pli(123, 456)));
    write_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(0))));

    assert!(sink.lines().is_empty(), "every packet was filtered out");
}

/// pion's `TestReceiverFilterNothing`: with everything accepted, the output is not empty.
#[test]
fn test_packetdump_receiver_filter_nothing() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_filter(|_| true)
        .rtcp_filter(|_| true)
        .sink(Box::new(sink.clone()))
        .build();

    read_one(&mut dump, AttributedPacket::new(pli(123, 456)));
    read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(0))));

    assert!(!sink.lines().is_empty(), "both packets were dumped");
}

/// The write leg of `TestReceiverFilterNothing`: pion's `TestSenderFilterNothing`.
#[test]
fn test_packetdump_sender_filter_nothing() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_filter(|_| true)
        .rtcp_filter(|_| true)
        .sink(Box::new(sink.clone()))
        .build();

    write_one(&mut dump, AttributedPacket::new(pli(123, 456)));
    write_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(0))));

    assert!(!sink.lines().is_empty(), "both packets were dumped");
}

/// pion's `TestReceiverCustomBinaryFormatter` (pion dumps bytes; here the formatter owns the
/// line): a custom RTP formatter writes the sequence number, a custom RTCP formatter the media
/// SSRC of a PLI.
#[test]
fn test_packetdump_receiver_custom_formatter() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_formatter(|p| format!("{}", p.header.sequence_number))
        .rtcp_formatter(|p| {
            let ssrcs = p.destination_ssrc();
            format!("{}", ssrcs.first().copied().unwrap_or_default())
        })
        .sink(Box::new(sink.clone()))
        .build();

    read_one(&mut dump, AttributedPacket::new(pli(123, 45)));
    read_one(
        &mut dump,
        AttributedPacket::new(Packet::Rtp(rtp_packet(123))),
    );

    assert_eq!(sink.lines(), vec!["45".to_owned(), "123".to_owned()]);
}

/// The write leg of `TestReceiverCustomBinaryFormatter`: pion's
/// `TestSenderCustomBinaryFormatter`.
#[test]
fn test_packetdump_sender_custom_formatter() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_formatter(|p| format!("{}", p.header.sequence_number))
        .rtcp_formatter(|p| {
            let ssrcs = p.destination_ssrc();
            format!("{}", ssrcs.first().copied().unwrap_or_default())
        })
        .sink(Box::new(sink.clone()))
        .build();

    write_one(&mut dump, AttributedPacket::new(pli(123, 45)));
    write_one(
        &mut dump,
        AttributedPacket::new(Packet::Rtp(rtp_packet(123))),
    );

    assert_eq!(sink.lines(), vec!["45".to_owned(), "123".to_owned()]);
}

/// pion's `TestReceiverRTCPPerPacketFilter`: the RTCP filter runs once per packet of a compound,
/// so a compound's PLI is dumped while its receiver report is not. pion sends the two packets
/// in separate batches; one compound is the stronger version of the same scenario.
#[test]
fn test_packetdump_receiver_rtcp_per_packet_filter() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtcp_filter(|p| p.header().packet_type == PacketType::PayloadSpecificFeedback)
        .rtcp_formatter(|_| "pli".to_owned())
        .sink(Box::new(sink.clone()))
        .build();

    // A compound holding one PLI and one receiver report, in that order.
    let compound = Packet::Rtcp(vec![
        Box::new(PictureLossIndication {
            sender_ssrc: 123,
            media_ssrc: 456,
        }),
        Box::new(ReceiverReport {
            ssrc: 789,
            ..Default::default()
        }),
    ]);
    read_one(&mut dump, AttributedPacket::new(compound));

    assert_eq!(
        sink.lines(),
        vec!["pli".to_owned()],
        "only the PLI was dumped"
    );
}

/// The write leg of `TestReceiverRTCPPerPacketFilter`: pion's
/// `TestSenderRTCPPerPacketFilter`.
#[test]
fn test_packetdump_sender_rtcp_per_packet_filter() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtcp_filter(|p| p.header().packet_type == PacketType::PayloadSpecificFeedback)
        .rtcp_formatter(|_| "pli".to_owned())
        .sink(Box::new(sink.clone()))
        .build();

    let compound = Packet::Rtcp(vec![
        Box::new(PictureLossIndication {
            sender_ssrc: 123,
            media_ssrc: 456,
        }),
        Box::new(ReceiverReport {
            ssrc: 789,
            ..Default::default()
        }),
    ]);
    write_one(&mut dump, AttributedPacket::new(compound));

    assert_eq!(
        sink.lines(),
        vec!["pli".to_owned()],
        "only the PLI was dumped"
    );
}

/// pion's `TestCustomLogger`: the sink sees exactly what was dumped, one line per packet.
#[test]
fn test_packetdump_custom_sink() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_formatter(|p| format!("seq={}", p.header.sequence_number))
        .rtcp_formatter(|_| "rtcp".to_owned())
        .sink(Box::new(sink.clone()))
        .build();

    let rtp = rtp_packet(7);
    dump.handle_read(tagged(AttributedPacket::new(Packet::Rtp(rtp))))
        .unwrap();
    dump.handle_read(tagged(AttributedPacket::new(pli(1, 2))))
        .unwrap();
    while dump.poll_read().is_some() {}

    assert_eq!(
        sink.lines(),
        vec!["seq=7".to_owned(), "rtcp".to_owned()],
        "the sink saw both packets, in order"
    );
}

/// The issue's (a): forwarded packets are the same packet, in both directions — same RTP bytes,
/// same RTCP contents, same attributes and transport context.
#[test]
fn test_packetdump_forwards_packets_unchanged_in_both_directions() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .sink(Box::new(sink.clone()))
        .build();

    let mut rtp = rtp_packet(42);
    rtp.header.timestamp = 0xdead_beef;
    rtp.payload = vec![1, 2, 3].into();
    let attributes =
        AttributedPacket::new(Packet::Rtp(rtp.clone())).with(Attribute::Retransmission);
    let forwarded = read_one(&mut dump, attributes).expect("the packet came through");

    assert_eq!(forwarded.message.packet, Packet::Rtp(rtp));
    assert!(forwarded.message.has(&Attribute::Retransmission));

    let rtcp = pli(123, 456);
    let forwarded =
        write_one(&mut dump, AttributedPacket::new(rtcp.clone())).expect("the packet came through");
    assert_eq!(forwarded.message.packet, rtcp);

    // Dumping both legs wrote two lines while forwarding both.
    assert_eq!(sink.lines().len(), 2);
}

/// The issue's (b), the sharp edge: a rejected packet is never formatted, so the formatter is
/// not even called.
#[test]
fn test_packetdump_rejected_packets_are_never_formatted() {
    let formatter_calls = Arc::new(Mutex::new(0u32));
    let calls = formatter_calls.clone();
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_filter(|_| false)
        .rtcp_filter(|_| false)
        .rtp_formatter(move |_| {
            *calls.lock().unwrap() += 1;
            String::new()
        })
        .sink(Box::new(sink.clone()))
        .build();

    read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(0))));
    read_one(&mut dump, AttributedPacket::new(pli(1, 2)));

    assert_eq!(
        0,
        *formatter_calls.lock().unwrap(),
        "the formatter never ran"
    );
    assert!(sink.lines().is_empty());
}

/// The issue's (c): a recording sink sees the lines in the order the packets arrived, and a
/// compound's packets in the order they sit in the compound.
#[test]
fn test_packetdump_sink_records_lines_in_order() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_formatter(|p| format!("rtp:{}", p.header.sequence_number))
        .rtcp_formatter(|p| format!("rtcp:{:?}", p.header().packet_type))
        .sink(Box::new(sink.clone()))
        .build();

    let compound = Packet::Rtcp(vec![
        Box::new(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        }),
        Box::new(ReceiverReport {
            ssrc: 3,
            ..Default::default()
        }),
    ]);
    read_one(&mut dump, AttributedPacket::new(compound));
    read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(9))));

    assert_eq!(
        sink.lines(),
        vec![
            "rtcp:PayloadSpecificFeedback".to_owned(),
            "rtcp:ReceiverReport".to_owned(),
            "rtp:9".to_owned(),
        ],
        "the compound's packets first, in order, then the RTP packet"
    );
}

/// The issue's (d): through a `Registry` the dumper sits wire-most, before the congestion
/// controller's send history and everything above it.
#[test]
fn test_packetdump_sits_wire_most_in_the_registry() {
    let registry = crate::Registry::new()
        .with(Slot::PacketDump, PacketDumpBuilder::new().build())
        .with(
            Slot::CongestionControl,
            crate::CongestionControlBuilder::new(crate::ConstantBitrate::new(1_000_000.0)).build(),
        )
        .with(
            Slot::NackGenerator,
            crate::NackGeneratorBuilder::new().build(),
        );

    assert_eq!(
        registry.slots(),
        vec![
            (Slot::PacketDump, "PacketDump".to_owned()),
            (
                Slot::CongestionControl,
                "CongestionControlInterceptor<ConstantBitrate>".to_owned()
            ),
            (Slot::NackGenerator, "NackGeneratorInterceptor".to_owned()),
        ],
        "the dump sees what really goes out and comes in: wire-most of everything"
    );
}

/// A sink that keeps the bytes of `write_bytes` apart from the text lines.
#[derive(Clone, Default)]
struct ByteSink {
    lines: Arc<Mutex<Vec<String>>>,
    bytes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PacketDumpSink for ByteSink {
    fn write(&mut self, line: &str) {
        self.lines.lock().unwrap().push(line.to_owned());
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.lock().unwrap().push(bytes.to_vec());
    }
}

/// pion's `TestReceiverCustomBinaryFormatter` and `TestSenderCustomBinaryFormatter`: a binary
/// formatter's bytes reach the sink as they are, and the default text line is off.
#[test]
fn test_packetdump_binary_formatters_write_raw_bytes() {
    for leg in ["read", "write"] {
        let sink = ByteSink::default();
        let mut dump = PacketDumpBuilder::new()
            .rtp_binary_formatter(|p| Ok(p.marshal()?.to_vec()))
            .rtcp_binary_formatter(|p| Ok(p.marshal()?.to_vec()))
            .sink(Box::new(sink.clone()))
            .build();

        let rtp = rtp_packet(77);
        let want_rtp = rtp.marshal().unwrap().to_vec();
        let want_pli = PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        }
        .marshal()
        .unwrap()
        .to_vec();

        for packet in [Packet::Rtp(rtp), pli(1, 2)] {
            let message = AttributedPacket::new(packet);
            if leg == "read" {
                read_one(&mut dump, message);
            } else {
                write_one(&mut dump, message);
            }
        }

        assert_eq!(
            *sink.bytes.lock().unwrap(),
            vec![want_rtp, want_pli],
            "{leg}"
        );
        assert!(sink.lines.lock().unwrap().is_empty(), "{leg}: no text line");
    }
}

/// A binary formatter that fails skips its packet and the packet still passes through.
#[test]
fn test_packetdump_binary_formatter_error_skips_the_packet() {
    let sink = ByteSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_binary_formatter(|_| Err(Error::ErrBufferShort))
        .sink(Box::new(sink.clone()))
        .build();
    let out = read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(5))));
    assert!(out.is_some(), "forwarded despite the failed format");
    assert!(sink.bytes.lock().unwrap().is_empty());
    assert!(sink.lines.lock().unwrap().is_empty());
}

/// Setting both a text and a binary formatter writes both, binary first, as pion does.
#[test]
fn test_packetdump_text_and_binary_formatters_both_write() {
    let sink = ByteSink::default();
    let mut dump = PacketDumpBuilder::new()
        .rtp_formatter(|_| "text".to_owned())
        .rtp_binary_formatter(|_| Ok(vec![1, 2, 3]))
        .sink(Box::new(sink.clone()))
        .build();
    read_one(&mut dump, AttributedPacket::new(Packet::Rtp(rtp_packet(5))));
    assert_eq!(*sink.bytes.lock().unwrap(), vec![vec![1, 2, 3]]);
    assert_eq!(*sink.lines.lock().unwrap(), vec!["text".to_owned()]);
}

/// pion's `RTCPFilter`: a compound filter decides on the whole compound, before the per-packet
/// filter sees any of it.
#[test]
fn test_packetdump_rtcp_compound_filter_runs_before_per_packet_filter() {
    let sink = RecordingSink::default();
    let mut dump = PacketDumpBuilder::new()
        // Only compounds of exactly two packets.
        .rtcp_compound_filter(|pkts| pkts.len() == 2)
        .rtcp_formatter(|p| format!("{:?}\n", p.header().packet_type))
        .sink(Box::new(sink.clone()))
        .build();

    let pair = || {
        Packet::Rtcp(vec![
            Box::new(PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: 2,
            }),
            Box::new(ReceiverReport {
                ssrc: 3,
                ..Default::default()
            }),
        ])
    };
    read_one(&mut dump, AttributedPacket::new(pli(1, 2)));
    assert!(sink.lines().is_empty(), "a lone PLI is rejected whole");
    read_one(&mut dump, AttributedPacket::new(pair()));
    assert_eq!(
        sink.lines().len(),
        2,
        "both packets of the accepted compound"
    );
}
