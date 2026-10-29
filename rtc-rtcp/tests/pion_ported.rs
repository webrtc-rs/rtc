//! Ports of pion/rtcp tests whose subject is encoder/decoder behaviour at its limits rather than
//! a particular byte string (those are replayed by `pion_golden.rs`).

use bytes::Bytes;
use rtc_rtcp::compound_packet::CompoundPacket;
use rtc_rtcp::header::{COUNT_MAX, Header, PacketType};
use rtc_rtcp::packet::unmarshal;
use rtc_rtcp::receiver_report::ReceiverReport;
use rtc_rtcp::reception_report::ReceptionReport;
use rtc_rtcp::sender_report::SenderReport;
use rtc_rtcp::source_description::SourceDescription;
use rtc_rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, StatusVectorChunk,
    SymbolSizeTypeTcc, SymbolTypeTcc, TransportLayerCc,
};
use rtc_rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtc_rtcp::{Packet, goodbye::Goodbye};
use shared::error::Error;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// pion `TestUnmarshalNil`
#[test]
fn unmarshal_empty_buffer_is_an_error() {
    assert!(unmarshal(&mut Bytes::new()).is_err());
}

/// pion `TestHeaderRoundTrip`
#[test]
fn header_round_trip() {
    for header in [
        Header {
            padding: true,
            count: 31,
            packet_type: PacketType::SenderReport,
            length: 4,
        },
        Header {
            padding: false,
            count: 28,
            packet_type: PacketType::ReceiverReport,
            length: 65535,
        },
    ] {
        let mut data = header.marshal().unwrap().freeze();
        assert_eq!(Header::unmarshal(&mut data).unwrap(), header);
    }
    let invalid = Header {
        count: 40,
        ..Default::default()
    };
    assert_eq!(invalid.marshal().unwrap_err(), Error::InvalidHeader);
}

/// pion `TestReportProfileExtensionsRoundTrip`: profile-specific extensions of any length are
/// padded to a word boundary on the wire, and the length field accounts for the padding.
///
/// Intended divergence: pion pads with zero bytes and no P bit; this crate sets the P bit and
/// ends the padding with its count (RFC 3550 §6.4.1), which pion reads back as opaque extension
/// bytes. The lengths and the leading extension bytes agree.
#[test]
fn report_profile_extensions_round_trip() {
    fn extensions(p: &dyn Packet) -> Bytes {
        p.as_any()
            .downcast_ref::<SenderReport>()
            .map(|x| x.profile_extensions.clone())
            .or_else(|| {
                p.as_any()
                    .downcast_ref::<ReceiverReport>()
                    .map(|x| x.profile_extensions.clone())
            })
            .unwrap()
    }
    for ext_len in [1usize, 4, 5, 8, 24] {
        let ext = Bytes::from(vec![0xab; ext_len]);
        let reports = vec![ReceptionReport {
            ssrc: 2,
            ..Default::default()
        }];
        let rr = ReceiverReport {
            ssrc: 1,
            reports: reports.clone(),
            profile_extensions: ext.clone(),
        };
        let sr = SenderReport {
            ssrc: 1,
            reports,
            profile_extensions: ext.clone(),
            ..Default::default()
        };
        for packet in [&rr as &dyn Packet, &sr as &dyn Packet] {
            let data = packet.marshal().unwrap();
            assert_eq!(data.len(), packet.marshal_size(), "ext {ext_len}");
            assert_eq!(
                packet.header().length as usize,
                data.len() / 4 - 1,
                "header length, ext {ext_len}"
            );
            let got = unmarshal(&mut data.freeze()).unwrap();
            assert_eq!(got.len(), 1);
            let got = extensions(got[0].as_ref());
            assert_eq!(got.len(), ext_len.div_ceil(4) * 4, "ext {ext_len}");
            assert_eq!(&got[..ext_len], &ext[..], "ext {ext_len}");
        }
    }
}

/// pion `TestCompoundPacketRoundTrip`
#[test]
fn compound_packet_round_trip() {
    let cname = SourceDescription::default();
    let _ = cname;
    let with_cname = CompoundPacket(vec![
        Box::new(ReceiverReport::default()),
        Box::new(rtc_rtcp::source_description::SourceDescription {
            chunks: vec![rtc_rtcp::source_description::SourceDescriptionChunk {
                source: 1234,
                items: vec![rtc_rtcp::source_description::SourceDescriptionItem {
                    sdes_type: rtc_rtcp::source_description::SdesType::SdesCname,
                    text: Bytes::from_static(b"cname"),
                }],
            }],
        }),
        Box::new(Goodbye {
            sources: vec![1234],
            ..Default::default()
        }),
    ]);
    let data = with_cname.marshal().unwrap();
    let decoded = CompoundPacket::unmarshal(&mut data.clone().freeze()).unwrap();
    assert_eq!(decoded.marshal().unwrap(), data);

    let no_cname = CompoundPacket(vec![Box::new(ReceiverReport::default())]);
    assert_eq!(no_cname.marshal().unwrap_err(), Error::MissingCname);
}

fn two_bit_vector(symbols: &[SymbolTypeTcc]) -> PacketStatusChunk {
    PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
        type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
        symbol_size: SymbolSizeTypeTcc::TwoBit,
        symbol_list: symbols.to_vec(),
    })
}

/// pion `TestTransportLayerCC_MarshalInvalidDelta`: a delta that does not fit its symbol size
/// is an error, never a silently wrapped value.
#[test]
fn transport_layer_cc_rejects_deltas_outside_their_symbol_size() {
    for (name, symbol, delta) in [
        (
            "small negative",
            SymbolTypeTcc::PacketReceivedSmallDelta,
            -250,
        ),
        (
            "small overflow",
            SymbolTypeTcc::PacketReceivedSmallDelta,
            256 * 250,
        ),
        (
            "large underflow",
            SymbolTypeTcc::PacketReceivedLargeDelta,
            -32769 * 250,
        ),
        (
            "large overflow",
            SymbolTypeTcc::PacketReceivedLargeDelta,
            32768 * 250,
        ),
    ] {
        let packet = TransportLayerCc {
            packet_status_count: 2,
            packet_chunks: vec![two_bit_vector(&[
                SymbolTypeTcc::PacketReceivedSmallDelta,
                symbol,
            ])],
            recv_deltas: vec![
                RecvDelta {
                    type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                    delta: 250,
                },
                RecvDelta {
                    type_tcc_packet: symbol,
                    delta,
                },
            ],
            ..Default::default()
        };
        assert!(packet.marshal().is_err(), "{name}");
    }
}

/// pion `TestTransportLayerCC_LengthOverflow`: the largest feedback that fits the 16-bit length
/// field round-trips; one that does not fit is refused rather than written with a short header.
#[test]
fn transport_layer_cc_length_overflow() {
    let mut packet = TransportLayerCc {
        packet_status_count: 32761,
        ..Default::default()
    };
    let mut remaining = packet.packet_status_count;
    while remaining > 0 {
        let count = remaining.min(8191);
        packet
            .packet_chunks
            .push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: SymbolTypeTcc::PacketReceivedLargeDelta,
                run_length: count,
            }));
        remaining -= count;
    }
    packet.recv_deltas = (0..packet.packet_status_count)
        .map(|_| RecvDelta {
            type_tcc_packet: SymbolTypeTcc::PacketReceivedLargeDelta,
            delta: -250,
        })
        .collect();

    assert_eq!(packet.marshal_size(), 65552);
    let data = packet.marshal().unwrap();
    assert_eq!(data.len(), 65552);
    let decoded = TransportLayerCc::unmarshal(&mut data.freeze()).unwrap();
    assert_eq!(decoded.packet_status_count, packet.packet_status_count);
    assert_eq!(decoded.recv_deltas, packet.recv_deltas);

    packet.packet_chunks = (0..(1usize << 18) / 2)
        .map(|_| two_bit_vector(&[]))
        .collect();
    assert_eq!(packet.marshal().unwrap_err(), Error::BadLength);
}

/// A NACK may list as many lost-packet pairs as the 16-bit length field allows, and no more.
#[test]
fn transport_layer_nack_lists_hundreds_of_pairs() {
    let nack = |n: usize| TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: 2,
        nacks: (0..n)
            .map(|i| NackPair {
                packet_id: i as u16,
                lost_packets: Default::default(),
            })
            .collect(),
    };
    for n in [1, 253, 254, 1000, 0xFFFF - 2] {
        let data = nack(n).marshal().unwrap();
        let got = TransportLayerNack::unmarshal(&mut data.freeze()).unwrap();
        assert_eq!(got.nacks.len(), n);
    }
    assert_eq!(nack(0xFFFF - 1).marshal().unwrap_err(), Error::BadLength);
}

#[test]
fn reports_with_the_maximum_reception_blocks_round_trip() {
    let rr = ReceiverReport {
        ssrc: 7,
        reports: (0..COUNT_MAX as u32)
            .map(|ssrc| ReceptionReport {
                ssrc,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let data = rr.marshal().unwrap();
    assert_eq!(ReceiverReport::unmarshal(&mut data.freeze()).unwrap(), rr);
}
