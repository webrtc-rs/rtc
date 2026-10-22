//! Ports of pion/rtcp's `*MaxLength` tests: every packet type must handle the largest packet an
//! RTCP length field can describe (0xFFFF words, 256 KiB) — decoding it without error or
//! truncation, and, for the types with variable-size bodies, encoding it back to the same bytes.

use bytes::Bytes;
use rtc_rtcp::application_defined::ApplicationDefined;
use rtc_rtcp::goodbye::Goodbye;
use rtc_rtcp::header::COUNT_MAX;
use rtc_rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc_rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
use rtc_rtcp::raw_packet::RawPacket;
use rtc_rtcp::receiver_report::ReceiverReport;
use rtc_rtcp::reception_report::ReceptionReport;
use rtc_rtcp::sender_report::SenderReport;
use rtc_rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtc_rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtc_rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// The biggest packet a 16-bit word-count length allows.
const MAX_PACKET: usize = 4 * (0xFFFF + 1);
const HEADER_LEN: usize = 4;

/// A maximal, otherwise-empty packet with the given first two bytes and the length field full.
fn max_packet(b0: u8, pt: u8) -> Bytes {
    let mut raw = vec![0u8; MAX_PACKET];
    raw[0] = b0;
    raw[1] = pt;
    raw[2] = 0xff;
    raw[3] = 0xff;
    Bytes::from(raw)
}

#[test]
fn sender_report_round_trip_max_length() {
    let mut report = SenderReport {
        ssrc: 1,
        ntp_time: 2,
        rtp_time: 3,
        packet_count: 4,
        octet_count: 5,
        reports: (0..COUNT_MAX)
            .map(|i| ReceptionReport {
                ssrc: i as u32 + 1,
                ..Default::default()
            })
            .collect(),
        profile_extensions: Bytes::new(),
    };
    let base = report.marshal_size();
    report.profile_extensions = Bytes::from(vec![0xab; MAX_PACKET - base]);

    let data = report.marshal().unwrap();
    assert_eq!(data.len(), MAX_PACKET);
    let decoded = SenderReport::unmarshal(&mut data.freeze()).unwrap();
    assert_eq!(decoded, report);
}

#[test]
fn receiver_report_unmarshal_max_length() {
    let mut raw = max_packet(0x80 | COUNT_MAX as u8, 0xc9);
    let rr = ReceiverReport::unmarshal(&mut raw).unwrap();
    assert_eq!(rr.reports.len(), COUNT_MAX);
    assert_eq!(rr.profile_extensions.len(), MAX_PACKET - 8 - COUNT_MAX * 24);
}

#[test]
fn goodbye_round_trip_max_field_sizes() {
    let bye = Goodbye {
        sources: (0..COUNT_MAX as u32).map(|i| i + 1).collect(),
        reason: Bytes::from(vec![b'x'; 255]),
    };
    let data = bye.marshal().unwrap();
    assert_eq!(data.len(), bye.marshal_size());
    let decoded = Goodbye::unmarshal(&mut data.freeze()).unwrap();
    assert_eq!(decoded, bye);
}

#[test]
fn source_description_round_trip_max_length() {
    const SDES_MAX_OCTET_COUNT: usize = 255;
    const TYPE_LEN: usize = 1;
    const OCTET_COUNT_LEN: usize = 1;
    const SOURCE_LEN: usize = 4;
    let remaining = MAX_PACKET - HEADER_LEN - SOURCE_LEN - TYPE_LEN;
    let full_item = TYPE_LEN + OCTET_COUNT_LEN + SDES_MAX_OCTET_COUNT;
    let (full_count, last) = (remaining / full_item, remaining % full_item);

    let mut items: Vec<SourceDescriptionItem> = (0..full_count)
        .map(|_| SourceDescriptionItem {
            sdes_type: SdesType::SdesNote,
            text: Bytes::from(vec![b'x'; SDES_MAX_OCTET_COUNT]),
        })
        .collect();
    if last > 0 {
        items.push(SourceDescriptionItem {
            sdes_type: SdesType::SdesNote,
            text: Bytes::from(vec![b'y'; last - TYPE_LEN - OCTET_COUNT_LEN]),
        });
    }
    let desc = SourceDescription {
        chunks: vec![SourceDescriptionChunk { source: 1, items }],
    };

    let data = desc.marshal().unwrap();
    assert_eq!(data.len(), MAX_PACKET);
    let decoded = SourceDescription::unmarshal(&mut data.freeze()).unwrap();
    assert_eq!(decoded, desc);
}

#[test]
fn transport_layer_nack_unmarshal_max_length() {
    let mut raw = max_packet(0x81, 0xcd);
    let nack = TransportLayerNack::unmarshal(&mut raw).unwrap();
    // Length 0xFFFF words less the 2 words of SSRCs.
    assert_eq!(nack.nacks.len(), 0xFFFF - 2);
}

#[test]
fn transport_layer_cc_unmarshal_max_length() {
    let mut raw = max_packet(0x8f, 0xcd);
    let cc = TransportLayerCc::unmarshal(&mut raw).unwrap();
    assert_eq!(cc.packet_status_count, 0);
}

#[test]
fn slice_loss_indication_unmarshal_max_length() {
    let mut raw = max_packet(0x82, 0xce);
    let sli = SliceLossIndication::unmarshal(&mut raw).unwrap();
    assert_eq!(sli.sli_entries.len(), 0xFFFF - 2);
}

#[test]
fn full_intra_request_unmarshal_max_length() {
    let mut raw = vec![0u8; HEADER_LEN + 4 * 0xFFFE];
    raw[0] = 0x84;
    raw[1] = 0xce;
    raw[2] = 0xff;
    raw[3] = 0xfe;
    let fir = FullIntraRequest::unmarshal(&mut Bytes::from(raw)).unwrap();
    // The body is the two SSRCs, then 8-byte entries.
    assert_eq!(fir.fir.len(), (4 * 0xFFFE - 8) / 8);
}

#[test]
fn application_defined_unmarshal_max_length() {
    let mut raw = max_packet(0x80, 0xcc).to_vec();
    raw[8..12].copy_from_slice(b"NAME");
    let app = ApplicationDefined::unmarshal(&mut Bytes::from(raw)).unwrap();
    assert_eq!(&app.name, b"NAME");
    assert_eq!(app.data.len(), MAX_PACKET - 12);
}

#[test]
fn unmarshal_max_length_raw_packet() {
    let raw = max_packet(0x80, 0xfa);
    let packets = rtc_rtcp::packet::unmarshal(&mut raw.clone()).unwrap();
    assert_eq!(packets.len(), 1);
    let parsed = packets[0]
        .as_any()
        .downcast_ref::<RawPacket>()
        .expect("an unknown packet type is kept raw");
    assert_eq!(&parsed.0[..], &raw[..]);
}
