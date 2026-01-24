// Silence warning on `..Default::default()` with no effect:
#![allow(clippy::needless_update)]

use bytes::{Bytes, BytesMut};
use criterion::{Criterion, criterion_group, criterion_main};
use rtc_rtcp::{
    goodbye::Goodbye,
    payload_feedbacks::picture_loss_indication::PictureLossIndication,
    receiver_report::ReceiverReport,
    reception_report::ReceptionReport,
    sender_report::SenderReport,
    source_description::{SdesType, SourceDescription},
    transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack},
};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

fn benchmark_sender_report(c: &mut Criterion) {
    let sr = SenderReport {
        ssrc: 0x902f9e2e,
        ntp_time: 0xda8bd1fcdddda05a,
        rtp_time: 0xaaf4edd5,
        packet_count: 1000,
        octet_count: 50000,
        reports: vec![
            ReceptionReport {
                ssrc: 0xbc5e9a40,
                fraction_lost: 10,
                total_lost: 100,
                last_sequence_number: 0x46e1,
                jitter: 273,
                last_sender_report: 0x9f36432,
                delay: 150137,
            },
            ReceptionReport {
                ssrc: 0xbc5e9a41,
                fraction_lost: 5,
                total_lost: 50,
                last_sequence_number: 0x46e2,
                jitter: 150,
                last_sender_report: 0x9f36433,
                delay: 150138,
            },
        ],
        profile_extensions: Bytes::new(),
    };

    let raw = sr.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = SenderReport::unmarshal(buf).unwrap();
    if sr != p {
        panic!("marshal or unmarshal not correct: \nsr: {sr:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(sr.marshal_size());
    buf.resize(sr.marshal_size(), 0);
    c.bench_function("SenderReport MarshalTo", |b| {
        b.iter(|| {
            let _ = sr.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("SenderReport Marshal", |b| {
        b.iter(|| {
            let _ = sr.marshal().unwrap();
        })
    });

    c.bench_function("SenderReport Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = SenderReport::unmarshal(buf).unwrap();
        })
    });
}

fn benchmark_receiver_report(c: &mut Criterion) {
    let rr = ReceiverReport {
        ssrc: 0x902f9e2e,
        reports: vec![
            ReceptionReport {
                ssrc: 0xbc5e9a40,
                fraction_lost: 10,
                total_lost: 100,
                last_sequence_number: 0x46e1,
                jitter: 273,
                last_sender_report: 0x9f36432,
                delay: 150137,
            },
            ReceptionReport {
                ssrc: 0xbc5e9a41,
                fraction_lost: 5,
                total_lost: 50,
                last_sequence_number: 0x46e2,
                jitter: 150,
                last_sender_report: 0x9f36433,
                delay: 150138,
            },
        ],
        profile_extensions: Bytes::new(),
    };

    let raw = rr.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = ReceiverReport::unmarshal(buf).unwrap();
    if rr != p {
        panic!("marshal or unmarshal not correct: \nrr: {rr:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(rr.marshal_size());
    buf.resize(rr.marshal_size(), 0);
    c.bench_function("ReceiverReport MarshalTo", |b| {
        b.iter(|| {
            let _ = rr.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("ReceiverReport Marshal", |b| {
        b.iter(|| {
            let _ = rr.marshal().unwrap();
        })
    });

    c.bench_function("ReceiverReport Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = ReceiverReport::unmarshal(buf).unwrap();
        })
    });
}

fn benchmark_picture_loss_indication(c: &mut Criterion) {
    let pli = PictureLossIndication {
        sender_ssrc: 0x902f9e2e,
        media_ssrc: 0xbc5e9a40,
    };

    let raw = pli.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = PictureLossIndication::unmarshal(buf).unwrap();
    if pli != p {
        panic!("marshal or unmarshal not correct: \npli: {pli:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(pli.marshal_size());
    buf.resize(pli.marshal_size(), 0);
    c.bench_function("PictureLossIndication MarshalTo", |b| {
        b.iter(|| {
            let _ = pli.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("PictureLossIndication Marshal", |b| {
        b.iter(|| {
            let _ = pli.marshal().unwrap();
        })
    });

    c.bench_function("PictureLossIndication Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = PictureLossIndication::unmarshal(buf).unwrap();
        })
    });
}

fn benchmark_transport_layer_nack(c: &mut Criterion) {
    let nack = TransportLayerNack {
        sender_ssrc: 0x902f9e2e,
        media_ssrc: 0xbc5e9a40,
        nacks: vec![
            NackPair {
                packet_id: 1000,
                lost_packets: 0b0101010101010101,
            },
            NackPair {
                packet_id: 2000,
                lost_packets: 0b1010101010101010,
            },
            NackPair {
                packet_id: 3000,
                lost_packets: 0b1111000011110000,
            },
        ],
    };

    let raw = nack.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = TransportLayerNack::unmarshal(buf).unwrap();
    if nack != p {
        panic!("marshal or unmarshal not correct: \nnack: {nack:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(nack.marshal_size());
    buf.resize(nack.marshal_size(), 0);
    c.bench_function("TransportLayerNack MarshalTo", |b| {
        b.iter(|| {
            let _ = nack.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("TransportLayerNack Marshal", |b| {
        b.iter(|| {
            let _ = nack.marshal().unwrap();
        })
    });

    c.bench_function("TransportLayerNack Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = TransportLayerNack::unmarshal(buf).unwrap();
        })
    });
}

fn benchmark_goodbye(c: &mut Criterion) {
    let goodbye = Goodbye {
        sources: vec![0x902f9e2e, 0xbc5e9a40, 0x12345678],
        reason: Bytes::from_static(b"Session ended"),
    };

    let raw = goodbye.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = Goodbye::unmarshal(buf).unwrap();
    if goodbye != p {
        panic!("marshal or unmarshal not correct: \ngoodbye: {goodbye:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(goodbye.marshal_size());
    buf.resize(goodbye.marshal_size(), 0);
    c.bench_function("Goodbye MarshalTo", |b| {
        b.iter(|| {
            let _ = goodbye.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("Goodbye Marshal", |b| {
        b.iter(|| {
            let _ = goodbye.marshal().unwrap();
        })
    });

    c.bench_function("Goodbye Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = Goodbye::unmarshal(buf).unwrap();
        })
    });
}

fn benchmark_source_description(c: &mut Criterion) {
    let sdes = SourceDescription {
        chunks: vec![
            rtc_rtcp::source_description::SourceDescriptionChunk {
                source: 0x902f9e2e,
                items: vec![
                    rtc_rtcp::source_description::SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: Bytes::from_static(b"user@example.com"),
                    },
                    rtc_rtcp::source_description::SourceDescriptionItem {
                        sdes_type: SdesType::SdesName,
                        text: Bytes::from_static(b"John Doe"),
                    },
                ],
            },
            rtc_rtcp::source_description::SourceDescriptionChunk {
                source: 0xbc5e9a40,
                items: vec![rtc_rtcp::source_description::SourceDescriptionItem {
                    sdes_type: SdesType::SdesCname,
                    text: Bytes::from_static(b"peer@example.com"),
                }],
            },
        ],
    };

    let raw = sdes.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = SourceDescription::unmarshal(buf).unwrap();
    if sdes != p {
        panic!("marshal or unmarshal not correct: \nsdes: {sdes:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(sdes.marshal_size());
    buf.resize(sdes.marshal_size(), 0);
    c.bench_function("SourceDescription MarshalTo", |b| {
        b.iter(|| {
            let _ = sdes.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("SourceDescription Marshal", |b| {
        b.iter(|| {
            let _ = sdes.marshal().unwrap();
        })
    });

    c.bench_function("SourceDescription Unmarshal", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = SourceDescription::unmarshal(buf).unwrap();
        })
    });
}

criterion_group!(
    benches,
    benchmark_sender_report,
    benchmark_receiver_report,
    benchmark_picture_loss_indication,
    benchmark_transport_layer_nack,
    benchmark_goodbye,
    benchmark_source_description
);
criterion_main!(benches);
