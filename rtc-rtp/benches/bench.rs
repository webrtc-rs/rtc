//! RTP packet marshalling, and H.264 packetization.
//!
//! Run with `cargo bench --package rtc-rtp --bench bench`.
//!
//! * `Benchmark MarshalTo`, `Benchmark Marshal`, `Benchmark Unmarshal` — one packet with two
//!   two-byte header extensions and a 15-byte payload, to and from its wire form.
//! * `H264/Payload/<input>` — `H264Payloader::payload` at a 1,200-byte MTU: finding the Annex B
//!   start codes in a frame, then emitting a STAP-A of the SPS and PPS and each slice whole or
//!   as FU-A fragments, which allocates and copies every fragment. Throughput is frame bytes.
//!   - `AccessUnit/<slice bytes>` — SPS, PPS and one IDR slice behind four-byte start codes,
//!     with pseudo-random slice data escaped as an encoder would, so the only start codes are
//!     the real ones. The size is the slice's: 1,200 bytes (sent whole), then 16 KiB and
//!     100 KiB (keyframe sizes, sent as FU-A).
//!   - `Slices/<count>x<bytes>` — SPS, PPS and many small slices behind three-byte start
//!     codes, where per-search overhead counts more than bytes scanned.
//!   - `AllOnes/<bytes>` and `AllZeros/<bytes>` — adversarial frames with no start code,
//!     scanned to the end and then fragmented as one NAL unit. Every byte of `AllOnes` is a
//!     candidate `01` and every byte of `AllZeros` extends a zero run.
//!
//! `next_ind`, the start-code scan, is private, so it is measured only as part of `payload`.
//! The RTP header, sequence numbers and SRTP are left out: `Packetizer` adds those.

// Silence warning on `..Default::default()` with no effect:
#![allow(clippy::needless_update)]

use bytes::{Bytes, BytesMut};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rtc_rtp::codec::h264::H264Payloader;
use rtc_rtp::packetizer::Payloader;
use rtc_rtp::{header::*, packet::*};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::hint::black_box;

fn benchmark_packet(c: &mut Criterion) {
    let pkt = Packet {
        header: Header {
            extension: true,
            csrc: vec![1, 2],
            extension_profile: EXTENSION_PROFILE_TWO_BYTE,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[3, 4]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[5, 6]),
                },
            ],
            ..Default::default()
        },
        payload: Bytes::from_static(&[0xFFu8; 15]), //vec![0x07, 0x08, 0x09, 0x0a], //MTU=1500
        ..Default::default()
    };
    let raw = pkt.marshal().unwrap();
    let buf = &mut raw.clone();
    let p = Packet::unmarshal(buf).unwrap();
    if pkt != p {
        panic!("marshal or unmarshal not correct: \npkt: {pkt:?} \nvs \np: {p:?}");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    let mut buf = BytesMut::with_capacity(pkt.marshal_size());
    buf.resize(pkt.marshal_size(), 0);
    c.bench_function("Benchmark MarshalTo", |b| {
        b.iter(|| {
            let _ = pkt.marshal_to(&mut buf).unwrap();
        })
    });

    c.bench_function("Benchmark Marshal", |b| {
        b.iter(|| {
            let _ = pkt.marshal().unwrap();
        })
    });

    c.bench_function("Benchmark Unmarshal ", |b| {
        b.iter(|| {
            let buf = &mut raw.clone();
            let _ = Packet::unmarshal(buf).unwrap();
        })
    });
}

/// MTU for the H.264 benchmarks, the usual WebRTC video payload budget.
const H264_MTU: usize = 1200;

/// `len` bytes of pseudo-random slice data with emulation prevention applied: a `03` is inserted
/// after any `00 00` that would otherwise be followed by `00`–`03`, as an encoder must, so the
/// data never contains a start code. It ends in a non-zero byte, as the RBSP stop bit ensures.
fn slice_data(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut data = Vec::with_capacity(len + len / 64);
    let mut zeros = 0;
    while data.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // Zeros more often than chance, so escapes actually occur.
        let byte = if state.is_multiple_of(16) {
            0
        } else {
            (state >> 32) as u8
        };
        if zeros >= 2 && byte <= 3 {
            data.push(3);
            zeros = 0;
        }
        data.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    data.truncate(len);
    if let Some(last) = data.last_mut() {
        *last = 0x80;
    }
    data
}

/// SPS and PPS behind four-byte start codes.
fn parameter_sets() -> Vec<u8> {
    let sps = [
        0x67, 0x42, 0xc0, 0x1f, 0xda, 0x01, 0x40, 0x16, 0xec, 0x04, 0x40,
    ];
    let pps = [0x68, 0xce, 0x3c, 0x80];
    let mut au = Vec::new();
    for nalu in [&sps[..], &pps[..]] {
        au.extend_from_slice(&[0, 0, 0, 1]);
        au.extend_from_slice(nalu);
    }
    au
}

/// An Annex B access unit: SPS, PPS and an IDR slice of `slice_len` bytes (header included).
fn access_unit(slice_len: usize) -> Bytes {
    let mut au = parameter_sets();
    au.extend_from_slice(&[0, 0, 0, 1, 0x65]);
    au.extend_from_slice(&slice_data(slice_len - 1, slice_len as u64));
    Bytes::from(au)
}

/// SPS, PPS and `count` non-IDR slices of `slice_len` bytes each, behind three-byte start codes.
fn many_slices(count: usize, slice_len: usize) -> Bytes {
    let mut au = parameter_sets();
    for i in 0..count {
        au.extend_from_slice(&[0, 0, 1, 0x41]);
        au.extend_from_slice(&slice_data(slice_len - 1, i as u64));
    }
    Bytes::from(au)
}

fn benchmark_h264_payload(c: &mut Criterion) {
    let inputs = [
        ("AccessUnit/1200", access_unit(1200)),
        ("AccessUnit/16384", access_unit(16 * 1024)),
        ("AccessUnit/102400", access_unit(100 * 1024)),
        ("Slices/16x150", many_slices(16, 150)),
        ("AllOnes/16384", Bytes::from(vec![1u8; 16 * 1024])),
        ("AllZeros/16384", Bytes::from(vec![0u8; 16 * 1024])),
    ];

    let mut g = c.benchmark_group("H264/Payload");
    for (name, frame) in &inputs {
        let mut payloader = H264Payloader::default();
        let payloads = payloader.payload(H264_MTU, frame).unwrap();
        assert!(!payloads.is_empty() && payloads.iter().all(|p| p.len() <= H264_MTU));

        g.throughput(Throughput::Bytes(frame.len() as u64));
        g.bench_function(*name, |b| {
            // The SPS and PPS a frame caches are consumed by its own slice, so every call starts
            // from the same state.
            b.iter(|| black_box(payloader.payload(H264_MTU, black_box(frame)).unwrap()))
        });
    }
    g.finish();
}

criterion_group!(benches, benchmark_packet, benchmark_h264_payload);
criterion_main!(benches);
