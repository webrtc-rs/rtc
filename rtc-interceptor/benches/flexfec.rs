//! FlexFEC draft-03 encode and recovery benchmarks.
//!
//! Media is shaped like a video stream: payloads of 1,100–1,199 bytes (unequal, so the repair
//! payload is longer than most of what it protects) behind a one-byte header extension carrying
//! abs-send-time and a transport-wide sequence number, which the recovery representation covers
//! along with the payload.
//!
//! * `Encode/<media>x<repair>` is one `FlexFec03Encoder::encode` call over a block of `media`
//!   packets asking for `repair` repair packets, on an encoder that has seen the block shape
//!   before (a steady sender's case: the coverage is already computed). It covers serialising the
//!   protected packets, XORing them together and building the repair headers. Throughput is the
//!   serialised media protected per call.
//! * `Recover/<media>x<repair>` is a fresh `FlexFec03Decoder` fed every media packet of one block
//!   but the middle one, then the block's repair packets, until the lost packet is rebuilt. It
//!   covers the decoder's bookkeeping (holding media, matching repair packets to it) as well as
//!   the recovery XOR, because a receiver pays both. Packet clones are made outside the timed
//!   region. Throughput is the serialised size of everything fed to the decoder.
//! * `RecoverRepair/<media>x<repair>` isolates the second half of that: the media has already
//!   been fed (untimed), and only the repair packets — including the one that rebuilds the loss —
//!   are timed.
//!
//! Deliberately not measured: the send and receive interceptors around the encoder and decoder,
//! packetisation, SRTP, multi-loss cascades, and the XOR kernel on its own — that is an internal
//! helper, pinned to a byte-wise reference by unit tests in `flexfec::xor` rather than exposed for
//! a benchmark.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-interceptor --bench flexfec
//! ```

use bytes::Bytes;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rtc_interceptor::{FlexFec03Decoder, FlexFec03Encoder};
use shared::marshal::MarshalSize;

const MEDIA_SSRC: u32 = 0x1B63_FA42;
const REPAIR_SSRC: u32 = 0x33B6_9A2A;
const REPAIR_PT: u8 = 49;

/// `(media packets, repair packets)` per block: a short block with light and heavy protection,
/// and a long one — the longer block needs the second packet mask and a much larger coverage.
const SHAPES: &[(u16, u32)] = &[(10, 2), (10, 5), (48, 2), (48, 10)];

/// One block of consecutive media packets with unequal payload lengths and a header extension.
fn media_block(count: u16) -> Vec<rtp::Packet> {
    (0..count)
        .map(|index| {
            let sequence_number = 1000u16.wrapping_add(index);
            // 1,100–1,199 bytes, deterministically scrambled so neighbours differ in length.
            let length = 1100 + (usize::from(index) * 37) % 100;
            let payload: Vec<u8> = (0..length)
                .map(|offset| (offset as u8).wrapping_mul(31) ^ index as u8)
                .collect();
            let mut header = rtp::header::Header {
                version: 2,
                marker: index + 1 == count,
                payload_type: 96,
                sequence_number,
                timestamp: 90_000,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            };
            header.extension = true;
            header.extension_profile = 0xBEDE;
            header
                .set_extension(3, Bytes::from_static(&[0x12, 0x34, 0x56]))
                .expect("abs-send-time");
            header
                .set_extension(5, Bytes::copy_from_slice(&sequence_number.to_be_bytes()))
                .expect("transport-wide sequence number");
            rtp::Packet {
                header,
                payload: payload.into(),
            }
        })
        .collect()
}

fn wire_size(packets: &[rtp::Packet]) -> u64 {
    packets
        .iter()
        .map(|packet| packet.marshal_size() as u64)
        .sum()
}

fn benchmark_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("FlexFec");
    for &(num_media, num_fec) in SHAPES {
        let media = media_block(num_media);
        let mut encoder = FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC);
        assert_eq!(
            num_fec as usize,
            encoder.encode(&media, num_fec).len(),
            "every repair packet is emitted"
        );

        group.throughput(Throughput::Bytes(wire_size(&media)));
        group.bench_function(format!("Encode/{num_media}x{num_fec}"), |b| {
            b.iter(|| encoder.encode(&media, num_fec));
        });
    }
    group.finish();
}

fn benchmark_recover(c: &mut Criterion) {
    let mut group = c.benchmark_group("FlexFec");
    for &(num_media, num_fec) in SHAPES {
        let media = media_block(num_media);
        let repair = FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC).encode(&media, num_fec);
        let lost = usize::from(num_media / 2);
        let received: Vec<rtp::Packet> = media
            .iter()
            .enumerate()
            .filter(|&(index, _)| index != lost)
            .map(|(_, packet)| packet.clone())
            .collect();

        // Validated once, outside the timed region: the loss comes back, byte for byte.
        let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
        let mut recovered = Vec::new();
        for packet in received.iter().chain(&repair) {
            recovered.extend(decoder.decode(packet.clone()));
        }
        assert_eq!(
            vec![media[lost].clone()],
            recovered,
            "the loss is recovered"
        );

        group.throughput(Throughput::Bytes(wire_size(&received) + wire_size(&repair)));
        group.bench_function(format!("Recover/{num_media}x{num_fec}"), |b| {
            b.iter_batched(
                || received.iter().chain(&repair).cloned().collect::<Vec<_>>(),
                |packets| {
                    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
                    let mut recovered = Vec::new();
                    for packet in packets {
                        recovered.extend(decoder.decode(packet));
                    }
                    (decoder, recovered)
                },
                BatchSize::SmallInput,
            );
        });

        group.throughput(Throughput::Bytes(wire_size(&repair)));
        group.bench_function(format!("RecoverRepair/{num_media}x{num_fec}"), |b| {
            b.iter_batched(
                || {
                    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
                    for packet in &received {
                        decoder.decode(packet.clone());
                    }
                    (decoder, repair.clone())
                },
                |(mut decoder, repair)| {
                    let mut recovered = Vec::new();
                    for packet in repair {
                        recovered.extend(decoder.decode(packet));
                    }
                    (decoder, recovered)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(group, benchmark_encode, benchmark_recover);
criterion_main!(group);
