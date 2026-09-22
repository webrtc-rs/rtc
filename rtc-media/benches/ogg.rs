//! Ogg page cost: writing a page, and reading one back with and without checksum verification.
//!
//! Run with `cargo bench --package rtc-media --bench ogg`.
//!
//! Every page carries a CRC-32 over the whole page, so recording (`OggWriter::write_rtp`) and
//! verified playback (`OggReader::parse_next_page` with `do_checksum`) scan every payload byte
//! once for the checksum on top of assembling or parsing the page. This measures those whole-page
//! operations, not the CRC kernel on its own, so a checksum change shows up in proportion to what
//! it costs next to page assembly, allocation and copying:
//!
//! * `Write/<payload>` — one RTP packet in, one page out, written to `io::sink`. Includes the
//!   Opus depacketization, the page buffer allocation and the segment table.
//! * `Read/checksum/<payload>` and `Read/no-checksum/<payload>` — one page parsed from memory.
//!   The difference between the two is what verification costs.
//!
//! Payloads cover an Opus frame at a typical voice bitrate (80 bytes), a larger one (1,200 bytes),
//! and multi-frame and maximum-size pages (8,192 and 65,025 bytes — 255 segments of 255). File
//! I/O is excluded: the reader reads from a `Cursor` and the writer to a sink.
//!
//! What it deliberately does not cover: the Opus header pages written once per file, and
//! `OggReader::new`, which parses them.

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rtc_media::io::Writer;
use rtc_media::io::ogg_reader::OggReader;
use rtc_media::io::ogg_writer::OggWriter;
use std::hint::black_box;
use std::io::Cursor;

const PAYLOAD_SIZES: [usize; 4] = [80, 1200, 8192, 65_025];

/// Pages per prepared file for the read benchmarks: enough that recreating the reader at the end
/// of the file costs well under 1% of a page, bounded at a few MiB for the largest page.
fn pages_for(payload_len: usize) -> usize {
    (4 << 20) / payload_len.max(4096)
}

fn packet(sequence_number: u16, payload_len: usize) -> rtp::Packet {
    let payload: Vec<u8> = (0..payload_len)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 7) as u8)
        .collect();
    rtp::Packet {
        header: rtp::header::Header {
            sequence_number,
            timestamp: 960 * sequence_number as u32,
            ..Default::default()
        },
        payload: Bytes::from(payload),
    }
}

/// An Ogg file: the OpusHead and OpusTags pages, then `pages` audio pages each carrying one
/// `payload_len`-byte packet.
fn prepared_file(payload_len: usize, pages: usize) -> Vec<u8> {
    let mut file = Vec::new();
    {
        let mut writer = OggWriter::new(&mut file, 48_000, 2).unwrap();
        for sequence_number in 0..pages {
            writer
                .write_rtp(&packet(sequence_number as u16, payload_len))
                .unwrap();
        }
    }
    file
}

fn benchmark_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ogg/Write");
    for payload_len in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(payload_len as u64));
        let packet = packet(1, payload_len);
        let mut writer = OggWriter::new(std::io::sink(), 48_000, 2).unwrap();
        group.bench_function(format!("{payload_len}B"), |b| {
            b.iter(|| writer.write_rtp(black_box(&packet)).unwrap())
        });
    }
    group.finish();
}

fn benchmark_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ogg/Read");
    for payload_len in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(payload_len as u64));
        let pages = pages_for(payload_len);
        let file = prepared_file(payload_len, pages);
        for (label, do_checksum) in [("checksum", true), ("no-checksum", false)] {
            // A reader positioned at the first audio page, past OpusHead and OpusTags.
            let fresh_reader = || {
                let mut reader = OggReader::new_with_options(Cursor::new(&file[..]), do_checksum);
                reader.parse_next_page().unwrap();
                reader.parse_next_page().unwrap();
                reader
            };
            let mut reader = fresh_reader();
            let mut remaining = pages;
            group.bench_function(format!("{label}/{payload_len}B"), |b| {
                b.iter(|| {
                    if remaining == 0 {
                        reader = fresh_reader();
                        remaining = pages;
                    }
                    remaining -= 1;
                    black_box(reader.parse_next_page().unwrap())
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, benchmark_write, benchmark_read);
criterion_main!(benches);
