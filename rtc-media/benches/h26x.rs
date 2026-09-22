//! Annex B reading cost: splitting an H.264 or H.265 byte stream into NAL units.
//!
//! Run with `cargo bench --package rtc-media --bench h26x`.
//!
//! * `Reader/<codec>/<buffer>` — `H26xReader::next_nal` from the start of a synthetic ~1 MiB
//!   stream to end of stream: finding every start code, copying each unit out of the read
//!   buffer, parsing its header and dropping SEI units. Throughput is stream bytes.
//!
//! The stream is 30-frame groups of pictures: parameter sets (VPS, SPS and PPS for H.265), an SEI
//! unit, a 48 KiB IDR slice, then P-frames of 2–12 KiB, some split into two slices. The first
//! unit of each frame has a four-byte start code and the rest three-byte ones, as x264 and x265
//! write them. Slice data is pseudo-random with emulation prevention applied, so the only start
//! codes are the real ones.
//!
//! `<buffer>` is the reader's capacity: 1 MiB, what `play-from-disk-h26x` uses, so one read
//! takes most of the stream; and 4 KiB, so most units span several refills and start codes
//! straddle refills.
//!
//! Reading is from a `Cursor`, so file I/O is excluded, but the copy into the read buffer is
//! included. Creating the reader (and allocating its buffer) is not timed, though the first
//! write to each page of that buffer is. `H26xSampleReader`, which groups units into frames on
//! top of this, is not measured.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rtc_media::io::h26x_reader::H26xReader;
use shared::error::Error;
use std::hint::black_box;
use std::io::Cursor;

/// Frames per group of pictures.
const GOP: usize = 30;
/// Approximate stream length.
const STREAM_LEN: usize = 1 << 20;
/// Read buffer capacities, with the names they are reported under.
const CAPACITIES: [(usize, &str); 2] = [(1 << 20, "1MiB"), (4 << 10, "4KiB")];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn range(&mut self, low: usize, high: usize) -> usize {
        low + (self.next() % (high - low) as u64) as usize
    }
}

/// Appends one NAL unit: a start code, `header`, then `body_len` bytes of pseudo-random data
/// with emulation prevention applied (a `03` after any `00 00` that would be followed by
/// `00`–`03`), ending in a non-zero byte as the RBSP stop bit ensures.
fn push_nal(
    stream: &mut Vec<u8>,
    rng: &mut Rng,
    long_start_code: bool,
    header: &[u8],
    body_len: usize,
) {
    let start_code: &[u8] = if long_start_code {
        &[0, 0, 0, 1]
    } else {
        &[0, 0, 1]
    };
    stream.extend_from_slice(start_code);
    stream.extend_from_slice(header);
    let mut zeros = 0;
    for _ in 1..body_len {
        let value = rng.next();
        // Zeros more often than chance, so escapes actually occur.
        let byte = if value.is_multiple_of(16) {
            0
        } else {
            (value >> 32) as u8
        };
        if zeros >= 2 && byte <= 3 {
            stream.push(3);
            zeros = 0;
        }
        stream.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    stream.push(0x80);
}

/// NAL unit headers for one codec.
struct Headers {
    parameter_sets: &'static [&'static [u8]],
    sei: &'static [u8],
    idr: &'static [u8],
    non_idr: &'static [u8],
}

const H264_HEADERS: Headers = Headers {
    parameter_sets: &[&[0x67], &[0x68]],
    sei: &[0x06],
    idr: &[0x65],
    non_idr: &[0x41],
};

const H265_HEADERS: Headers = Headers {
    parameter_sets: &[&[0x40, 0x01], &[0x42, 0x01], &[0x44, 0x01]],
    sei: &[0x4e, 0x01],
    idr: &[0x26, 0x01],
    non_idr: &[0x02, 0x01],
};

/// A synthetic stream of about `STREAM_LEN` bytes, and the number of units a reader should
/// return from it (every unit but the SEI ones).
fn stream(is_hevc: bool) -> (Vec<u8>, usize) {
    let headers = if is_hevc {
        &H265_HEADERS
    } else {
        &H264_HEADERS
    };
    let mut rng = Rng(if is_hevc { 0x265 } else { 0x264 });
    let mut stream = Vec::with_capacity(STREAM_LEN + (64 << 10));
    let mut units = 0;
    for frame in 0.. {
        if stream.len() >= STREAM_LEN {
            break;
        }
        if frame % GOP == 0 {
            for (i, header) in headers.parameter_sets.iter().enumerate() {
                let len = rng.range(4, 24);
                push_nal(&mut stream, &mut rng, i == 0, header, len);
                units += 1;
            }
            let len = rng.range(20, 40);
            push_nal(&mut stream, &mut rng, false, headers.sei, len);
            push_nal(&mut stream, &mut rng, false, headers.idr, 48 << 10);
            units += 1;
        } else {
            let len = rng.range(2 << 10, 12 << 10);
            let slices = if frame % 4 == 0 { 2 } else { 1 };
            for slice in 0..slices {
                push_nal(
                    &mut stream,
                    &mut rng,
                    slice == 0,
                    headers.non_idr,
                    len / slices,
                );
                units += 1;
            }
        }
    }
    (stream, units)
}

/// Reads units until end of stream, returning how many there were.
fn read_to_end(reader: &mut H26xReader<Cursor<&[u8]>>) -> usize {
    let mut units = 0;
    loop {
        match reader.next_nal() {
            Ok(nal) => {
                black_box(nal);
                units += 1;
            }
            Err(Error::ErrIoEOF) => return units,
            Err(err) => panic!("{err}"),
        }
    }
}

fn benchmark_reader(c: &mut Criterion) {
    let mut g = c.benchmark_group("H26x/Reader");
    for (codec, is_hevc) in [("H264", false), ("H265", true)] {
        let (stream, units) = stream(is_hevc);
        g.throughput(Throughput::Bytes(stream.len() as u64));
        for (capacity, capacity_name) in CAPACITIES {
            let new_reader = || H26xReader::new(Cursor::new(&stream[..]), capacity, is_hevc);
            assert_eq!(read_to_end(&mut new_reader()), units);

            g.bench_function(format!("{codec}/{capacity_name}"), |b| {
                b.iter_batched(
                    new_reader,
                    |mut reader| {
                        black_box(read_to_end(&mut reader));
                        // Returned so it is dropped outside the timing.
                        reader
                    },
                    BatchSize::LargeInput,
                )
            });
        }
    }
    g.finish();
}

criterion_group!(benches, benchmark_reader);
criterion_main!(benches);
