//! Audio buffer layout conversion.
//!
//! Run with `cargo bench --package rtc-media --bench bench`.
//!
//! Audio APIs mostly hand over interleaved samples (one sample per channel, frame after frame),
//! while per-channel processing wants each channel contiguous. These measure the conversions
//! between the two:
//!
//! * `Audio/Deinterleave/<type>/<channels>ch/<frames>` converts a
//!   `BufferRef<T, Interleaved>` into a new `Buffer<T, Deinterleaved>`, and
//!   `Audio/Interleave/...` converts the other way. Each is the whole public operation:
//!   allocating the output, filling it and dropping it again. Mono, stereo and four channels of
//!   `i16`, `f32` and `i32`, at 480 and 960 frames (10 ms and 20 ms at 48 kHz), plus 100,000
//!   frames of stereo `i16`, and of four-channel `i32`: the one case this benchmark used to run.
//! * `Audio/FromBytes/<byte order>/<from>-to-<to>/i16/2ch/960` decodes 20 ms of raw stereo
//!   `i16` PCM in little- or big-endian byte order into the other layout: the byte swap and the
//!   layout conversion in one pass.
//!
//! Deliberately not measured: codecs, resampling, and the RTP path. The peer connection does not
//! call these utilities; they are for applications that process decoded PCM themselves, so
//! nothing here says anything about forwarding encoded audio.
//!
//! `i16`/`f32` sample conversion is in the `pcm` target.

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_main};
use rtc_media::audio::buffer::layout::{Deinterleaved, Interleaved};
use rtc_media::audio::buffer::{Buffer, FromBytes};
use std::hint::black_box;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

/// 10 ms and 20 ms at 48 kHz: what an audio callback or an Opus frame typically holds.
const TYPICAL_FRAMES: [usize; 2] = [480, 960];
const CHANNELS: [usize; 3] = [1, 2, 4];
/// A long buffer: over two seconds at 48 kHz.
const LARGE_FRAMES: usize = 100_000;

/// A sample type the layout benchmarks run on.
trait BenchSample: Copy + Default {
    const NAME: &'static str;
    fn make(index: usize) -> Self;
}

impl BenchSample for i16 {
    const NAME: &'static str = "i16";
    fn make(index: usize) -> Self {
        index as i16
    }
}

impl BenchSample for f32 {
    const NAME: &'static str = "f32";
    fn make(index: usize) -> Self {
        index as f32
    }
}

impl BenchSample for i32 {
    const NAME: &'static str = "i32";
    fn make(index: usize) -> Self {
        index as i32
    }
}

/// Runs `bench` with each channel count at each typical frame count.
fn for_each_typical_case(mut bench: impl FnMut(usize, usize)) {
    for channels in CHANNELS {
        for frames in TYPICAL_FRAMES {
            bench(channels, frames);
        }
    }
}

fn deinterleave<T: BenchSample>(
    g: &mut BenchmarkGroup<'_, WallTime>,
    channels: usize,
    frames: usize,
) {
    let samples = (0..channels * frames).map(T::make).collect();
    let input: Buffer<T, Interleaved> = Buffer::new(samples, channels);
    g.throughput(Throughput::Elements((channels * frames) as u64));
    g.bench_function(
        BenchmarkId::new(format!("{}/{channels}ch", T::NAME), frames),
        |b| b.iter(|| Buffer::<T, Deinterleaved>::from(black_box(input.as_ref()))),
    );
}

fn interleave<T: BenchSample>(
    g: &mut BenchmarkGroup<'_, WallTime>,
    channels: usize,
    frames: usize,
) {
    let samples = (0..channels * frames).map(T::make).collect();
    let input: Buffer<T, Deinterleaved> = Buffer::new(samples, channels);
    g.throughput(Throughput::Elements((channels * frames) as u64));
    g.bench_function(
        BenchmarkId::new(format!("{}/{channels}ch", T::NAME), frames),
        |b| b.iter(|| Buffer::<T, Interleaved>::from(black_box(input.as_ref()))),
    );
}

fn benchmark_layout(c: &mut Criterion) {
    let mut g = c.benchmark_group("Audio/Deinterleave");
    for_each_typical_case(|channels, frames| deinterleave::<i16>(&mut g, channels, frames));
    for_each_typical_case(|channels, frames| deinterleave::<f32>(&mut g, channels, frames));
    for_each_typical_case(|channels, frames| deinterleave::<i32>(&mut g, channels, frames));
    deinterleave::<i16>(&mut g, 2, LARGE_FRAMES);
    deinterleave::<i32>(&mut g, 4, LARGE_FRAMES);
    g.finish();

    let mut g = c.benchmark_group("Audio/Interleave");
    for_each_typical_case(|channels, frames| interleave::<i16>(&mut g, channels, frames));
    for_each_typical_case(|channels, frames| interleave::<f32>(&mut g, channels, frames));
    for_each_typical_case(|channels, frames| interleave::<i32>(&mut g, channels, frames));
    interleave::<i16>(&mut g, 2, LARGE_FRAMES);
    interleave::<i32>(&mut g, 4, LARGE_FRAMES);
    g.finish();
}

fn from_bytes<B: ByteOrder>(g: &mut BenchmarkGroup<'_, WallTime>, order: &str) {
    const CHANNELS: usize = 2;
    const FRAMES: usize = 960;
    let samples: Vec<i16> = (0..CHANNELS * FRAMES).map(i16::make).collect();
    let mut bytes = vec![0; 2 * samples.len()];
    B::write_i16_into(&samples, &mut bytes);

    g.throughput(Throughput::Elements(samples.len() as u64));
    let id =
        |conversion| BenchmarkId::new(format!("{order}/{conversion}/i16/{CHANNELS}ch"), FRAMES);
    g.bench_function(id("interleaved-to-deinterleaved"), |b| {
        b.iter(|| {
            <Buffer<i16, Deinterleaved> as FromBytes<Interleaved>>::from_bytes::<B>(
                black_box(&bytes),
                CHANNELS,
            )
        })
    });
    g.bench_function(id("deinterleaved-to-interleaved"), |b| {
        b.iter(|| {
            <Buffer<i16, Interleaved> as FromBytes<Deinterleaved>>::from_bytes::<B>(
                black_box(&bytes),
                CHANNELS,
            )
        })
    });
}

fn benchmark_from_bytes(c: &mut Criterion) {
    let mut g = c.benchmark_group("Audio/FromBytes");
    from_bytes::<LittleEndian>(&mut g, "le");
    from_bytes::<BigEndian>(&mut g, "be");
    g.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_layout(&mut c);
    benchmark_from_bytes(&mut c);
}

criterion_main!(benches);
