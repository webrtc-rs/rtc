//! PCM sample conversion between `i16` and `f32`.
//!
//! Run with `cargo bench --package rtc-media --bench pcm`.
//!
//! `Audio/PCM/<from>-to-<to>/<method>/<samples>` converts a slice of `Sample<i16>` to
//! `Sample<f32>` or back, into an existing slice, so nothing is allocated:
//!
//! * `per-sample` is a loop over the per-sample `From` conversion, which LLVM already vectorizes;
//! * `slice` is the slice conversion (`Sample::<f32>::convert_from_i16_slice`,
//!   `Sample::<i16>::convert_from_f32_slice`), eight samples at a time with `wide`.
//!
//! Both give bit-identical results, so the pair measures only how the loop is vectorized. 1,920
//! samples is 20 ms of stereo at 48 kHz; 200,000 is a long buffer.
//!
//! Deliberately not measured: layout conversion (the `bench` target), codecs and resampling. The
//! peer connection does not call these utilities.
//!
//! The slice conversions are newer than the per-sample ones. `scripts/bench.py compare
//! --overlay-benches` against a revision without them reports this target as measured at head
//! only; the `per-sample` rows are the comparison within one run.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rtc_media::audio::Sample;
use std::hint::black_box;

/// 20 ms of stereo at 48 kHz, and 100,000 stereo frames.
const PCM_SAMPLES: [usize; 2] = [1_920, 200_000];

/// Deterministic samples spread over the whole `i16` range.
fn pcm_samples(len: usize) -> Vec<Sample<i16>> {
    let mut state = 0x2545_f491_u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            Sample::from((state >> 16) as i16)
        })
        .collect()
}

fn benchmark_pcm(c: &mut Criterion) {
    let mut g = c.benchmark_group("Audio/PCM");
    for len in PCM_SAMPLES {
        let ints = pcm_samples(len);
        let floats: Vec<Sample<f32>> = ints.iter().map(|&s| Sample::<f32>::from(s)).collect();
        let mut float_out = vec![Sample::<f32>::default(); len];
        let mut int_out = vec![Sample::<i16>::default(); len];
        g.throughput(Throughput::Elements(len as u64));

        g.bench_function(BenchmarkId::new("i16-to-f32/per-sample", len), |b| {
            b.iter(|| {
                for (dst, src) in float_out.iter_mut().zip(black_box(&ints)) {
                    *dst = Sample::<f32>::from(*src);
                }
                black_box(&mut float_out);
            })
        });
        g.bench_function(BenchmarkId::new("i16-to-f32/slice", len), |b| {
            b.iter(|| {
                Sample::<f32>::convert_from_i16_slice(black_box(&ints), &mut float_out);
                black_box(&mut float_out);
            })
        });

        g.bench_function(BenchmarkId::new("f32-to-i16/per-sample", len), |b| {
            b.iter(|| {
                for (dst, src) in int_out.iter_mut().zip(black_box(&floats)) {
                    *dst = Sample::<i16>::from(*src);
                }
                black_box(&mut int_out);
            })
        });
        g.bench_function(BenchmarkId::new("f32-to-i16/slice", len), |b| {
            b.iter(|| {
                Sample::<i16>::convert_from_f32_slice(black_box(&floats), &mut int_out);
                black_box(&mut int_out);
            })
        });
    }
    g.finish();
}

criterion_group!(benches, benchmark_pcm);
criterion_main!(benches);
