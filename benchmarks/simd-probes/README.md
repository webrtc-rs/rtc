# Exploratory SIMD probes

These are analysis artifacts for [`SIMD.md`](../../SIMD.md), not production implementations
or additions to the main workspace benchmark suite. They compare small kernels using hot
buffers, rotated sample order, and upper medians. They do not provide confidence intervals
or predict whole-stack performance.

## What shipped

Each probe's idea is now implemented in the library, portably, and measured by a criterion
benchmark; SIMD.md's sections record the results.

| Probe | Production | Benchmark |
|---|---|---|
| `annexb_scan` | `H264Payloader::next_ind` and `H26xReader::next_nal`, with a prebuilt `memchr::memmem::Finder` | `rtc-rtp:bench` `H264/Payload/*`, `rtc-media:h26x` |
| `receiver_loss` | `rtc-interceptor/src/bitmap.rs`, used by receiver reports and the NACK receive log | `rtc-interceptor:feedback` |
| `ogg_crc` | `PageChecksum` in `rtc-media/src/io/ogg_reader`, on the `crc-fast` crate | `rtc-media:ogg` |

The Ogg probe used ARM intrinsics (`std::arch::aarch64`: NEON bit reversal around the CRC32
instructions) and runs only on aarch64. Production does not: `crc-fast` folds with carry-less
multiplication on x86, x86-64 and aarch64, detected at runtime, and falls back to slice-by-16 tables
elsewhere. Timed back to back on the same M1 Max it was 2.7× faster than the probe's best variant
at 1,200 bytes (45.5 against 121.6 ns) and 4.7× at 65,307 (1.60 against 7.59 µs): folding needs no
per-byte bit reversal.

From the repository root, test the portable probes before timing:

```sh
cargo test --manifest-path benchmarks/simd-probes/Cargo.toml
cargo run --release --manifest-path benchmarks/simd-probes/Cargo.toml --bin annexb_scan
cargo run --release --manifest-path benchmarks/simd-probes/Cargo.toml --bin receiver_loss
```

`annexb_scan` compares the current H.264 start-code loop with byte-search and substring-search
variants using pinned `memchr`. The synthetic cases include dense false matches as well as
mixed data and zero runs. The tests preserve the current scanner's handling of extra zeros
and nonzero start offsets.

`receiver_loss` compares a per-sequence bitmap walk with masked word popcounts. It preserves
the bitmap's cyclic reads, including ranges larger than the retained history. Integrating
it requires preserving `generate_report`'s exact endpoint semantics and testing full reports.

The Ogg CRC probe is ARM64-only and is deliberately excluded from the portable Cargo targets:

```sh
rustc --edition=2024 --test -C opt-level=3 benchmarks/simd-probes/ogg_crc.rs -o /tmp/rtc-ogg-crc-test
/tmp/rtc-ogg-crc-test
rustc --edition=2024 -C opt-level=3 benchmarks/simd-probes/ogg_crc.rs -o /tmp/rtc-ogg-crc-bench
/tmp/rtc-ogg-crc-bench
```

It compares the existing table recurrence with scalar and NEON bit reversal around ARM
hardware CRC instructions. Accelerated execution is skipped when CRC support is absent.

Record the toolchain, target, effective flags, input distribution, and machine for any
comparison. The published exploratory figures came from direct `rustc -C opt-level=3`
builds on ARM64; the Cargo entry points make the probes easier to rerun but do not imply
identical code generation under different flags or toolchains.
