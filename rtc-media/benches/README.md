# rtc-media benchmarks

## Audio: `bench`

```bash
cargo bench --package rtc-media --bench bench
```

Buffer layout conversion (`Audio/Deinterleave/*`, `Audio/Interleave/*`, `Audio/FromBytes/*`); the
source's opening comment describes each case. `i16`/`f32` sample conversion (`Audio/PCM/*`) is the
`pcm` target.

### Fast paths for mono, stereo and four channels (2026-09-21)

Measured with `python3 scripts/bench.py compare refs/bench/pre-simd --overlay-benches --rounds 2`
on an Apple M1 Max, macOS 27.0, `rustc 1.99.0-nightly` (2026-08-04); before is the tree just ahead of
the change. [SIMD.md](../../SIMD.md) has the full record.

Every case got 5–17× faster, allocation included; for example:

| Benchmark | Before | After |
|---|---:|---:|
| `Audio/Deinterleave/i16/2ch/960` | 1.24 µs | 79.8 ns |
| `Audio/Interleave/i16/2ch/960` | 938 ns | 81.5 ns |
| `Audio/Deinterleave/f32/4ch/960` | 2.17 µs | 263 ns |
| `Audio/FromBytes/le/interleaved-to-deinterleaved/i16/2ch/960` | 1.24 µs | 80.7 ns |
| `Audio/Deinterleave/i32/4ch/100000` | 219 µs | 37.1 µs |
| `Audio/Interleave/i32/4ch/100000` | 187 µs | 26.7 µs |

The results below come from the earlier version of this benchmark, which measured only
four-channel, 100,000-frame `i32` buffers. Its two labels were reversed relative to the
operations: `Media/Buffer/Interleaved to Deinterleaved` timed the conversion *to* interleaved,
and `Media/Buffer/Deinterleaved to Interleaved` the conversion *to* deinterleaved. Today these
are `Audio/Interleave/i32/4ch/100000` and `Audio/Deinterleave/i32/4ch/100000` respectively.

### Earlier results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-media --bench bench

     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [163.04 µs 164.17 µs 165.51 µs]
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [173.43 µs 173.54 µs 173.68 µs]
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.38s
     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [165.07 µs 166.93 µs 169.17 µs]
                        change: [−0.7800% +0.5789% +1.9084%] (p = 0.39 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  9 (9.00%) high mild
  3 (3.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [185.39 µs 193.68 µs 204.31 µs]
                        change: [+9.4776% +13.570% +18.775%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 16 outliers among 100 measurements (16.00%)
  4 (4.00%) high mild
  12 (12.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.17s
     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [160.14 µs 160.28 µs 160.45 µs]
                        change: [−4.2455% −3.2315% −2.2214%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 14 outliers among 100 measurements (14.00%)
  3 (3.00%) high mild
  11 (11.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [173.40 µs 173.46 µs 173.52 µs]
                        change: [−15.667% −12.005% −8.5621%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  1 (1.00%) high mild
  4 (4.00%) high severe

```
## PCM: `pcm`

```bash
cargo bench --package rtc-media --bench pcm
```

`Sample<i16>` ↔ `Sample<f32>` a slice at a time with `wide` (`slice`) against a loop over the
per-sample `From` (`per-sample`); both are bit-identical. The slice API is new, so there is no
before. Same machine and toolchain as above:

| Benchmark | Per sample | Slice |
|---|---:|---:|
| `Audio/PCM/i16-to-f32/*/1920` | 402 ns | 230 ns |
| `Audio/PCM/i16-to-f32/*/200000` | 42.0 µs | 24.4 µs |
| `Audio/PCM/f32-to-i16/*/1920` | 191 ns | 191 ns |
| `Audio/PCM/f32-to-i16/*/200000` | 19.9 µs | 19.9 µs |

## H.264/H.265 Annex B reader: `h26x`

```bash
cargo bench --package rtc-media --bench h26x
```

`H26xReader` reading a synthetic ~1 MiB stream to the end. After it scanned for start codes with
`memchr::memmem` and copied spans in bulk rather than a byte at a time (2026-09-21):

| Benchmark | Before | After |
|---|---:|---:|
| `H26x/Reader/H264/1MiB` | 5.88 ms | 76.9 µs |
| `H26x/Reader/H265/1MiB` | 5.65 ms | 79.3 µs |

## Ogg pages: `ogg`

```bash
cargo bench --package rtc-media --bench ogg
```

Whole-page writing, and reading with and without checksum verification. After the page CRC moved
from a byte-at-a-time table walk to `crc-fast` (2026-09-21):

| Benchmark | Before | After |
|---|---:|---:|
| `Ogg/Write/80B` | 358 ns | 91.3 ns |
| `Ogg/Write/1200B` | 3.52 µs | 155 ns |
| `Ogg/Write/8192B` | 23.4 µs | 442 ns |
| `Ogg/Write/65025B` | 184 µs | 3.15 µs |
| `Ogg/Read/checksum/80B` | 337 ns | 107 ns |
| `Ogg/Read/checksum/1200B` | 3.54 µs | 170 ns |
| `Ogg/Read/checksum/8192B` | 23.4 µs | 548 ns |
| `Ogg/Read/checksum/65025B` | 186 µs | 4.00 µs |
| `Ogg/Read/no-checksum/*` | unchanged | |
