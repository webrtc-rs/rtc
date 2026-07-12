# AES-GCM A/B benchmark: RustCrypto `aes-gcm` vs `ring`

Reproducible micro-benchmark behind moving rtc's AES-GCM hot paths (SRTP/SRTCP
media, DTLS records) from RustCrypto `aes-gcm` to `ring`, and enabling the
RustCrypto hardware-AES backends on aarch64.

It times one **seal + open** of a `size`-byte packet with a 12-byte nonce and a
12-byte AAD (an RTP-header stand-in), matching how the SRTP cipher keeps the tag
detached. Only the AEAD backend differs between arms, so the delta is the crypto.

This is a **standalone** crate (its own `[workspace]`) so its `aes-gcm`
comparison dependency stays out of the main workspace's dependency tree.

## Run it directly

```console
$ cargo run --release -- ring 256 1200 100000
ring aes256 size=1200 iters=100000 -> 432.2 ns/op(seal+open) 43.22 ms total  ...

$ cargo run --release -- --help      # documents every argument
```

Arguments: `<backend: rustcrypto|ring> <bits: 128|256> <size_bytes> <iters>`.

> Built from inside the rtc tree, cargo picks up the repo's `.cargo/config.toml`,
> so the `rustcrypto` arm runs the *hardware* AES backend on aarch64. To time the
> software backend, override with an empty `RUSTFLAGS` — an exported `RUSTFLAGS`
> *replaces* (does not merge with) config rustflags. That is what the two builds
> below do.

## The three-way A/B (with a benchmark harness)

Use [`crap`](https://github.com/D-Berg/crap) (macOS) or
[`poop`](https://github.com/andrewrk/poop) (Linux). Under `sudo` they add kperf/
perf hardware counters (cycles, instructions) — the direct power proxy.

Build the harness twice:

```console
# software baseline + ring: empty RUSTFLAGS overrides the repo's .cargo/config.toml,
# so RustCrypto uses the software backend even in the default target dir.
$ RUSTFLAGS="" cargo build --release

# RustCrypto with aarch64 hardware AES + PMULL, into a separate target dir.
$ RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" \
  CARGO_TARGET_DIR=target-hw2 cargo build --release
```

Then compare RustCrypto-software vs RustCrypto-hardware vs ring in one shot
(`ring` ignores the flags, so the software build's `ring` arm is used):

```console
$ sudo crap -w 1 -d 8000 \
    './target/release/aead-bench     rustcrypto 256 1200 100000' \
    './target-hw2/release/aead-bench rustcrypto 256 1200 100000' \
    './target/release/aead-bench     ring       256 1200 100000'
```

(Drop `sudo` for wall-time only; the cycle/instruction columns need root.)

## Results (Apple M2, AES-256-GCM, 1200 B seal+open, 100k iters)

Benchmark 1 = RustCrypto software (rtc's default build), 2 = RustCrypto + flags,
3 = ring:

```
Benchmark 1 (4 runs): ./target/release/aead-bench rustcrypto 256 1200 100000
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          1.87s  ± 20.6ms                              1.86s  … 1.90s                                     0 ( 0%)        0%
  peak_rss           1.49MB ±    0                                1.49MB … 1.49MB                                    0 ( 0%)        0%
  cpu_cycles          268M  ± 2.82M                                266M  …  272M                                     0 ( 0%)        0%
  instructions        147M  ± 1.02M                                146M  …  148M                                     0 ( 0%)        0%
  cache_misses       94.1K  ± 26.1K                               55.0K  …  108K                                     1 (25%)        0%
  branch_misses      7.88K  ±  222                                7.66K  … 8.14K                                     0 ( 0%)        0%
Benchmark 2 (17 runs): ./target-hw2/release/aead-bench rustcrypto 256 1200 100000
  measurement          mean ± σ            min … max           outliers         delta
  wall_time           157ms ± 3.04ms                               149ms …  160ms                                    0 ( 0%)        ⚡- 91.6% ±  0.5%
  peak_rss           1.51MB ±    0                                1.51MB … 1.51MB                                    0 ( 0%)        💩+  1.1% ±  0.0%
  cpu_cycles         22.1M  ±  607K                               21.0M  … 23.0M                                     0 ( 0%)        ⚡- 91.7% ±  0.5%
  instructions       12.3M  ±  403K                               11.4M  … 12.9M                                     0 ( 0%)        ⚡- 91.6% ±  0.4%
  cache_misses       8.20K  ± 1.62K                               4.55K  … 9.47K                                     3 (18%)        ⚡- 91.3% ± 13.0%
  branch_misses       830   ±  155                                 615   … 1.14K                                     0 ( 0%)        ⚡- 89.5% ±  2.5%
Benchmark 3 (21 runs): ./target/release/aead-bench ring 256 1200 100000
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          74.2ms ± 5.40ms                              62.9ms … 82.9ms                                    0 ( 0%)        ⚡- 96.0% ±  0.5%
  peak_rss           1.51MB ±    0                                1.51MB … 1.51MB                                    0 ( 0%)        💩+  1.1% ±  0.0%
  cpu_cycles         9.50M  ±  816K                               8.33M  … 10.7M                                     0 ( 0%)        ⚡- 96.5% ±  0.5%
  instructions       5.94M  ±  627K                               5.04M  … 7.18M                                     0 ( 0%)        ⚡- 96.0% ±  0.5%
  cache_misses       4.32K  ±  511                                2.90K  … 5.07K                                     0 ( 0%)        ⚡- 95.4% ± 11.3%
  branch_misses       451   ±  181                                 275   …  836                                      0 ( 0%)        ⚡- 94.3% ±  2.7%
```

So per AES-256-GCM packet: ~2,680 cyc (software) -> ~221 (hw flags) -> ~95 (ring)
— ring is ~28x fewer cycles than the default build, ~2.7x fewer than even
hardware-flagged RustCrypto (ring's single pass vs `aes-gcm`'s two). AES-128-GCM
tracks it (ring ~395 ns/op vs ~14.3 us software).

This is a **media-path CPU/power** win, not a throughput fix — WebRTC crypto is
not the data-channel bottleneck.
