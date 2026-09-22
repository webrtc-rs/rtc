# SIMD opportunities

Analysis of the working tree on 2026-09-21. The strongest candidates for additional SIMD are
H.264 start-code scanning and audio layout conversion. FlexFEC payload XOR already
auto-vectorizes in an isolated compiler probe, and much of the cryptographic work delegates
to accelerated dependencies.

A second pass identified Ogg page checksums as a strong hardware-acceleration candidate
for recording/playback, plus narrower opportunities in feedback decoding and circular
buffer processing. Ogg measurements below separate hardware CRC gains from SIMD gains.

## Implementation status

Every section below was implemented on 2026-09-21; each ends with a **Resolution** recording what
changed, how equivalence was checked, and before/after numbers. SIMD work uses portable
abstractions only — [`wide`](https://docs.rs/wide) vectors (SSE2/AVX2, NEON, `simd128` or scalar,
chosen at compile time), `memchr`'s substring search and the [`crc-fast`](https://docs.rs/crc-fast)
CRC library — or safe Rust the compiler vectorizes; there are no `std::arch` intrinsics.

| Section | Change | Headline result |
|---|---|---|
| 1. H.264 start codes | `memchr::memmem` with a prebuilt finder; bulk span copies in the reader | Reader 71–76× faster, payloader 2.8–5.9× |
| 2. Audio layout | Mono, stereo and four-channel fast paths | 5–17× faster on every case |
| 3. ARM crypto | `aes` 0.9 / `ctr` 0.10 / `ccm` 0.6; `bench.py external` | Applications get hardware AES without configuration (14× faster there); in-repository SRTP AES-CM 11–12% and DTLS CBC encryption 19% slower |
| 4. CBC decryption | Batches of 32 blocks from 512 bytes | 7–10% at 512 B and up; unchanged DTLS record decrypt despite a slower `aes` |
| 5. FlexFEC | Serialize once per block, reused buffers, `wide` XOR | Encode 1.4–1.7×, recovery 1.07–1.34× |
| 6. STUN fingerprint | `crc-fast` | 3.8× at 100 bytes, 5–9× on larger messages |
| 7. Ogg checksums | `crc-fast`, incremental, shared parameters | Checksummed pages 3–59× faster by size |
| 8. RFC 8888 decode | Bulk decode from a contiguous chunk (plain Rust beat `wide`) | 3.3–4.3× |
| 9. TWCC gaps | Slice fills and copies; `wide` scan for long runs | 9.6% on long gaps, neutral otherwise |
| 10. NACK scans | Word-wise bit scans; iterator in the responder | Generation 1.2–8.1×, responder up to 1.7× |
| 11. Receiver-report loss | Masked word popcount | 36% on a report after an outage; neutral otherwise, as predicted |
| 12. PCM conversion | `wide` slice conversions, bit-exact | `i16`→`f32` 1.75×; `f32`→`i16` ties the compiler's own vectorization |

**How it was measured.** `python3 scripts/bench.py compare refs/bench/pre-simd --overlay-benches
--rounds 2` on an Apple M1 Max (macOS 27.0, `rustc 1.99.0-nightly` 2026-08-04, no `RUSTFLAGS`),
criterion at 3 s warm-up and 5 s measurement. The base, `refs/bench/pre-simd` (`d465afd`), is the
tree immediately before this work; both sides ran the same benchmark sources, and the two sides
alternated. Of 131 comparable benchmarks, 95 were faster, 30 within noise and 6 slower. Four of
the six are SRTP AES-CM and DTLS CBC encryption, section 3's trade; `CCFB/Marshal/1x590`, whose
code did not change, re-measured as noise over three rounds; and `Feedback/TwccReceiver/steady`
led to a follow-up change that brought it within noise (section 9). The end-to-end
`Track/{Send,Receive}/*` benchmarks, which run AES-GCM on `ring` and the default interceptors, were
unchanged. **x86-64 was not measured.** The code is portable and CI builds and tests on x86-64
Linux, but this work has not been through CI yet, and no figure here speaks for x86-64.

## Evidence and limits

The review covered the packet-processing, media, crypto, checksum, and benchmark code.
Isolated loop probes were compiled with `rustc 1.99.0-nightly (1ed2df61a 2026-08-04)`, LLVM
22.1.8, optimization level 3, targeting `aarch64-apple-darwin`.

The probes establish code-generation behavior for those loop shapes, not end-to-end
speedups or the exact instructions in every application build. No x86-64 measurements or
whole-stack profiling were performed. Audio prototypes matched the existing functions for
every frame count from 0 through 2,048. No production code was changed as part of this analysis;
the implementation that followed is recorded in each section's Resolution.

The second pass used the same compiler settings and target. It added isolated Ogg CRC
timings and correctness/code-generation probes for feedback, TWCC gap clearing, and NACK
bit scans. These are described below; none establishes a whole-stack speedup. The Ogg
probe is retained in [`benchmarks/simd-probes/ogg_crc.rs`](benchmarks/simd-probes/ogg_crc.rs).

The third pass measured H.264 scanner alternatives and receiver-report bitmap loss counts,
and inspected batched PCM conversion and replay-window shifts. Reproducible probes and
their standalone build instructions are collected in
[`benchmarks/simd-probes/README.md`](benchmarks/simd-probes/README.md).

## 1. H.264 start-code scanning

Relevant code:

- [`H264Payloader::next_ind`](rtc-rtp/src/codec/h264/mod.rs) examines each byte and maintains a
  zero counter.
- [`H26xReader::next_nal`](rtc-media/src/io/h26x_reader/mod.rs) reads, processes, and appends
  individual bytes within its buffered reader.
- [`HevcPayloader::parse`](rtc-rtp/src/codec/h265/mod.rs) already uses `memchr::memmem`.

Use `memchr` or `memmem` to locate candidate start codes, validate their surrounding bytes,
and copy spans in bulk. `rtc-rtp` already depends on `memchr`; the crate provides SIMD search
implementations for x86-64 and ARM64. See the [memchr documentation](https://docs.rs/memchr/).

Preserve the existing treatment of mixed three- and four-byte prefixes, longer zero runs,
empty units, and prefixes spanning reader buffers. The H.265 implementation is evidence of
an available dependency, not a drop-in replacement for H.264's boundary semantics.

This is the first implementation candidate for workloads doing video packetization or
reading Annex B streams. Benchmark both the scanner and complete packetization/reading.

### Follow-up: choose the search strategy carefully

The retained [Annex B probe](benchmarks/simd-probes/annexb_scan.rs) copies `next_ind`'s loop
with a slice input and compares two alternatives using `memchr 2.8.3`:

- Find each `0x01`, then check whether two or more zeros precede it.
- Find `00 00 01` with `memmem::find`, then walk backward over additional preceding zeros
  without crossing the caller's `start` offset.

Both matched the original on every input of lengths 0–9 over the alphabet `{0, 1, 7}` at
every valid start offset, plus long zero prefixes through 4,096 bytes. This validates
scanner boundary behavior; streaming reader state and full packetization remain untested
by this probe.

Selected local hot-buffer timings, in nanoseconds per scan:

| Input | Bytes | Original loop | Find `0x01` candidates | Find `00 00 01` |
|---|---:|---:|---:|---:|
| Mixed bytes, trailing four-byte prefix | 64 | 49.8 | 8.4 | 12.1 |
| Mixed bytes, trailing four-byte prefix | 1,200 | 951.9 | 68.1 | 48.5 |
| Mixed bytes, trailing four-byte prefix | 16,384 | 12,272.1 | 746.8 | 548.1 |
| All `0x01`, no prefix | 1,200 | 792.2 | 7,775.5 | 47.2 |
| All zero, no prefix | 1,200 | 398.2 | 16.5 | 47.1 |

The substring variant was about 20–22× faster on the larger mixed samples. Finding each
`0x01` was roughly 10× slower than the original on dense false matches. Prefer substring
search as the first production experiment, and include adversarial byte distributions
in its benchmarks. Finder reuse across searches within a frame is another experiment;
the measured variant used `memmem::find` per call.

These are synthetic, hot-buffer scanner timings with six rotated-order samples, upper
medians, non-inlined kernels, and `black_box`. They exclude packetization, copying, and I/O,
and do not establish the same gain on actual encoded frames or the complete sender.

### Resolution

`H264Payloader::next_ind` now searches for `00 00 01` with a `memchr::memmem::Finder` built once in
a `static`, then walks back over preceding zeros without crossing `start` — the probe's substring
variant. A prebuilt finder matters for short units: `memmem::find` builds a new searcher per call
and uses scalar Rabin–Karp below 64 bytes. `H26xReader::next_nal` scans the unread part of its
buffer with the same finder, resolves a `01` in the first two positions from the zero count carried
across refills, and appends whole spans with `extend_from_slice` instead of reading, classifying and
pushing one byte at a time.

Both keep copies of the old byte loops as test references. The scanner matches on every input of
lengths 0–9 over `{0, 1, 7}` at every start, on zero runs to 4,096 and on random buffers; whole
`payload()` output matches across random access units, MTUs and successive calls. The reader matches
the old one's full result sequence — NAL data, parsed headers, errors and bytes consumed — over
random and adversarial streams at buffer capacities 1–8, 13, 64 and 4,096, with short, irregular,
paused and failing reads. One deliberate difference: the old reader panicked on a `usize` underflow
if a source returned `Ok(0)`, the final unit was returned, and more data then arrived starting with
a short zero run and a `01`. That is now treated as the empty unit it is.

| Benchmark | Before | After | Speed-up |
|---|---:|---:|---:|
| `H264/Payload/AccessUnit/1200` | 725 ns | 150 ns | 4.8× |
| `H264/Payload/AccessUnit/16384` | 8.24 µs | 1.55 µs | 5.3× |
| `H264/Payload/AccessUnit/102400` | 52.1 µs | 10.2 µs | 5.1× |
| `H264/Payload/Slices/16x150` | 1.76 µs | 633 ns | 2.8× |
| `H264/Payload/AllOnes/16384` | 8.60 µs | 1.45 µs | 5.9× |
| `H264/Payload/AllZeros/16384` | 7.74 µs | 1.45 µs | 5.3× |
| `H26x/Reader/H264/1MiB` | 5.88 ms | 76.9 µs | 76× |
| `H26x/Reader/H265/1MiB` | 5.65 ms | 79.3 µs | 71× |

The dense-`0x01` input that made the byte-search variant ten times slower is 5.9× faster with
substring search. The reader's gain is mostly the per-byte call and push overhead gone, not the
search itself.

## 2. Audio layout conversion

[`deinterleaved_by` and `interleaved_by`](rtc-media/src/audio/buffer/layout.rs) use runtime
strides and indexed nested loops. This makes vectorization harder when the channel count
is unknown at compile time.

The isolated `i16` probes produced:

| Loop shape | ARM64 output |
|---|---|
| Existing functions with runtime channel count | Scalar |
| Existing deinterleave function with constant stereo channel count | NEON `ld2` |
| Existing interleave function with constant stereo channel count | Scalar |
| Stereo deinterleave using separate output slices | NEON `ld2` |
| Stereo interleave using separate input slices | NEON `st2` |

Add mono and stereo fast paths, retaining the generic fallback. For stereo, split the planar
buffer into left/right slices and zip those slices with interleaved `chunks_exact(2)` or
`chunks_exact_mut(2)`. Safe Rust was sufficient to obtain vector instructions in the probes;
start there before introducing architecture-specific intrinsics. Evaluate four-channel
specialization if representative workloads justify it.

The split-slice prototypes matched the existing conversions for frame counts 0 through
2,048. A production change should also exercise supported sample types, unusual channel
counts, and byte-order conversion paths.

The benefit is application-dependent: the review found no production calls to these PCM
utilities from the main peer-connection code. Improving them will not automatically speed
up forwarding of encoded audio packets.

### Resolution

`deinterleaved_by` and `interleaved_by` have mono, stereo and four-channel fast paths, each
splitting the planar side into per-channel slices zipped with whole interleaved frames
(`as_chunks::<N>`); other channel counts keep the original loop. The functions are generic over the
sample type and a mapping closure, so `wide` cannot express them; the compiler emits NEON
`ld2`/`ld4`/`st2`/`st4` for `i16`, `i32` and `f32`, confirmed in the benchmark binary. The four-channel
path was kept because it measured decisively: 2.17 µs to 141 ns for 960 frames of `i16`.

The old loops are kept as test oracles and compared for channels 1–8, `i16`/`i32`/`f32` (floats bit
for bit), every frame count 0–2,048 in release builds, the `MaybeUninit` path behind
`From<BufferRef>` — outputs wrapped so a slot the fast path never writes fails the test — and both
byte orders of `FromBytes`.

The benchmark now covers mono, stereo and four channels of each sample type at 480 and 960 frames,
plus the old large case, with its reversed labels fixed. All 44 cases were faster, 5–17×:

| Benchmark (whole `Buffer` conversion, allocation included) | Before | After | Speed-up |
|---|---:|---:|---:|
| `Audio/Deinterleave/i16/1ch/960` | 676 ns | 51.4 ns | 13× |
| `Audio/Deinterleave/i16/2ch/960` | 1.24 µs | 79.8 ns | 16× |
| `Audio/Interleave/i16/2ch/960` | 938 ns | 81.5 ns | 12× |
| `Audio/Deinterleave/f32/2ch/960` | 1.25 µs | 148 ns | 8.4× |
| `Audio/Interleave/f32/4ch/960` | 1.85 µs | 274 ns | 6.8× |
| `Audio/FromBytes/be/interleaved-to-deinterleaved/i16/2ch/960` | 1.24 µs | 72.5 ns | 17× |
| `Audio/Deinterleave/i32/4ch/100000` | 219 µs | 37.1 µs | 5.9× |
| `Audio/Interleave/i32/4ch/100000` | 187 µs | 26.7 µs | 7.0× |

## 3. Reliability of ARM crypto acceleration

This is hardware crypto acceleration rather than general SIMD, but it may have greater
practical impact than adding new vector loops.

[`.cargo/config.toml`](.cargo/config.toml) enables `aes_armv8`, required to select the ARM
hardware backend in the pinned `aes 0.8.4` dependency. These flags affect RustCrypto-backed
AES-CTR, CCM, CBC, and SRTP key derivation. The GCM AEAD paths delegated to `ring` or
`aws-lc-rs` do not depend on this RustCrypto flag.

Two build situations need attention:

- An application consuming RTC from another project does not automatically inherit this
  repository's Cargo configuration. Cargo discovers configuration from its invocation
  directory and ancestors, rather than loading each dependency's configuration.
- Exported `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS` can replace the configured flags and
  silently disable the accelerated RustCrypto backend.

See [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html) and the
existing [benchmarking notes](docs/benchmarking.md#rustflags-silently-changes-the-numbers).
Those notes report a substantial penalty when the flags disappear; those timings were not
remeasured during this review.

Add a benchmark built from an external consumer project and document its required
configuration. Longer term, evaluate a dependency version or backend that enables ARM
acceleration without consumer-provided cfg flags. Verify that behavior before migrating.

### Resolution

`benchmarks/external-consumer` and `python3 scripts/bench.py external` build a stand-in application
three ways: from outside the repository with no rustflags from any source (an empty
`CARGO_ENCODED_RUSTFLAGS` also overrides user-wide `~/.cargo` configuration), from the repository
root, and with RustCrypto's software AES forced. Against the tree before this work it confirmed the
problem on 1,200-byte inputs:

| | In the repository | As an application | Ratio |
|---|---:|---:|---:|
| AES-128-CTR (SRTP AES-CM) | 223 ns | 5,977 ns | 27× |
| AES-128-CCM seal (DTLS) | 992 ns | 26,413 ns | 27× |
| AES-256-CBC decrypt (DTLS) | 289 ns | 28,831 ns | 100× |
| AES-128-GCM seal (`ring`, control) | 217 ns | 219 ns | 1× |

`aes` 0.9.3 enables its ARMv8 backend by runtime detection alone, so `rtc-crypto` moved to `aes`
0.9.3, `ctr` 0.10.1 and `ccm` 0.6.1 (the only direct users of the RustCrypto cipher APIs are in
`rtc-crypto/src/common.rs`). An application now gets 433 ns for the CTR case, 14× faster, with no
configuration, and `bench.py external` passes at 0.95–1.01× of the repository build.

Verifying before migrating found a cost: 0.9.3's ARMv8 backend is slower than 0.8.4's with the cfg.
Raw AES over 75 blocks took 219 ns against 81 ns, the CTR case 433 against 223 ns, a CCM seal about
2.0 against 1.0 µs. The likely cause is that 0.8.4 emits each AESE/AESMC pair as one asm block,
which the core fuses, where 0.9.3 uses separate intrinsics. Offered a hybrid (0.8 when the cfg is
set, 0.9 otherwise), keeping 0.8 with documentation, or 0.9 alone, the owner chose 0.9 alone:
correct by default for applications, one code path, at a measured in-repository cost:

| Benchmark | Before | After | Change |
|---|---:|---:|---:|
| `SRTP/Encrypt/RTP` (AES-128-CM-HMAC-SHA1-80) | 1.70 µs | 1.91 µs | +12% |
| `SRTP/Decrypt/RTP` | 1.72 µs | 1.90 µs | +11% |
| `DTLS/Encrypt/AES-256-CBC/ring` | 2.89 µs | 3.43 µs | +19% |
| `DTLS/Decrypt/AES-256-CBC/ring` | 1.84 µs | 1.85 µs | ~ (section 4's batching absorbs it) |
| `SRTP/*/AEAD-AES-128-GCM`, `DTLS/*/AES-128-GCM`, `Track/*` | | | unchanged |

Revisit if a later `aes` release recovers the ARMv8 difference. `.cargo/config.toml` keeps its
cfgs only for dev dependencies — `aes` 0.8.4 and `polyval` 0.6.2 under the `webrtc` 0.14 interop
crate, and `benchmarks/aead-gcm` — and its comment and
[docs/benchmarking.md](docs/benchmarking.md#builds-outside-this-repository) say so.
`bench.py external` is not in CI, which never gates on timing; run it after changing crypto
dependencies or cargo configuration.

## 4. CBC decryption batching

[`AesCbc::decrypt_blocks`](rtc-crypto/src/common.rs) decrypts one AES block per call.
Decrypting separate ciphertext blocks is independent; the chaining XOR uses the previous
ciphertext block after decryption.

Process bounded batches through the AES backend's multi-block decryption API, retaining
the original ciphertext needed for chaining. This gives the backend an opportunity to
exploit parallel block processing and instruction-level parallelism. Preserve in-place
behavior, the IV for the first block, and chaining across batch boundaries.

CBC encryption has a dependency on the previous encrypted block, so the same approach
does not apply there. Prioritize this work only for workloads using CBC suites. The CTR
path already delegates bulk processing to the `ctr` crate.

### Resolution

`AesCbc::decrypt_blocks` decrypts batches of 32 blocks through the backend's multi-block API, from a
512-byte stack copy of each batch's ciphertext, which the chaining XOR then reads; the IV masks the
first block and the previous batch's last ciphertext block masks each later batch's first.

The expected gain was mostly already there. The block decryptions are independent, so an
out-of-order core overlapped consecutive single-block calls: with `aes` 0.8.4 the old loop decrypted
1,200 bytes in 289 ns. Timed with `aes` 0.9.3 on a quiet machine, batching wins only from one full
batch up, and loses below it to the buffer setup, so shorter input stays block at a time:

| Input | Block at a time | Batched |
|---:|---:|---:|
| 128 B | 32 ns | 41 ns |
| 320 B | 76 ns | 83 ns |
| 512 B | 120 ns | 111 ns |
| 1,200 B | 274–305 ns | 272–280 ns |
| 16 KiB | 3.73 µs | 3.40 µs |

In the DTLS record benchmark, CBC decryption stayed at 1.84–1.85 µs despite `aes` 0.9's slower
blocks (section 3). VAES backends on x86-64 process 30 or 64 blocks per step and may gain more; not
measured. A test compares batched and block-at-a-time decryption for every length from 1 to 97
blocks and on arbitrary ciphertext.

## 5. FlexFEC XOR and surrounding work

Relevant code:

- [`FlexFec03Encoder::encode_one`](rtc-interceptor/src/flexfec/draft03/encoder.rs)
- [`FlexFec03Decoder` recovery code](rtc-interceptor/src/flexfec/draft03/decoder.rs)

The byte-wise zipped payload XOR loop already generated four 128-bit NEON XORs per main
iteration in the isolated probe, with remainder handling. Explicit intrinsics therefore
have no demonstrated advantage yet.

Both paths allocate and marshal packets around the XOR. Investigate reusable scratch
storage and serializing each protected packet once per encoding group before replacing
the loop. Preserve the recovery representation: it covers everything after the fixed RTP
header, including CSRCs and extensions, not just `packet.payload`.

Benchmark the XOR separately from complete FEC encoding and recovery. Exercise unequal
packet lengths, short inputs, vector-width boundaries, RTP extensions, and loss patterns.
Only pursue explicit SIMD if profiling and generated assembly show an additional benefit.

### Resolution

Profiling `FlexFec/Encode/48x2` first showed about 40% of the time in allocation (a fresh buffer
per protected packet per repair packet), 30% in marshalling and 26% in the XOR. Now:

- `encode` serializes each media packet once per block into a buffer the encoder reuses, and
  `encode_one` reads from it. The buffer is never zeroed: only each packet's written prefix is
  used, and the old fresh buffer's unwritten tail was zero, which XOR ignores.
- `recover` serializes each surviving packet once, not header and then packet, into a reused
  scratch buffer, and folds the recovery fields and payload into one pass.
- The payload XOR is `xor_into` in `rtc-interceptor/src/flexfec/xor.rs`: `wide::u8x32` for the main
  loop and an overlapping final vector, computed before the loop, instead of a byte remainder. It ties
  the auto-vectorized `zip` loop in complete encoding and recovery; kernel alone it is about 10%
  slower at 200 bytes and 2× faster at 33–63 bytes. Kept for the short lengths and the project's
  preference for explicit portable SIMD.

Verbatim copies of the old encoder and recovery are test references: byte-identical output across
random blocks of 1–110 packets and 1–120 repair packets, payloads 0–1,500 bytes weighted to vector
boundaries, CSRCs, all extension profiles, padding, unserializable packets and sequence wrap, with
stale bytes in the reused buffer; every single-loss position recovers identically, including with
damaged repair packets.

| Benchmark | Before | After | Speed-up |
|---|---:|---:|---:|
| `FlexFec/Encode/10x2` | 1.35 µs | 793 ns | 1.71× |
| `FlexFec/Encode/48x2` | 5.95 µs | 3.60 µs | 1.65× |
| `FlexFec/Encode/48x10` | 6.69 µs | 4.79 µs | 1.40× |
| `FlexFec/Recover/10x2` | 1.95 µs | 1.65 µs | 1.18× |
| `FlexFec/Recover/48x2` | 10.6 µs | 8.75 µs | 1.21× |
| `FlexFec/RecoverRepair/48x2` | 6.43 µs | 4.78 µs | 1.34× |

After the change, serializing is about 45% of encoding and the XOR 30%; an encoder that XORed
`packet.payload` directly, re-creating `marshal_to`'s layout, is the next step. Recovery is now
dominated by bookkeeping left alone: cloning packets into per-repair lists and re-sorting recovered
packets on every insert.

Found in passing, not fixed: `ProtectionCoverage` accepts 110-packet blocks, but draft-03's masks
name only 109 positions (15 + 31 + 63). The 110th packet is XORed into its repair packet without
being declared, so no loss under that repair packet recovers correctly. The previous code behaved
the same; the default block is 5 packets.

## 6. STUN fingerprint CRC

[`fingerprint_value`](rtc-stun/src/fingerprint.rs) uses a precomputed, table-based IEEE
CRC-32 implementation. Compare it against an accelerated IEEE CRC implementation such as
[`crc32fast`](https://docs.rs/crc32fast/latest/crc32fast/), which offers SIMD acceleration.

Typical STUN messages are small, so dispatch and setup costs may limit the gain. Keep this
below payload scanning and layout conversion unless ICE/STUN processing dominates the
workload. Retain the protocol's final fingerprint XOR.

SCTP already uses hardware-dispatched `crc32c` in
[`packet.rs`](rtc-sctp/src/packet.rs) and [`util.rs`](rtc-sctp/src/util.rs). Its Castagnoli
polynomial differs from STUN's IEEE polynomial; the checksum implementations are not
interchangeable. Hardware CRC instructions are also distinct from general SIMD.

### Resolution

`fingerprint_value` uses `crc-fast`'s CRC-32/ISO-HDLC, retaining the final XOR. `crc-fast` folds with
carry-less multiplication (PCLMULQDQ/VPCLMULQDQ on x86 and x86-64, PMULL on aarch64, detected at
runtime) and falls back to slice-by-16 tables — what the fingerprint used before — elsewhere. It was
chosen over `crc32fast` because it also handles section 7's non-reflected CRC, so one dependency
serves both; the two tied at STUN sizes. A test checks it against the previous table-driven `crc`
implementation at every length through 1,500 bytes and every alignment.

| Benchmark | Before | After | Speed-up |
|---|---:|---:|---:|
| `Fingerprint/value/20B` | 7.98 ns | 3.91 ns | 2.0× |
| `Fingerprint/value/100B` | 26.2 ns | 6.96 ns | 3.8× |
| `Fingerprint/value/200B` | 57.7 ns | 6.67 ns | 8.6× |
| `Fingerprint/value/548B` | 133 ns | 16.6 ns | 8.0× |
| `Fingerprint/value/1200B` | 276 ns | 55.0 ns | 5.0× |
| `BenchmarkFingerprint_Check` | 50.4 ns | 28.9 ns | 1.7× |

`crc-fast` is built without its default `ffi` and `panic-handler` features. Cargo still builds its
declared `cdylib` and `staticlib` crate types alongside the library, which adds a few seconds to a
clean build.

## 7. Ogg page checksums: measured hardware-acceleration candidate

[`OggWriter::write_page`](rtc-media/src/io/ogg_writer/mod.rs) checksums every output page
with a byte-at-a-time table recurrence. [`OggReader::parse_next_page`](rtc-media/src/io/ogg_reader/mod.rs)
does the same over the header, segment table, and payload when checksum verification is
enabled. Each reader/writer also builds and stores its own 256-entry checksum table.

This scans the entire encoded payload, making it more substantial than small header
operations. It affects Ogg recording/playback, not ordinary RTP forwarding.

Ogg uses polynomial `0x04c11db7`, non-reflected processing, initial state zero, and no final
XOR. The checksum field is zeroed while calculating and stored little-endian afterward.
See [Xiph's framing specification](https://xiph.org/ogg/doc/framing.html). Neither SCTP's
CRC-32C nor STUN's CRC configuration is interchangeable with this algorithm. The normal
`crc32fast::hash` API is not a drop-in replacement either.

An ARM64 prototype uses IEEE hardware CRC instructions after reversing the bits of each
input byte, with the accumulator reversed at entry and exit. Two variants were evaluated:

- Scalar bit reversal over 8-byte chunks plus hardware CRC.
- NEON `vrbitq_u8` over 16-byte chunks, followed by two hardware CRC updates.

The second variant emitted `rbit.16b` and `crc32x`. Both matched the existing recurrence
for four initial states, all starting alignments modulo 16, lengths 0–256 and selected
larger sizes through 65,307 bytes. The NEON version also matched continuation across
split updates. This checks the transformation against the existing implementation;
production integration still needs page-level fixtures and corruption tests.

Exploratory results from the current ARM64 host, in nanoseconds per buffer:

| Bytes | Existing table recurrence | Scalar reversal + CRC | NEON reversal + CRC |
|---:|---:|---:|---:|
| 80 | 134.3 | 4.7 | 3.2 |
| 1,200 | 3,287.2 | 121.3 | 120.7 |
| 8,192 | 23,008.0 | 938.9 | 936.7 |
| 65,307 | 183,718.5 | 7,625.3 | 7,627.7 |

These are hot-buffer kernel timings, using six rotated-order samples and the upper
median, with non-inlined calls and `black_box`. They exclude dispatch, table construction,
page assembly, allocation, and I/O; they have no statistical confidence intervals. The
machine's CPU model could not be read under the sandbox, so treat them as local exploratory
evidence rather than a portable performance claim.

The measured 24–27× advantage for the larger inputs comes primarily from **hardware CRC**.
NEON and scalar bit reversal were essentially tied at those sizes. Prefer the simplest
accelerated variant that wins complete reader/writer benchmarks rather than adding SIMD
for its own sake. A portable fallback can also share a static table instead of building
one per instance; slice-by-N CRC is another baseline to compare before choosing a backend.

Reproduce on an ARM64 machine with CRC support:

```sh
rustc --edition=2024 --test -C opt-level=3 benchmarks/simd-probes/ogg_crc.rs -o /tmp/rtc-ogg-crc-test
/tmp/rtc-ogg-crc-test
rustc --edition=2024 -C opt-level=3 benchmarks/simd-probes/ogg_crc.rs -o /tmp/rtc-ogg-crc-bench
/tmp/rtc-ogg-crc-bench
```

The probe skips accelerated execution without CRC support. An implementation should
select its backend once, retain a portable fallback, and preserve incremental checksum
updates so the reader does not need to concatenate its buffers.

### Resolution

The ARM-only probe was not the production route. `PageChecksum` (in `rtc-media/src/io/ogg_reader`)
wraps `crc-fast` with the Ogg parameters, built once in a `static`, and updates incrementally: the
reader feeds the header with its checksum field zeroed, the segment table and the payload in turn,
without concatenating them, and the writer checksums the assembled page. The per-instance 256-entry
tables are gone. Being carry-less-multiply folding, it needs no per-byte bit reversal: timed back to
back it was 2.7× faster than the probe's best variant at 1,200 bytes (45.5 against 121.6 ns) and 4.7×
at 65,307. Other targets get slice-by-16 tables.

Tests: the check value; agreement with the old table walk for every length through 256 bytes at
every alignment and at larger sizes to 65,307; any split into three updates; the existing fixture
pages; and every single-bit corruption of a written page is rejected.

| Benchmark (whole page) | Before | After | Speed-up |
|---|---:|---:|---:|
| `Ogg/Write/80B` | 358 ns | 91.3 ns | 3.9× |
| `Ogg/Write/1200B` | 3.52 µs | 155 ns | 23× |
| `Ogg/Write/65025B` | 184 µs | 3.15 µs | 59× |
| `Ogg/Read/checksum/80B` | 337 ns | 107 ns | 3.2× |
| `Ogg/Read/checksum/1200B` | 3.54 µs | 170 ns | 21× |
| `Ogg/Read/checksum/65025B` | 186 µs | 4.00 µs | 46× |
| `Ogg/Read/no-checksum/*` | | | unchanged |

Verification now costs about as much as parsing the page without it.

## 8. RFC 8888 feedback: target decoding, verify encoding first

[`CcFeedbackReportBlock`](rtc-rtcp/src/transport_feedbacks/cc_feedback_report/mod.rs)
encodes and decodes contiguous runs of two-byte metric words. Each carries a received
bit, two ECN bits, and a 13-bit arrival offset. Those fields can be processed independently
across packets, unlike TWCC's cumulative arrival deltas.

The detailed compiler probes narrow the opportunity:

| Probe | ARM64 result |
|---|---|
| Existing metric packing through `bytes::BufMut::put_u16` | Auto-vectorized |
| Packing into `chunks_exact_mut(2)` | Also auto-vectorized |
| Existing metric decoding through `bytes::Buf::get_u16` and `Vec::push` | Scalar metric loop |
| Decode into a preallocated output slice | Still scalar |
| Mask-based rewrite of lost-packet handling | Still scalar |

The probes reused the actual metric type and word conversion methods, with a slice-backed
`Buf` and the locally resolved `bytes` dependency. They model the inner loops, not the
complete generic parser. Do not claim a new packing speedup merely from replacing
`put_u16`: the compiler already performed vector work in that probe.

The remaining experiment is a bounded bulk decoder for contiguous input, with explicit
SIMD or a layout that permits vector stores. Keep the generic `Buf` fallback because a
buffer may be fragmented. Avoid unsafe casts to the Rust-layout metric struct; construct
valid `bool` and `Ecn` fields. The cost of converting vector results to that struct may
erase the arithmetic gain, so this remains an unmeasured candidate.

Preserve lost-packet normalization: when the received bit is clear, the remaining bits
decode as zero. The probe checked all 65,536 wire words, and short/tail cases at different
byte offsets. Keep report bounds, odd-count padding, and reserved arrival offsets intact.
Measure realistic MTU-sized feedback: the recorder divides its byte budget between streams,
so the format's 16,384-metric maximum is not representative of every report.

[`StreamLog::metrics_after`](rtc-interceptor/src/rfc8888/stream_log.rs) is a separate
constraint: it performs per-sequence hash lookups/removals and time conversion. A bounded
ring with contiguous arrival/ECN storage could expose bulk processing, but would be a larger
data-structure change. Profile it before optimizing only the wire codec, and preserve the
rule that the first missing packet stops advancement of the retained report window.

### Resolution

`CcFeedbackReportBlock::unmarshal_from` decodes the metric words straight from `Buf::chunk()` when
that chunk holds all of them — the usual case, since a datagram arrives whole — and advances past
them and the padding; a fragmented buffer keeps the `get_u16` loop. Every bounds and budget check
runs before either path.

The bulk decoder is plain Rust (`as_chunks::<2>()`, the existing per-word decoder, `collect`). LLVM
vectorizes it itself, eight words per iteration, widening straight into the metric struct's layout.
A `wide::u16x8` version did the same arithmetic but then had to build each struct from vector lanes
through safe constructors, which cost more than it saved: 580 words took 120 ns plain, 400 ns with
`wide` and 530 ns through `get_u16`. So section 8's caution held, and `wide` was not kept. Encoding
was left alone; it already vectorized.

Tests: all 65,536 wire words decode identically in bulk and one at a time, contiguous and in 1-, 3-
and 16-byte fragments; reports split at every byte, compound packets, truncations and overstated
counts produce identical results and errors either way.

| Benchmark (MTU-sized reports) | Before | After | Speed-up |
|---|---:|---:|---:|
| `CCFB/Unmarshal/1x590` | 684 ns | 157 ns | 4.3× |
| `CCFB/Unmarshal/4x144` | 781 ns | 236 ns | 3.3× |
| `CCFB/Unmarshal/4x144/split` | 1.64 µs | 602 ns | 2.7× (the unsplit blocks take the bulk path) |
| `CCFB/Unmarshal/1x590/split` | 1.58 µs | 1.58 µs | unchanged (fallback) |

As suspected, the codec is not where the sender spends its time. For one MTU report of about 590
packets, `CcFeedbackRecorder::build_report` (`StreamLog::metrics_after`) took about 17 µs against
0.15 µs to marshal it, dominated by SipHash lookups and removals in its `HashMap` and
`Instant` arithmetic. The ring-buffer restructuring is left for a separate change.

## 9. TWCC circular-buffer gaps and scans

[`PacketArrivalTimeMap::set_not_received`](rtc-interceptor/src/twcc/arrival_time_map.rs)
sets each missing entry to `-1` through a masked circular index. For a range fitting within
the buffer, split at the wrap into at most two contiguous slices and use `.fill(-1)`.

The isolated indexed loop remained scalar. The two-slice prototype lowered to `memset`
calls, exposing the operation to the platform's bulk-memory implementation. This removes
per-element circular indexing; it is not evidence that custom SIMD is needed or that the
particular `memset` implementation was measured.

Equivalence checks covered power-of-two capacities through 512, negative and positive
sequence numbers, wrapping ranges, empty ranges, and full-capacity clears. Production
code must establish the range-length invariant after resizing. Keep the existing path
that handles a jump beyond the retained window without clearing every skipped sequence.

`reallocate` similarly copies through per-sequence circular indices. A small number of
contiguous copies can handle the old/new wrap boundaries. `find_next_at_or_after` and
`remove_old_packets` could scan contiguous timestamp blocks using comparison masks, but
benchmark this only for loss/reordering patterns with long gaps; normal short scans may
not repay dispatch/setup. Preserve sequence-order early termination when arrivals are
not time-ordered.

### Resolution

`set_not_received` splits its range at the wrap into at most two slices and fills them with `-1`
(the whole buffer when the range covers it), keeping the reset path for jumps beyond the window.
`reallocate` copies at most three contiguous runs. `find_next_at_or_after` and `remove_old_packets`
scan at most two contiguous slices, stopping at the first match in sequence order as before; after
eight values checked one at a time, the scan compares eight per step as two `wide::i64x4` vectors.
The scalar prefix matters: `remove_old_packets` runs for every packet and usually stops at the first
value, and without it the steady-state benchmark was 4.5% slower.

Verbatim copies of the old map are test references over random operation sequences — negative and
positive unwrapped sequence numbers, out-of-order times, growth, shrinking, resets and refused
packets — comparing every slot, and over arbitrary states at capacities 128–32,768.

| Benchmark | Before | After | Change |
|---|---:|---:|---:|
| `Feedback/TwccReceiver/steady` | 9.46 µs | 9.66 µs | ~ (+2.1%, within noise) |
| `Feedback/TwccReceiver/gap-1000` | 12.9 µs | 12.5 µs | ~ (−3.0%) |
| `Feedback/TwccReceiver/gap-8000` | 32.0 µs | 29.0 µs | −9.6% |

`wide` compiles 64-bit lane comparisons to NEON on aarch64 and to SSE4.2 or AVX2 on x86-64 only when
those are enabled at build time; baseline x86-64 builds (SSE2) get per-lane scalar code, no worse
than the loop it replaced.

## 10. NACK bit scans: use whole words before SIMD

Two existing bitmaps still get scanned bit by bit:

- [`ReceiveLog::missing_seq_numbers`](rtc-interceptor/src/nack/receive_log.rs) tests every
  sequence number, despite storing receipt state in `Vec<u64>`.
- [`NackIterator::next`](rtc-rtcp/src/transport_feedbacks/transport_layer_nack/mod.rs)
  starts its bit-position search at zero on every call, despite already having a `u16`
  mask of the remaining losses.

For the receive log, mask the first/last words to the requested range, invert received
bits, skip zero words, and enumerate missing bits with `trailing_zeros` and `word &= word - 1`.
For the wire NACK iterator, use the same bit-scan operation directly on the remaining mask.
Keep wrapping sequence arithmetic and ascending output order.

An isolated receive-log prototype matched the current function across all supported
window sizes (64–32,768), all-received/all-missing/mixed patterns, sequence wraparound, and
five skip settings per scenario. The NACK-pair bit scan matched for all 65,536 `u16` masks.
The ten existing receive-log tests also passed in the copied probe module.

These are scalar word-processing improvements, not new SIMD. Larger bitmap batches might
eventually justify vector comparisons to skip several full words at once, but first measure
the simpler approach. Clearing intermediate gaps and finding the last consecutive packet
can likewise use word masks; `add` already uses a full-buffer `.fill(0)` for jumps larger
than its window, so that case is already addressed.

The [NACK responder](rtc-interceptor/src/nack/responder.rs) separately enumerates all 16
positions in every `NackPair::lost_packets`. It does not currently use `NackIterator`.
Any iterator improvement should be wired into this path, or the retransmission handler
will retain its existing scan. Preserve the base packet, ascending sequence order, and
wrapping additions.

### Resolution

A crate-private module, `rtc-interceptor/src/bitmap.rs`, provides circular-bitmap operations a word
at a time — count, enumerate and find clear bits, and clear a range — splitting at the wrap and
masking edge words, with ranges longer than the bitmap re-reading it exactly as the per-bit loops
did. `ReceiveLog::missing_seq_numbers` enumerates with `trailing_zeros` and `w &= w - 1`, its gap
clearing uses masked edge words and filled full words, and `fix_last_consecutive` finds the first
clear bit a word at a time. `NackIterator::next` scans the remaining mask directly and has an exact
`size_hint`; the NACK responder now iterates pairs through it, in the same order, without collecting
sequence numbers into a `Vec`. This is scalar word processing, as the section recommended; no wider
vectors were needed.

Tests compare against verbatim copies of the old code: every window size 64–32,768 under random
loss, reordering, duplicates and jumps around the window size and the wrap, arbitrary starting
states, all 65,536 NACK masks at wrapping bases, and the responder's retransmission order with and
without RTX.

| Benchmark (16 streams) | Before | After | Speed-up |
|---|---:|---:|---:|
| `Feedback/NackGenerator/loss-1pct/512` | 6.84 µs | 2.20 µs | 3.1× |
| `Feedback/NackGenerator/loss-1pct/8192` | 107 µs | 13.3 µs | 8.1× |
| `Feedback/NackGenerator/loss-10pct/512` | 13.0 µs | 7.98 µs | 1.6× |
| `Feedback/NackGenerator/burst-200/512` | 13.5 µs | 11.4 µs | 1.2× |
| `Feedback/NackResponder/absent` | 472 ns | 284 ns | 1.7× |
| `Feedback/NackResponder/sparse` | 1.49 µs | 1.30 µs | 1.14× |
| `Feedback/NackResponder/dense` | 7.32 µs | 6.76 µs | 1.08× |

## 11. Receiver-report loss counts: vectorize the bitmap reduction

[`ReceiverStream::generate_report`](rtc-interceptor/src/report/receiver_stream.rs) walks
each sequence number and checks one bit to count losses. Its receipt history is already
a `Vec<u64>` with 128 words, covering 8,192 packets. Unlike NACK generation, it only needs
a count, so it can use a reduction rather than enumerate individual missing packets.

Mask partial first/last words, split at the circular-buffer boundary, and sum
`(!word).count_ones()` over the full-word slices. This uses safe Rust. The
[retained prototype](benchmarks/simd-probes/receiver_loss.rs) generated NEON `cnt.16b` and
vector reduction instructions; the per-bit reference remained scalar. Explicit SIMD
intrinsics were unnecessary.

Local isolated timings for a mixed 8,192-bit bitmap, in nanoseconds per query:

| Sequence positions examined | Per-bit walk | Masked word popcount |
|---:|---:|---:|
| 32 | 29.2 | 3.5 |
| 256 | 254.3 | 9.1 |
| 1,024 | 1,024.5 | 10.3 |
| 8,191 | 8,223.2 | 31.8 |

The kernel tests cover zero/full/mixed words, partial words, sequence wrap, empty ranges,
and ranges longer than the bitmap capacity. They passed for bitmap sizes from 64 through
32,768 bits and selected counts through 65,535. As with the other probes, timings use
hot buffers and upper medians of six rotated-order samples, without confidence intervals.
They exclude report allocation, serialization, jitter updates, and scheduling.

Preserve the existing endpoints when integrating: `generate_report` counts from
`last_report_seq_num + 1` up to, but excluding, `last_seq_num`, and uses a separate wrapping
distance as the fraction-lost denominator. A kernel replacement must not silently change
that behavior. Nor does reproducing cyclic reads resolve the separate question of reporting
intervals that exceed retained history; those need explicit semantics and full-report tests.

This path is present in the default interceptor configuration, but receiver reports are
generated once per second by default. The large kernel improvement does not translate to
the same per-packet gain. Measure complete report generation with realistic packet rates
and many streams before assigning it a whole-stack priority.

The adjacent `process_rtp` gap-clearing loop also clears one bit per skipped sequence.
Masked edge words plus bulk-cleared full words can reduce that work, but preserve the
relationship between clearing old history and recording the newly received packet when
a jump wraps the bitmap. This was not implemented or timed in the prototype.

### Resolution

`generate_report` counts losses with `bitmap::count_zeros` (section 10) over exactly the old range —
`last_report_seq_num + 1` up to, but excluding, `last_seq_num` — keeping the separate fraction-lost
denominator and the 24-bit clamps. The full-word popcount sum vectorizes to NEON `cnt.16b` on its own.
The `process_rtp` gap clearing uses `bitmap::clear` after `set_received`, so a jump longer than the
8,192-packet bitmap still clears the new packet's own bit, as before. Reports over random RTP
sequences with wrap, reordering, duplicates and jumps above 8,192 and 32,768 match the per-packet
reference, bitmap included, at every step.

| Benchmark (one report interval, packets included) | Before | After | Change |
|---|---:|---:|---:|
| `Feedback/ReceiverReport/audio-50pps/64-streams` | 173 µs | 175 µs | ~ |
| `Feedback/ReceiverReport/video-1000pps/16-streams` | 837 µs | 838 µs | ~ |
| `Feedback/ReceiverReport/video-outage/16-streams` | 1.32 ms | 843 µs | −36% |

As predicted, a once-per-second report hides the kernel's gain behind per-packet processing; it
shows only when an outage leaves thousands of packets to count and clear.

## 12. PCM sample conversion: expose batches, preserve arithmetic

[`Sample<i16>` / `Sample<f32>` conversions](rtc-media/src/audio/sample.rs) are per-sample,
inline operations. A slice loop invoking the existing conversions already produced SIMD
in both directions in the third-pass compiler probe:

- `i16` to `f32`: vector widening, integer-to-float conversion, selection, and `fdiv.4s`.
- `f32` to `i16`: vector comparisons/selections, multiplication, conversion, and narrowing.

A bulk conversion API, or fusing conversion with the stereo layout paths, could make this
behavior easier for applications to obtain and avoid intermediate buffers. There is no
evidence here that handwritten conversion intrinsics beat the compiler-generated loop.
These PCM helpers still have the application-usage limitation described in section 2.

Do not replace the division with reciprocal multiplication as an exact optimization:
an exhaustive local probe of all 65,536 `i16` inputs found **768 differing `f32` bit patterns**.
The current normalization also deliberately uses 32,768 for negative values and 32,767
for nonnegative values. Uniform scaling would change its endpoint behavior.

Any bulk API should preserve clamping, NaN behavior, float-to-integer conversion semantics,
tails, and exactness expectations. Benchmark it independently from allocation and layout
conversion. Approximate arithmetic would require an explicitly different contract.

### Resolution

`Sample::<f32>::convert_from_i16_slice` and `Sample::<i16>::convert_from_f32_slice` convert a slice at
a time with `wide`, eight lanes and four vectors per iteration, and fall back to the per-sample
`From` for the tail. `i16`→`f32` divides by the sign-selected divisor with IEEE division; `f32`→`i16`
multiplies by the sign-selected factor, truncates with saturation and NaN→0 (`wide` masks NaN
explicitly on its SSE2 and AVX paths), and narrows with saturation — exactly Rust's `as i16`. Results
are bit-identical to the per-sample conversions for all 65,536 `i16` inputs and all 2^32 `f32` bit
patterns (a release-only test, run once), including the NaN a clamped `Sample<f32>` can still hold.

| Benchmark (`rtc-media:pcm`, new API, so head only) | Per sample | Slice | Speed-up |
|---|---:|---:|---:|
| `i16-to-f32`, 1,920 samples | 402 ns | 230 ns | 1.75× |
| `i16-to-f32`, 200,000 samples | 42.0 µs | 24.4 µs | 1.72× |
| `f32-to-i16`, 1,920 samples | 191 ns | 191 ns | tie |
| `f32-to-i16`, 200,000 samples | 19.9 µs | 19.9 µs | tie |

`f32`→`i16` emits the same instructions as the compiler's own vectorization of the per-sample loop.
It stays on `wide` because, reading the generated code for wasm32 with `simd128`, the per-sample
loop stays scalar there while the `wide` kernel vectorizes; that was not timed. Fused
layout-plus-conversion was not implemented.

## Lower-priority areas

- Small nonce, header, and key-derivation XORs offer little bulk work per call.
- Packet state machines and congestion-control updates have branches and sequential
  dependencies; vectorizing individual updates is unlikely to be the first useful change.
- NACK bitmap scans are better candidates for whole-word masks and bit scans before
  introducing SIMD; see the concrete candidates above.
- TWCC status-vector chunks contain only 7 or 14 symbols. The recorder allocates/clones
  small vectors around them; compact storage and run-length handling are better first
  experiments than dispatching SIMD per chunk.
- SDP already uses `BufRead::read_until` and `read_line` for major delimiters. Its per-field
  allocation and seek behavior should be profiled before adding another scanner. DNS names
  and RTP extension headers also have short, variable-length, branch-heavy structure.
- The default 64-bit replay window is only one word. Larger windows merit separate
  investigation, but custom SIMD should not complicate the common one-word path. A third-pass
  probe of the current multi-word shift and a simpler reverse loop specialized for a one-bit
  shift generated scalar code for both. The specialized loop matched the original for full-word windows
  of 1–128 words over 130 successive shifts, but no SIMD or timing benefit was demonstrated.
- AV1 variable-length size fields and SCTP SACK handling have short/dependent parses or
  per-chunk state updates. No new bulk SIMD candidate was established there in this pass.

Prefer auto-vectorization and existing accelerated dependencies first. If explicit SIMD
is justified, retain scalar fallbacks and dispatch appropriately for the target CPU.
Avoid requiring nightly solely for this work: `std::simd` remains experimental according
to the [Rust documentation](https://doc.rust-lang.org/std/simd/struct.Simd.html).

## Benchmark and implementation sequence

1. Add representative H.264 scanner and full packetization/reader benchmarks, then evaluate
   SIMD-backed search with unchanged boundary semantics.
2. Expand audio benchmarks to include mono/stereo, realistic frame counts, and relevant
   sample types. Compare allocation-free kernels and complete buffer conversions.
3. Verify crypto acceleration from an external consumer build and with the supported
   providers. Benchmark CBC batching separately if CBC is used.
4. Add FlexFEC encode/recovery benchmarks to determine whether allocation, serialization,
   or XOR dominates before choosing an optimization.
5. Evaluate STUN CRC alternatives on realistic message sizes.
6. For Ogg recording/playback workloads, prioritize a portable bulk-checksum API and
   hardware CRC backend; compare whole-page operations using both accelerated probes.
7. Add realistic RFC 8888 decode and TWCC loss/reordering benchmarks. Verify the inner
   loops' share of complete feedback processing before changing data layouts.
8. Measure word-wise NACK scans against the current bitmap walk before considering wider
   vector scans.
9. Replace receiver-report per-bit loss counting with a word reduction as a measured
   experiment, then benchmark full report generation and many-stream workloads.
10. If applications use PCM conversion heavily, expose slice conversion and fused layout
    paths while retaining the existing arithmetic semantics.

All ten steps were carried out; each section's Resolution has the outcome. The audio benchmark's
reversed labels are fixed and it now covers mono, stereo and four channels at realistic frame
counts; the RTP benchmark now measures H.264 packetization; and the new targets are listed in
[docs/benchmarking.md](docs/benchmarking.md#inventory).

Compare changes on the same machine with identical toolchains, optimization settings,
CPU targeting, and effective rustflags. Measure ARM64 and x86-64 independently. Inspect
release assembly, validate correctness outside timed regions, and use the existing
[benchmark workflow](docs/benchmarking.md) to connect kernel results with whole-operation
and end-to-end costs.
