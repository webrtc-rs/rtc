# Benchmarking

How the workspace's benchmarks are organised, how to run and compare them, and how to add one.

The one rule, from [`benchmarking-crypto-migration.md`](benchmarking-crypto-migration.md), which
learned it the hard way: **compare only numbers taken on the same machine, in the same session,
with the same settings.** `scripts/bench.py compare` exists so that following it takes one
command.

## Contents

- [The suite](#the-suite)
- [Running](#running)
- [Comparing two revisions](#comparing-two-revisions)
- [Comparing with upstream](#comparing-with-upstream)
- [RUSTFLAGS silently changes the numbers](#rustflags-silently-changes-the-numbers)
- [Builds outside this repository](#builds-outside-this-repository)
- [The end-to-end harness](#the-end-to-end-harness)
- [Allocations per packet](#allocations-per-packet)
- [Not covered yet](#not-covered-yet)
- [Adding a benchmark](#adding-a-benchmark)
- [CI](#ci)

## The suite

Five kinds of measurement, each answering a different question:

| Kind | Where | Answers |
|---|---|---|
| Protocol | `rtc-*/benches/` | What does one operation cost — marshal a packet, protect a record, check a replay window? |
| End-to-end | `benchmarks/rtc-bench/` | What does the assembled stack cost inside an `RTCPeerConnection` — per packet, per byte, per connection? |
| Allocation | `benchmarks/rtc-bench/benches/allocations.rs` | How many heap allocations does each packet or message cost, and on which side? |
| Behaviour | `rtc-interceptor/benches/congestion_control.rs` | How *well* does an algorithm do — convergence, utilisation — rather than how fast it runs |
| Fixed-work | `rtc-sctp/examples/sctp_{e2e,micro}.rs`, `benchmarks/aead-gcm/` | A deterministic workload for `perf`, `poop` or a one-off A/B, where a statistical harness gets in the way |

The protocol and end-to-end layers are designed to be read together. The same data-channel transfer
is measured three times, and the gaps between the three show what each layer costs:

| Benchmark | Measures |
|---|---|
| `SCTP/Packet/*` | the SCTP packet codec alone |
| `SCTP/Transfer/*` | two SCTP associations, no encryption |
| `DataChannel/Throughput/*` | the same transfer through DTLS, the data-channel layer, and the peer-connection pipeline |

Media works the same way: `SRTP/*` and the RTP marshal benches measure the parts, and
`Track/Send/*` and `Track/Receive/*` measure a packet's whole path through a connected peer, with
and without the default interceptor chain.

### Inventory

`python3 scripts/bench.py list` prints the current set. At the time of writing:

| Target | Benchmark groups |
|---|---|
| `rtc-bench:peer_connection` | `PeerConnection/Build/*`, `PeerConnection/Signaling/offer-answer/*`, `PeerConnection/Connect/*` |
| `rtc-bench:data_channel` | `DataChannel/Throughput/{reliable,unreliable}/<size>/<provider>` |
| `rtc-bench:media` | `Track/{Send,Receive}/{audio,video}/{no,default}-interceptors/<provider>`, `Track/{Send,Receive}/{4,16}-video-tracks/default-interceptors/<provider>` |
| `rtc-bench:allocations` | allocation report, not a criterion benchmark |
| `rtc-dtls:record_protection` | `DTLS/{Setup,Encrypt,Decrypt}/<cipher>/<provider>` |
| `rtc-srtp:bench` | `SRTP/{Encrypt,Decrypt}/{RTP,RTCP}`, `SRTP/Setup/*`, AEAD per provider |
| `rtc-sctp:bench` | `SCTP/Transfer/reliable/<size>`, `SCTP/Packet/{marshal,unmarshal}/*` |
| `rtc-shared:replay_detector` | `ReplayDetector/{SlidingWindow,WrappedSlidingWindow}/{in-order,reordered,duplicate}/<window>` |
| `rtc-ice:bench` | `ICE/Candidate/{marshal,unmarshal}/<form>` |
| `rtc-stun:bench`, `rtc-turn:bench` | message and attribute encode/decode, integrity, fingerprint; `Fingerprint/value/<size>` is the CRC alone across STUN message sizes |
| `rtc-rtp:bench` | packet marshal and unmarshal; `H264/Payload/*`, H.264 packetization including the Annex B start-code scan |
| `rtc-rtcp:bench` | packet marshal and unmarshal; `CCFB/{Marshal,Unmarshal}/*`, RFC 8888 feedback at MTU size, contiguous and fragmented |
| `rtc-sdp:bench` | session description marshal and unmarshal |
| `rtc-media:bench` | `Audio/{Deinterleave,Interleave,FromBytes}/*`, audio buffer layout conversion |
| `rtc-media:pcm` | `Audio/PCM/*`, `i16`/`f32` sample conversion, per sample and a slice at a time |
| `rtc-media:h26x` | `H26x/Reader/*`, reading an Annex B stream into NAL units |
| `rtc-media:ogg` | `Ogg/{Write,Read}/*`, whole Ogg pages including the page checksum |
| `rtc-interceptor:feedback` | `Feedback/{NackGenerator,NackResponder,ReceiverReport,TwccReceiver}/*`, feedback interceptors under loss and gaps |
| `rtc-interceptor:flexfec` | `FlexFec/{Encode,Recover,RecoverRepair}/*`, FlexFEC-03 repair packets |
| `rtc-interceptor:congestion_control` | behaviour report, not a criterion benchmark |

The two report targets are not run by `bench.py run` unless named (`--bench
rtc-bench:allocations`), since there is nothing for criterion to save or compare. `bench.py check`
runs them.

Each target's source opens with a comment saying what it measures, what it deliberately does not,
and how to run it on its own. The crates that have recorded results keep them in
`benches/README.md`.

## Running

```bash
python3 scripts/bench.py run                         # everything, criterion's default timing
python3 scripts/bench.py run --quick                 # 1 s warm-up, 2 s measurement
python3 scripts/bench.py run -p rtc-srtp -p rtc-bench
python3 scripts/bench.py run --bench rtc-bench:media --filter 'Send/video'
python3 scripts/bench.py run --providers all         # both crypto backends, side by side
```

`run` builds every selected target before measuring any of them, runs each with identical
criterion arguments, and saves the results as a named criterion baseline. The name defaults to the
short commit, with `-dirty` appended when the tree has uncommitted changes. It prints a table of the
results and records the machine, OS, toolchain, `RUSTFLAGS` and criterion arguments alongside them
in `target/criterion/rtc-bench-meta/`. `report NAME` reprints that table later; `report A B` compares
two saved baselines.

`--quick` numbers are for spotting a gross change while iterating. Do not quote them.

`--filter` is criterion's: a regex matched anywhere in the benchmark id, so `'AEAD'` or
`'/aws-lc-rs$'` both work. A target with no matching benchmark runs nothing.

### Running with cargo directly

Always name the target:

```bash
cargo bench --package rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5
```

`cargo bench -p rtc-srtp -- <args>` without `--bench` also passes the arguments to the library's
libtest harness, which rejects criterion's options and aborts the run before any benchmark starts.
`--benches` does not help, since it includes the library. (`rtc-bench` sets `bench = false` on its
library, so it alone tolerates the short form.)

Some targets need a feature to cover everything. `rtc-sctp`'s packet benchmarks need `--features
bench`, which exposes the codec through the `fuzzing` shims. `bench.py` knows this; with cargo you
have to pass it yourself.

## Comparing two revisions

```bash
python3 scripts/bench.py compare master                        # master vs. the working tree
python3 scripts/bench.py compare master --rounds 3             # what to quote
python3 scripts/bench.py compare v0.21.0 --head master -p rtc-srtp
```

What it does, in order:

1. **Checks out BASE in a git worktree outside this repository** (`~/.cache/rtc-bench/worktrees/`
   by default) and reuses it next time, so its `target/` stays warm. Outside, because cargo merges
   `.cargo/config.toml` from every parent directory: a worktree nested in this checkout would build
   the old revision with the current revision's rustflags.
2. **Copies this tree's `Cargo.lock` into the worktree.** The lockfile is not tracked here, so a
   fresh checkout would resolve every dependency anew — perhaps to a newer `ring` than the tree it
   is compared with, which would be measured as a change in `rtc`. Any dependency that still
   resolves differently after that is listed in the report.
3. **Builds both sides before measuring either.** Compilation does not heat the machine between
   two measurements.
4. **Runs BASE and HEAD alternately**, `--rounds` times, into one results directory
   (`target/bench-compare/<base>-vs-<head>/`), so slow drift — thermal throttling, a background
   indexer — lands on both sides instead of one.
5. **Writes `report.md`** with the machine, toolchain, flags, notes and a table. A benchmark process
   that fails partway — killed from outside, say — is noted in the report and the rest of the run
   carries on; its rows cover the rounds that completed.

The selection (`-p`, `--bench`, `--filter`) is defined against HEAD. BASE runs whatever part of it
exists there, and anything new appears under *Only in head* rather than failing the comparison.
For a BASE that predates part of the suite, `--overlay-benches` runs HEAD's benchmarks there
instead; see [Comparing with upstream](#comparing-with-upstream).

### Reading the report

```text
**0 slower, 0 faster, 8 within noise.** Ranges are the fastest and slowest round. `~` means the
ranges overlap or the change is under 3%.

| Benchmark                                | Base     | Head     | Change |   |
|------------------------------------------|---------:|---------:|-------:|---|
| `SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring` | 334.5 ns | 325.1 ns |  -2.8% | ~ |
| `SRTP/Encrypt/RTP`                       | 7.283 µs | 7.28 µs  |  -0.0% | ~ |
```

That is an A/A run — `rtc-srtp` identical on both sides, two quick rounds on an M1 Max — and it is
worth doing once on a new machine. It shows the noise floor directly: here, nothing moved by more
than 2.8%. (The 7.28 µs is not a typo: that shell exported `RUSTFLAGS`. See the next section.)

- With one round, a benchmark's range is criterion's 95% confidence interval. With several, it is
  the spread between the fastest and slowest round, and the headline is their median. The
  run-to-run spread is the noise that matters for a before/after question; a single run's interval
  understates it. Use `--rounds 3` for anything you will quote.
- A result is flagged `slower` or `faster` only when the two ranges do not overlap **and** the
  change exceeds `--threshold` (3% by default — the noise floor measured during the crypto
  migration). Everything else is `~`.
- The headline figure is the one criterion prints: the regression slope under linear sampling,
  otherwise the mean.
- A comparison is only as sound as the benchmark being the same on both sides. If the benchmark's
  source changed between BASE and HEAD, check the diff (`git diff BASE -- path/to/bench.rs`) before
  trusting the row, or compare with `--overlay-benches`, which runs HEAD's benchmark sources on both
  sides. Procedure A in the migration doc covers this.

For quoting results in a crate's `benches/README.md`, follow the
[reporting rules](benchmarking-crypto-migration.md#reporting). The report header already carries
most of what they ask for.

## Comparing with upstream

```bash
python3 scripts/bench.py upstream                              # this fork vs. webrtc-rs/rtc master
python3 scripts/bench.py upstream --rounds 3 -p rtc-bench      # what to quote
python3 scripts/bench.py upstream --branch v1.x --head master  # another branch, a committed fork revision
python3 scripts/bench.py upstream --no-fetch --quick           # reuse the last fetch
```

This repository is a fork of [webrtc-rs/rtc](https://github.com/webrtc-rs/rtc). `upstream` measures
what the fork's changes are worth against it: BASE is upstream's branch (`master` by default), HEAD
is this fork — the working tree, or `--head REV`. It is `compare` with two additions:

1. **It fetches the upstream branch** into a private ref, `refs/bench/upstream/<branch>`. No remote
   or branch is added to the repository. `--url` points it at a different repository;
   `--no-fetch` reuses the last fetch.
2. **It runs this fork's benchmarks on upstream too** (the same as `compare --overlay-benches`).
   Upstream has only the per-crate benchmarks it shipped with — none of `benchmarks/rtc-bench`,
   and not the `rtc-sctp`, `rtc-shared` or `rtc-ice` benches — so a plain comparison would measure
   only those. The overlay copies every HEAD bench source that is missing or different into
   upstream's worktree, then adds what upstream's manifests lack for them: `[[bench]]` targets,
   dev-dependencies, bench features, and `benchmarks/rtc-bench` as a workspace member. Both sides
   then compile identical benchmark code, and the only difference measured is the library under
   it.

The report says exactly what the overlay copied and added. Everything else in upstream's tree is
left as it is, and the overlaid worktree (`…/worktrees/rtc-<sha>-overlay`) is kept apart from a
plain one and reset before each run, so a later plain `compare` never sees the overlay.

A benchmark written against an API this fork added or changed may not compile against upstream.
Such a target is left out at BASE, listed in the report as *measured at head only*, and the rest of
the comparison goes ahead. Everything else from [Comparing two revisions](#comparing-two-revisions)
applies unchanged: same machine, alternating rounds, `--rounds 3` for anything you will quote.

## RUSTFLAGS silently changes the numbers

An exported `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS` **replaces** the rustflags in
`.cargo/config.toml` rather than adding to them, and whatever it adds — a `target-cpu`, a codegen
option — applies to every crate. Even something as innocuous as `RUSTFLAGS=-Awarnings` changes what
is built.

This used to cost 4× on SRTP. `rtc-crypto` ran on `aes` 0.8, whose ARMv8 backend was compiled in
only with `--cfg aes_armv8`, which the config supplied. Measured on an M1 Max, `SRTP/Encrypt/RTP`
(AES-128-CM-HMAC-SHA1-80) took **7.28 µs** with `RUSTFLAGS=-Awarnings` and **1.72 µs** with the
cfgs added back, while the AEAD path on `ring` stayed at about 313 ns either way. An asymmetry
between cipher suites was the signature. `rtc-crypto` now uses `aes` 0.9, which detects the
hardware at runtime, so no rtc crate depends on the config's cfgs any more; they remain only for
dev dependencies (see the comment in `.cargo/config.toml`).

`bench.py` still prints a warning when either variable is set and records its value in every
report. A comparison is sound as long as both sides see the same flags, which `compare`
guarantees. The absolute numbers are what change.

## Builds outside this repository

The same mechanism has a second consequence, for applications rather than benchmarks: cargo reads
`.cargo/config.toml` from the directory it runs in, so a project depending on rtc never gets this
repository's rustflags. Every number measured here would stay fast while an application's build was
slow, and no in-repository benchmark could notice. That was the case with `aes` 0.8: an application
built on aarch64 got software AES, 27× slower on a 1,200-byte AES-128-CTR keystream.

```bash
python3 scripts/bench.py external
```

This builds [`benchmarks/external-consumer`](../benchmarks/external-consumer) three ways — from
outside the repository with rustflags cleared, as an application would; from the repository root;
and with RustCrypto's software AES forced, for reference — and fails if the first is more than 1.5×
slower than the second on any RustCrypto path. Run it after changing crypto dependencies or
`.cargo/config.toml`.

## The end-to-end harness

`benchmarks/rtc-bench` is a workspace member that is never published. Its library provides
`PeerPair`, two `RTCPeerConnection`s joined by an in-memory wire, and the benches build on it. The
crate documentation has the detail; the points that decide how to read its numbers are:

- **No sockets, virtual time.** The peer connection is sans-I/O, so the harness moves datagrams
  between two queues and advances the clock by arithmetic, jumping straight to the next deadline
  when both sides are idle. A run measures CPU spent in `rtc` and nothing else — no syscalls, no
  scheduler, no sleeping to reach a retransmission timer.
- **Lossless and zero-latency.** Congestion control, loss recovery and pacing never engage. These
  are CPU-cost numbers, not network-throughput predictions. Dynamics belong to the behaviour
  reports.
- **Cost is attributed per side.** Every call into a peer is timed and charged to it
  (`Peer::busy`), which is how `Track/Send/*` and `Track/Receive/*` separate the sender's work from
  the receiver's on one connection. Packets go in bursts of 16 so the stopwatch reads amortise to a
  small fraction of a microsecond-scale cost.
- **Certificates are made once.** Otherwise ECDSA key generation (about 42 µs) would dominate
  anything measured around construction. `PeerConnection/Build/generate-certificate/*` measures it
  on its own.
- **Periodic work is included, at its real rate.** Virtual time advances by the media's packet
  interval, so RTCP reports, TWCC feedback and ICE consent checks fire as they would in a call and
  are amortised over the packets.
- **Every benchmark checks it measured the intended path.** A transfer waits until every byte is
  read; a media run asserts every packet was delivered; the harness errors if either side reaches
  `failed` or makes no progress within 120 s of virtual time. A benchmark that silently measures a
  failing path is worse than one that fails.

## Allocations per packet

```bash
python3 scripts/bench.py run --bench rtc-bench:allocations
```

Timing says how long the packet path takes; allocation counts say a good part of why. The
`allocations` target installs a counting global allocator and runs the same workloads as `media`
and `data_channel` on the same harness, charging every allocation to the peer whose call made it:

```text
| Workload                              | Per     | Send allocs | Send bytes | Receive allocs | Receive bytes |
|---------------------------------------|---------|------------:|-----------:|---------------:|--------------:|
| `Track/video/default-interceptors`    | packet  |        4.25 |       3082 |           6.07 |          2400 |
| `DataChannel/reliable/1KiB`           | message |       15.12 |       9264 |          16.12 |          8131 |
```

Unlike timings, these counts are deterministic: two runs of the same revision print identical
tables, on any machine. So they can be compared across machines and sessions, and a change of one
allocation per packet is a real change, never noise. They are allocation *traffic* — frees are not
subtracted — which is what allocator pressure follows; retained memory needs a different tool.

To count allocations in a new benchmark, install `rtc_bench::allocations::CountingAllocator` as the
`#[global_allocator]` of that bench binary and read `Peer::allocations()`. Keep it out of criterion
targets: the counter's atomic increments are cheap, but they are not free, and they would be timed.

## Not covered yet

The harness is built to make these straightforward to add, but today it has none of them:

- **Loss, reordering and duplication.** The wire is a pair of FIFO queues. A lossy wire — dropping or
  reordering inside `PeerPair::pump` under a seeded RNG — would bring NACK, RTX, SCTP retransmission
  and the replay window's reorder path into the end-to-end numbers. (`rtc-interceptor:feedback`
  drives the NACK, receiver-report and TWCC interceptors under loss and gaps directly, but not
  through a connection.)
- **A consumer that stops reading.** `pump` always drains `poll_read`. Measuring back-pressure needs
  a driver that withholds it, as `tests/data_channel_backpressure_rtc2rtc.rs` does over sockets.
- **Simulcast.** Tracks have one encoding each; RID-tagged layers and RTX pairing are not exercised.
- **Many connections.** Every benchmark uses one pair. Per-connection overhead at scale — the SFU
  case — needs a harness that multiplexes many.
- **Latency percentiles.** Criterion reports central estimates. A p99 per-packet figure needs
  per-packet timing recorded into a histogram.

## Adding a benchmark

**Where.** An operation belonging to one crate goes in that crate's `benches/`. Anything that needs
a connected peer goes in `benchmarks/rtc-bench/benches/`, built on `PeerPair`. The protocol crates
cannot depend on `rtc-bench`, which depends on all of them.

**Shape.** A criterion target with `harness = false` whose entry point is
`Criterion::default().configure_from_args()`, so the runner's arguments reach it. Open the file with
a comment saying what is measured, what is not, and the `cargo bench` line that runs it alone.

**Ids.** Name benchmarks `Group/Operation/Variant/provider`, with the variable parts last:
`DTLS/Encrypt/AES-128-GCM/ring`, `Track/Send/video/default-interceptors/ring`. Reports sort and
compare by id. **Renaming a benchmark breaks its history**: the old id appears as *Only in base* and
the new one as *Only in head*. Rename only when the old name was wrong.

**Separate setup from the hot path.** Build contexts, ciphers and connections outside the timed
region (`iter_batched` for per-iteration setup) and, where setup cost matters, benchmark it under its
own `Setup/*` id. The crypto migration deliberately moved work from the per-packet path into setup;
a combined number would have hidden both directions of that change.

**Loop over providers** for anything that touches cryptography, using `rtc_bench::providers()` or
the same pattern locally (see `rtc-srtp/benches/bench.rs`). `--providers all` then reports both
backends under identical inputs.

**Set throughput** (`Throughput::Bytes` or `Elements`) when a rate means more than a time. Reports
then show MiB/s or packets per second.

**Assert that the path you think you are measuring is the one that ran.** A replay detector that
rejects, a receiver that drops, or a decrypt that fails still produces a timing. Check outcomes
outside the timed region: `rtc-shared`'s replay benchmark verifies its sequence patterns are
accepted, and `Track/*` verifies delivery after every sample.

**Long iterations** — anything in the milliseconds — should use `SamplingMode::Flat` and a smaller
`sample_size`, or criterion cannot fit its samples into the measurement time.

**Features.** If a target needs a feature, prefer `required-features` in the manifest. If it only
needs one for part of its coverage, as `rtc-sctp` does, gate that part on `cfg(feature)` and add the
feature to `EXTRA_FEATURES` in `scripts/bench.py`.

**Check it** before committing:

```bash
python3 scripts/bench.py check --bench rtc-foo:bench --providers all
python3 scripts/bench.py run --quick --bench rtc-foo:bench
```

## CI

The *Benchmarks build and run once* job runs `python3 scripts/bench.py check --providers all`. It
builds every target and runs every criterion benchmark once in `--test` mode (one iteration, nothing
timed), with both crypto providers where a crate supports both. The workspace provider matrix also
builds all targets and runs `rtc-bench`'s harness tests.

That catches a benchmark that no longer builds, panics, or stalls. **Nothing in CI measures time.**
Shared runners vary too much between runs for a timing gate to be anything but noise or a
permanently ignored red job. And the rule this document opens with rules out comparing a CI
number with anything measured elsewhere. Regressions are caught by running `compare` before merging
a change to a hot path.
