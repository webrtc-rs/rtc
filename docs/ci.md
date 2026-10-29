# Continuous integration

Linux and macOS are first-class platforms, on both x86-64 and arm64. Every pull request is built
and tested on all four, in debug and release, on both built-in crypto providers. Slower checks
run nightly.

## Workflows

| Workflow | Runs | What it guards |
|---|---|---|
| `platform.yml` | every push / PR | the matrix below |
| `cargo.yml` | every push / PR | the feature graph, crypto-provider boundaries, packaging order |
| `nightly.yml` | 02:17 UTC + manual | long fuzzing (every parser, and the mDNS, TURN and ICE receive paths), Miri, 25× test repetition, beta/nightly compilers, careful benchmarks |
| `grcov.yml` | every push / PR | coverage |
| `semver.yml` | every push / PR | public-API breakage |
| `release.yml` | tag `vX.Y.Z` / manual | full platform matrix, then publish to crates.io in dependency order behind an approval gate, then a GitHub release |

### `platform.yml`

| Job | Matrix | Guards |
|---|---|---|
| `test` | `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest` (arm64), `macos-15-intel` × debug/release × ring/aws-lc-rs | the whole workspace builds and passes everywhere; release catches optimiser- and overflow-dependent behaviour |
| `pion-golden` | the four runners | each protocol parser (SDP, RTCP, RTP, STUN, TURN, ICE candidates, mDNS, DCEP, DTLS, SCTP, SRTP, and the NACK buffers) agrees with pion on its differential corpus, in release |
| `lint` | Linux, macOS | `rustfmt`; `clippy -D warnings` on library code; `clippy::correctness` as an error everywhere; rustdoc warnings |
| `musl` | x86-64 and arm64 | static Linux builds are tested, not just compiled |
| `msrv` | Linux | builds on the `rust-version` the workspace declares |
| `bench-vs-pion` | Linux x64/arm64, macOS arm64 | we stay faster than pion and allocate no more; see `benchmarks/pion-compare` |
| `publish-dry-run` | Linux, macOS | `cargo publish --workspace --dry-run`: every crate packages and builds from its packaged contents, in publication order |
| `supply-chain` | Linux | `cargo deny`: advisories, licences, sources (`deny.toml`) |

The superproject (`webrtc`) has its own `platform.yml`: the async crate on tokio and smol, with
both providers, on the same four runners; interop against pion over real sockets
(`interop/run.sh`); and `e2e-vs-pion`, which runs `benches/pion/compare.py` — data-channel
throughput, the CPU and memory it cost, and connect latency, webrtc-rs against pion — and fails
if webrtc-rs falls behind.

### Why these choices

* **Native arm64 Linux and macOS runners** are the only way the ARMv8 AES / SHA-1 / PMULL fast
  paths execute in CI. Emulated runs would test the software fallbacks.
* **Both providers** because users choose; `ring` is the default and `aws-lc-rs` is a supported
  alternative, and a bug in either backend's glue only shows up when that backend is built.
* **Release as well as debug** because overflow checks, inlining and alignment-dependent code
  paths differ.
* **Differential tests against pion** run on every platform because byte-level behaviour (endian
  handling, integer widths) is exactly what differs across targets.

## Releasing

Bump the version, merge, and push a tag `vX.Y.Z`. `release.yml` runs the whole platform matrix on
the tag, then waits for approval on the `crates-io` environment (which holds the
`CARGO_REGISTRY_TOKEN` secret) before `cargo publish --workspace` publishes every crate in
dependency order, and finally creates the GitHub release. A manual run of the workflow is a dry
run unless `publish` is ticked. The `webrtc` superproject releases the same way, after the `rtc`
crates it depends on are on crates.io (the workflow checks).

## Reproducing CI locally

```sh
scripts/ci-local.sh                    # lint, test, golden, docs, deny
BACKEND=crypto-aws-lc-rs PROFILE_FLAG=--release scripts/ci-local.sh test
scripts/ci-local.sh bench              # needs Go
```

A few network tests need the host to be able to deliver a datagram to its own non-loopback
address (the wildcard UDP mux test). A host firewall that blocks that — macOS's Application
Firewall does for unsigned test binaries — makes those tests skip rather than fail; CI runners and
Docker containers run them for real.

To reproduce a Linux failure from a Mac (Docker or Colima required):

```sh
scripts/ci-linux-docker.sh                                   # test workspace, native arch
scripts/ci-linux-docker.sh -p linux/amd64                    # x86-64 under emulation (slow)
scripts/ci-linux-docker.sh -- cargo clippy --workspace --lib -- -D warnings
```

## Fuzzing

`cargo install cargo-fuzz`, then from a crate that has a `fuzz/` directory
(`rtc-rtp`, `rtc-rtcp`, `rtc-sdp`, `rtc-stun`, `rtc-dtls`, `rtc-sctp`, `rtc-srtp`,
`rtc-datachannel`):

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run header_peek -- -max_total_time=60
```

Targets worth knowing about:

* `rtc-rtp/header_peek` — `Header::peek` (what SRTP trusts) must agree with `Header::unmarshal`.
* `rtc-rtp/depacketize`, `payload` — every codec's depacketizer and payloader.
* `rtc-srtp/unprotect`, `roundtrip` — network bytes into `decrypt_rtp`/`decrypt_rtcp`, and
  protect→unprotect identity on every profile.
* `rtc-datachannel/dcep_message` — DCEP parse, re-marshal, re-parse.

## Benchmarks against pion

`benchmarks/pion-compare` builds a Rust and a Go program that run the same micro-benchmarks
(RTP, SRTP, STUN, SDP, RTCP, payloaders, DTLS handshakes and records, SCTP, an ICE session, TWCC,
DCEP, mDNS) and prints them side by side:

```sh
python3 benchmarks/pion-compare/compare.py --backend ring
```

A benchmark we win must stay within 25 % of pion's time and never allocate more; one we do not yet
win has a ceiling it may not regress past. Shared CI runners are noisy, so each side runs several
times and the fastest run is kept; allocation counts are exact.

`benchmarks/turn-load` compares the TURN servers end to end on real sockets (CPU and memory per
relayed round trip). It is run by hand: it needs loopback sockets and takes a minute.
