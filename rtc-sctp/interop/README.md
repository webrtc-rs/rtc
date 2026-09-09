SCTP packet interoperability tests

These test adapters exchange raw SCTP packets between the public `rtc-sctp` API
and two independent implementations. They open no UDP or DTLS sockets. C/C++ and
the external sources are test dependencies only; the normal Cargo build does
not compile or link them.

**Build and run**

Requirements: Rust/Cargo, Python 3.12+, git, a C11/C++20 compiler, and CMake 3.16+.
The scripts support macOS and Linux. The initial external builds download pinned
public sources; subsequent builds reuse them. Build artifacts stay outside the
checkout.

```sh
python3 rtc-sctp/interop/build_usrsctp.py --build-dir /tmp/rtc-237-usrsctp --self-test
python3 rtc-sctp/interop/build_dcsctp.py --build-dir /tmp/rtc-237-dcsctp --self-test
CARGO_TARGET_DIR=/tmp/rtc-237-target-implementation cargo build -p rtc-sctp --example sctp_interop --release
python3 rtc-sctp/interop/run.py \
  --rtc /tmp/rtc-237-target-implementation/release/examples/sctp_interop \
  --usrsctp /tmp/rtc-237-usrsctp/build/usrsctp_peer \
  --dcsctp /tmp/rtc-237-dcsctp/build/dcsctp-peer \
  --output /tmp/rtc-237-interop-traces
```

Use different `CARGO_TARGET_DIR` values when comparing source snapshots. Each
trace records the exact adapter binary SHA-256. `--scenario` and `--role` may be
repeated to select cases; role describes the rtc endpoint. For example:

```sh
python3 rtc-sctp/interop/run.py \
  --rtc /tmp/rtc-237-target-implementation/release/examples/sctp_interop \
  --usrsctp /tmp/rtc-237-usrsctp/build/usrsctp_peer \
  --output /tmp/rtc-237-interop-reset \
  --scenario forgotten_result_recovery --role client --seed 237
```

The default suite has 40 cases: two peers × both rtc handshake roles × ten
scenarios. Application traffic runs in both directions. Each command has a
5-second wall-clock limit; each case has a 45-second limit and bounded packet,
command, and virtual-time loops. Failed cases produce nonzero exit status and
retain their traces. `summary.json` records every result; `*.jsonl` contains
application commands, original packet hex, decoded DATA/SACK/RE-CONFIG/FORWARD-TSN,
network actions, virtual timestamps and application events. `*.stderr` retains
adapter diagnostics.

| Scenario | Checked property |
|---|---|
| `reliable` | Fragmented ordered and unordered messages arrive byte-for-byte once; a held DATA followed by a duplicate preserves ordered delivery. |
| `timed_rtc`, `timed_peer` | Lose the first of two fragments; after Timed(100), no DATA is transmitted for that message, FORWARD-TSN completes abandonment, and the next reliable message is readable. Two fragments avoid legitimate fast recovery before the deadline. |
| `rexmit_rtc`, `rexmit_peer` | Lose the first fragment of a 9000-byte Rexmit(0) message; no TSN is transmitted twice, the message is abandoned as a whole, and subsequent reliable traffic works. |
| `lost_response_rtc`, `lost_response_peer` | Remove the first successful reset response parameter, preserving any bundled request/SACK. Reset recovers and ordered messages work on the reused SID. |
| `simultaneous_reset` | Both endpoints issue outgoing reset before either request is delivered. Both can subsequently send on the reused SID. |
| `sequential_resets` | Lose an explicit result, exchange an unrelated peer reset, complete two more resets, then deliver an actual delayed duplicate of the first request. Both real peers return BadSequence for the evicted result; the stale response must not rewind SSN. |
| `forgotten_result_recovery` | Hold successful responses to N, supply an implicit ACK, queue two further resets and a write. A real retry must repeat the unchanged N; no newer request or queued DATA may escape before its result. Restore responses, verify N succeeds without cache eviction, and verify the two queued resets start and DATA uses the correct SSNs. |

The last case has one explicitly logged compatibility adjustment: the pinned
dcSCTP fills OutgoingResetRequest.response_sequence with its own request number,
so it cannot naturally supply the intended E1 acknowledgement. The harness
corrects that field to the last request actually received, retaining dcSCTP's
request RSN, TSN boundary, SID list, and all other parameters, then recomputes
CRC32C. Its actual receive/reset/result-cache implementation handles the replay.
The correction is recorded as `normalize_peer_A4`. usrsctp already sends the
proper field, and all other scenarios use unmodified peer fields. This case
must not be described as an unmodified dcSCTP implicit-ACK trace.

**Pinned implementations and clocks**

| Peer | Sources | Clock and entropy |
|---|---|---|
| usrsctp | `fd070e05a7474f38c7fecdf4d4b6005d2547ee00`, [upstream](https://github.com/sctplab/usrsctp/tree/fd070e05a7474f38c7fecdf4d4b6005d2547ee00) | AF_CONN, `usrsctp_init_nothreads`, explicit `usrsctp_handle_timers`; a test-build `gettimeofday` hook advances TTL and callouts together. Original system entropy generates association IDs/cookies. Build configuration is in `build/build.json`. |
| dcSCTP | WebRTC `dab572fd15e3fb975ed14a9e9290f723bb6e3f30`, [upstream](https://webrtc.googlesource.com/src/+/dab572fd15e3fb975ed14a9e9290f723bb6e3f30/net/dcsctp/); Abseil `c2336f9b5cb94b877ae3e38629e3b4530e60c89f` from pinned DEPS | Public packet API, virtual callbacks/timeouts, fixed per-role random seed, no task queue or real clock. |
| rtc | Current Cargo snapshot, `examples/sctp_interop.rs` | Only public Endpoint/Association/Stream APIs. One startup Instant anchors elapsed virtual time; all subsequent time comes from TICK. Production random Initial TSN/vtag generation is preserved. |

Ports are 5000 in both directions; message size is limited to 1 MiB. The rtc and
usrsctp adapters use a 1200-byte SCTP packet budget. Message interleaving is
disabled on dcSCTP so DATA/FORWARD-TSN properties are directly comparable.
Incoming application messages are read immediately by each adapter; delayed
application reads and DataChannel registry event ordering are tested at the
Rust integration layer.

The driver advances both peer clocks in steps of at most 10 ms before delivering
new packets. An external callback may have run inside that interval; the JSONL
timestamp is its end. dcSCTP additionally emits `EVENT packet_time:<ms>` before
each packet; the driver records this callback time as `send_time_ms` and uses it
for lifetime checks. Exact deadline equality belongs in the deterministic rtc
unit tests. This suite uses Timed(100) and retransmission times well beyond that
deadline. It does not equate rtc's compatibility mapping of Timed(0) with
dcSCTP's one-millisecond lifetime quantization.

`--seed` reproduces application payloads and network decisions. Cryptographic
association numbers and cookies in rtc/usrsctp intentionally remain random;
bit-for-bit packet equality across fresh processes is not promised. Captured
bytes are preserved for diagnosis, while protocol comparisons should normalize
TSNs/RSNs relative to each association's recorded initial values. No manually
invented RSN is substituted for an emitted request.

**Adapter protocol**

Every command is a single line; its zero or more output lines end with `DONE`.
The driver serializes commands, so the terminator unambiguously marks completion.

| Input | Meaning |
|---|---|
| `INIT client` / `INIT server` | Create an active/passive endpoint. |
| `CONNECT` | Active endpoint starts association establishment. |
| `INPUT <hex>` | Receive one complete SCTP packet. |
| `SEND <sid> ordered\|unordered reliable\|timed:N\|rexmit:N <ppid> <hex>` | Queue a complete application message with immutable policy. Use WebRTC PPID 53 for binary data. |
| `RESET <sid[,sid...]>` | Request outgoing reset. rtc maps this to its existing `stop(now)` API, preserving writable behavior. |
| `TICK <elapsed-ms>` | Advance virtual time and process due timers. |
| `POLL` | Drain work at the current time. |
| `QUIT` | End this test process. |

Output is `PACKET <hex>`, `MESSAGE <sid> <ppid> <hex>`, `EVENT <description>` or
`ERROR <description>`. Error output fails a scenario. RFC stream reset direction
events are available from external peers; rtc exposes its existing public stream
events. Assertions use actual messages and decoded request/response exchanges
instead of inventing a private rtc state query.

Packet faults inspect chunk/parameter contents and SID/RSN/TSN, not packet index
or bundling shape. `rewrite()` can remove a selected DATA or RE-CONFIG parameter,
preserve unrelated chunks, fix length/padding and recompute CRC32C. The decoder
validates every emitted/reconstructed checksum. `held` and `release_held()` model
delay, reordering and duplication; these preserve original packet bytes unless
a recorded filter is applied. Built-in codec checks cover the CRC32C known
vector, bundled chunks/parameters, filtering and corruption detection.

These tests do not replace the workspace suites or claim that either external
stack implements every RFC transition correctly.

**Continuous integration**

[SCTP interoperability](../../.github/workflows/sctp-interop.yml) runs the same
40-case command on Ubuntu 24.04 for relevant pushes and pull requests targeting
`master`, `v0.20.x`, or `v0.21.x`, matching the existing Cargo workflow. Paths are
limited to SCTP, its shared/datachannel dependencies, the affected handlers,
the root Cargo manifest, and the workflow itself. It can also be run manually
from the Actions tab after the workflow is available on the default branch:

```sh
gh workflow run sctp-interop.yml --ref <branch>
```

The job installs native tools only for these external adapters; ordinary Cargo
builds remain independent of them. Both peer adapter self-tests run before the
packet suite. The `sctp-interop-<run-id>-<attempt>` artifact is uploaded even when
a build or scenario fails, and contains available JSONL traces, scenario summary,
compiler/toolchain versions, resolved Cargo.lock, build logs and external build
manifests. Packet traces record binary hashes and pinned peer revisions. Artifacts
are retained for 14 days; the job has a 25-minute limit in addition to the harness
limits. The local build/run commands above reproduce the CI suite without GitHub
services or credentials.

**Identical public-API performance workloads**

`perf_scenarios.rs` drives two real SCTP associations through public APIs with
virtual time and no sockets. `build_perf.py` copies this same runner into an
external Cargo project and points its dependencies at a chosen source checkout.
It does not edit that checkout's source or Cargo manifests. The default target
directory is inside the external build directory; `--target-dir` may reuse an
existing cache. Use separate target directories for baseline and candidate.

```sh
python3 rtc-sctp/interop/build_perf.py \
  --source /path/to/baseline --build-dir /tmp/sctp-perf-baseline
python3 rtc-sctp/interop/build_perf.py \
  --source /path/to/candidate --build-dir /tmp/sctp-perf-candidate
/tmp/sctp-perf-candidate/perf-scenarios \
  --scenario small-rwnd --messages 32768 --size 256 --streams 1 --rwnd 4096
```

Pass `--offline` when the selected snapshot's dependencies are already cached.
Each build saves its compiler version, source revision, runner SHA-256 and binary
SHA-256 in `perf-scenarios-build.json`. Both builds must use the same runner hash.
Keep the generated Cargo.lock with the measurements.

The fixed comparisons in `benchmark.py` use these additional workloads:

| Case | Runner parameters | Required completed work |
|---|---|---|
| `small_rwnd` | `--scenario small-rwnd --messages 32768 --size 256 --streams 1 --rwnd 4096` | 65,536 complete messages, 16 MiB, across both directions. |
| `multi_stream` | `--scenario multi-stream --messages 60000 --size 32 --streams 32 --rwnd 65536` | 120,000 complete messages across 32 simultaneous streams in each direction. |
| `many_resets` | `--scenario reset-reuse --size 32 --streams 512 --cycles 1 --iterations 4 --rwnd 65536` | 8,192 complete messages and 4,096 close/reopen operations. |
| `sid_reuse` | `--scenario reset-reuse --size 32 --streams 1 --cycles 512 --iterations 4 --rwnd 65536` | 4,104 complete messages and 4,096 close/reopen operations on the reused SID. |

`--messages` counts messages per direction. Reset workloads send one message per
direction/SID before each close and one more after the last reopen, verifying
every reopened stream. `--seed` defaults to 237; each message carries a sequence
number and checked payload. A short write, missing/duplicate message, failed
close/reopen, wrong final count, association failure, or stalled timer fails the
process. Loops also have explicit step, wall-time and virtual-time bounds.

For `small-rwnd`, the application reads after each received datagram, keeping a
receive burst below the 4096-byte window. This measures a constrained window with
a responsive reader; it does not substitute for the separate zero-window and
slow-reader correctness tests. `min_advertised_rwnd` records the actual SACK
window. All workloads emit one JSON line with exact message/byte/stream counts,
packet and timer counts, virtual time and `elapsed_ns`. `benchmark.py` accepts
these binaries as `--baseline-workloads-bin` and `--candidate-workloads-bin`; it
retains external wall time/RSS separately and uses the runner's timed interval
for these cases, excluding process startup.

For a separate allocation probe, repeat each build with `--allocation-probe`.
The resulting `perf-scenarios-alloc` binary additionally counts allocations,
reallocations and requested bytes during the workload. The normal latency binary
contains no allocator instrumentation. Requested bytes include the full new size
of reallocations; these counters describe allocation pressure, not physical
payload copies or retained heap size. Peak RSS remains an external measurement.

To measure cumulative SACK processing with substantial DATA still in flight,
build the same normal and allocation runners against the clean PR base, the
version before the optimization, and the candidate. For `git archive` snapshots,
pass their full commit ID as `build_perf.py --source-revision`. Set
`SCTP_MASTER_REV`, `SCTP_BEFORE_REV` and `SCTP_CANDIDATE_REV` to those commit IDs:

```sh
python3 rtc-sctp/interop/benchmark.py --samples 15 \
  --matrix-variant master "$SCTP_MASTER_REV" \
    /tmp/sctp-perf-master/perf-scenarios /tmp/sctp-perf-master/perf-scenarios-alloc \
  --matrix-variant before "$SCTP_BEFORE_REV" \
    /tmp/sctp-perf-before/perf-scenarios /tmp/sctp-perf-before/perf-scenarios-alloc \
  --matrix-variant candidate "$SCTP_CANDIDATE_REV" \
    /tmp/sctp-perf-candidate/perf-scenarios /tmp/sctp-perf-candidate/perf-scenarios-alloc \
  --output /tmp/sctp-sack-comparison.json
```

The four fixed `sack_*` cases send 60,000 messages of 32 bytes per direction on
one SID with a 1 MiB receive window: ordered Reliable or unordered `Rexmit(0)`,
each with a receive budget of 1 or 32 datagrams per pump. They verify delivery,
the absence of DATA retransmissions and Gap ACKs, and at least 1,024 DATA TSNs
remaining after a SACK. Wire DATA/SACK/FORWARD-TSN counts are recorded to expose
differences in protocol work between revisions. This is a public SCTP API
workload, not a reproduction of the full Linux DataChannel benchmark in #111.

Run measurements without concurrent builds or tests. Matrix mode verifies the
runner, binary and Cargo.lock hashes, rotates revision order, and records all
pairwise ratios with median/MAD/range and peak RSS. Five allocation probes run
separately after the latency phase. The default 15% regression threshold is a
gate, not a claim of zero overhead; comparisons with relative MAD above 5% are
inconclusive. Matrix mode saves every comparison, including known slow versions,
and does not turn the report into a pass/fail process exit code.
