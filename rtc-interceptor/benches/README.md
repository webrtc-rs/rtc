# Congestion-control behaviour

```bash
cargo bench --package rtc-interceptor --bench congestion_control
```

Not a criterion target. The other benches in this workspace time code; there is nothing worth timing
here, because how fast the simulation loop runs says nothing about the estimator. What is worth
measuring is convergence time, steady-state utilisation, and the response to a step change in
available bandwidth, so this is a `harness = false` binary that prints those.

**Closed loop.** The sender paces at whatever the estimator currently believes, unlike
`tests/path_simulation.rs`'s fixtures, which offer a packet every 10 ms regardless. Utilisation only
means something when the sender actually follows the estimate — and an estimate that runs away then
shows up as a queue the sender itself built, exactly as on a real path.

**Not loopback.** A loopback run reports a large number and proves nothing: no bottleneck, so no
queue; no loss, so the loss half never fires; the delay half never leaves its initial state and the
"result" is whatever the sender happened to offer.

## Metrics

- **settled** — mean target over the last 30% of the run. Not the final sample, which on an AIMD
  sawtooth is wherever the tooth happened to end.
- **utilisation** — bits delivered over the last 30% of the run, against what the path could have
  carried in that time. Measured over the tail because a whole-run average is dominated by the ramp
  from the initial rate and says more about where the sender started than about where it settled.
- **converged** — when a two-second rolling mean of the target first came within ±35% of capacity
  *and stayed there*. Both halves matter: without "stayed there" a trajectory that merely crosses
  the right value counts as converged, and without the rolling mean nothing with an AIMD sawtooth
  ever converges, since probing upward and backing off is the whole design.

## Results

One machine, simulated paths, 30 s per shape (40 s for the step). Rates in Mb/s.

| path | final | settled | capacity | utilisation | loss | converged |
|---|---|---|---|---|---|---|
| steady | 3.02 | 2.19 | 3.00 | 73.0% | 0.0% | 25.3 s |
| queue building (4×) | 0.84 | 0.36 | 0.30 | 79.6% | 19.8% | never |
| lossy (1 in 5) | 0.10 | 0.10 | 3.00 | 2.7% | 20.0% | never |
| mildly lossy (1 in 20) | 1.32 | 1.32 | 3.00 | 42.3% | 5.0% | never |
| recovering (5× step) | 2.15 | 1.79 | 3.00 | 59.9% | 5.6% | 37.7 s |

Step response: **0.28 Mb/s** in the three seconds before the widening → **1.85 Mb/s** settled after,
into a path that went from 0.60 to 3.00 Mb/s.

The estimator converges on a clean path, backs off on a queue build-up, and climbs back after a step
change. The regression gate for those three properties is in `tests/path_simulation.rs`; this
reports *how well*, those assert *whether*.

## What the numbers say

**Convergence is slow, by design.** 25 s to reach a 3 Mb/s path from a 300 kb/s start. That is the
multiplicative-increase rate doing exactly what it is configured to do — 1.08 per second, so a
tenfold climb takes ln(10)/ln(1.08) ≈ 30 s. It matches draft-ietf-rmcat-gcc-02 and upstream, and it
is the reason a sensible initial bitrate matters more than it looks like it should.

**Heavy rate-independent loss drives the target to the floor.** The 1-in-5 path settles at the
100 kb/s minimum and uses 2.7% of a link that would have carried about 2.4 Mb/s of goodput. The loss
controller applies `× (1 − 0.5p)` per decision, and this fixture's loss does not respond to rate, so
backing off never improves the loss it is reacting to and the decay runs all the way down.

Two things make it worse than the draft intends. `DEFAULT_LOSS_INTERVAL` is 200 ms where the draft's
pseudocode makes this decision at roughly 1 s, so the decay compounds about five times as fast; and
nothing floors the loss-based target against the rate actually being delivered. Real paths usually
shed load as the sender backs off, which is the feedback this fixture deliberately omits — so this
is a worst case rather than a typical one. It is still the sharpest edge these numbers found, and it
is the mirror image of the deliberate divergence from upstream: upstream computes a loss estimate
and never applies it, while this one applies it without a floor.

Changing that tuning is a behavioural change and wants its own falsification, so it is recorded here
rather than quietly adjusted.

**The 4× queue-building path loses 19.8% in closed loop**, where the open-loop fixture loses nothing.
Nothing is wrong: a sender that begins 4× over capacity overflows the bottleneck before the delay
signal has moved it, and only a closed loop can show that. It is worth knowing that the delay half
does not save you from a bad starting estimate.

## Not covered

A real-socket run against an induced-impairment path. That needs `dnctl`/`pfctl` under root on
macOS, which was not available. Every number above is simulated.

# Feedback interceptors: `feedback`

```bash
cargo bench --package rtc-interceptor --bench feedback
```

The NACK generator and responder, receiver reports and the TWCC receiver, driven through their
public interceptors with loss, bursts, outages and sequence gaps; the source's opening comment
describes each case. After the bitmap and gap handling moved to whole-word and whole-slice
operations (2026-09-21), selected cases:
Measured with `python3 scripts/bench.py compare refs/bench/pre-simd --overlay-benches --rounds 2`
on an Apple M1 Max, macOS 27.0, `rustc 1.99.0-nightly` (2026-08-04); before is the tree just ahead of
the change. [SIMD.md](../../SIMD.md) has the full record.

| Benchmark | Before | After |
|---|---:|---:|
| `Feedback/NackGenerator/loss-1pct/512/16-streams` | 6.84 µs | 2.20 µs |
| `Feedback/NackGenerator/loss-1pct/8192/16-streams` | 107 µs | 13.3 µs |
| `Feedback/NackGenerator/loss-10pct/512/16-streams` | 13.0 µs | 7.98 µs |
| `Feedback/NackResponder/absent` | 472 ns | 284 ns |
| `Feedback/ReceiverReport/video-outage/16-streams` | 1.32 ms | 843 µs |
| `Feedback/ReceiverReport/video-1000pps/16-streams` | 837 µs | 838 µs |
| `Feedback/TwccReceiver/gap-8000` | 32.0 µs | 29.0 µs |
| `Feedback/TwccReceiver/steady` | 9.46 µs | 9.66 µs (within noise) |

# FlexFEC: `flexfec`

```bash
cargo bench --package rtc-interceptor --bench flexfec
```

FlexFEC-03 encoding and single-loss recovery for blocks of 10 and 48 media packets of about 1,150
bytes. After encoding serialized each packet once per block into a reused buffer, recovery once per
surviving packet, and the XOR moved to `wide` (2026-09-21), same conditions as above:

| Benchmark | Before | After |
|---|---:|---:|
| `FlexFec/Encode/10x2` | 1.35 µs | 793 ns |
| `FlexFec/Encode/48x2` | 5.95 µs | 3.60 µs |
| `FlexFec/Encode/48x10` | 6.69 µs | 4.79 µs |
| `FlexFec/Recover/10x2` | 1.95 µs | 1.65 µs |
| `FlexFec/Recover/48x2` | 10.6 µs | 8.75 µs |
| `FlexFec/RecoverRepair/48x2` | 6.43 µs | 4.78 µs |
