# The sans-I/O deterministic time boundary

**Enforced by:** `scripts/check-sans-io-deterministic-time.py` (CI job *Sans-I/O Deterministic Time boundary*)
**Allow-list:** `docs/sans-io-deterministic-time-allowlist.txt`
**Design:** [Deterministic time in the `rtc` core](https://github.com/webrtc-rs/webrtc/issues/854)

## The rule

> **Sans-I/O protocol code is told the time. It does not ask.**

A protocol object must never call `Instant::now()`. Every decision it makes is made against an
instant its caller supplied. This is what makes a run reproducible, and it is what lets a test
advance a virtual clock by thirty seconds without waiting thirty seconds.

## Where to get an instant

In order of preference:

| You are in | Use |
|---|---|
| `handle_timeout(now)` | the `now` parameter |
| `handle_read(msg)` / `handle_write(msg)` | `msg.now` — `TaggedRTCMessageInternal` and `TaggedBytesMut` both carry one |
| `handle_event(evt)` | `evt.now` — `TaggedRTCEventInternal` carries one |
| an internal helper | a `now: Instant` parameter, threaded down from whichever of the above called you |
| `poll_*` or `close` | the instant retained from the last `handle_*`, seeded at construction |
| a constructor | a `now` from the config; do not implement `Default` on a clock-bearing type |

The retained instant is a last resort, not a shortcut. Inside a `handle_*` the caller's instant is
right there — using a stored one instead reintroduces exactly the staleness this boundary exists to
remove.

## Comparisons

Use `saturating_duration_since`, never `.elapsed()`:

```rust
// wrong — reads the ambient clock, and compiles happily on a retained Instant field
if self.last_consent_sent.elapsed() >= self.keepalive_interval { ... }

// right
if now.saturating_duration_since(self.last_consent_sent) >= self.keepalive_interval { ... }
```

`saturating_duration_since` also cannot panic when the two instants arrive out of order, which
`Instant` subtraction can on some platforms.

## Prefer deleting a clock read to moving it

The best fix is often to discover the read was never needed. `rtc` b3ac944 is the precedent: two
`poll_timeout` implementations opened with

```rust
let max_eto = Instant::now() + DEFAULT_TIMEOUT_DURATION;   // 86_400 s — one day
```

which looks like a deadline but is a sentinel for *nothing pending*, expressed as a far-future
instant. It became `None`, and the "don't sleep forever" policy moved to the driver where it
belongs. Two reads eliminated, nothing relocated.

Ask of every default duration: is this protocol state, or caller policy that leaked in?

## What stays on the wall clock

Some reads are correct. They are listed in the allow-list's *permanent* section with a reason, and
they fall into four categories:

- **NTP / RTP baselines.** An RTCP sender report carries real wall-clock time in NTP format. A
  virtual instant would put a fictional timestamp on the wire. These are real-world observations
  and are correctly *not* reproducible under replay.
- **`SystemInstant`'s own construction** (`rtc-shared/src/time.rs`), the primitive that pairs a
  monotonic reading with a wall-clock one. Everything above is built from it.
- **`Instant` ↔ epoch conversion** (`rtc-shared/src/serde.rs`). `Instant` is opaque, so a portable
  absolute timestamp can only be derived from a `SystemTime` sampled alongside it.
- **Fields specified as wall-clock by a protocol or format.** DTLS `gmt_unix_time`
  (RFC 5246 §7.4.1.2), SDP session version (RFC 4566 §5.2), and X.509 validity windows — a virtual
  instant would happily accept an expired certificate.

Everything else in the allow-list is temporary and is being removed phase by phase.

## When CI fails

**"clock reads that the allow-list does not permit"** — you added an ambient read. Take the instant
from the table above instead. If you genuinely believe the read belongs in one of the permanent
categories, add it to `PERMANENT` in the script with a reason, and say why in the PR.

**"clock reads were removed but the allow-list still budgets for them"** — you fixed something.
Record it:

```console
$ python3 scripts/check-sans-io-deterministic-time.py --snapshot
```

and commit the updated allow-list alongside your change.

Never run `--snapshot` to silence the first failure. The allow-list is a ratchet: counts go down,
never up.

## Why a count and not a line number

The allow-list records `path:count:reason`. Pinning line numbers would mean any edit above a
tracked site breaks CI, which during a migration that touches these files constantly is a tax with
no benefit. The count is stable under line shifts, still fails when a read is added, and the script
prints the exact lines it found so the diff is obvious either way.

## Testing against a virtual clock

Advance time by arithmetic. `Instant` is opaque and only differences are meaningful, so a base
instant plus `Duration` gives fully deterministic time:

```rust
let base = Instant::now();
let t = |secs| base + Duration::from_secs(secs);

let mut agent = Agent::new(AgentConfig { now: t(0), ..config })?;
agent.handle_timeout(t(0))?;
agent.handle_timeout(t(30))?;      // 30 seconds later, instantly

assert_eq!(agent.connection_state(), RTCIceConnectionState::Failed);
```

A test that sleeps to reach a protocol deadline is a bug in the test.
