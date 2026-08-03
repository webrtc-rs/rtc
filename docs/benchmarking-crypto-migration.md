# Benchmarking against a pre-migration baseline

How the before/after figures in `rtc-srtp/benches/README.md`, `rtc-dtls/benches/README.md`, and
`rtc-stun/benches/README.md` were produced, and how to reproduce or extend them.

The G3 crypto migration moved every cryptographic operation behind `rtc-crypto`. That is a
performance-sensitive change on paths that run per packet, so each affected crate was measured
against the last commit before *its own* migration. Three real regressions were found this way and
none of them were visible from code review.

## Contents

- [The rule that makes or breaks this](#the-rule-that-makes-or-breaks-this)
- [Baseline commits](#baseline-commits)
- [Procedure A — a benchmark already exists at the baseline](#procedure-a--a-benchmark-already-exists-at-the-baseline)
- [Procedure B — no benchmark exists at the baseline](#procedure-b--no-benchmark-exists-at-the-baseline)
- [Procedure C — micro-benchmarks for diagnosis](#procedure-c--micro-benchmarks-for-diagnosis)
- [Interpreting the results](#interpreting-the-results)
- [Pitfalls hit during G3](#pitfalls-hit-during-g3)
- [Reporting](#reporting)

## The rule that makes or breaks this

**Both sides must be measured on the same machine, in the same session, with the same criterion
settings.** Everything else in this document is detail.

This is not a formality. `rtc-srtp/benches/README.md` previously carried results from a MacBook
Air M3 showing `Encrypt/RTP` at 5.69 µs. The post-migration figure on an M1 Max was 4.95 µs.
Comparing those two numbers says performance *improved*. Measuring the actual baseline on the same
M1 Max gave 1.73 µs — a 2.9x regression. The stale cross-machine figure did not merely add noise,
it inverted the conclusion.

Delete or clearly quarantine historical numbers from other machines before comparing.

## Baseline commits

Use the last commit **before the crate in question was migrated**, not a single global baseline —
each crate moved in a different phase, and an earlier commit drags in unrelated changes.

| Crate | Migrated in | Baseline commit | Baseline is |
|---|---|---|---|
| `rtc-stun` | P2 `f8298ce` | `b8bb313` | P1 — rtc-crypto exists, STUN not yet using it |
| `rtc-srtp` | P4 `fd81f68` | `425494c` | P3 |
| `rtc-dtls` | P5 `219788a` | `fd81f68` | P4 |

Verify a baseline before trusting it:

```bash
# The crate must not yet depend on rtc-crypto at the baseline.
for c in 425494c HEAD; do
  echo "${c}: $(git show "${c}:rtc-srtp/Cargo.toml" | grep -cE '^crypto[ .=]')"
done
# 425494c: 0    <- baseline, not yet migrated
# HEAD:     1
```

Match the dependency line, not the word. A bare `grep -c crypto` returns 1 even at the baseline,
because `rtc-shared` is pulled in with `features = ["crypto", …]` — that is `rtc-shared`'s own
feature gate, not the `rtc-crypto` crate. Anchoring to `^crypto[ .=]` matches only the dependency
entry.

In zsh, write `"${c}:path"` and not `"$c:path"`: `$c:r` is parsed as a history modifier and
silently mangles the revision.

## Procedure A — a benchmark already exists at the baseline

This is the strong case: the same benchmark source runs on both sides, so the only variable is the
code under test. Used for **SRTP** and **STUN**.

**1. Confirm the benchmark exists and is unchanged.**

```bash
git cat-file -e 425494c:rtc-srtp/benches/bench.rs && echo present

# Byte-compare the region you intend to compare. For SRTP the first 151 lines — the four
# original Encrypt/Decrypt RTP/RTCP benchmarks and their key constants — are identical between
# the baseline and today; everything added later sits after them.
git show 425494c:rtc-srtp/benches/bench.rs > /tmp/base_bench.rs
diff <(sed -n '1,151p' /tmp/base_bench.rs) <(sed -n '1,151p' rtc-srtp/benches/bench.rs)
```

If that diff is empty, the comparison is sound. If the benchmark changed for reasons unrelated to
the migration, compare only the benchmarks that did not, or fall back to Procedure B.

Where the benchmark *had* to change because the API under test changed — STUN's
`new_short_term_integrity` becoming `new_short_term_integrity_with_provider` — that is
unavoidable and is exactly the migration being measured. Keep every other input identical.

**2. Create a worktree and run it.**

```bash
git worktree add /tmp/rtc-srtp-base 425494c
cd /tmp/rtc-srtp-base
cargo bench -p rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5
```

A worktree gets its own `target/`, so the two builds do not share artifacts. Do not set a shared
`CARGO_TARGET_DIR`.

**3. Run the current tree with identical arguments.**

```bash
cd /path/to/rtc
cargo bench -p rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5
```

**4. Repeat the baseline and quote a representative run, not the fastest.** Three independent runs
of the SRTP baseline gave 1.725, 1.766, and 1.780 µs for `Encrypt/RTP` — a spread of about ±3%,
which is the noise floor on this machine. Reporting the minimum from one side and a typical value
from the other manufactures a difference of that size out of nothing. Take the median, or quote
the range, and treat anything inside ±3% here as parity.

**5. Remove the worktree.**

```bash
cd /path/to/rtc && git worktree remove /tmp/rtc-srtp-base --force
```

## Procedure B — no benchmark exists at the baseline

The weaker case: you write the baseline harness yourself, so a mistake in the port silently
corrupts the comparison. Used for **DTLS**. Say so explicitly when reporting.

**1. Write the benchmark for the current tree first**, and get it passing. That file is the
specification the baseline port must match.

**2. Port it back to the pre-migration API.** For DTLS the deltas were:

| | Baseline (`fd81f68`) | Current |
|---|---|---|
| `CryptoGcm::new` | `(local_key, local_iv, remote_key, remote_iv) -> Self` | `(provider, …) -> Result<Self>` |
| `CryptoCbc::new` | `(local_key, local_mac, remote_key, remote_mac) -> Result<Self>` | `(provider, …) -> Result<Self>` |
| `encrypt` / `decrypt` | `&self` | `&mut self` |

So the port drops the provider argument, drops `?`/`.unwrap()` where the old constructor returned
`Self`, and drops `mut` on the cipher bindings. Nothing else may change.

**3. Hold every input identical** — payload length, key and IV constants, record construction,
criterion settings. Copy them literally rather than retyping. In the DTLS bench the header must be
marshalled rather than zero-filled, because `decrypt` re-parses it from the ciphertext buffer;
getting that wrong produces `ErrUnsupportedProtocolVersion` rather than a wrong number, which is
the good failure mode.

**4. Add the harness plumbing to the worktree**, since it will not be there:

```toml
# rtc-dtls/Cargo.toml in the worktree
[dev-dependencies]
criterion.workspace = true

[[bench]]
name = "record_protection"
harness = false
```

**5. Sanity-check the port before trusting it.** A ported harness that produces plausible-looking
numbers can still be measuring the wrong thing. Two cheap checks:

- Does an unrelated benchmark in the same file match between the two sides? If the port is sound,
  operations the migration did not touch should be within noise.
- Does the result *predict* something? The DTLS port showed encryption regressing while decryption
  did not. That asymmetry pointed at randomness, an independent micro-benchmark (Procedure C)
  confirmed the RNG cost, and removing the RNG moved the figure to 270.1 ns against a predicted
  270.5 ns. A broken harness is unlikely to survive that.

## Procedure C — micro-benchmarks for diagnosis

Once a regression is confirmed, a throwaway crate isolates the cause far faster than profiling the
whole path. These are **diagnostic only** — never quote them as headline results, and never commit
them.

```bash
mkdir -p /tmp/rngbench/src && cd /tmp/rngbench
cat > Cargo.toml <<'EOF'
[package]
name = "rngbench"
version = "0.0.0"
edition = "2021"
[dependencies]
ring = "0.17.14"
rand = "0.10.1"
EOF
cat > src/main.rs <<'EOF'
use ring::rand::{SecureRandom, SystemRandom};
use std::time::Instant;

fn main() {
    const N: u32 = 200_000;
    let mut buf = [0u8; 8];

    let t = Instant::now();
    for _ in 0..N { SystemRandom::new().fill(&mut buf).unwrap(); }
    println!("ring SystemRandom : {:>7.1} ns", t.elapsed().as_nanos() as f64 / N as f64);

    let t = Instant::now();
    for _ in 0..N { rand::fill(&mut buf); }
    println!("rand thread-local : {:>7.1} ns", t.elapsed().as_nanos() as f64 / N as f64);
}
EOF
cargo run --release -q
```

Rules that keep these honest: build with `--release`, use `std::hint::black_box` around anything
the optimiser could elide, run enough iterations that per-call cost dwarfs timer overhead, and
compare candidates **in the same binary** so the environment is shared.

This is how the two dominant causes were found — an 8-byte OS read at 829 ns versus 8.3 ns, and
`ring`'s HMAC-SHA1 at 4469 ns versus RustCrypto's 1373 ns over the same 1212 bytes.

## Interpreting the results

**Separate setup from per-operation cost.** Benchmark them as different groups. The migration
deliberately moves work from the per-packet path to context construction — keyed cipher and MAC
objects are built once. A `Setup/*` figure rising while `Encrypt/*` falls is the design working,
not a regression. Reporting only a combined number hides both directions.

**Measure every enabled provider under identical inputs.** The benchmarks loop over the built-in
providers, so `--features ring,aws-lc-rs` reports both side by side. This is what showed that
`aws-lc-rs` was *worse* on DTLS encrypt while faster everywhere else, which localised the cause to
the encrypt-only RNG call.

**Asymmetries are the most useful signal.** Encrypt regressed and decrypt did not; large payloads
improved and small ones did not. Each asymmetry excludes whole classes of explanation before any
profiling.

**A backend difference is not an architecture problem.** `ring`'s slow SHA-1 was a property of the
backend, not of the provider abstraction. It was fixed by composing RustCrypto's HMAC-SHA1 into
the `ring` provider — the built-ins are already composite — rather than by changing the default
provider, which would have imposed a C toolchain on every downstream build.

## Pitfalls hit during G3

**Cross-machine comparison inverted a conclusion.** Covered above. The single most dangerous item
here.

**Sequential runs of the same command are cached.** Running `cargo clippy` twice and grepping each
output separately gives real diagnostics from the first and an empty second. Capture one run to a
file and derive every count from that file.

**zsh eats `:r` in a revision string.** `git show "$c:rtc-srtp/Cargo.toml"` parses `$c:r` as a
history modifier and looks up `425494ctc-srtp/Cargo.toml`. Use `"${c}:path"`.

**zsh does not word-split unquoted variables.** `F="--no-default-features --features ring"; cargo build $F` passes one bogus argument. This produced four false "failures" in a feature-matrix loop.
Write the invocations out, or use an array.

**Bisecting can misattribute.** An early bisect blamed the AES-CTR rewrite for a set of DTLS test
failures. The real cause was a text-slice deletion that had removed a provider method along with
its neighbours; the CTR change was innocent. Confirm a bisect result by reverting *only* the
suspected hunk, not a whole file.

**Build-only verification is not verification.** After the last code edit before a commit, only
build and clippy were re-run — both clean — while the tests were not. Nine DTLS tests were broken
at that commit. Re-run the full suite after the final edit, not the second-to-last.

## Reporting

Each crate's `benches/README.md` carries its own table. State, every time:

- the machine and OS;
- the baseline commit and what it precedes;
- the exact criterion arguments, identical on both sides;
- whether the baseline benchmark was pre-existing (Procedure A) or reconstructed (Procedure B);
- for reconstructed harnesses, that the comparison rests on the port being faithful.

Quarantine or delete numbers from other machines. If a table mixes measurements taken at different
points — for example a "before fix / after fix" column pair captured as work progressed rather
than in one sweep — label it, or re-run everything at HEAD in a single session.
