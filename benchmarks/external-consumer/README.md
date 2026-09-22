# External consumer

A stand-in for an application that depends on rtc: it times the AES paths rtc runs on RustCrypto
(SRTP AES-CM, DTLS AES-CCM and AES-CBC) through `rtc-crypto`'s public API, with AES-GCM on `ring`
as a control.

```bash
python3 scripts/bench.py external
```

## Why it exists

Cargo reads `.cargo/config.toml` from the directory it runs in and that directory's ancestors — not
from each dependency. Rustflags this repository sets therefore never reach an application that
depends on rtc from its own project. Anything whose speed depended on them is fast in every
benchmark here and slow in production, and no in-repository measurement can notice.

That happened. `aes` 0.8 compiled its ARMv8 backend in only when the final build passed
`--cfg aes_armv8`, which this repository's config did and applications did not. Measured with this
crate on an M1 Max, against the tree before the fix:

| 1,200 bytes | In the repository | As an application | Ratio |
|---|---:|---:|---:|
| AES-128-CTR (SRTP AES-CM) | 223 ns | 5,977 ns | 27× |
| AES-128-CCM seal (DTLS) | 992 ns | 26,413 ns | 27× |
| AES-256-CBC decrypt (DTLS) | 289 ns | 28,831 ns | 100× |
| AES-128-GCM seal (control, `ring`) | 217 ns | 219 ns | 1× |

`rtc-crypto` now uses `aes` 0.9, which selects its hardware backend at runtime without any cfg, so
applications need no configuration. See the comment at the top of `rtc-crypto/src/common.rs` for
what that cost the in-repository numbers.

## What `bench.py external` does

It builds and runs this crate three ways and prints them side by side:

| Build | Run from | Rustflags |
|---|---|---|
| consumer | outside the repository (`~/.cache/rtc-bench/external-consumer/cwd`) | none, from any source — including a user-wide `~/.cargo/config.toml`, whose flags (a `target-cpu=native`, say) an application's build would not share |
| repository | the repository root, so `.cargo/config.toml` applies | the config's |
| software | outside the repository | `--cfg aes_backend="soft"`, forcing RustCrypto's software AES |

It fails if the consumer build is more than 1.5× slower than the repository build on any
RustCrypto path. Noise between two hardware-backend runs is a few percent; a software fallback is an
order of magnitude. The software build shows what that looks like on the machine at hand.

The binary also prints whether `aes_armv8` reached it, which is the quickest way to see which
configuration a build got.

## Why it is not in CI

The workflow never gates on timing, because shared runners are too noisy for it; see
[docs/benchmarking.md](../../docs/benchmarking.md#ci). The ratio this checks is large enough that
an Apple-silicon runner would probably be reliable, but run it locally after changing crypto
dependencies or `.cargo/config.toml`.

## Standalone on purpose

This crate has its own `[workspace]` and is not a member of the rtc workspace: as a member it
would be built from the repository and would inherit exactly the configuration it exists to leave
out. `bench.py` copies the workspace `Cargo.lock` next to it before building, so shared
dependencies resolve to the same versions as the rest of the tree.
