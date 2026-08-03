# SRTP benchmarks

```bash
cargo bench --package rtc-srtp --bench bench
```

Benchmarks run against every enabled built-in provider, so `--features ring,aws-lc-rs` reports
both backends side by side under identical inputs.

The groups are:

* `Encrypt/*`, `Decrypt/*` — per-packet cost on an already-keyed context. This is the hot path.
* `Setup/*` — context construction: provider dispatch, RFC 3711 §4.3 key derivation, and the
  cipher key schedule. Paid **once per one-way context**, not per packet.

The split is deliberate. The crypto-provider design concentrates provider indirection in setup: a
keyed cipher object is obtained once and used per packet with no further dispatch. If `Encrypt/*`
ever regresses while `Setup/*` holds steady, that property has broken.

---

## G3 crypto-provider migration: measured impact

All figures below were taken on **one machine** (Apple M1 Max, macOS 26.5.2) with identical
criterion settings, comparing a git worktree at `425494c` (P3 — the last commit before SRTP moved
to `rtc-crypto`) against the current tree.

```bash
cargo bench --package rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5
```

### AES-128-CM + HMAC-SHA1-80, 1200-byte payload

| Benchmark | Pre-migration (`425494c`) | ring (default) | aws-lc-rs |
|---|---|---|---|
| `Encrypt/RTP` | 1.725-1.780 µs | 1.723 µs | 1.018 µs |
| `Decrypt/RTP` | 1.731-1.751 µs | 1.714 µs | 1.019 µs |
| `Encrypt/RTCP` | 295.0-295.6 ns | 296.0 ns | 347.2 ns |
| `Decrypt/RTCP` | 303.1-311.6 ns | 312.4 ns | 353.0 ns |

**At parity with the pre-migration baseline** on the default provider, after the three fixes
below. `aws-lc-rs` is faster still on the RTP path.

The baseline column gives the range over three independent runs; run-to-run spread on this machine
is about ±3%, so treat anything inside that as parity rather than a difference. See
`docs/benchmarking-crypto-migration.md` for the procedure.

### AEAD-AES-128-GCM, 1200-byte payload

| Benchmark | Current |
|---|---|
| `Encrypt/RTP/AEAD-AES-128-GCM/ring` | 326.8 ns |
| `Decrypt/RTP/AEAD-AES-128-GCM/ring` | 333.6 ns |

No pre-migration equivalent exists — the old bench covered only the CM/HMAC profile. Worth noting
it is roughly **15× faster** than AES-CTR + HMAC-SHA1 on the same payload, consistent with making
one keyed AEAD call instead of a keystream pass plus a separately keyed HMAC.

### Construction cost

| Benchmark | Current |
|---|---|
| `Setup/AES-128-CM-HMAC-SHA1-80/ring` | 1.198 µs |
| `Setup/AEAD-AES-128-GCM/ring` | 925.5 ns |

## Fixed: block-at-a-time AES-CTR

`rtc-crypto`'s `AesCtr::apply_keystream` originally drove `encrypt_block` once per 16-byte block —
75 serialized AES calls for a 1200-byte payload, defeating the batching that lets AES-NI / ARMv8
crypto instructions pipeline. It now delegates to the `ctr` crate, matching what the pre-migration
SRTP cipher used.

This accounts for only a small part of the regression; the cipher was not the bottleneck.

The effect is size-dependent and honestly mixed:

| Benchmark | Manual per-block loop | `ctr` crate | Change |
|---|---|---|---|
| `Encrypt/RTP` (1200 B) | 5.462 µs | 4.949 µs | 9% faster |
| `Decrypt/RTP` (1200 B) | 5.478 µs | 4.945 µs | 10% faster |
| `Encrypt/RTCP` (24 B) | 956.8 ns | 1.034 µs | 8% slower |
| `Decrypt/RTCP` (24 B) | 960.0 ns | 1.057 µs | 10% slower |

For a two-block RTCP packet the `ctr` crate's per-call setup exceeds the batching benefit. It is
retained because 1200-byte RTP dominates real media traffic and because it restores the
pre-migration implementation choice. Bit-exactness is covered by the RFC 3711 known-answer tests
in `rtc-srtp` and the `rtc-crypto` conformance suite, both passing unchanged.

## Fixed: per-packet HMAC key setup

Pre-migration, `CipherAesCmHmacSha1` held a pre-keyed `Hmac<Sha1>` built once during context
construction, so the ipad/opad key schedule was computed once. After the migration the auth tag
went through a stateless provider call that rebuilt the key on every packet — the same
anti-pattern the design rejects for ciphers in §15.8, applied to AEAD, stream, and CBC ciphers but
originally not to MACs.

`RTCCrypto::new_hmac` now returns a keyed [`Mac`] object, mirroring the cipher factories, and
`rtc-srtp` keys its SRTP and SRTCP MACs once per context. The one-shot `hmac()` and `verify_hmac()`
methods were removed from the trait: they are exactly `new_hmac(..)?.sign(..)` and
`new_hmac(..)?.verify(..)`, and keeping them would preserve the path that invites per-packet
keying.

| Benchmark | Per-packet keying | Pre-keyed `Mac` | Change |
|---|---|---|---|
| `Encrypt/RTP` (1200 B) | 4.949 µs | 4.606 µs | 7% faster |
| `Encrypt/RTCP` (24 B) | 1.034 µs | 642.0 ns | **38% faster** |
| `Decrypt/RTCP` (24 B) | 1.057 µs | 628.7 ns | **41% faster** |

The gain is largest for small packets, where key setup dominated the message pass. Context setup
correspondingly rises (1.198 µs → ~2.09 µs) because two MACs are now keyed there — the intended
trade: once per context instead of once per packet.

`rtc-srtp/tests/provider_profiles.rs` guards this with a counting provider asserting the MAC is
constructed exactly twice per context and not per packet.

## Fixed: ring's software SHA-1

`ring` exposes SHA-1 only as `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1
instructions. Measured directly over a 1212-byte message:

| HMAC-SHA1, 1212 B | ns/call |
|---|---|
| `ring` | 4468.6 |
| RustCrypto `hmac` + `sha1` (pre-migration) | 1373.0 |

3.3x, and the whole of the residual SRTP gap. The built-in providers are **composite** by design
(§2.4 — AES-CTR, CCM, CBC and MD5 already come from RustCrypto), so the `ring` provider now
composes RustCrypto's HMAC-SHA1 as well. SHA-256 stays on `ring`, which does use the hardware
instructions. `aws-lc-rs` keeps its own SHA-1, which is faster than both.

This closes the gap without making `aws-lc-rs` the default, which would have imposed the
`aws-lc-sys` C toolchain on every downstream build.

## Reproducing

```bash
# Current numbers
cargo bench --package rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5

# Same-machine pre-migration baseline
git worktree add /tmp/rtc-baseline 425494c
cd /tmp/rtc-baseline
cargo bench --package rtc-srtp --bench bench -- --warm-up-time 2 --measurement-time 5

# Both backends, identical inputs
cargo bench --package rtc-srtp --bench bench --features ring,aws-lc-rs
```

Cross-machine comparison is not meaningful. Earlier revisions of this file recorded results from a
MacBook Air M3; those predate P3 and are not comparable to anything above.
