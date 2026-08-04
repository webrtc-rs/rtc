# DTLS record-protection benchmarks

```bash
cargo bench --package rtc-dtls --bench record_protection
cargo bench --package rtc-dtls --bench record_protection --no-default-features --features crypto-aws-lc-rs
```

`Setup/*` constructs a cipher — provider dispatch, key import, key schedule, and (after G3) keying
the record MAC. Paid once per DTLS epoch. `Encrypt/*` and `Decrypt/*` protect one 1200-byte record
on an already-keyed cipher; that is the hot path.

## G3 crypto-provider migration: measured impact

One machine (Apple M1 Max, macOS 26.5.2), identical criterion settings, comparing a worktree at
`fd81f68` (P4 — the last commit before DTLS moved to `rtc-crypto`) against the current tree.

| Benchmark | Pre-migration | ring (default) | aws-lc-rs |
|---|---|---|---|
| `Setup/AES-128-GCM` | 274.2 ns | 326.9 ns | 296.6 ns |
| `Encrypt/AES-128-GCM` | 270.5 ns | 270.1 ns | 245.8 ns |
| `Decrypt/AES-128-GCM` | 280.6 ns | 274.8 ns | 225.6 ns |
| `Setup/AES-256-CBC` | 86.5 ns | 755.9 ns | 818.4 ns |
| `Encrypt/AES-256-CBC` | 3.419 µs | 3.204 µs | 2.498 µs |
| `Decrypt/AES-256-CBC` | 2.036 µs | 1.882 µs | 1.194 µs |

**Every per-record path is at parity or better than before the migration**, on both providers.

`Setup/*` rose, which is the intended trade: the record MAC key schedule moved there from the
per-record path, so it is paid once per epoch instead of once per record.

Getting here took three fixes, each found by an initial measurement that showed encryption
3-8x slower. They are documented below in the order they were diagnosed.

## Fixed: per-record `SystemRandom`

DTLS generates fresh randomness per record — the GCM explicit nonce (`crypto_gcm.rs`, RFC 5288
§3) and the CBC record IV (`crypto_cbc.rs`, RFC 5246 §6.2.3.2). Decryption does not, which is why
only encryption had regressed, and why `aws-lc-rs` — faster everywhere else — was the worse of the
two.

Before G3 that randomness came from `rand::rng()`, a thread-local ChaCha CSPRNG. After it, it went
through `RTCRandom`, whose built-ins called the backend's `SystemRandom`, which reaches the
operating system on every call:

| 8-byte fill | ns/call |
|---|---|
| `rand::fill` (thread-local) | **8.3** |
| `ring::rand::SystemRandom` | 829.1 |
| `aws_lc_rs::rand::SystemRandom` | 2196.5 |

That accounted for the deltas almost exactly. Caching one `SystemRandom` instead of constructing
per call recovers only ~9% — the OS round trip dominates, so the handle was never the problem.

The built-in `RTCRandom` implementations now use an OS-seeded, periodically reseeded thread-local
CSPRNG (`common::fill_random`), restoring what the pre-provider code did and what BoringSSL and
OpenSSL do internally. `SystemRandom` is still used where the backend owns the operation —
keypair generation and signing.

| Benchmark (ring) | Backend `SystemRandom` | Thread-local CSPRNG |
|---|---|---|
| `Encrypt/AES-128-GCM` | 1.015 µs | **262.4 ns** |
| `Encrypt/AES-256-CBC` | 6.928 µs | 6.003 µs |

A deployment that requires every byte of entropy to come from a validated module supplies its own
`RTCRandom`; that is what the trait is for.

## Fixed: per-record HMAC key setup in CBC

`CryptoCbc` passed raw key bytes to `prf_mac` on every record, so the HMAC key schedule was
re-derived per record — the same defect found in SRTP. It now holds two keyed `Mac` objects, keyed
once per epoch, and `prf_mac` takes `&mut dyn Mac` rather than a crypto handle plus a key.

| Benchmark (ring) | Per-record keying | Pre-keyed `Mac` |
|---|---|---|
| `Encrypt/AES-256-CBC` | 7.240 µs | 6.928 µs |
| `Decrypt/AES-256-CBC` | 5.127 µs | 4.749 µs |

`Setup/AES-256-CBC` rises correspondingly: two MACs are keyed there instead of on every record.

## Fixed: `ring`'s software SHA-1

CBC authenticates every record with HMAC-SHA1, and `ring` exposes SHA-1 only as
`HMAC_SHA1_FOR_LEGACY_USE_ONLY`, without the ARMv8 SHA-1 instructions — 4469 ns against
RustCrypto's 1373 ns over 1212 bytes. The `ring` provider now composes RustCrypto's HMAC-SHA1, as
it already composes RustCrypto for AES-CTR, CCM, CBC and MD5. See `rtc-srtp/benches/README.md`.

| Benchmark (ring) | `ring` SHA-1 | RustCrypto SHA-1 |
|---|---|---|
| `Encrypt/AES-256-CBC` | 6.003 µs | **3.204 µs** |
| `Decrypt/AES-256-CBC` | 4.702 µs | **1.882 µs** |

## Reproducing

```bash
# Current
cargo bench --package rtc-dtls --bench record_protection -- --warm-up-time 2 --measurement-time 4

# Pre-migration baseline: the bench does not exist at fd81f68, so port this file to the
# pre-G3 API — CryptoGcm::new / CryptoCbc::new took keys directly, without a provider.
git worktree add /tmp/rtc-dtls-base fd81f68
```

The methodology, including why cross-machine numbers must not be compared, is in
`docs/benchmarking-crypto-migration.md`.
