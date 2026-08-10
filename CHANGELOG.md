# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RTCCrypto::new_hmac` returns a keyed `Mac` whose key schedule is derived once, mirroring the
  existing keyed cipher factories. It replaces the removed one-shot `hmac`/`verify_hmac`.
- **New `rtc-crypto` crate: a provider-neutral cryptographic API**
  ([webrtc#839](https://github.com/webrtc-rs/webrtc/issues/839),
  [rtc#128](https://github.com/webrtc-rs/rtc/issues/128)). `RTCCryptoProvider` bundles an
  `RTCCrypto` operations trait and an `RTCRandom` CSPRNG. Two built-in providers ship,
  `RingProvider` and `AwsLcRsProvider`, and applications can supply their own — for OpenSSL, a
  FIPS-validated module, an HSM, or a platform backend — by implementing the public traits. A
  reusable conformance suite (`rtc_crypto::conformance::assert_provider`, behind the
  `test-support` feature) validates any implementation against the same RFC vectors the built-ins
  pass.
- `SettingEngine::set_crypto_provider` selects the provider per peer connection. Two peer
  connections in one process may use different providers. There is no process-global provider to
  install.
- Explicit provider constructors on the standalone protocol crates:
  `rtc_dtls::ConfigBuilder::with_crypto_provider`, `rtc_srtp::Context::new_with_provider`, and
  `MessageIntegrity::{new_raw,new_short_term,new_long_term}_integrity_with_provider`.
- Provider-neutral certificate construction: `RTCCertificate::generate`,
  `RTCCertificate::generate_from_signing_key`, and `RTCCertificate::from_pkcs8`.
  `rcgen::CertificateParams` is re-exported from `rtc::peer_connection::certificate`, so callers
  no longer need a direct `rcgen` dependency to name it.
- DTLS record-protection benchmarks (`cargo bench --package rtc-dtls --bench record_protection`)
  and SRTP AEAD plus context-construction benchmarks, all reporting each enabled provider under
  identical inputs and separating one-time key-schedule cost from per-packet cost.

### Changed

- **No library code resolves a default crypto provider.** `crypto::default_provider()` is now
  called in exactly one place — peer-connection construction — where the application either
  supplied one via `SettingEngine::set_crypto_provider` or gets the feature-selected built-in.
  Every constructor below that takes an `Arc<dyn RTCCryptoProvider>` from its caller, so a
  `--no-default-features` build fails at configuration time instead of deep inside a handshake.
  The `*_with_provider` constructor pairs are collapsed into single provider-taking constructors
  (`Context::new`, `Client::new`, `Agent::new`, `Certificate::generate_self_signed`,
  `Certificate::from_pem`, `RTCCertificate::from_pem`, `RTCCertificate::get_fingerprints`, the
  `MessageIntegrity` constructors). `Default` impls that resolved a provider — `HandshakeConfig`,
  `rtc_dtls::State`, `Agent`, `RTCDtlsTransport` — are removed in favour of those constructors,
  and `ConfigBuilder::build` errors when no provider was configured rather than inventing one.
- Each protocol crate re-exports the crypto API (`rtc_srtp::crypto`, `rtc_stun::crypto`,
  `rtc_ice::crypto`, `rtc_turn::crypto`, `rtc_dtls::crypto_provider`) so standalone users can name
  `Arc<dyn RTCCryptoProvider>` without a direct `rtc-crypto` dependency.
- **`crypto-ring` and `crypto-aws-lc-rs` Cargo features are now additive.** Enabling both builds successfully
  and is covered in CI. Previously each of `rtc`, `rtc-dtls`, `rtc-srtp`, and `rtc-stun` carried a
  `compile_error!` rejecting the combination, which made an otherwise valid build fail whenever
  Cargo feature unification pulled in both. `rtc_crypto::default_provider()` still prefers `ring`
  when both are enabled, so default behaviour is unchanged.
- DTLS, SRTP, STUN, ICE, TURN, and the top-level `rtc` crate perform all cryptography through the
  configured provider. Protocol composition is unchanged and stays in its own crate: the TLS 1.2
  PRF in DTLS, SRTP key derivation and packet layout in SRTP, STUN integrity framing in STUN.
  Default algorithm selection and wire behaviour are unchanged.
- `rtc_dtls::State::export_keying_material` is now an inherent method returning `SecretVec`, and
  `rtc_srtp::Config::set_session_keys_from_keying_material` consumes the exported bytes. The
  top-level crate performs the handoff, so `rtc-srtp` and `rtc-dtls` remain independent of each
  other. `rtc_srtp::config::LABEL_EXTRACTOR_DTLS_SRTP` is now public for standalone callers.
- `rtc_stun::MessageIntegrity` changed from a public tuple struct to named fields and now holds
  its provider, because `Setter::add_to` and `check` have no parameter through which to receive
  one. Its key is stored as a `SecretVec`.
- **`MediaEngine::register_default_codecs` no longer registers `video/ulpfec`**
  ([#837](https://github.com/webrtc-rs/webrtc/issues/837)). The receive path does not recover
  media from ULPFEC packets, so offering the codec invited peers to send repair packets that
  could not be used. Applications that want it can still register it explicitly with
  `MIME_TYPE_ULP_FEC`, which remains public. **This changes the default offer's SDP**: payload
  type 116 is no longer present. ULPFEC will return to the defaults once receive-side recovery
  is implemented.
- Upgrade `nix` to the newer version that allow compile `ohos` targets.

### Deprecated

-

### Removed

These are deliberate pre-1.0 API removals, not behaviour changes. Every entry has a replacement;
see `docs/crypto-provider-migration.md` for before/after examples.

- Removed the partial `openssl` and `vendored-openssl` Cargo features from `rtc-srtp` and `rtc`; SRTP cryptography now uses the selected `rtc-crypto` provider for every protection profile. They selected only an alternate AES-CTR path and never implemented the full provider contract. An OpenSSL backend can return as a complete downstream `RTCCryptoProvider`.
- Removed `rtc_shared::crypto::KeyingMaterialExporter`. `rtc-shared` performs no cryptography and
  no longer carries a crypto bridge.
- Removed `rtc_srtp::Config::extract_session_keys_from_dtls`; use
  `set_session_keys_from_keying_material` with material exported from the DTLS session.
- Removed the default-resolving `MessageIntegrity::{new_raw_integrity, new_short_term_integrity,
  new_long_term_integrity}` constructors and the derived `Default` impl. `Default` produced a
  credential with an empty key, which is never valid; use the `_with_provider` constructors.
- Removed `rtc_dtls::crypto::CustomSigner` and `CryptoPrivateKey::from_custom_signer`. Implement
  `rtc_crypto::SigningKey` and use `CryptoPrivateKey::from_signing_key`. This is a superset of the
  old capability: non-exportable HSM and KMS keys are supported, and `to_pkcs8_der()` returns
  `Ok(None)` for them instead of fabricating key bytes.
- Removed `CryptoPrivateKey::from_key_pair`, its `TryFrom<&rcgen::KeyPair>` impl, and the
  `serialized_der` field.
- Removed `RTCCertificate::from_key_pair` and `from_key_pair_with_provider`; use
  `RTCCertificate::generate` or `generate_from_signing_key`.
- Removed the `Sec1`, `P256`, `RcGen`, `AesGcm`, and `Aes` variants from `rtc_shared::Error`,
  along with the `sec1`, `p256`, `rcgen`, `aes`, and `aes-gcm` dependencies of `rtc-shared`. These
  put crypto-crate types in the public API of every crate in the workspace and pinned their major
  versions there. Crypto failures now cross crate boundaries as `Error::Crypto(String)`.
- Removed `RTCCrypto::hmac` and `RTCCrypto::verify_hmac`. They are exactly
  `new_hmac(..)?.sign(..)` and `new_hmac(..)?.verify(..)`, and retaining them preserved a path
  that re-derives the HMAC key schedule on every call.
- Removed the four duplicated `compile_error!` backend guards and the four
  `extern crate aws_lc_rs as ring;` aliases.

### Fixed

- `rtc-crypto`'s AES-CTR keystream now uses a batched implementation instead of one
  `encrypt_block` call per 16-byte block, which defeated AES-NI / ARMv8 instruction pipelining.
  Roughly 9-10% faster on a 1200-byte SRTP payload.
- **SRTP no longer derives the HMAC key schedule on every packet.** `RTCCrypto::new_hmac` returns
  a keyed `Mac`, and `rtc-srtp` keys its SRTP and SRTCP MACs once per context instead of passing
  raw key bytes per packet. Roughly 40% faster per RTCP packet and 7% per 1200-byte RTP packet.
  A counting provider in `rtc-srtp/tests/provider_profiles.rs` guards the invariant.
- **DTLS CBC no longer derives its record MAC key on every record.** `CryptoCbc` holds two keyed
  `Mac` objects instead of passing raw key bytes to `prf_mac` per record: ~4% faster on encrypt and
  ~7% on decrypt, with the key schedule moving to epoch setup.
- STUN `MESSAGE-INTEGRITY` was measured against its pre-migration baseline and shows no regression
  (see `rtc-stun/benches/README.md`); it already used `ring`'s HMAC-SHA1 before G3.
- **The built-in `RTCRandom` implementations no longer read the operating system on every call.**
  DTLS generates a GCM explicit nonce and a CBC record IV per record; routing those through the
  backend's `SystemRandom` cost ~829 ns on `ring` and ~2196 ns on `aws-lc-rs`, against ~8 ns for
  the thread-local CSPRNG the pre-provider code used. They now use an OS-seeded, periodically
  reseeded thread-local CSPRNG, as BoringSSL and OpenSSL do internally. `SystemRandom` is still
  used where the backend owns the operation — keypair generation and signing. DTLS GCM encryption
  went from 1.015 µs to 262 ns per record. A deployment needing validated entropy everywhere
  supplies its own `RTCRandom`.
- **The `ring` provider composes RustCrypto's HMAC-SHA1.** `ring` exposes SHA-1 only as
  `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1 instructions: 4469 ns against
  RustCrypto's 1373 ns over a 1212-byte message. The built-in providers are already composite —
  AES-CTR, CCM, CBC and MD5 come from RustCrypto — so HMAC-SHA1 is composed the same way. This
  closes the gap without making `aws-lc-rs` the default, which would impose the `aws-lc-sys` C
  toolchain on every downstream build. SHA-256 stays on `ring`; `aws-lc-rs` keeps its own SHA-1.

**Net effect: every per-packet and per-record benchmark is at parity with or faster than the
pre-migration baseline on the default provider.** SRTP AES-CM/HMAC RTP encryption 1.725 µs before
and 1.723 µs after; DTLS GCM record encryption 270.5 ns before and 270.1 ns after; DTLS CBC 6-8%
faster than before. Context and epoch setup costs rose, which is the intended trade — key
schedules moved off the per-packet path. See the three `benches/README.md` files for the full
tables and methodology.

- Add RSA as an allowed private key kind in rtc_dtls::ConfigBuilder::
  validate- [PR #141](https://github.com/webrtc-rs/rtc/pull/141)

### Security

-

## [0.20.0] - 2026-07-31

### Added

- The `rtc` v0.20.0 is Sans-I/O protocol core with complete WebRTC stack (95%+ W3C API compliance)

[Unreleased]: https://github.com/webrtc-rs/rtc/compare/0.20.0...HEAD

[0.20.1]: https://github.com/webrtc-rs/rtc/compare/0.20.0...0.20.1

[0.20.0]: https://github.com/webrtc-rs/rtc/releases/tag/0.20.0
