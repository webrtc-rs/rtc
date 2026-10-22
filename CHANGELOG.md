# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `rtc-rtp`: H.266/VVC payloader and depacketizer ([RFC 9328]), byte-compatible with pion's
  `H266Packetizer`/`H266Depacketizer` (aggregation packets, fragmentation units, DONL handling).
  The 320 H.266 rows of the pion golden corpus now run, and pion's 13 `TestH266*` unit tests
  are ported. New public items: `codec::h266::{H266Payloader, H266Depacketizer, H266NALUHeader}`.
- `rtc-shared`: H.266 error variants (`ErrH266*`).

[RFC 9328]: https://datatracker.ietf.org/doc/html/rfc9328

### Changed (breaking, hence 0.22.0)
- `rtc-rtp`: `Header` gains `padding_size`; `HevcPayloader` is a struct with parameter-set state.
- `rtc-sctp`: `PayloadProtocolIdentifier` is a struct (it carries unknown values), not an enum.

### Security / hardening (ported from pion's tests)
- DTLS: the handshake fragment buffer is bounded in fragment count and bytes and reassembles
  overlapping retransmits; the handshake cache and the next-epoch packet queue are bounded.
- SCTP: DATA more than a bounded number of TSNs ahead of the cumulative TSN is not queued.
- RTCP: a maximum-length FIR or transport-wide CC packet no longer overflows the parser; marshal
  refuses packets the 16-bit length cannot describe, and NACKs may list up to that many pairs.
- Data channels: an OPEN message with a label or protocol over 65535 bytes is refused, not truncated.


### Security

- **SRTCP accepted forged packets with the E bit clear.** The authentication tag was only checked
  for encrypted SRTCP, so anyone able to send a datagram could inject RTCP (BYE, PLI, REMB, …) into
  a session. The tag is now verified before the E bit is looked at.
- **SRTP and SRTCP no longer allocate per-SSRC state before a packet authenticates.** The SSRC is
  read from an unauthenticated header, so spraying random SSRCs used to grow the receiver's memory
  without bound; state is now created only for an SSRC that has delivered an authentic packet.
- SRTP located the payload with the *re-marshalled* header size rather than the size on the wire, so
  a packet whose extension block was padded by the sender was encrypted from the wrong offset.
- Remotely triggerable panics fixed: SCTP error causes, the DCEP threshold parser, AV1 payloading
  and OBU parsing, RTCP SLI, and VP9 scalability-structure parsing.

### Added (transport performance)

- **RACK-TLP loss detection for SCTP** ([RFC 8985]; `TransportConfig::with_enable_rack`, on by
  default). A chunk is declared lost once a chunk sent after it has been delivered and a round
  trip plus a reordering allowance has passed, and a tail-loss probe re-sends the newest
  outstanding chunk after about two round trips of silence. Before, a lost tail left nothing to
  open a gap, so recovery waited for T3-rtx — one second at minimum, with the congestion window
  collapsed to one MTU. On a path that drops a few datagrams per second that was most of the
  throughput: over loopback on Linux, a 256 MiB transfer ran at 25–45 MiB/s and now runs at
  110–190 MiB/s. `AssociationStats` gains `get_num_rack_losses` and `get_num_pto_probes`.
- **Window-update SACK.** When the application drains a receive buffer that had been advertised
  as (nearly) full, the receiver now reports the reopened window at once (RFC 9260 §6.2) instead
  of leaving a stopped sender to find out from its next zero-window probe — a retransmission
  timeout away. Every transfer whose reader started a moment after the sender used to lose a
  second to this.

[RFC 8985]: https://datatracker.ietf.org/doc/html/rfc8985

- **`RTCDataChannel::outstanding_bytes_handle()` and `data_channel::OutstandingBytes`.** A cheap,
  clonable, lock-free view of a channel's outstanding send bytes (`get()`, plus `is_detached()` once
  the channel is gone). `outstanding_bytes()` itself is unchanged. A driver that keeps the core
  behind a lock can sample the handle without taking it, so an application polling for send room no
  longer contends with the I/O loop that is making room: on Linux the poll-style data-channel
  benchmark was spending most of its time waiting for that lock.
- The data-channel registry and the per-channel statistics are keyed with `FxHashMap` rather than
  SipHash: their keys are connection-local handles and SCTP stream ids, looked up for every
  acknowledged chunk.
- **`rtp::packet::PacketView`**, a borrowed, allocation-free parse of an RTP packet: the header
  fields, the CSRC list, the extension elements (`extension(id)`, `extensions()`) and the payload,
  all read from the datagram it was parsed from. `parse` accepts and rejects exactly what
  `Packet::unmarshal` does (a differential test holds it to that on 20,000 random inputs). It takes
  10 ns on a 1200-byte packet with three extensions, against 60 ns for an owned `Packet` and 26 ns
  for `Packet::unmarshal_reuse`: the owned forms pay for reference-counted payloads, which a packet
  that is inspected and forwarded never needed.
- `Packet::unmarshal_reuse` fills in one pass when the packet already owns an extension table
  (30 ns to 26 ns).
- SDP marshalling writes `m=`, `o=`, `c=` and `b=` lines piece by piece instead of through
  `format_args!`, and sizes its output from the attribute count; and the output goes through a small
  text writer that copies short pieces inline instead of calling `memcpy` for each. A browser offer
  marshals in 3.4 µs, down from 5.6 µs (pion: 4.2 µs). The writer is the only `unsafe` in `rtc-sdp`;
  it is Miri-clean and tested at every piece length.

### Changed (breaking)

- SDP `Attribute::key` and `Attribute::value` are `smol_str::SmolStr` instead of `String`. Text up
  to 23 bytes is stored inline, so parsing a browser offer allocates 219 times instead of 902 and
  runs in about 20 µs (pion: 23 µs). They dereference to `&str` and compare equal to `&str` and
  `String`; `Attribute::new` still takes `String`s, and `Attribute::from_parts` takes anything
  convertible. `SessionDescription::attribute` returns `Option<&str>`.

### Added

- **Differential tests against pion.** Every protocol parser — SDP, RTCP, RTP (and the codec
  depacketizers/payloaders), STUN, SCTP, DCEP, DTLS records, SRTP — is checked against pion's own
  verdicts and parsed fields on corpora of valid and mutated inputs harvested from pion's tests
  (`tests/pion_golden.rs`, regenerated with the Go oracle in `tests/oracle/`). Where we deliberately
  differ because pion is wrong (for example pion's H.265 payloader hangs at an MTU of 3 and its PACI
  accessor mis-parses the A bit), the test names the divergence.
- RTCP `ApplicationDefined` (APP) packets, `SdesType::Unknown`, and the SDP lexer/state machine are
  now ports of pion's, so malformed input is accepted and rejected the same way.
- `rtp::Header::peek` reads the routing fields of an RTP header without allocating, accepting and
  rejecting exactly what `Header::unmarshal` does; `Packet::unmarshal_reuse` parses into an existing
  packet and allocates nothing in steady state.
- `rtc_srtp::Context::{encrypt_rtp_into, decrypt_rtp_into}` append to a caller-owned buffer, so a
  send or receive loop that keeps one `BytesMut` allocates nothing per packet.
- `rtc_stun::Message::{get_value, build_with}` and `Attributes::find` borrow instead of copying and
  boxing.
- New fuzz targets: RTP depacketizers and payloaders, `Header::peek` against `Header::unmarshal`,
  SRTP/SRTCP unprotect and round trip, and DCEP.
- `benchmarks/pion-compare`: the same micro-benchmarks run against this workspace and against pion,
  side by side, with gates (see `docs/ci.md`).
- CI on Linux and macOS, x86-64 and arm64: see `docs/ci.md`.

### Changed

- **Hardware AES and SHA-1 everywhere, with no build flags.** `aes` 0.9, `ctr` 0.10, `ccm` 0.6,
  `sha1` 0.11, `hmac` 0.13 and `md-5` 0.11 detect the CPU's AES/SHA instructions at run time on
  aarch64 and x86-64. Before this, a downstream build on Apple silicon or Linux/arm64 silently used
  the software implementations unless it passed `--cfg aes_armv8`, which only worked inside this
  repository (`.cargo/config.toml` is not inherited by dependents). The AES-CTR key schedule is now
  expanded once per context rather than once per packet. SRTP AES-CM-HMAC-SHA1 is about 2.3×
  faster than before and about 2× faster than pion on the same machine.
- The workspace declares `rust-version = "1.91"`.
- Faster parsing and marshalling: RTCP compound packets, H.264 payloading (SIMD start-code
  search), SDP marshalling and codec-map construction, STUN decode and build.

### Fixed

- Many parse paths now agree with pion where we differed: RTP header/extension/padding validation,
  RTCP header lengths on re-marshal, TWCC status vectors, SDP fields and numeric ranges, STUN
  attribute ordering after MESSAGE-INTEGRITY, SCTP unknown PPIDs and reconfiguration results.

### Added

- **SCTP zero checksum (RFC 9653)**: `TransportConfig::with_enable_zero_checksum` advertises the capability (parameter 0x8001, EDMID 1, byte-compatible with pion/sctp) and accepts zero-checksum packets on the DTLS-protected association; the send side arms when the peer advertises back, and then skips the CRC-32C on the DATA/SACK/FORWARD-TSN hot paths. INIT and COOKIE ECHO stay checksummed per section 5; a zero-checksum packet reaching an association that never enabled it is dropped.
- **DTLS key logging**: `ConfigBuilder::with_key_logger` receives the NSS key log line once the master secret is derived, on both client and server ends — and both ends of the same association log the identical line, which is the property that makes the log usable.
- **sctp-transport stats entry** read live from the SCTP association (smoothed RTT, congestion window, receiver window, MTU, bytes sent/received), matching pion's `SCTPTransportStats`; `AssociationStats` gains byte counters (counted once per accepted DATA chunk, retransmissions not double-counted) and the association exposes `cwnd()`, `rwnd()`, `mtu()` alongside `rtt()`.
- **csrc stats entry** per (inbound stream, CSRC) with `packetsContributedTo`. `getContributingSources` / `getSynchronizationSources` were stubs returning empty lists; receivers now record CSRCs/SSRC per packet (RFC 3550 section 5.1) with a 10-second memory window, per-packet counting, and per-receiver origin timestamps.

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

### Fixed

- **Connect latency: the first DTLS flight no longer waits on a later flush, and can no
  longer overtake the ICE nomination.** When the controlling side's ICE selects a pair,
  the DTLS handler's `connect` buffers the ClientHello inside the endpoint; nothing in
  that event drained it, so the first flight waited for the driver's write drain of a
  later iteration — a ~200 ms tick on the wire. The handler now pumps the flight into
  its `write_outs` the moment `connect` returns, so it leaves on the same iteration's
  drain. Flushing it early resurfaces an ordering hazard the tick flush had been
  masking: the ClientHello could overtake the ICE nomination (USE-CANDIDATE) ahead of
  it, reach a peer whose pair was not yet selected, and be dropped — a full 1 s DTLS
  retransmit cycle. The ICE handler therefore front-inserts its agent's transmits in
  `poll_write`: the control plane stays first on the wire, its own order preserved.
  Measured end-to-end connect (in-process loopback, 20 rounds): median 204 ms → 2 ms.

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
