# Crypto provider migration

`rtc` 0.21 routes every cryptographic operation through `rtc-crypto`. Protocol crates no longer
depend on `ring`, `aws-lc-rs`, or RustCrypto primitive crates; they take an
`Arc<dyn RTCCryptoProvider>` and call provider traits.

This guide covers what changed for callers. For *why*, see `docs/crypto-provider-decisions.md`.

## Contents

- [Choosing a provider](#choosing-a-provider)
- [Cargo features are now additive](#cargo-features-are-now-additive)
- [Removed and changed public items](#removed-and-changed-public-items)
- [Top-level `rtc`](#top-level-rtc)
- [Certificates](#certificates)
- [Standalone DTLS](#standalone-dtls)
- [Standalone SRTP](#standalone-srtp)
- [Standalone STUN, ICE, and TURN](#standalone-stun-ice-and-turn)
- [Writing your own provider](#writing-your-own-provider)
- [OpenSSL](#openssl)

## Choosing a provider

```rust
use std::sync::Arc;
use rtc_crypto::{RTCCryptoProvider, default_provider};
use rtc_crypto::providers::{AwsLcRsProvider, RingProvider};

// The feature-selected default: ring when enabled, otherwise aws-lc-rs.
// Returns Err(CryptoError::NoDefaultProvider) when neither feature is on.
let provider: Arc<dyn RTCCryptoProvider> = default_provider()?;

// Or name one explicitly. Both can be compiled in at once.
let ring: Arc<dyn RTCCryptoProvider> = Arc::new(RingProvider::new());
let aws: Arc<dyn RTCCryptoProvider> = Arc::new(AwsLcRsProvider::new());
```

There is no process-global provider and nothing to install at startup. A provider is an ordinary
value passed through configuration, so two peer connections in one process can use different
providers.

## The provider is always passed in

**No library code resolves a default provider.** `crypto::default_provider()` is called in exactly
one place in the workspace — peer-connection construction, where the application either supplied
one via `SettingEngine::set_crypto_provider` or gets the feature-selected built-in. Everything
below that receives an `Arc<dyn RTCCryptoProvider>` from its caller.

This is why the `*_with_provider` constructor pairs are gone. Each had a default-resolving sibling
that hid the choice — and, in a `--no-default-features` build, panicked or failed deep inside a
call rather than at configuration time. There is now one constructor per type and it takes the
provider:

| Before | Now |
|---|---|
| `Context::new(key, salt, profile, a, b)` | `Context::new(key, salt, profile, a, b, provider)` |
| `Context::new_with_provider(…)` | (folded into `new`) |
| `Client::new(config)` | `Client::new(config, provider)` |
| `Agent::new(config)` | `Agent::new(config, provider)` |
| `Certificate::generate_self_signed(names)` | `Certificate::generate_self_signed(names, provider)` |
| `Certificate::from_pem(pem)` | `Certificate::from_pem(pem, provider)` |
| `RTCCertificate::from_pem(pem)` | `RTCCertificate::from_pem(pem, provider)` |
| `RTCCertificate::get_fingerprints()` | `get_fingerprints(provider) -> Result<…>` |
| `MessageIntegrity::new_short_term_integrity(pw)` | `…(pw, provider)` |

`Default` impls that resolved a provider are removed rather than reworked, because `Default` has
nowhere to accept one. `HandshakeConfig`, `rtc_dtls::State`, `Agent`, and `RTCDtlsTransport` are
now built through constructors that take the provider. `ConfigBuilder::build` returns an error
instead of inventing a provider when none was configured.

Each protocol crate re-exports the crypto API — `rtc_srtp::crypto`, `rtc_stun::crypto`,
`rtc_ice::crypto`, `rtc_turn::crypto`, and `rtc_dtls::crypto_provider` (named differently because
`rtc-dtls` already has its own `crypto` module) — so a standalone user can name
`Arc<dyn RTCCryptoProvider>` without adding and version-matching a direct `rtc-crypto` dependency.

Tests, examples, and benchmarks are the outside caller and may call `default_provider()` directly.

## Cargo features are now additive

Before 0.21, `rtc`, `rtc-dtls`, `rtc-srtp`, and `rtc-stun` each carried:

```rust
#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("At most one of the features \"aws-lc-rs\" and \"ring\" can be enabled.");
```

Enabling both is now supported and tested in CI. This matters because Cargo unifies features: a
transitive dependency enabling the other backend used to break an otherwise valid build, with no
fix available to the person hitting it.

| Build | Result |
|---|---|
| `--features ring` | ring only |
| `--features aws-lc-rs` | aws-lc-rs only |
| `--features ring,aws-lc-rs` | both compiled; `default_provider()` returns ring |
| `--no-default-features` | no built-in provider; supply your own |

`default_provider()` prefers ring when both are enabled, matching the previous precedence.
Enabling `aws-lc-rs` alongside the default never silently switches the default.

## Removed and changed public items

| Item | Status | Replacement |
|---|---|---|
| `rtc_shared::crypto::KeyingMaterialExporter` | removed | inherent `rtc_dtls::State::export_keying_material` |
| `rtc_srtp::Config::extract_session_keys_from_dtls` | removed | `set_session_keys_from_keying_material` |
| `rtc_stun::MessageIntegrity` (tuple struct) | changed | named fields; `key` is a `SecretVec` |
| `MessageIntegrity::new_short_term_integrity` | changed | `new_short_term_integrity(password, provider)` |
| `MessageIntegrity::new_long_term_integrity` | changed | `new_long_term_integrity(user, realm, pass, provider)` |
| `MessageIntegrity::new_raw_integrity` | changed | `new_raw_integrity(key, provider)` |
| `MessageIntegrity::default()` | removed | construct with an explicit key and provider |
| `rtc_dtls::crypto::CustomSigner` | removed | implement `rtc_crypto::SigningKey` |
| `CryptoPrivateKey::from_custom_signer` | removed | `CryptoPrivateKey::from_signing_key` |
| `CryptoPrivateKey::from_key_pair(&KeyPair)` | changed | now takes a provider: `from_key_pair(&KeyPair, provider)` |
| `CryptoPrivateKey::serialized_der` field | removed | `SigningKey::to_pkcs8_der()` |
| `rtc_dtls::crypto::CryptoPrivateKeyKind` | removed | opaque `Arc<dyn SigningKey>` |
| `RTCCertificate::from_key_pair` | removed | `RTCCertificate::generate` |
| `RTCCertificate::from_key_pair_with_provider` | removed | `RTCCertificate::generate_from_signing_key` |
| `rtc_shared::Error::{Sec1, P256, RcGen, AesGcm, Aes}` | removed | `Error::Crypto(String)` |
| `RTCCrypto::hmac` | removed | `new_hmac(alg, key)?.sign(input, out)` |
| `RTCCrypto::verify_hmac` | removed | `new_hmac(alg, key)?.verify(input, tag)` |
| `rtc_srtp` `openssl` / `vendored-openssl` features | removed | see [OpenSSL](#openssl) |

`MessageIntegrity::default()` produced a credential with an empty key, which was never useful. No
in-tree caller existed; downstream code that relied on it must supply a real key.

### Keyed MACs

`RTCCrypto::hmac` and `verify_hmac` are gone. They were exactly `new_hmac(..)?.sign(..)` and
`new_hmac(..)?.verify(..)`, and keeping them preserved a path that derives the HMAC key schedule
on every call — which cost SRTP roughly 40% of its per-RTCP-packet time. There is now one way to
compute an HMAC, and it makes the keying cost visible at the call site.

Before:

```rust
let mut tag = [0u8; 20];
crypto.hmac(HmacAlgorithm::Sha1, &key, &[header, payload], &mut tag)?;
crypto.verify_hmac(HmacAlgorithm::Sha1, &key, &[header, payload], &tag)?;
```

After — one-shot:

```rust
let mut tag = [0u8; 20];
let mut mac = crypto.new_hmac(HmacAlgorithm::Sha1, &key)?;
mac.sign(&[header, payload], &mut tag)?;
mac.verify(&[header, payload], &tag)?;
```

After — repeated authentication with one key, which is the point: hold the `Mac` in your state and
key it once.

```rust
struct MyContext {
    auth: Box<dyn Mac>,   // keyed once at construction
}

impl MyContext {
    fn new(crypto: &dyn RTCCrypto, key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self { auth: crypto.new_hmac(HmacAlgorithm::Sha1, key)? })
    }

    // `&mut self`, because Mac methods take &mut self like the cipher traits.
    fn tag(&mut self, message: &[&[u8]]) -> Result<[u8; 20], CryptoError> {
        let mut tag = [0u8; 20];
        self.auth.sign(message, &mut tag)?;
        Ok(tag)
    }
}
```

`Mac` is `Send` and its methods take `&mut self`, matching `StreamCipher`, `AeadCipher`, and
`CbcCipher`. A caller whose own signature is fixed to `&self` can still build a local `Mac` per
message and use it mutably.

## Top-level `rtc`

`SettingEngine` carries the provider. It is resolved once during peer-connection construction and
cloned into DTLS, SRTP, STUN, certificate, and fingerprint state.

```rust
use std::sync::Arc;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc_crypto::providers::AwsLcRsProvider;

let mut setting_engine = SettingEngine::default();
setting_engine.set_crypto_provider(Arc::new(AwsLcRsProvider::new()));
```

Omitting the call keeps the feature-selected default, so existing code needs no change.

## Certificates

`rcgen::KeyPair`-based construction is gone. Certificate *formatting* still uses `rcgen` —
X.509 is deliberately not a provider concern — but key generation and signing go through the
provider. `CertificateParams` is re-exported so callers need no direct `rcgen` dependency.

Before:

```rust
use rcgen::KeyPair;

let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
let certificate = RTCCertificate::from_key_pair(key_pair)?;
```

After:

```rust
use rtc::crypto::{self, SignatureScheme};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};

let certificate = RTCCertificate::generate(
    crypto::default_provider()?,
    SignatureScheme::EcdsaP256Sha256,
    CertificateParams::new(vec!["localhost".to_owned()])?,
)?;
```

Three construction paths are available:

| Need | Use |
|---|---|
| Provider generates the key | `RTCCertificate::generate(provider, scheme, params)` |
| Key already exists (imported PKCS#8, HSM, KMS) | `RTCCertificate::generate_from_signing_key(params, scheme, signing_key)` |
| Certificate chain already exists | `RTCCertificate::from_pkcs8(provider, scheme, chain, der, expires)` |

### External and non-exportable signing keys

`CustomSigner` is replaced by `rtc_crypto::SigningKey`, which is also what the built-in providers
implement. An HSM or KMS key returns `Ok(None)` from `to_pkcs8_der()`; PEM serialization of such a
key returns an explicit error rather than fabricating bytes.

```rust
use std::sync::Arc;
use rtc_crypto::{CryptoError, PublicKey, PublicKeyEncoding, SignatureScheme, SigningKey};

#[derive(Debug)]
struct KmsKey { /* handle, cached SPKI */ }

impl SigningKey for KmsKey {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        scheme == SignatureScheme::EcdsaP256Sha256
    }

    fn public_key(&self) -> PublicKey<'_> {
        PublicKey {
            encoding: PublicKeyEncoding::SubjectPublicKeyInfoDer,
            bytes: &[], // cached SPKI DER
        }
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let _ = (scheme, message);
        todo!("call the KMS")
    }
}

let key: Arc<dyn SigningKey> = Arc::new(KmsKey { /* … */ });
```

Pass it to `RTCCertificate::generate_from_signing_key`, or to
`rtc_dtls::crypto::CryptoPrivateKey::from_signing_key` for standalone DTLS.

## Standalone DTLS

```rust
use rtc_dtls::config::ConfigBuilder;

let config = ConfigBuilder::default()
    .with_crypto_provider(provider.clone())
    .with_certificates(vec![certificate])
    .build(true, None)?;
```

`Certificate::generate_self_signed`, `generate_self_signed_with_alg`, and `from_pem` all take the
provider as their last argument. The default-resolving overloads are gone, as is
`ConfigBuilder::build`'s silent fallback — it now returns an error if no provider was configured.

### DTLS-SRTP keying material

`KeyingMaterialExporter` is gone. Export is an inherent method on the DTLS session, and SRTP takes
the resulting bytes, so `rtc-srtp` and `rtc-dtls` stay independent of each other.

Before:

```rust
srtp_config.extract_session_keys_from_dtls(dtls_state, is_client)?;
```

After:

```rust
use rtc_srtp::config::LABEL_EXTRACTOR_DTLS_SRTP;

let material = dtls_state.export_keying_material(
    LABEL_EXTRACTOR_DTLS_SRTP,
    &[],
    srtp_config.keying_material_len(),
)?;
srtp_config.set_session_keys_from_keying_material(&material, dtls_state.is_client())?;
```

## Standalone SRTP

`Context::new` takes the provider. It validates the protection
profile against `RTCCrypto::supports`, derives session material through the provider, and builds
keyed cipher objects **once per one-way context**. Packet indexes, rollover counters, replay
windows, IVs, AAD, tag truncation, and wire layout stay in `rtc-srtp`.

```rust
let context = Context::new(
    &master_key,
    &master_salt,
    ProtectionProfile::Aes128CmHmacSha1_80,
    None,
    None,
    provider.clone(),
)?;
```

There is no default-resolving overload. `rtc-srtp` never calls `default_provider()`; an
application that wants the feature-selected built-in passes `crypto::default_provider()?`.

## Standalone STUN, ICE, and TURN

`MessageIntegrity` now holds its provider, because `Setter::add_to` and `check` have no place to
receive one. The struct changed from a public tuple to named fields, and the default-resolving
constructors were removed.

Before:

```rust
let integrity = MessageIntegrity::new_short_term_integrity(password);
```

After:

```rust
let integrity = MessageIntegrity::new_short_term_integrity(password, provider.clone());

let integrity = MessageIntegrity::new_long_term_integrity(
    username, realm, password, provider.clone(),
)?;   // returns Result: MD5 must be available
```

ICE and TURN reach crypto only through these values; they hold one provider handle and clone it
into the integrity attributes they build.

## Writing your own provider

Implement `RTCCryptoProvider` plus the component traits. Nothing needs to be registered — pass the
value in through configuration.

```rust
use std::sync::Arc;
use rtc_crypto::{RTCCrypto, RTCCryptoProvider, RTCRandom};

#[derive(Debug)]
struct MyProvider { crypto: MyCrypto, random: MyRandom }

impl RTCCryptoProvider for MyProvider {
    fn name(&self) -> &'static str { "my-provider" }
    fn crypto(&self) -> &dyn RTCCrypto { &self.crypto }
    fn random(&self) -> &dyn RTCRandom { &self.random }
}

setting_engine.set_crypto_provider(Arc::new(MyProvider { /* … */ }));
```

Validate it against the same conformance suite the built-ins use:

```rust
// Cargo.toml: rtc-crypto = { version = "0.21", features = ["test-support"] }
#[test]
fn my_provider_conforms() {
    rtc_crypto::conformance::assert_provider(&MyProvider::new());
}
```

`assert_provider` runs the whole suite. Individual sections are also public
(`assert_hashes_and_hmac`, `assert_aead`, `assert_cbc`, `assert_block_and_stream_ciphers`,
`assert_key_exchange`, `assert_signatures`, `assert_random`) for a provider that implements only
part of the surface.

The suite covers RFC known-answer vectors, round trips, tag-length and nonce-length validation,
and unsupported-algorithm reporting. `cargo test --package rtc-crypto --no-default-features
--features test-support --test custom_provider` shows a complete downstream-style provider built
with no built-in enabled.

Report unsupported algorithms honestly through `RTCCrypto::supports` — negotiation intersects
protocol support, provider capability, and application configuration before advertising anything,
so an accurate answer turns an unusable combination into a construction-time error instead of a
stalled handshake.

## Provider performance

The built-in providers are **composite**: each uses its primary backend where that backend is
strong and RustCrypto elsewhere. `ring` supplies SHA-256, AEAD, key exchange and signatures;
AES-CTR, CCM, CBC, MD5 and HMAC-SHA1 come from RustCrypto because `ring`'s SHA-1 does not use the
ARMv8 instructions. `aws-lc-rs` keeps its own SHA-1, which is faster than both.

Randomness for protocol values — DTLS randoms and record IVs, cookies, transaction IDs — comes
from an OS-seeded, periodically reseeded thread-local CSPRNG rather than a per-call read of the
operating system, which measured 100-250x slower and showed up directly on the DTLS record path.
Keypair generation and signing still use the backend's own RNG.

After these choices, SRTP and DTLS per-packet throughput is at parity with, or better than,
pre-`rtc-crypto` releases on the default provider. `aws-lc-rs` is faster on the SRTP AES-CM/HMAC
and DTLS CBC paths if you can accept the `aws-lc-sys` C toolchain in your build. Measurements and
methodology are in `rtc-srtp/benches/README.md`, `rtc-dtls/benches/README.md`, and
`rtc-stun/benches/README.md`.

A custom provider is free to make different choices; the conformance suite checks correctness, not
speed.

## OpenSSL

The `openssl` and `vendored-openssl` features on `rtc-srtp` were removed. They selected an
alternate AES-CTR path inside SRTP only and never implemented the full provider contract, so
keeping the names would imply a completeness that did not exist.

An OpenSSL backend can return as a complete `RTCCryptoProvider` — in an application or a separate
crate — that passes the public conformance suite. No `rtc` change is required to enable that.
