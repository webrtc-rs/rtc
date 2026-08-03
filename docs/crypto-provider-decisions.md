# Crypto provider migration decisions

These decisions freeze the boundaries needed to start G3 implementation. Reopening one requires an explicit design change because provider implementations and protocol migrations depend on them.

## SRTP OpenSSL features

The `openssl` and `vendored-openssl` features were partial SRTP implementation choices, not complete RTC crypto providers, and were removed when SRTP migrated to `rtc-crypto`. A future OpenSSL provider is possible only as a complete downstream implementation of the public provider traits that passes the same conformance suite as the built-in providers; partial protocol-specific backend features will not return.

The removal is recorded in the changelog and the crypto-provider migration guide. This pre-1.0 cleanup is intentional: retaining the feature names would falsely imply that OpenSSL provided the complete algorithm surface now required by SRTP and the rest of the RTC stack.

## Crypto errors and protocol boundaries

`rtc-crypto` owns a backend-neutral, non-exhaustive `CryptoError`. The initial variants are `NoDefaultProvider`, `UnsupportedAlgorithm(CryptoAlgorithm)`, `InvalidKeyLength { expected, actual }`, `InvalidNonceLength { expected, actual }`, `InvalidTagLength { expected, actual }`, `InvalidPublicKey`, `InvalidPrivateKey`, `AuthenticationFailed`, `InvalidSignature`, `RandomnessFailed`, `OutputTooSmall { required, actual }`, and `Provider(String)`. Authentication, tag, and padding failures from decryption converge on `AuthenticationFailed`; signature verification uses `InvalidSignature`. These failures must not expose backend-specific distinctions that could become an oracle.

Protocol crates convert `CryptoError` at their own boundary. `rtc-shared` must not depend on `rtc-crypto`, and G3 will not introduce that dependency merely to obtain an automatic `From` conversion. During migration, each call site maps a provider failure to the protocol's existing semantic error where one exists; otherwise it maps to a backend-neutral shared crypto error without retaining the backend error type. This mapping is explicit rather than a blanket conversion.

The string in `Provider(String)` is sanitized local diagnostic context, is not a stable matching surface, and may be logged at trace level. It must not be serialized into packets, alerts, or peer-visible protocol messages. All other variants use stable provider-neutral wording. Secret material, keys, plaintext, nonces, tags, and complete signatures are never included in `Debug`, `Display`, or error sources.

The existing shared public error type remains available during G3 to avoid mixing a workspace-wide error redesign into provider migration. Backend-specific shared variants are removed in P7-01. Moving protocols to crate-local error types can be considered separately and is not required to finish G3.

## Public keys and certificate adapters

The initial non-exhaustive `PublicKeyEncoding` distinguishes these encodings:

| Variant | Encoding |
|---|---|
| `SubjectPublicKeyInfoDer` | Complete DER-encoded SubjectPublicKeyInfo |
| `EcUncompressedPoint` | SEC1 uncompressed P-256 or P-384 point; the signature scheme determines the curve |
| `Ed25519Raw` | Raw 32-byte Ed25519 public key |
| `RsaPkcs1Der` | PKCS#1 DER `RSAPublicKey` |

The canonical certificate-facing public-key boundary is complete DER-encoded SubjectPublicKeyInfo. Certificate parsing and policy remain outside `RTCCrypto`; adapters parse SPKI and construct the operation-specific `PublicKey` passed to signature verification. This preserves an unambiguous public boundary while matching the encodings accepted by current providers.

A `SigningKey` may be non-exportable. Public-key access and signing are mandatory; `to_pkcs8_der()` returns `Ok(None)` for a non-exportable key. PEM/private-key serialization built on that operation returns an explicit adapter error rather than fabricating bytes. Key equality or certificate identity must use public material or a stable provider-neutral identifier, never private-key export.

The current `rcgen::KeyPair`, `CryptoPrivateKeyKind`, and `CustomSigner` APIs remain only as migration adapters. Provider-neutral key generation/import and signing land first; the old adapters are then deprecated and removed before 1.0 in P7-02. Internal DTLS named-curve private-key types are replaced by provider-owned active key-exchange objects and do not become public compatibility APIs.

rustls/webpki certificate-chain verification remains an explicitly separate adapter and policy layer. `RTCCrypto` performs cryptographic primitives and signing-key operations; it does not own trust stores, certificate path building, hostname validation, revocation policy, or application identity policy.

## Feature and provider selection invariants

`ring` remains the default built-in provider. `ring` and `aws-lc-rs` become additive in P1-09: enabling both compiles both and does not silently select AWS-LC-RS. Construction resolves the chosen provider once and protocol objects store an `Arc<dyn RTCCryptoProvider>`; packet paths do not read a mutable global or repeatedly resolve defaults.

The protocol crates still intentionally reject both built-ins together and cannot yet build the full RTC stack without one while their direct backend calls remain. P1-09 makes these configurations pass for `rtc-crypto`; P2 through P6 migrate the consumers, and P7 adds the corresponding full-workspace matrix. This sequencing keeps the new provider contract independently testable without claiming that unmigrated protocol crates are already additive.
