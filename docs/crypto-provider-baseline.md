# Crypto provider baseline

This document records the crypto behavior and compatibility surface before the `rtc-crypto` provider migration. It is the baseline for G3 and must be updated when a migration intentionally changes an algorithm, preference, public adapter, or test expectation.

## DTLS

### Cipher suites

All current suites use SHA-256 for the TLS 1.2 PRF and Finished calculation. CBC suites additionally use HMAC-SHA1 for record authentication.

| Preference | Cipher suite | Code point | Record protection | Authentication |
|---:|---|---:|---|---|
| 1 | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `0xc02b` | AES-128-GCM | ECDSA certificate |
| 2 | `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | `0xc00a` | AES-256-CBC plus HMAC-SHA1 | ECDSA certificate |
| 3 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `0xc02f` | AES-128-GCM | RSA certificate |
| 4 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | `0xc014` | AES-256-CBC plus HMAC-SHA1 | RSA certificate |
| 5 | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | `0xcca9` | ChaCha20-Poly1305 | ECDSA certificate |
| Explicit only | `TLS_ECDHE_ECDSA_WITH_AES_128_CCM` | `0xc0ac` | AES-128-CCM, 16-byte tag | ECDSA certificate |
| Explicit only | `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` | `0xc0ae` | AES-128-CCM, 8-byte tag | ECDSA certificate |
| Explicit only | `TLS_PSK_WITH_AES_128_CCM` | `0xc0a4` | AES-128-CCM, 16-byte tag | PSK |
| Explicit only | `TLS_PSK_WITH_AES_128_CCM_8` | `0xc0a8` | AES-128-CCM, 8-byte tag | PSK |
| Explicit only | `TLS_PSK_WITH_AES_128_GCM_SHA256` | `0x00a8` | AES-128-GCM | PSK |
| Explicit only | `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | `0xcca8` | ChaCha20-Poly1305 | RSA certificate |

The first five rows are the order returned by `default_cipher_suites()`. G3 must preserve this order unless a separate compatibility change explicitly changes it.

### Named groups

| Group | Code point | Current use |
|---|---:|---|
| P-256 | `0x0017` | Advertised first |
| P-384 | `0x0018` | Advertised third |
| X25519 | `0x001d` | Advertised second and defined as `DEFAULT_NAMED_CURVE` |

The provider API therefore needs P-256, P-384, and X25519 key agreement. The current concrete `NamedCurvePrivateKey` remains crate-private.

### Signatures and key encodings

The default advertised signature/hash list is ECDSA with SHA-256, SHA-384, and SHA-512; RSA PKCS#1 with SHA-256, SHA-384, and SHA-512; and Ed25519. Current signing supports Ed25519, ECDSA P-256/SHA-256, RSA PKCS#1/SHA-256, and `CustomSigner`. Current verification additionally accepts ECDSA P-384/SHA-384 and RSA PKCS#1/SHA-1, SHA-384, and SHA-512.

The `SignatureScheme` enum names RSA-PSS and SHA-1 combinations beyond that set, but they are not complete negotiated implementations. They are not part of the initial provider contract.

| Signature operation | Current verifier input |
|---|---|
| Ed25519 | Raw 32-byte public key |
| ECDSA P-256/SHA-256 | Uncompressed SEC1 point and ASN.1 DER signature |
| ECDSA P-384/SHA-384 | Uncompressed SEC1 point and ASN.1 DER signature |
| RSA PKCS#1/SHA-1, SHA-256, SHA-384, or SHA-512 | PKCS#1 DER `RSAPublicKey` and PKCS#1 v1.5 signature |

Certificate parsing currently extracts the subject-public-key bit string from X.509. The provider-neutral certificate boundary will instead use complete SPKI DER, with built-in adapters converting it to the operation-specific encodings above.

## SRTP

| Protection profile | Master key | Master salt | RTP auth tag | RTCP auth tag | AEAD tag | Auth key |
|---|---:|---:|---:|---:|---:|---:|
| `SRTP_AES128_CM_HMAC_SHA1_80` | 16 | 14 | 10 | 10 | 0 | 20 |
| `SRTP_AES128_CM_HMAC_SHA1_32` | 16 | 14 | 4 | 10 | 0 | 20 |
| `SRTP_AES256_CM_HMAC_SHA1_80` | 32 | 14 | 10 | 10 | 0 | 20 |
| `SRTP_AES256_CM_HMAC_SHA1_32` | 32 | 14 | 4 | 10 | 0 | 20 |
| `SRTP_AEAD_AES_128_GCM` | 16 | 12 | 0 | 0 | 16 | 0 |
| `SRTP_AEAD_AES_256_GCM` | 32 | 12 | 0 | 0 | 16 | 0 |

Lengths are bytes. DTLS-SRTP negotiation currently exposes AES-128-CM HMAC-SHA1 80/32 and AEAD AES-128/256-GCM; the two AES-256-CM profiles are implemented by `rtc-srtp` but are not currently represented in the DTLS `use_srtp` extension.

## STUN

| Operation | Current call site and behavior |
|---|---|
| MD5 | `rtc-stun/src/integrity.rs` derives a long-term credential key from `username:realm:password`. |
| HMAC-SHA1 | `rtc-stun/src/integrity.rs` calculates and verifies `MESSAGE-INTEGRITY`. |
| Constant-time equality | `rtc-stun/src/checks.rs` compares complete integrity values with `subtle::ConstantTimeEq`. |
| Transaction randomness | `TransactionId::new()` and `Message::new_transaction_id()` use `rand::rng().fill` for the 96-bit ID. |

`ATTR_MESSAGE_INTEGRITY_SHA256` is defined, but the current implementation only implements HMAC-SHA1 `MESSAGE-INTEGRITY`. Adding STUN SHA-256 integrity is not implicit G3 work. `MessageIntegrity` publicly wraps a `Vec<u8>`, and its current `Display` implementation exposes the key; migration must replace this with a redacted secret type without changing wire behavior.

## Public backend-bound compatibility surface

| Surface | Current dependency | G3 disposition |
|---|---|---|
| `rtc_dtls::crypto::CryptoPrivateKeyKind` | Ring-compatible Ed25519/ECDSA key pairs, RSA key pair, or `CustomSigner` | Compatibility adapter during migration; remove before 1.0. |
| `rtc_dtls::crypto::CryptoPrivateKey` and `Certificate` | Concrete key variants and X.509 parsing | Replace internals with provider-neutral signing keys and SPKI DER. |
| `rtc_dtls::crypto::CustomSigner` | DTLS-specific signing extension | Adapt temporarily to `SigningKey`; remove before 1.0. |
| DTLS `Config` certificate verification | rustls `RootCertStore`, verifier traits, and certificate types | Keep behind an explicit certificate-verification adapter; do not put X.509 policy into `RTCCrypto`. |
| Top-level `RTCCertificate::from_key_pair` | `rcgen::KeyPair` | Keep as a deprecated migration adapter until provider-neutral import/generation lands; remove before 1.0. |
| `rtc_shared::crypto::KeyingMaterialExporter` | DTLS-to-SRTP trait coupling | Replace with byte-oriented keying material and remove. |
| `ring` and `aws-lc-rs` feature guards and aliases | DTLS, SRTP, STUN, ICE, TURN, and top-level RTC | Replace with additive provider selection in P1-09 and remove per-crate direct dependencies after migration. |
| `openssl` and `vendored-openssl` | Partial SRTP AES-CTR implementation only | Deprecate and remove before 1.0; no partial provider will remain. |
| Shared backend error variants | Ring, AWS-LC-RS, and OpenSSL errors in `rtc-shared` | Map provider failures at protocol boundaries, then remove backend-specific variants. |

## Initial provider operation-to-caller map

Only operations with a current caller belong in the initial trait. Algorithm identifiers used inside a signature or HMAC operation do not require an equivalent standalone hash operation.

| Provider operation | Initial algorithms | Current callers |
|---|---|---|
| Hash | MD5, SHA-256 | STUN long-term credentials; RTC fingerprints and DTLS transcript/PRF composition. |
| HMAC | SHA-1, SHA-256 | STUN and SRTP authentication and DTLS CBC record MAC; DTLS TLS 1.2 PRF. |
| Constant-time equality | Byte slices | STUN, SRTP, and DTLS authentication checks. |
| Random bytes | CSPRNG bytes | DTLS protocol randoms and key generation; optional STUN transaction-ID generation where provider propagation is practical. |
| AES block encryption | AES-128, AES-256 | SRTP key derivation. |
| Stream cipher | AES-128-CTR, AES-256-CTR | SRTP AES-CM profiles. |
| AEAD | AES-128-GCM, AES-256-GCM, AES-128-CCM, AES-128-CCM-8, ChaCha20-Poly1305 | DTLS record protection and SRTP AEAD profiles. |
| CBC | AES-256-CBC | DTLS CBC record protection. |
| Key agreement | P-256, P-384, X25519 | DTLS ECDHE. |
| Signature verification | Ed25519; ECDSA P-256/SHA-256 and P-384/SHA-384; RSA PKCS#1/SHA-1, SHA-256, SHA-384, SHA-512 | DTLS certificate authentication. |
| Signing | Ed25519, ECDSA P-256/SHA-256, RSA PKCS#1/SHA-256 | DTLS CertificateVerify. |
| Signing-key generation | Ed25519, ECDSA P-256 | Current certificate generation paths. |
| Signing-key import | Ed25519, ECDSA P-256, RSA | Current PKCS#8/key-pair import paths. |

Standalone SHA-1, SHA-384, and SHA-512 hashing has no current caller and is excluded from the initial `HashAlgorithm`. RSA-PSS is also excluded until an independently tested protocol requirement exists.

## Existing and missing validation

| Area | Existing baseline | Explicit follow-up gap |
|---|---|---|
| DTLS | Cipher-suite unit tests, handshake tests, key-exchange/signature tests, and repository interoperability coverage | Provider-level vectors for every primitive and cross-provider DTLS handshakes belong to P1-08 and P6-06. |
| SRTP AES-CM | RFC 3711 Appendix B.3 AES-128 derivation vector and RFC 6188 section 7.2 AES-256 derivation vector; RTP/RTCP round trips, replay, rollover, and bad-auth tests | Cross-provider packets for every profile belong to P1-08/P4; retain exact ciphertext and tag fixtures during migration. |
| SRTP AEAD | AES-128-GCM and AES-256-GCM tests, including RFC 7714-derived layouts and RTP/RTCP round trips | Consolidated published known-answer fixtures for every AEAD packet shape belong to P1-08/P4. |
| STUN | Long-term MD5 key expectations, HMAC behavior, tamper rejection, fingerprint ordering, and message round trips | Add RFC 5769 full-message vectors and cross-provider equality in P1-08/P2. |
| Browser/interoperability | Existing repository integration workflows | Add a provider-by-provider DTLS-SRTP browser/interoperability matrix in P7-03/P8-02. |
