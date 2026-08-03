# Crypto provider migration

## SRTP in 0.21

`rtc-srtp::context::Context::new_with_provider` is the provider-selecting constructor. It accepts an `Arc<dyn RTCCryptoProvider>`, validates the selected protection profile against `RTCCrypto::supports`, derives the SRTP and SRTCP session material through that provider, and creates reusable keyed cipher objects once per one-way context. Packet indexes, rollover counters, replay windows, IVs, AAD, authentication-tag truncation, and wire layout remain owned by `rtc-srtp`.

`Context::new` remains available as a compatibility constructor and resolves `rtc_crypto::default_provider()`. Applications that need deterministic provider selection, use both built-ins in one process, or supply their own implementation should migrate to `Context::new_with_provider`.

The `ring` and `aws-lc-rs` features on `rtc-srtp` now forward additively to `rtc-crypto`. Ring remains the default when enabled, including builds that enable both features. A no-built-in build is supported when the application supplies its own provider.

The former `openssl` and `vendored-openssl` features were removed. They selected only an alternate AES-CTR path inside SRTP and did not implement the complete `RTCCryptoProvider` contract, so retaining them would create a misleading partial-provider surface. An OpenSSL integration can be added in the future as a complete application or crate-provided `RTCCryptoProvider` that passes the public conformance suite.
