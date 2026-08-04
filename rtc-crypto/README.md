# rtc-crypto

`rtc-crypto` provides the provider-neutral cryptographic operations used by the webrtc-rs RTC stack. Applications can use a built-in Ring or AWS-LC-RS provider, or implement the public provider traits without registration or sealing.

The crate owns primitives and opaque keyed state. DTLS, SRTP, STUN, certificate policy, and wire-format composition remain in their protocol crates.

Enable `test-support` to run the reusable provider conformance suite from a downstream provider's tests.

```rust
#[test]
fn provider_conforms() {
    let provider = MyProvider::new();
    rtc_crypto::conformance::assert_provider(&provider);
}
```

Partial providers can invoke the public operation-family helpers that match their advertised capabilities. The feature adds no built-in backend, so a downstream provider can test with `default-features = false, features = ["test-support"]`.

The `ring` and `aws-lc-rs` features are additive. Ring is the default when enabled, including builds that enable both backends. With neither backend enabled, applications construct their own `Arc<dyn RTCCryptoProvider>` and `default_provider()` returns `CryptoError::NoDefaultProvider`.
