//! Shared helpers for the interop tests.

/// Installs a process-wide rustls `CryptoProvider` if one is not already installed.
///
/// The interop tests drive the published `webrtc` crate alongside this one, and its `dtls 0.13`
/// dependency asks rustls to infer the provider from crate features. That inference only works
/// when exactly one of rustls' `ring`/`aws-lc-rs` features is enabled — but in a test build both
/// are: `dtls 0.13` turns on `rustls/ring` while `rtc` turns on whichever its own feature selects.
/// Cargo unifies the two, rustls finds an ambiguity, and the old crate panics.
///
/// Naming a provider here resolves it for that crate. `rtc` itself no longer consults this
/// default — it passes its provider explicitly (see `rtc_dtls::config`) — so which one we install
/// only has to satisfy the old code. `ring` is always available in a test build: either `rtc`
/// selected it, or `dtls 0.13` pulled it in.
///
/// Idempotent, and safe to call from every test: `install_default` returns `Err` once a provider
/// is set, which is ignored here, so the first caller wins and an application that installed its
/// own is unaffected.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
