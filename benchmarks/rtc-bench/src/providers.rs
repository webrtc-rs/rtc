use std::sync::Arc;

use rtc::crypto::RTCCryptoProvider;

/// The built-in crypto providers compiled into this build, labelled for use in benchmark ids.
///
/// Benchmarks loop over these so that `--features crypto-ring,crypto-aws-lc-rs` reports both
/// backends side by side under identical inputs, as the SRTP and DTLS benches already do.
///
/// Enabling a backend on `rtc` directly (`--features rtc/crypto-aws-lc-rs`) rather than on this
/// crate leaves both of this crate's features off. The provider `rtc` resolves by default is still
/// a valid subject, so it is returned under the label `default` rather than failing.
///
/// # Panics
///
/// If no built-in provider is compiled in at all.
pub fn providers() -> Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> {
    let mut providers: Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push((
        "ring",
        Arc::new(rtc::crypto::providers::RingProvider::default()),
    ));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push((
        "aws-lc-rs",
        Arc::new(rtc::crypto::providers::AwsLcRsProvider::default()),
    ));
    if providers.is_empty()
        && let Ok(provider) = rtc::crypto::default_provider()
    {
        providers.push(("default", provider));
    }
    assert!(
        !providers.is_empty(),
        "enable `crypto-ring` or `crypto-aws-lc-rs` to run these benchmarks"
    );
    providers
}
