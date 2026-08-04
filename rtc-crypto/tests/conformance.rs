#![cfg(feature = "test-support")]

#[cfg(feature = "crypto-ring")]
#[test]
fn ring_provider_conforms() {
    rtc_crypto::conformance::assert_provider(&rtc_crypto::providers::RingProvider::new());
}

#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn aws_lc_rs_provider_conforms() {
    rtc_crypto::conformance::assert_provider(&rtc_crypto::providers::AwsLcRsProvider::new());
}
