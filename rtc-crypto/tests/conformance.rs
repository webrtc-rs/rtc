#![cfg(feature = "test-support")]

#[cfg(feature = "ring")]
#[test]
fn ring_provider_conforms() {
    rtc_crypto::conformance::assert_provider(&rtc_crypto::providers::RingProvider::new());
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn aws_lc_rs_provider_conforms() {
    rtc_crypto::conformance::assert_provider(&rtc_crypto::providers::AwsLcRsProvider::new());
}
