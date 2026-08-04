#[cfg(feature = "ring")]
#[test]
fn ring_is_the_default_when_enabled() {
    assert_eq!(rtc_crypto::default_provider().unwrap().name(), "ring");
}

#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
#[test]
fn aws_lc_rs_is_the_default_when_it_is_the_only_builtin() {
    assert_eq!(rtc_crypto::default_provider().unwrap().name(), "aws-lc-rs");
}
