#![cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]

use rtc::peer_connection::RTCPeerConnectionBuilder;

#[test]
fn peer_connection_without_a_provider_returns_actionable_error() {
    let error = match RTCPeerConnectionBuilder::new().build() {
        Ok(_) => panic!("a no-built-in build must require an application crypto provider"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("crypto provider"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("SettingEngine::set_crypto_provider"),
        "error must explain how to configure a provider: {message}"
    );
}
