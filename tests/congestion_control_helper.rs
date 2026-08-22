//! `configure_congestion_control` composes a working chain (P7-08).
//!
//! The helper declares three named slots and never has to know what else the caller registered, or
//! in what order — so what is worth checking is that it composes at all, with either feedback
//! format and with an estimator the application brought itself.

use rtc::interceptor::{ConstantBitrate, Gcc};
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, RegistryBuilder, configure_congestion_control,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;

/// The estimator seam is what #840's second requirement asks for: an application supplies its own,
/// and it drives the same machinery `Gcc` does.
#[test]
fn an_application_can_supply_its_own_estimator() {
    let mut media_engine = MediaEngine::default();
    let registry = configure_congestion_control(
        RegistryBuilder::new(),
        ConstantBitrate::new(900_000.0),
        CongestionFeedback::Twcc,
        &mut media_engine,
    )
    .expect("congestion control")
    .build();

    let _chain = registry.build();
}

/// RFC 8888 instead of TWCC, end to end through the helper. D7 makes "both" unrepresentable: the
/// two produce indistinguishable `PacketReport`s, so registering both would double-count every
/// packet — an enum rather than two booleans is what rules that out at compile time.
#[test]
fn rfc8888_is_selectable() {
    let mut media_engine = MediaEngine::default();
    let registry = configure_congestion_control(
        RegistryBuilder::new(),
        Gcc::default(),
        CongestionFeedback::Rfc8888,
        &mut media_engine,
    )
    .expect("congestion control")
    .build();

    let _chain = registry.build();
}
