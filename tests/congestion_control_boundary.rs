//! An attribute reaching the end of the chain, where it becomes a statistic.
//!
//! `Ein`/`Eout` on the interceptor trait are `()`, so an attribute riding on a packet is the only
//! way information crosses an interceptor. That gets it as far as the end of the chain and no
//! further — these tests are about the last hop, and about the carrier that makes it possible when
//! there is no real packet going the same way.

use rtc::interceptor::Registry;
use rtc::interceptor::{Attribute, AttributedPacket, Gcc, Interceptor, Packet, TaggedPacket};
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use sansio::Protocol;
use shared::TransportContext;
use std::time::Instant;

/// A chain built the way an application would, then driven directly — the peer connection needs a
/// live DTLS session before its handler forwards anything, which is a lot of machinery for a
/// question about one hop.
fn chain_with_congestion_control() -> impl Interceptor {
    let mut media_engine = MediaEngine::default();
    configure_congestion_control(
        Registry::new(),
        Gcc::default(),
        CongestionFeedback::Twcc,
        &mut media_engine,
    )
    .expect("congestion control")
    .build()
}

fn annotated_report(attribute: Attribute) -> TaggedPacket {
    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
            rtcp::receiver_report::ReceiverReport::default(),
        )]))
        .with(attribute),
    }
}

/// An estimate attached to inbound feedback survives the terminus
/// as an empty-RTCP carrier — payload stripped, attribute intact — which is the only way it can
/// reach the handler that turns it into an event.
#[test]
fn an_estimate_reaches_the_end_of_the_chain_as_a_carrier() {
    let mut chain = chain_with_congestion_control();

    chain
        .handle_read(annotated_report(Attribute::TargetBitrateChanged {
            bits_per_second: 640_000.0,
        }))
        .expect("read");

    let mut carriers = 0;
    while let Some(packet) = chain.poll_read() {
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            packet.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            assert_eq!(640_000.0, *bits_per_second);
            assert!(
                matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()),
                "the payload must be stripped — the application did not ask for RTCP"
            );
            carriers += 1;
        }
    }

    assert_eq!(
        1, carriers,
        "the estimate must reach the crate boundary, or #840's third requirement cannot be met"
    );
}

/// A report nobody annotated still stops at the terminus, so turning this on has not quietly turned
/// inbound RTCP into something the application receives.
#[test]
fn an_unannotated_report_still_stops_at_the_terminus() {
    let mut chain = chain_with_congestion_control();

    chain
        .handle_read(TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                rtcp::receiver_report::ReceiverReport::default(),
            )])),
        })
        .expect("read");

    assert!(
        chain.poll_read().is_none(),
        "inbound RTCP is for the interceptors unless something asked for it"
    );
}
