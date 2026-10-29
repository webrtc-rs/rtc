//! The simulated network connects two peers and carries a data-channel message, deterministically.

mod common;

use common::sim::Sim;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use std::time::{Duration, Instant};

#[test]
fn two_peers_connect_and_exchange_a_message() {
    let a = RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap();
    let b = RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap();
    let mut sim = Sim::new(a, b);
    sim.a.pc.create_data_channel("chat", None).unwrap();
    sim.negotiate(true);
    assert!(
        sim.run_until(Duration::from_secs(10), |s| s.a.connected()
            && s.b.connected()),
        "a: {:?}, b: {:?}",
        sim.a.pc.connection_state(),
        sim.b.pc.connection_state()
    );
    assert_eq!(
        sim.a.pc.connection_state(),
        RTCPeerConnectionState::Connected
    );

    let opened = sim.run_until(Duration::from_secs(10), |s| {
        s.a.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
            )
        })
    });
    assert!(opened, "the channel opened on the offering side");
    let id = sim
        .a
        .events
        .iter()
        .find_map(|e| match e {
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
            _ => None,
        })
        .unwrap();
    let now = sim.now;
    sim.a
        .pc
        .data_channel(id)
        .unwrap()
        .send_text(now, "hello".to_owned())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        s.b.messages.iter().any(|m| {
            matches!(m, RTCMessage::DataChannelMessage(_, msg) if msg.data.as_ref() == b"hello")
        })
    }));
}
