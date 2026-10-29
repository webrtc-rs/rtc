//! Ported from pion/webrtc v4.2.24 `peerconnection_go_test.go`: whole-connection ICE behaviour
//! (lite agents, restart, recovery after the path dies) on the deterministic simulated network.

mod common;

use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};

fn peer(lite: bool) -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .with_setting_engine(SettingEngineBuilder::new().with_lite(lite).build())
        .build(Instant::now())
        .unwrap()
}

fn ice_ufrag(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .unwrap_or_default()
        .to_owned()
}

fn opened_channel(sim: &mut Sim, a: bool) -> Option<rtc::data_channel::RTCDataChannelId> {
    sim.side(a).events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn texts(sim: &mut Sim, a: bool) -> Vec<String> {
    sim.side(a)
        .messages
        .iter()
        .filter_map(|m| match m {
            RTCMessage::DataChannelMessage(_, msg) => {
                Some(String::from_utf8_lossy(&msg.data).into_owned())
            }
            _ => None,
        })
        .collect()
}

/// `TestPeerConnection_IceLite`: a data channel opens whichever side (or both) is lite.
#[test]
fn test_peer_connection_ice_lite() {
    for (offer_lite, answer_lite) in [(true, false), (false, true), (true, true)] {
        let mut sim = Sim::new(peer(offer_lite), peer(answer_lite));
        sim.a.pc.create_data_channel("d", None).unwrap();
        sim.negotiate(true);
        assert!(
            sim.run_until(Duration::from_secs(15), |s| {
                s.a.connected() && s.b.connected() && opened_channel(s, false).is_some()
            }),
            "offer_lite={offer_lite} answer_lite={answer_lite}: a={:?} b={:?}",
            sim.a.pc.connection_state(),
            sim.b.pc.connection_state()
        );
    }
}

/// `TestICERestart`: after a restart both sides reconnect with fresh ICE credentials.
#[test]
fn test_ice_restart_regathers_and_reconnects() {
    let mut sim = Sim::new(peer(false), peer(false));
    sim.a.pc.create_data_channel("d", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));

    let first_offer = ice_ufrag(&sim.a.pc.local_description().unwrap().sdp);
    let first_answer = ice_ufrag(&sim.b.pc.local_description().unwrap().sdp);

    sim.negotiate_with(true, true);
    assert!(
        sim.run_until(Duration::from_secs(10), |s| s.a.connected()
            && s.b.connected()),
        "a={:?} b={:?}",
        sim.a.pc.connection_state(),
        sim.b.pc.connection_state()
    );

    assert_ne!(
        first_offer,
        ice_ufrag(&sim.a.pc.local_description().unwrap().sdp)
    );
    assert_ne!(
        first_answer,
        ice_ufrag(&sim.b.pc.local_description().unwrap().sdp)
    );
}

/// `TestICERestart_Error_Handling`: after the path dies ICE fails; once it is back, a restart
/// recovers and a message sent while it was down is delivered.
#[test]
fn test_ice_restart_recovers_after_failure() {
    let mut sim = Sim::new(peer(false), peer(false));
    sim.b.pc.create_data_channel("foo", None).unwrap();
    sim.negotiate(false);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        opened_channel(s, true).is_some() && opened_channel(s, false).is_some()
    }));

    let id = opened_channel(&mut sim, true).unwrap();
    let now = sim.now;
    sim.a
        .pc
        .data_channel(id)
        .unwrap()
        .send_text(now, "testMessage".to_owned())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |s| texts(s, false).len() == 1));

    sim.blackhole = true;
    assert!(
        sim.run_until(Duration::from_secs(120), |s| {
            s.a.pc.ice_connection_state() == RTCIceConnectionState::Failed
        }),
        "ice state {:?}",
        sim.a.pc.ice_connection_state()
    );
    let now = sim.now;
    sim.a
        .pc
        .data_channel(id)
        .unwrap()
        .send_text(now, "testMessage".to_owned())
        .unwrap();

    sim.blackhole = false;
    sim.negotiate_with(false, true);
    assert!(
        sim.run_until(Duration::from_secs(60), |s| s.a.connected()
            && s.b.connected()),
        "a={:?} b={:?}",
        sim.a.pc.connection_state(),
        sim.b.pc.connection_state()
    );
    assert!(
        sim.run_until(Duration::from_secs(60), |s| texts(s, false).len() == 2),
        "the message sent while the path was down is delivered after the restart: {:?}",
        texts(&mut sim, false)
    );
    assert_eq!(
        sim.a.pc.connection_state(),
        RTCPeerConnectionState::Connected
    );
}

/// `TestAlwaysNegotiateDataChannels_CreateDataChannel`: with the option set the SCTP association
/// comes up with no channel, and a channel created later opens on both sides without another
/// negotiation.
#[test]
fn test_always_negotiate_data_channels_create_data_channel() {
    use rtc::peer_connection::configuration::RTCConfigurationBuilder;

    fn always() -> RTCPeerConnection {
        RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_always_negotiate_data_channels(true)
                    .build(),
            )
            .build(Instant::now())
            .unwrap()
    }

    let mut sim = Sim::new(always(), always());
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    // Give the SCTP association time to come up; nothing may announce a channel.
    sim.run_for(Duration::from_secs(2));
    assert!(opened_channel(&mut sim, true).is_none());
    assert!(opened_channel(&mut sim, false).is_none());
    let needed = sim.a.negotiation_needed();

    sim.a.pc.create_data_channel("post-connect", None).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(10), |s| {
            opened_channel(s, true).is_some() && opened_channel(s, false).is_some()
        }),
        "the channel opens on both sides"
    );
    assert_eq!(
        sim.a.negotiation_needed(),
        needed,
        "creating a data channel needs no new negotiation"
    );
}

fn peer_with(builder: SettingEngineBuilder) -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .with_setting_engine(builder.build())
        .build(Instant::now())
        .unwrap()
}

/// `SettingEngine.SetIPFilter`: an address the filter refuses never becomes a local candidate.
#[test]
fn test_ip_filter_drops_local_candidates() {
    use ice::agent::agent_config::IpFilter;
    for refuse in [false, true] {
        let filter = IpFilter::new(move |ip| !(refuse && ip.to_string() == "10.0.0.1"));
        let mut sim = Sim::new(
            peer_with(SettingEngineBuilder::new().with_ip_filter(filter)),
            peer(false),
        );
        sim.a.pc.create_data_channel("d", None).unwrap();
        sim.negotiate(true);
        let sdp = sim.a.pc.local_description().unwrap().sdp;
        let has_candidate = sdp.lines().any(|l| l.starts_with("a=candidate:"));
        assert_eq!(has_candidate, !refuse, "refuse={refuse}: {sdp}");
    }
}

/// `SettingEngine.SetRemoteIPFilter`: candidates from a refused address are ignored, so the
/// connection cannot form to it.
#[test]
fn test_remote_ip_filter_ignores_remote_candidates() {
    use ice::agent::agent_config::IpFilter;
    for refuse in [false, true] {
        let filter = IpFilter::new(move |ip| !(refuse && ip.to_string() == "10.0.0.2"));
        let mut sim = Sim::new(
            peer_with(SettingEngineBuilder::new().with_remote_ip_filter(filter)),
            peer(false),
        );
        sim.a.pc.create_data_channel("d", None).unwrap();
        sim.negotiate(true);
        let connected = sim.run_until(Duration::from_secs(8), |s| s.a.connected());
        assert_eq!(connected, !refuse, "refuse={refuse}");
    }
}

/// `TestSetICEBindingRequestHandler`: the handler sees the binding requests of both roles while a
/// connection forms, and declining them (`false`) leaves the connection working.
#[test]
fn test_ice_binding_request_handler_sees_both_roles() {
    use ice::agent::agent_config::BindingRequestHandler;
    use std::sync::{Arc, Mutex};
    use stun::attributes::{ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING};

    let seen = Arc::new(Mutex::new((false, false)));
    let recorder = seen.clone();
    let handler = BindingRequestHandler::new(move |message, _, _, _| {
        let mut seen = recorder.lock().unwrap();
        for attribute in message.iter_attributes() {
            if attribute.typ == ATTR_ICE_CONTROLLED {
                seen.0 = true;
            } else if attribute.typ == ATTR_ICE_CONTROLLING {
                seen.1 = true;
            }
        }
        false
    });
    // The handler sits on both peers: each sees the other's request.
    let mut sim = Sim::new(
        peer_with(SettingEngineBuilder::new().with_ice_binding_request_handler(handler.clone())),
        peer_with(SettingEngineBuilder::new().with_ice_binding_request_handler(handler)),
    );
    sim.a.pc.create_data_channel("d", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    let (controlled, controlling) = *seen.lock().unwrap();
    assert!(controlled, "a request from a controlled agent was seen");
    assert!(controlling, "a request from a controlling agent was seen");
}
