//! Ported from pion/webrtc v4.2.24 `datachannel_go_test.go`, on the deterministic in-memory
//! network (`common::sim`).

mod common;

use std::time::{Duration, Instant};

use bytes::BytesMut;
use common::sim::Sim;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};

fn pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap()
}

fn opened(sim: &mut Sim, a: bool) -> Option<RTCDataChannelId> {
    sim.side(a).events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn received(sim: &mut Sim, a: bool) -> Vec<Vec<u8>> {
    sim.side(a)
        .messages
        .iter()
        .filter_map(|m| match m {
            RTCMessage::DataChannelMessage(_, msg) => Some(msg.data.to_vec()),
            _ => None,
        })
        .collect()
}

fn pc_unbounded() -> RTCPeerConnection {
    use rtc::peer_connection::configuration::setting_engine::{
        SctpMaxMessageSize, SettingEngineBuilder,
    };
    RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
                .build(),
        )
        .build(Instant::now())
        .unwrap()
}

/// `TestDataChannelMessageSize`: messages from zero up to the largest this stack allows (four
/// times 64 KiB; pion's own limit is about 1 GiB, ours is capped at 256 KiB on purpose) cross
/// intact, and with the default limit anything above 64 KiB is refused at the sender.
#[test]
fn test_message_sizes_up_to_the_configured_maximum() {
    let mut sim = Sim::new(pc_unbounded(), pc_unbounded());
    sim.a.pc.create_data_channel("", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        opened(s, true).is_some() && opened(s, false).is_some()
    }));
    let id = opened(&mut sim, true).unwrap();
    for i in 0..=4usize {
        // A repeatable pattern; random bytes add nothing to a byte-for-byte comparison.
        let message: Vec<u8> = (0..65536 * i).map(|n| (n * 31 % 251) as u8).collect();
        let before = received(&mut sim, false).len();
        let now = sim.now;
        let result = sim
            .a
            .pc
            .data_channel(id)
            .unwrap()
            .send(now, BytesMut::from(&message[..]));
        assert!(result.is_ok(), "size {}: {result:?}", message.len());
        assert!(
            sim.run_until(Duration::from_secs(20), |s| received(s, false).len()
                > before),
            "size {} never arrived",
            message.len()
        );
        assert_eq!(
            received(&mut sim, false)[before],
            message,
            "size {}",
            message.len()
        );
    }
}

/// `TestDataChannel_BundleOnlyPortZero`: an offer whose data section is `m=application 0` with
/// `a=bundle-only` is answered and the channel opens.
#[test]
fn test_data_section_bundle_only_with_port_zero() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .add_transceiver_from_kind(rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Audio, None)
        .unwrap();
    sim.a.pc.create_data_channel("data", None).unwrap();
    sim.negotiate_edited(true, false, |sdp| {
        let line = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel";
        assert!(sdp.contains(line), "{sdp}");
        sdp.replacen(
            line,
            "m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\na=bundle-only",
            1,
        )
    });
    assert!(
        sim.run_until(Duration::from_secs(10), |s| opened(s, true).is_some()),
        "the offerer's channel opens"
    );
}

/// `TestDataChannel_NonStandardSessionDescription`: the legacy `DTLS/SCTP 5000` with
/// `a=sctpmap` instead of `a=sctp-port` is still understood.
#[test]
fn test_legacy_sctpmap_offer() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("foo", None).unwrap();
    sim.negotiate_edited(true, false, |sdp| {
        let mut out = vec![];
        for line in sdp.split("\r\n") {
            if line.starts_with("m=application ") {
                out.push("m=application 63743 DTLS/SCTP 5000".to_owned());
            } else if line.starts_with("a=sctp-port") {
                out.push("a=sctpmap:5000 webrtc-datachannel 256".to_owned());
            } else {
                out.push(line.to_owned());
            }
        }
        out.join("\r\n")
    });
    assert!(
        sim.run_until(Duration::from_secs(10), |s| opened(s, false).is_some()),
        "OnDataChannel fires on the answerer"
    );
}

/// `TestDataChannelBufferedAmount`, "set before the channel becomes open": a low threshold set
/// early survives opening, and sending past it makes `OnBufferedAmountLow` fire on both ends.
#[test]
fn test_buffered_amount_low_fires_on_both_sides() {
    let mut sim = Sim::new(pc(), pc());
    let mut channel = sim.a.pc.create_data_channel("data", None).unwrap();
    let offer_channel = channel.id();
    channel.set_buffered_amount_low_threshold(1500);
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        opened(s, true).is_some() && opened(s, false).is_some()
    }));
    let answer_channel = opened(&mut sim, false).unwrap();
    sim.b
        .pc
        .data_channel(answer_channel)
        .unwrap()
        .set_buffered_amount_low_threshold(1400);
    assert_eq!(
        sim.a
            .pc
            .data_channel(offer_channel)
            .unwrap()
            .buffered_amount_low_threshold(),
        1500
    );
    assert_eq!(
        sim.b
            .pc
            .data_channel(answer_channel)
            .unwrap()
            .buffered_amount_low_threshold(),
        1400
    );

    let payload = BytesMut::from(&[0u8; 1000][..]);
    for _ in 0..10 {
        let now = sim.now;
        sim.a
            .pc
            .data_channel(offer_channel)
            .unwrap()
            .send(now, payload.clone())
            .unwrap();
        sim.b
            .pc
            .data_channel(answer_channel)
            .unwrap()
            .send(now, payload.clone())
            .unwrap();
    }
    let low = |s: &mut Sim, a: bool| {
        s.side(a).events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnBufferedAmountLow(_))
            )
        })
    };
    assert!(
        sim.run_until(Duration::from_secs(5), |s| low(s, true) && low(s, false)),
        "both sides report the buffer draining below the threshold"
    );
}

/// The default limit is the RFC 8841 64 KiB: a bigger message is refused up front.
#[test]
fn test_default_message_limit_refuses_larger_messages() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| opened(s, true).is_some()));
    let id = opened(&mut sim, true).unwrap();
    let now = sim.now;
    let mut channel = sim.a.pc.data_channel(id).unwrap();
    assert!(
        channel
            .send(now, BytesMut::from(&vec![0u8; 65536][..]))
            .is_ok()
    );
    assert!(
        channel
            .send(now, BytesMut::from(&vec![0u8; 65537][..]))
            .is_err()
    );
}
