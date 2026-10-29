//! Ported from pion/webrtc v4.2.24 `peerconnection_close_test.go`, on the deterministic in-memory
//! network (`common::sim`): closing at each stage of a connection leaves both sides closed and
//! never stalls.

mod common;

use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use sansio::Protocol;

fn pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap()
}

fn open(sim: &mut Sim, a: bool) -> Option<rtc::data_channel::RTCDataChannelId> {
    sim.side(a).events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn connected_pair() -> Sim {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("data", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        s.a.connected() && s.b.connected() && open(s, true).is_some() && open(s, false).is_some()
    }));
    sim
}

fn closed_ice(sim: &Sim, a: bool) -> bool {
    let side = if a { &sim.a } else { &sim.b };
    eprintln!(
        "a={a} ice={:?} conn={:?}",
        side.pc.ice_connection_state(),
        side.pc.connection_state()
    );
    side.pc.ice_connection_state() == RTCIceConnectionState::Closed
        && side.pc.connection_state() == RTCPeerConnectionState::Closed
}

/// `TestPeerConnection_Close`: closing both ends of a live connection ends ICE and the
/// connection on each, and closing again is harmless.
#[test]
fn test_close_a_live_connection() {
    let mut sim = connected_pair();
    sim.a.pc.close().unwrap();
    sim.b.pc.close().unwrap();
    sim.run_for(Duration::from_millis(100));
    assert!(closed_ice(&sim, true) && closed_ice(&sim, false));
    sim.a.pc.close().unwrap();
    sim.b.pc.close().unwrap();
}

/// A peer that closes tells the other (SCTP ABORT), so it need not wait for consent to expire.
#[test]
fn test_close_is_noticed_by_the_peer() {
    let mut sim = connected_pair();
    sim.a.pc.close().unwrap();
    assert!(
        sim.run_until(Duration::from_secs(2), |s| {
            s.b.events.iter().any(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(_))
                )
            })
        }),
        "the remote channel closes soon after the peer closed"
    );
}

/// `TestPeerConnection_Close_PreICE`: an answerer closed while still `Checking` shuts its ICE
/// transport down, and the offerer that vanished before ICE started leaves nothing behind.
#[test]
fn test_close_before_ice_completes() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("test-channel", None).unwrap();
    let now = sim.now;
    let offer = sim.a.pc.create_offer(None).unwrap();
    sim.a.pc.close().unwrap();
    sim.b.pc.set_remote_description(now, offer).unwrap();
    sim.run_for(Duration::from_millis(100));
    assert_eq!(
        sim.b.pc.ice_connection_state(),
        RTCIceConnectionState::Checking
    );
    sim.b.pc.close().unwrap();
    assert!(closed_ice(&sim, false));
}

/// `TestPeerConnection_Close_DuringICE`: closing from inside the callback that reports ICE
/// connected (answerer first, then the offerer) completes without a stall.
#[test]
fn test_close_during_ice() {
    let mut sim = Sim::new(pc(), pc());
    sim.a.pc.create_data_channel("test-channel", None).unwrap();
    sim.negotiate_without_waiting();
    assert!(
        sim.run_until(Duration::from_secs(10), |s| {
            s.b.pc.ice_connection_state() == RTCIceConnectionState::Connected
        }),
        "ice connects"
    );
    sim.b.pc.close().unwrap();
    sim.a.pc.close().unwrap();
    sim.run_for(Duration::from_millis(100));
    assert!(closed_ice(&sim, true) && closed_ice(&sim, false));
}

/// `TestPeerConnection_GracefulCloseWithIncomingMessages`: the answerer keeps sending while the
/// offerer closes half way; nothing panics or errors on close, and both end closed.
#[test]
fn test_close_with_incoming_messages() {
    let mut sim = connected_pair();
    let answer_channel = open(&mut sim, false).unwrap();
    for i in 0..100 {
        if i == 50 {
            sim.a.pc.close().unwrap();
        }
        let now = sim.now;
        // Sends toward a closed peer may be refused; they must not panic.
        let _ = sim
            .b
            .pc
            .data_channel(answer_channel)
            .map(|mut dc| dc.send_text(now, "hello!".to_owned()));
        sim.run_for(Duration::from_millis(5));
    }
    sim.b.pc.close().unwrap();
    sim.run_for(Duration::from_millis(100));
    assert!(closed_ice(&sim, true) && closed_ice(&sim, false));
}

/// `TestPeerConnection_GracefulCloseWhileOpening`: closing the offerer straight after the offer,
/// and the answerer after it applied that offer, both succeed.
#[test]
fn test_close_while_opening() {
    let mut sim = Sim::new(pc(), pc());
    sim.a
        .pc
        .create_data_channel("initial_data_channel", None)
        .unwrap();
    let now = sim.now;
    let offer = sim.a.pc.create_offer(None).unwrap();
    sim.a.pc.set_local_description(now, offer.clone()).unwrap();
    sim.a.pc.close().unwrap();
    sim.b.pc.set_remote_description(now, offer).unwrap();
    sim.b.pc.close().unwrap();
    assert!(closed_ice(&sim, true) && closed_ice(&sim, false));
}

/// A forwarder keeps writing to a viewer that has hung up until its own ICE consent fails, which
/// takes seconds. Once the peer's `close_notify` has closed the DTLS transport, media writes fail
/// at once (pion's closed pipe) and nothing more is sent: no protecting and no datagram per packet.
#[test]
fn media_writes_fail_and_send_nothing_once_the_peer_has_closed() {
    use rtc::media_stream::MediaStreamTrack;
    use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
    use rtc::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
    };

    let media_pc = || {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .build(Instant::now())
            .unwrap()
    };
    let ssrc = 0x4444_0001;
    let mut sim = Sim::new(media_pc(), media_pc());
    let sender = sim
        .a
        .pc
        .add_track(MediaStreamTrack::new(
            "s".to_owned(),
            "t".to_owned(),
            "l".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                ..Default::default()
            }],
        ))
        .unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));

    sim.send_video(true, sender, ssrc, 3);
    assert!(
        sim.b.rtp_received() > 0,
        "media flows while the peer is there"
    );

    sim.b.pc.close().unwrap();
    sim.run_for(Duration::from_millis(200));

    let now = sim.now;
    let payload_type = sim
        .a
        .pc
        .rtp_sender(sender)
        .unwrap()
        .get_parameters()
        .rtp_parameters
        .codecs[0]
        .payload_type;
    let written = sim.a.pc.rtp_sender(sender).unwrap().write_rtp(
        now,
        rtp::packet::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type,
                sequence_number: 100,
                ssrc,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(&[0x10, 0, 0]),
        },
    );
    assert!(
        written.is_err(),
        "writing to a closed transport must fail: {written:?}"
    );
    assert!(
        sim.a.pc.poll_write().is_none(),
        "and nothing may be queued for the wire"
    );
}
