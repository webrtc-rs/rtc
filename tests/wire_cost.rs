//! What a connection puts on the wire when nothing is being asked of it: datagrams and bytes per
//! second by kind, for an idle data-channel pair and for a pair with video flowing.
//!
//! `cargo test --release --test wire_cost -- --nocapture`

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use common::sim::Sim;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

type Tally = Rc<RefCell<BTreeMap<&'static str, (u64, u64)>>>;

fn kind(datagram: &[u8]) -> &'static str {
    match datagram.first() {
        Some(0..=3) => "stun",
        Some(20..=63) => "dtls",
        Some(128..=191) => match datagram.get(1) {
            Some(192..=223) => "srtcp",
            _ => "srtp",
        },
        _ => "other",
    }
}

fn count(sim: &mut Sim) -> Tally {
    let tally: Tally = Rc::default();
    let seen = tally.clone();
    sim.drop_if = Some(Box::new(move |from_a, datagram| {
        let label = match (from_a, kind(datagram)) {
            (true, "stun") => "a>b stun",
            (false, "stun") => "b>a stun",
            (true, "dtls") => "a>b dtls (sctp)",
            (false, "dtls") => "b>a dtls (sctp)",
            (true, "srtcp") => "a>b srtcp",
            (false, "srtcp") => "b>a srtcp",
            (true, "srtp") => "a>b srtp",
            (false, "srtp") => "b>a srtp",
            _ => "other",
        };
        let mut seen = seen.borrow_mut();
        let entry = seen.entry(label).or_default();
        entry.0 += 1;
        entry.1 += datagram.len() as u64;
        false
    }));
    tally
}

/// Prints the tally and returns the datagrams and bytes per second that are not media.
fn report(name: &str, tally: &Tally, seconds: f64) -> (f64, f64) {
    println!("wire_cost: {name} over {seconds:.0} s");
    let mut datagrams = 0;
    let mut bytes = 0;
    for (label, (n, b)) in tally.borrow().iter() {
        println!(
            "  {label:<18} {:>7.2} datagrams/s {:>9.1} B/s  (avg {:>5.0} B)",
            *n as f64 / seconds,
            *b as f64 / seconds,
            *b as f64 / (*n).max(1) as f64
        );
        datagrams += n;
        bytes += b;
    }
    println!(
        "  {:<18} {:>7.2} datagrams/s {:>9.1} B/s",
        "total",
        datagrams as f64 / seconds,
        bytes as f64 / seconds
    );
    let (control, control_bytes) = tally
        .borrow()
        .iter()
        .filter(|(label, _)| !label.ends_with("srtp"))
        .fold((0, 0), |(n, b), (_, (dn, db))| (n + dn, b + db));
    (control as f64 / seconds, control_bytes as f64 / seconds)
}

fn media_pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let registry = register_default_interceptors(Registry::new(), &mut me).unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(std::time::Instant::now())
        .unwrap()
}

#[test]
fn idle_data_channel_pair() {
    let mut sim = Sim::new(media_pc(), media_pc());
    sim.a.pc.create_data_channel("", None).unwrap();
    sim.negotiate(true);
    assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
        && s.b.connected()));
    sim.run_for(Duration::from_secs(2));
    let tally = count(&mut sim);
    sim.run_for(Duration::from_secs(60));
    let (datagrams, bytes) = report("idle data channel", &tally, 60.0);
    // 2 datagrams and 176 B a second when this was written: a consent check each way every 2 s.
    // The bound leaves room for a busier schedule but not for a keepalive an order of magnitude
    // chattier, which an idle connection pays for the whole time a participant sits in a room.
    assert!(
        datagrams < 6.0 && bytes < 600.0,
        "an idle connection now sends {datagrams:.1} datagrams and {bytes:.0} B a second"
    );
}

#[test]
fn video_pair() {
    const SSRC: u32 = 0x2222_0001;
    let mut sim = Sim::new(media_pc(), media_pc());
    let sender = sim
        .a
        .pc
        .add_track(MediaStreamTrack::new(
            "stream".to_owned(),
            "video".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(SSRC),
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
    sim.send_video(true, sender, SSRC, 100);
    let tally = count(&mut sim);
    // 50 packets a second, 3 bytes of payload each: the cost is what is around the payload.
    sim.send_video(true, sender, SSRC, 3000);
    let (datagrams, bytes) = report("video, 50 packets/s of 3 B payload", &tally, 60.0);
    // 5 datagrams and about 330 B a second of keepalive and reports beside the media when this was
    // written: sender and receiver reports once a second and a consent check each way.
    assert!(
        datagrams < 12.0 && bytes < 800.0,
        "a video connection now spends {datagrams:.1} datagrams and {bytes:.0} B a second beside the media"
    );
}

/// CPU spent bringing a connection up (key generation, ICE, DTLS, SCTP), in real time: the
/// network is virtual, so the wall clock here is the library's own work for both ends. A figure to
/// read, not a bound: a wall clock on a shared CI machine would make it flaky.
#[test]
#[ignore]
fn join_cost() {
    let pairs = 100;
    let warm = Sim::new(media_pc(), media_pc());
    drop(warm);
    let built = std::time::Instant::now();
    let mut sims: Vec<Sim> = (0..pairs)
        .map(|_| Sim::new(media_pc(), media_pc()))
        .collect();
    let build = built.elapsed();
    let started = std::time::Instant::now();
    for sim in &mut sims {
        sim.a.pc.create_data_channel("", None).unwrap();
        sim.negotiate(true);
        assert!(sim.run_until(Duration::from_secs(10), |s| s.a.connected()
            && s.b.connected()));
    }
    let connect = started.elapsed();
    println!(
        "wire_cost: per peer connection: build {:.0} us, negotiate+connect {:.0} us (a pair {:.0} us)",
        build.as_secs_f64() * 1e6 / (2 * pairs) as f64,
        connect.as_secs_f64() * 1e6 / (2 * pairs) as f64,
        connect.as_secs_f64() * 1e6 / pairs as f64,
    );
}
