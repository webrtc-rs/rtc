//! Google Congestion Control driven through two real peer connections over a bottleneck link:
//! the estimate has to find the link's capacity, back off when the capacity drops or the link
//! loses packets, and recover afterwards. The unit tests cover each stage of the algorithm; this
//! covers the loop the stages are for (send history, TWCC feedback, estimator, pacer).

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::sim::{Link, Sim};
use rtc::interceptor::{BandwidthEstimator, EstimatorStats, Gcc, PacketReport, Registry};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

const SSRC: u32 = 0x2222_0001;
const PACKET: usize = 1200;
const MIN: f64 = 100_000.0;
const MAX: f64 = 8_000_000.0;

/// Publishes the estimate so the test (standing in for the encoder) can follow it.
struct Reporting {
    inner: Gcc,
    target: Arc<Mutex<f64>>,
}

impl Reporting {
    fn publish(&self) {
        *self.target.lock().unwrap() = self.inner.target_bitrate();
    }
}

impl BandwidthEstimator for Reporting {
    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        self.inner.on_reports(now, reports);
        self.publish();
    }
    fn target_bitrate(&self) -> f64 {
        self.inner.target_bitrate()
    }
    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
        self.publish();
    }
    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }
    fn stats(&self) -> EstimatorStats {
        self.inner.stats()
    }
}

fn peer(initial: f64) -> (RTCPeerConnection, Arc<Mutex<f64>>) {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let target = Arc::new(Mutex::new(initial));
    let registry = configure_congestion_control(
        Registry::new(),
        Reporting {
            inner: Gcc::new(initial, MIN, MAX),
            target: target.clone(),
        },
        CongestionFeedback::Twcc,
        &mut me,
    )
    .unwrap();
    let registry = register_default_interceptors(registry, &mut me).unwrap();
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap();
    (pc, target)
}

struct Call {
    sim: Sim,
    sender: RTCRtpSenderId,
    estimate: Arc<Mutex<f64>>,
    seq: u16,
    credit: f64,
}

fn call(link: Link) -> Call {
    let (a, estimate) = peer(300_000.0);
    let (b, _) = peer(300_000.0);
    let mut sim = Sim::new(a, b);
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
    sim.link_a_to_b = Some(link);
    Call {
        sim,
        sender,
        estimate,
        seq: 0,
        credit: 0.0,
    }
}

impl Call {
    fn estimate(&self) -> f64 {
        *self.estimate.lock().unwrap()
    }

    fn received_bytes(&self) -> usize {
        self.sim
            .b
            .messages
            .iter()
            .filter_map(|m| match m {
                RTCMessage::RtpPacket(_, p) => Some(p.payload.len()),
                _ => None,
            })
            .sum()
    }

    /// Sends like an encoder that follows the estimate (capped at `ceiling`) for `span`, and
    /// returns the goodput the receiver saw over the last `tail` of it.
    fn run(&mut self, span: Duration, ceiling: f64, tail: Duration) -> f64 {
        let step = Duration::from_millis(5);
        let mut at_tail = 0;
        let steps = (span.as_millis() / step.as_millis()) as u32;
        let tail_steps = (tail.as_millis() / step.as_millis()) as u32;
        for i in 0..steps {
            if i == steps - tail_steps {
                at_tail = self.received_bytes();
            }
            let rate = self.estimate().min(ceiling);
            self.credit += rate / 8.0 * step.as_secs_f64();
            while self.credit >= PACKET as f64 {
                self.credit -= PACKET as f64;
                let now = self.sim.now;
                let (sender, seq) = (self.sender, self.seq);
                self.seq = self.seq.wrapping_add(1);
                self.sim
                    .a
                    .pc
                    .rtp_sender(sender)
                    .unwrap()
                    .write_rtp(
                        now,
                        rtp::packet::Packet {
                            header: rtp::header::Header {
                                version: 2,
                                payload_type: 96,
                                sequence_number: seq,
                                timestamp: u32::from(seq) * 3000,
                                ssrc: SSRC,
                                ..Default::default()
                            },
                            payload: bytes::Bytes::from(vec![0x10; PACKET]),
                        },
                    )
                    .unwrap();
            }
            self.sim.run_for(step);
        }
        (self.received_bytes() - at_tail) as f64 * 8.0 / tail.as_secs_f64()
    }
}

fn link(bps: u64) -> Link {
    Link::new(bps, Duration::from_millis(40), Duration::from_millis(150))
}

/// Starting well below a 1.5 Mbps link, the estimate climbs to use it without sitting on a
/// standing queue (which would show as an estimate far above capacity).
#[test]
fn the_estimate_finds_the_capacity_of_the_link() {
    let mut c = call(link(1_500_000));
    let goodput = c.run(
        Duration::from_secs(60),
        5_000_000.0,
        Duration::from_secs(10),
    );
    let est = c.estimate();
    eprintln!("estimate {est:.0}, goodput {goodput:.0}");
    assert!(est > 900_000.0, "the estimate stayed low: {est}");
    assert!(est < 2_200_000.0, "the estimate overshot the link: {est}");
    assert!(goodput > 800_000.0, "the link was left idle: {goodput}");
}

/// A capacity drop is noticed within seconds and the sender follows it down; when capacity
/// returns the estimate climbs again.
#[test]
fn the_estimate_follows_a_capacity_drop_and_recovery() {
    let mut c = call(link(2_000_000));
    c.run(Duration::from_secs(40), 5_000_000.0, Duration::from_secs(5));
    let before = c.estimate();
    assert!(
        before > 1_200_000.0,
        "never reached the first capacity: {before}"
    );

    c.sim.link_a_to_b = Some(link(500_000));
    c.run(Duration::from_secs(20), 5_000_000.0, Duration::from_secs(5));
    let squeezed = c.estimate();
    eprintln!("before {before:.0}, squeezed {squeezed:.0}");
    assert!(
        squeezed < 800_000.0,
        "kept sending above the new capacity: {squeezed}"
    );
    assert!(
        squeezed > 200_000.0,
        "collapsed far below the new capacity: {squeezed}"
    );

    c.sim.link_a_to_b = Some(link(2_000_000));
    c.run(Duration::from_secs(60), 5_000_000.0, Duration::from_secs(5));
    let recovered = c.estimate();
    eprintln!("recovered {recovered:.0}");
    assert!(recovered > 1_200_000.0, "did not recover: {recovered}");
}

/// Random loss on an otherwise roomy link pulls the estimate down: loss above the loss-based
/// controller's threshold must not be answered by sending faster.
#[test]
fn heavy_random_loss_lowers_the_estimate() {
    let mut roomy = link(10_000_000);
    roomy.loss = 0.15;
    let mut c = call(roomy);
    c.run(Duration::from_secs(40), 4_000_000.0, Duration::from_secs(5));
    let lossy = c.estimate();

    let mut clean = call(link(10_000_000));
    clean.run(Duration::from_secs(40), 4_000_000.0, Duration::from_secs(5));
    let healthy = clean.estimate();
    eprintln!("lossy {lossy:.0}, healthy {healthy:.0}");
    assert!(
        lossy < healthy * 0.6,
        "loss did not lower the estimate: {lossy} vs {healthy}"
    );
}
