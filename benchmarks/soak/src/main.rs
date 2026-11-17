//! The rtc half of the soak harness (see ../README.md): one WebRTC peer that sends audio, video
//! and data and logs what it receives as JSONL. It drives the sans-IO API with its own UDP loop
//! over loopback. Mirrors ../go/ in behaviour and flags.

mod abuse;
mod stats;

use bytes::{Bytes, BytesMut};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp::codec::vp8::Vp8Payloader;
use rtc::rtp::packetizer::Payloader;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::{StatsSelector, report::RTCStatsReportEntry};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stats::{Logger, ProcSampler, RecvStats, now_us, percentile};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const START_SEQ: u16 = (65536u32 - 300) as u16;
const START_AUDIO_TS: u32 = (1u64 << 32).wrapping_sub(20 * 48_000) as u32; // 20 s before the 32-bit wrap
const START_VIDEO_TS: u32 = (1u64 << 32).wrapping_sub(20 * 90_000) as u32;
const VIDEO_MTU: usize = 1200;
const KEYFRAME_EVERY: u64 = 120; // frames: four seconds at 30 fps
const KEYFRAME_BYTES: usize = 24_000;
const INTER_BYTES: usize = 4_875; // together about 1.2 Mbit/s with the keyframes
const REPORT_EVERY: Duration = Duration::from_secs(5);
const AUDIO_EVERY: Duration = Duration::from_millis(20);
const VIDEO_EVERY: Duration = Duration::from_nanos(33_333_333);
const DATA_EVERY: Duration = Duration::from_millis(100);
const PATIENT_ICE_FAILED: Duration = Duration::from_secs(240); // the abuse profile's longest outage is 120 s, a trace's stall 78 s
const DC_STREAM_ID: u16 = 1; // the id both peers agree on out-of-band

static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
struct SignalMsg {
    sdp: RTCSessionDescription,
    candidates: Vec<RTCIceCandidateInit>,
}

struct Args {
    role: String,
    signal: String,
    minutes: f64,
    out: String,
    id: String,
    profile: String,
    seed: u64,
    only: Vec<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        role: "offerer".into(),
        signal: "127.0.0.1:7100".into(),
        minutes: 1.0,
        out: "rtc.jsonl".into(),
        id: String::new(),
        profile: "call".into(),
        seed: 1,
        only: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let v = it.next().unwrap_or_else(|| usage());
        match k.trim_start_matches('-') {
            "role" => a.role = v,
            "signal" => a.signal = v,
            "minutes" => a.minutes = v.parse().unwrap_or_else(|_| usage()),
            "out" => a.out = v,
            "id" => a.id = v,
            "profile" => a.profile = v,
            "only" => a.only = v.split(',').map(str::to_owned).collect(),
            "seed" => a.seed = v.parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    if a.role != "offerer" && a.role != "answerer"
        || !matches!(a.profile.as_str(), "call" | "abuse" | "trace")
    {
        usage();
    }
    if a.id.is_empty() {
        a.id = format!("rtc-{}", a.role);
    }
    a
}

fn usage() -> ! {
    eprintln!(
        "usage: soak-rtc [--role offerer|answerer] [--signal HOST:PORT] [--minutes N] [--out FILE.jsonl] [--id NAME] [--profile call|abuse|trace] [--seed N] [--only CLASS,...]"
    );
    std::process::exit(2);
}

fn write_frame<T: Serialize>(c: &mut TcpStream, m: &T) -> std::io::Result<()> {
    let b = serde_json::to_vec(m)?;
    c.write_all(&(b.len() as u32).to_be_bytes())?;
    c.write_all(&b)
}

fn read_frame<T: DeserializeOwned>(c: &mut TcpStream) -> std::io::Result<T> {
    let mut n = [0u8; 4];
    c.read_exact(&mut n)?;
    let mut b = vec![0u8; u32::from_be_bytes(n) as usize];
    c.read_exact(&mut b)?;
    Ok(serde_json::from_slice(&b)?)
}

/// The offerer listens on `addr` and the answerer dials it; each sends one framed message.
fn rendezvous(role: &str, addr: &str) -> std::io::Result<TcpStream> {
    if role == "offerer" {
        return Ok(TcpListener::bind(addr)?.accept()?.0);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match TcpStream::connect(addr) {
            Ok(c) => return Ok(c),
            Err(e) if Instant::now() > deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Deterministic filler bytes (xorshift), so payloads cost no randomness crate.
struct Filler(u64);

impl Filler {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// What a sender needs to stamp onto each outgoing packet, read once the session is negotiated.
struct Out {
    id: RTCRtpSenderId,
    ssrc: u32,
    pt: u8,
    ext_id: Option<u8>,
}

fn out_params(
    pc: &mut rtc::peer_connection::RTCPeerConnection,
    id: RTCRtpSenderId,
) -> Result<Out, Box<dyn std::error::Error>> {
    let mut s = pc.rtp_sender(id).ok_or("no sender")?;
    let ssrc = s.track().ssrcs().last().ok_or("no ssrc")?;
    let p = &s.get_parameters().rtp_parameters;
    let pt = p.codecs.first().ok_or("no negotiated codec")?.payload_type;
    let ext_id = p
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL_URI)
        .map(|e| e.id as u8);
    Ok(Out {
        id,
        ssrc,
        pt,
        ext_id,
    })
}

fn main() {
    let a = parse_args();
    let mut log = match Logger::open(&a.out, &a.id) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("soak-rtc: {e}");
            std::process::exit(1);
        }
    };
    if a.profile == "abuse" {
        log.event("seed", &format!("profile abuse seed {}", a.seed));
        // A panic on any thread (the hostile sessions run on their own) is a crash, not a warning.
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            default(info);
            std::process::exit(101);
        }));
    }
    if let Err(e) = run(&mut log, &a) {
        log.event("error", &e.to_string());
        eprintln!("soak-rtc: {e}");
        std::process::exit(1);
    }
}

fn codec(mime: &str, rate: u32, channels: u16, fmtp: &str, pt: u8) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime.to_owned(),
            clock_rate: rate,
            channels,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: pt,
    }
}

/// One peer connection with the soak's tracks (Opus audio, VP8 video) and the negotiated data
/// channel. `alt_video_ssrc` gives the video track a second SSRC to switch to (the abuse sessions);
/// `patient` lets ICE ride out a long outage (the measured call of the abuse profile, whose network
/// goes down for up to two minutes, and of the trace profile, whose recorded links stall for over a
/// minute) instead of failing after 25 s.
struct Peer {
    pc: rtc::peer_connection::RTCPeerConnection,
    audio: RTCRtpSenderId,
    video: RTCRtpSenderId,
    dc: rtc::data_channel::RTCDataChannelId,
}

fn build_peer(alt_video_ssrc: bool, patient: bool) -> Result<Peer, Box<dyn std::error::Error>> {
    let audio_codec = codec(MIME_TYPE_OPUS, 48_000, 2, "minptime=10;useinbandfec=1", 111);
    let video_codec = codec(MIME_TYPE_VP8, 90_000, 0, "", 96);
    let mut me = MediaEngine::default();
    me.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;
    me.register_codec(video_codec.clone(), RtpCodecKind::Video)?;
    me.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: AUDIO_LEVEL_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;
    let registry = register_default_interceptors(Registry::new(), &mut me)?;
    let mut builder = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(me)
        .with_interceptor_registry(registry);
    if patient {
        builder = builder.with_setting_engine(
            SettingEngineBuilder::new()
                .with_ice_timeouts(None, Some(PATIENT_ICE_FAILED), None)
                .build(),
        );
    }
    let mut pc = builder.build(Instant::now())?;

    let mut ids = Vec::new();
    for (kind, codec) in [
        (RtpCodecKind::Audio, &audio_codec),
        (RtpCodecKind::Video, &video_codec),
    ] {
        let ssrcs = if alt_video_ssrc && kind == RtpCodecKind::Video {
            2
        } else {
            1
        };
        let track = MediaStreamTrack::new(
            "soak".to_owned(),
            format!("soak-{kind}"),
            format!("soak-{kind}"),
            kind,
            (0..ssrcs)
                .map(|i| RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(rand_ssrc().wrapping_add(i * 2)),
                        ..Default::default()
                    },
                    codec: codec.rtp_codec.clone(),
                    ..Default::default()
                })
                .collect(),
        );
        ids.push(pc.add_track(track)?);
    }
    let dc = pc
        .create_data_channel(
            "soak",
            Some(rtc::data_channel::RTCDataChannelInit {
                negotiated: Some(DC_STREAM_ID),
                ..Default::default()
            }),
        )?
        .id();
    Ok(Peer {
        pc,
        audio: ids[0],
        video: ids[1],
        dc,
    })
}

/// The host candidate for a UDP socket bound to `addr`, as signaled.
fn host_candidate(addr: SocketAddr) -> Result<RTCIceCandidateInit, Box<dyn std::error::Error>> {
    Ok(RTCIceCandidate::from(
        &CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    )
    .to_json()?)
}

/// The port of a signaled candidate line ("candidate:1 1 udp 2130706431 127.0.0.1 40000 typ host").
fn candidate_port(c: &RTCIceCandidateInit) -> Option<u16> {
    c.candidate.split_whitespace().nth(5)?.parse().ok()
}

fn run(log: &mut Logger, a: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let _ = ctrlc_stop();
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let local_addr = socket.local_addr()?;

    let Peer {
        mut pc,
        audio,
        video,
        dc: dc_id,
    } = build_peer(false, a.profile != "call")?;
    let sender_ids = HashMap::from([(RtpCodecKind::Audio, audio), (RtpCodecKind::Video, video)]);
    let host = host_candidate(local_addr)?;

    let mut conn = rendezvous(&a.role, &a.signal)?;
    let mut media_ports = Vec::new();
    let remote = if a.role == "offerer" {
        let offer = pc.create_offer(None)?;
        pc.set_local_description(Instant::now(), offer.clone())?;
        pc.add_local_candidate(host.clone())?;
        write_frame(
            &mut conn,
            &SignalMsg {
                sdp: offer,
                candidates: vec![host.clone()],
            },
        )?;
        let answer: SignalMsg = read_frame(&mut conn)?;
        pc.set_remote_description(Instant::now(), answer.sdp)?;
        media_ports.extend(answer.candidates.iter().filter_map(candidate_port));
        answer.candidates
    } else {
        let offer: SignalMsg = read_frame(&mut conn)?;
        pc.set_remote_description(Instant::now(), offer.sdp)?;
        pc.add_local_candidate(host.clone())?;
        media_ports.extend(offer.candidates.iter().filter_map(candidate_port));
        for c in &offer.candidates {
            pc.add_remote_candidate(c.clone())?;
        }
        let answer = pc.create_answer(None)?;
        pc.set_local_description(Instant::now(), answer.clone())?;
        write_frame(
            &mut conn,
            &SignalMsg {
                sdp: answer,
                candidates: vec![host.clone()],
            },
        )?;
        vec![]
    };
    for c in remote {
        pc.add_remote_candidate(c)?;
    }
    drop(conn);

    let id = a.id.clone();
    let connect_deadline = Instant::now() + Duration::from_secs(60);
    let dur = Duration::from_secs_f64(a.minutes * 60.0);
    let mut state = Loop {
        recv: HashMap::new(),
        track_media: HashMap::new(),
        dc_lat: Vec::new(),
        dc_sent: 0,
        dc_recv: 0,
        dc_id,
        dc_open: false,
        keyframe: false,
        pli_wanted: Vec::new(),
        failed: false,
        connected: false,
    };
    let mut proc = ProcSampler::default();
    let mut audio: Option<Out> = None;
    let mut video: Option<Out> = None;
    let (mut a_seq, mut a_ts, mut v_seq, mut v_ts) =
        (START_SEQ, START_AUDIO_TS, START_SEQ, START_VIDEO_TS);
    let (mut a_n, mut v_n, mut d_n) = (0u64, 0u64, 0u64);
    let mut fill = Filler(0x9e37_79b9_7f4a_7c15);
    let mut vp8 = Vp8Payloader::default();
    vp8.enable_picture_id = true;
    let mut buf = vec![0u8; 2048];
    let mut t_audio = Instant::now();
    let (mut t_video, mut t_data) = (t_audio, t_audio);
    let mut t_report = t_audio + REPORT_EVERY;
    let mut end = None::<Instant>;
    let mut abusers = None;

    loop {
        let now = Instant::now();
        if STOP.load(Ordering::Relaxed) || state.failed {
            break;
        }
        if !state.connected && now > connect_deadline {
            return Err("not connected after 60 s".into());
        }
        if end.is_some_and(|e| now >= e) {
            break;
        }

        // Media, the data channel and the report are paced from absolute deadlines (no drift).
        if state.connected && end.is_none() {
            log.event("join", "connected");
            audio = Some(out_params(&mut pc, sender_ids[&RtpCodecKind::Audio])?);
            video = Some(out_params(&mut pc, sender_ids[&RtpCodecKind::Video])?);
            end = Some(now + dur);
            if a.profile == "abuse" {
                abusers = Some(abuse::start(abuse::Cfg::new(
                    a,
                    now + dur,
                    media_ports.clone(),
                )));
            }
            (t_audio, t_video, t_data, t_report) = (now, now, now, now + REPORT_EVERY);
        }
        if let (Some(au), Some(vi)) = (&audio, &video) {
            while t_audio <= now {
                let mut p = rtc::rtp::Packet::default();
                p.header.version = 2;
                p.header.marker = a_n == 0;
                p.header.payload_type = au.pt;
                p.header.sequence_number = a_seq;
                p.header.timestamp = a_ts;
                p.header.ssrc = au.ssrc;
                p.payload = Bytes::from(fill.bytes(80));
                if let Some(ext) = au.ext_id {
                    p.header.set_extension(
                        ext,
                        Bytes::from(vec![0x80 | (30 + (fill.next() % 30) as u8)]),
                    )?;
                }
                pc.rtp_sender(au.id)
                    .ok_or("no audio sender")?
                    .write_rtp(now, p)?;
                a_n += 1;
                a_seq = a_seq.wrapping_add(1);
                if a_seq == 0 {
                    log.event("wrap", "send audio seq wrap");
                }
                a_ts = a_ts.wrapping_add(960);
                if a_ts < 960 {
                    log.event("wrap", "send audio ts wrap");
                }
                t_audio += AUDIO_EVERY;
            }
            while t_video <= now {
                let key = v_n % KEYFRAME_EVERY == 0 || std::mem::take(&mut state.keyframe);
                let size = if key {
                    KEYFRAME_BYTES
                } else {
                    INTER_BYTES - INTER_BYTES / 4 + (fill.next() as usize % (INTER_BYTES / 2))
                };
                let mut frame = fill.bytes(size);
                frame[0] = if key { frame[0] & !1 } else { frame[0] | 1 }; // VP8 frame tag bit 0: 0 is a keyframe
                let parts = vp8.payload(VIDEO_MTU, &Bytes::from(frame))?;
                let last = parts.len().saturating_sub(1);
                for (i, part) in parts.into_iter().enumerate() {
                    let mut p = rtc::rtp::Packet::default();
                    p.header.version = 2;
                    p.header.marker = i == last;
                    p.header.payload_type = vi.pt;
                    p.header.sequence_number = v_seq;
                    p.header.timestamp = v_ts;
                    p.header.ssrc = vi.ssrc;
                    p.payload = part;
                    pc.rtp_sender(vi.id)
                        .ok_or("no video sender")?
                        .write_rtp(now, p)?;
                    v_seq = v_seq.wrapping_add(1);
                    if v_seq == 0 {
                        log.event("wrap", "send video seq wrap");
                    }
                }
                v_n += 1;
                v_ts = v_ts.wrapping_add(3000);
                if v_ts < 3000 {
                    log.event("wrap", "send video ts wrap");
                }
                t_video += VIDEO_EVERY;
            }
            while t_data <= now {
                t_data += DATA_EVERY;
                if state.dc_open
                    && let Some(mut dc) = pc.data_channel(state.dc_id)
                    && dc
                        .send_text(now, json!({"n": d_n, "ts": now_us()}).to_string())
                        .is_ok()
                {
                    d_n += 1;
                    state.dc_sent += 1;
                }
            }
        }
        if state.connected && now >= t_report {
            report(log, &id, &mut pc, &mut state, &mut proc, now);
            t_report += REPORT_EVERY;
        }

        while let Some(event) = pc.poll_event() {
            state.on_event(log, &mut pc, event);
        }
        while let Some(TaggedRTCMessage { message, .. }) = pc.poll_read() {
            state.on_message(log, message);
        }
        for rid in std::mem::take(&mut state.pli_wanted) {
            if let Some(mut r) = pc.rtp_receiver(rid)
                && let Some(media_ssrc) = r.track().ssrcs().last()
            {
                r.write_rtcp(
                    now,
                    vec![Box::new(PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc,
                    })],
                )?;
            }
        }
        while let Some(msg) = pc.poll_write() {
            let _ = socket.send_to(&msg.message, msg.transport.peer_addr);
        }

        let mut deadline = now + Duration::from_millis(200);
        if state.connected {
            deadline = deadline.min(t_audio).min(t_video).min(t_data).min(t_report);
        }
        if let Some(t) = pc.poll_timeout() {
            if t <= now {
                pc.handle_timeout(now)?;
                continue;
            }
            deadline = deadline.min(t);
        }
        socket.set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_micros(500)),
        ))?;
        if let Ok((n, peer_addr)) = socket.recv_from(&mut buf) {
            pc.handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&buf[..n]),
            })?;
        }
    }
    if let Some(h) = abusers {
        h.stop();
    }
    if state.connected {
        report(log, &id, &mut pc, &mut state, &mut proc, Instant::now());
    }
    let failed = state.failed;
    if !failed {
        log.event("leave", "done");
    }
    let _ = pc.close();
    if failed {
        Err("peer connection failed".into())
    } else {
        Ok(())
    }
}

/// SIGINT/SIGTERM only flag the loop to finish, so the last report and `leave` are written.
fn ctrlc_stop() -> std::io::Result<()> {
    extern "C" fn handler(_: i32) {
        STOP.store(true, Ordering::Relaxed);
    }
    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        signal(2, handler);
        signal(15, handler);
    }
    Ok(())
}

fn rand_ssrc() -> u32 {
    (now_us() as u64 ^ (std::process::id() as u64) << 20) as u32 | 1
}

struct Loop {
    recv: HashMap<RTCRtpReceiverId, RecvStats>,
    track_media: HashMap<rtc::media_stream::MediaStreamTrackId, RTCRtpReceiverId>,
    dc_lat: Vec<f64>,
    dc_sent: u64,
    dc_recv: u64,
    dc_id: rtc::data_channel::RTCDataChannelId,
    dc_open: bool,
    keyframe: bool,
    pli_wanted: Vec<RTCRtpReceiverId>,
    failed: bool,
    connected: bool,
}

impl Loop {
    fn on_event(
        &mut self,
        log: &mut Logger,
        pc: &mut rtc::peer_connection::RTCPeerConnection,
        event: RTCPeerConnectionEvent,
    ) {
        match event {
            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(s) => {
                log.event("ice_state", &s.to_string())
            }
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => match s {
                RTCPeerConnectionState::Connected => self.connected = true,
                RTCPeerConnectionState::Failed => self.failed = true,
                _ => {}
            },
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                self.dc_open = true
            }
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                if let Some(r) = pc.rtp_receiver(init.receiver_id) {
                    let (media, rate): (&'static str, u32) = match r.track().kind() {
                        RtpCodecKind::Audio => ("audio", 48_000),
                        _ => ("video", 90_000),
                    };
                    self.recv
                        .insert(init.receiver_id, RecvStats::new(media, rate));
                    self.track_media.insert(init.track_id, init.receiver_id);
                }
            }
            _ => {}
        }
    }

    fn on_message(&mut self, log: &mut Logger, message: RTCMessage) {
        let now = Instant::now();
        match message {
            RTCMessage::RtpPacket(track_id, p) => {
                if let Some((rid, r)) = self
                    .track_media
                    .get(&track_id)
                    .and_then(|rid| self.recv.get_mut(rid).map(|r| (*rid, r)))
                    && r.on_packet(
                        log,
                        now,
                        p.header.sequence_number,
                        p.header.timestamp,
                        p.header.marker,
                    )
                {
                    self.pli_wanted.push(rid);
                }
            }
            RTCMessage::RtcpPacket(_, pkts) => {
                for p in pkts {
                    let any = p.as_any();
                    if any.is::<PictureLossIndication>() || any.is::<FullIntraRequest>() {
                        self.keyframe = true;
                    }
                }
            }
            RTCMessage::DataChannelMessage(_, m) => {
                if let Ok(v) = serde_json::from_slice::<Value>(&m.data)
                    && let Some(ts) = v["ts"].as_i64()
                {
                    self.dc_recv += 1;
                    if self.dc_lat.len() < 4096 {
                        self.dc_lat.push((now_us() - ts) as f64 / 1000.0);
                    }
                }
            }
            _ => {}
        }
    }
}

fn report(
    log: &mut Logger,
    id: &str,
    pc: &mut rtc::peer_connection::RTCPeerConnection,
    st: &mut Loop,
    proc: &mut ProcSampler,
    now: Instant,
) {
    let (mut nack, mut pli, mut rtt) = (HashMap::new(), HashMap::new(), HashMap::new());
    for e in pc.get_stats(now, StatsSelector::None).iter() {
        match e {
            RTCStatsReportEntry::InboundRtp(s) => {
                let k = s.received_rtp_stream_stats.rtp_stream_stats.kind;
                nack.insert(k, s.nack_count);
                pli.insert(k, s.pli_count);
            }
            RTCStatsReportEntry::RemoteInboundRtp(s) if s.round_trip_time > 0.0 => {
                rtt.insert(
                    s.received_rtp_stream_stats.rtp_stream_stats.kind,
                    stats::round1(s.round_trip_time * 1000.0),
                );
            }
            _ => {}
        }
    }
    let mut lines = Vec::new();
    for r in st.recv.values_mut() {
        let kind = if r.media == "audio" {
            RtpCodecKind::Audio
        } else {
            RtpCodecKind::Video
        };
        let rtt = rtt.get(&kind).map_or(Value::Null, |v| json!(v));
        lines.push((
            format!("{id}-{}", r.media),
            r.snapshot(
                now,
                *nack.get(&kind).unwrap_or(&0),
                *pli.get(&kind).unwrap_or(&0),
                rtt,
            ),
        ));
    }
    for (rid, fields) in lines {
        log.emit("recv", &rid, fields);
    }
    log.emit("proc", id, proc.sample());
    let lat = std::mem::take(&mut st.dc_lat);
    log.emit("dc", id, json!({"sent": st.dc_sent, "recv": st.dc_recv, "lat_ms_p50": percentile(&lat, 50.0), "lat_ms_p99": percentile(&lat, 99.0)}));
}
