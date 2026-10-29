//! What a peer connection holds on to: live heap bytes per connection, idle and connected, to put
//! next to pion's `benchmarks/pion-compare/go` figure for the same shape (one data channel, no media).
//!
//! `cargo test --release --test memory_per_connection -- --nocapture` (`PAIRS=200` for more pairs)
//!
//! It also guards the figure: a connection that grows past the bound below fails the test, so a
//! buffer added to the connection path shows up here and not in a production memory graph.
//!
//! A counting allocator wraps the system one, so the figure is the bytes the library asks for and
//! has not given back, not the pages the allocator happens to keep: it does not move with the
//! platform's malloc, and a second run gives the same number.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
/// Live allocations per power-of-two size class, to see whether a few big buffers or many small
/// objects make up the figure.
static CLASS_COUNT: [AtomicUsize; 40] = [const { AtomicUsize::new(0) }; 40];

fn class_of(size: usize) -> usize {
    (usize::BITS - size.max(1).leading_zeros()) as usize
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        CLASS_COUNT[class_of(layout.size())].fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        CLASS_COUNT[class_of(layout.size())].fetch_sub(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size, Ordering::Relaxed);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        CLASS_COUNT[class_of(new_size)].fetch_add(1, Ordering::Relaxed);
        CLASS_COUNT[class_of(layout.size())].fetch_sub(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap()
}

/// A peer with the default codecs and interceptors, as an application would build it.
fn media_pc() -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let registry = register_default_interceptors(Registry::new(), &mut me).unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap()
}

/// A connected pair where `a` has been sending video to `b` for three seconds, long enough for the
/// per-stream state (send buffers, receive logs, reports) to have been used.
fn media_sim() -> Sim {
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
    sim.send_video(true, sender, SSRC, 150);
    sim
}

fn data_channel_open(sim: &Sim, a: bool) -> bool {
    let side = if a { &sim.a } else { &sim.b };
    side.events.iter().any(|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
        )
    })
}

#[test]
fn memory_per_connection() {
    let pairs: usize = std::env::var("PAIRS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    // One pair first: whatever is built once per process (lazy statics, the crypto provider's
    // tables) is not a cost of the next connection.
    let mut warm = Sim::new(pc(), pc());
    warm.a.pc.create_data_channel("", None).unwrap();
    warm.negotiate(true);
    assert!(warm.run_until(Duration::from_secs(10), |s| {
        data_channel_open(s, true) && data_channel_open(s, false)
    }));
    drop(warm);

    // Idle connections, built and counted on their own.
    let base = live();
    let idle: Vec<RTCPeerConnection> = (0..2 * pairs).map(|_| pc()).collect();
    let idle_bytes = live() - base;
    drop(idle);

    // Connected ones live in their `Sim`s, which hold the connections by value, so the vector
    // that holds them is counted: it is where a connection's own struct lives.
    let base = live();
    let mut sims: Vec<Sim> = Vec::with_capacity(pairs);
    let class_base: Vec<usize> = CLASS_COUNT
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    for _ in 0..pairs {
        let mut sim = Sim::new(pc(), pc());
        sim.a.pc.create_data_channel("", None).unwrap();
        sim.negotiate(true);
        assert!(sim.run_until(Duration::from_secs(10), |s| {
            data_channel_open(s, true) && data_channel_open(s, false)
        }));
        sims.push(sim);
    }
    let connected_bytes = live() - base;

    let per_pc = |bytes: usize| bytes as f64 / (2 * pairs) as f64 / 1024.0;
    println!(
        "memory_per_connection: pairs={pairs} idle={:.1} KiB/pc connected+datachannel={:.1} KiB/pc",
        per_pc(idle_bytes),
        per_pc(connected_bytes)
    );
    // Which size classes hold the bytes (upper bound of the class times the count it grew by).
    let mut classes: Vec<(usize, usize)> = (0..CLASS_COUNT.len())
        .map(|c| {
            let grew = CLASS_COUNT[c].load(Ordering::Relaxed) as isize - class_base[c] as isize;
            (c, grew.max(0) as usize)
        })
        .filter(|&(_, n)| n > 0)
        .collect();
    classes.sort_by_key(|&(c, n)| std::cmp::Reverse(n << c));
    for (c, n) in classes.iter().take(8) {
        println!(
            "  allocations of <= {:>7} B: {:>8.1} per connection (up to {:>7.1} KiB)",
            1usize << c,
            *n as f64 / (2 * pairs) as f64,
            (*n << c) as f64 / (2 * pairs) as f64 / 1024.0
        );
    }
    drop(sims);

    // The same with media: a video track one way, the default interceptors on both ends.
    let base = live();
    let mut media: Vec<Sim> = Vec::with_capacity(pairs);
    for _ in 0..pairs {
        media.push(media_sim());
    }
    let media_bytes = live() - base;
    println!(
        "memory_per_connection: pairs={pairs} connected+video={:.1} KiB/pc",
        per_pc(media_bytes)
    );
    drop(media);
    // 130 KiB when this was written, 172 before the NACK send buffer grew with the stream: a
    // window of 1024 packets allocated whole is over 100 KiB for every stream that sends.
    assert!(
        per_pc(media_bytes) < 150.0,
        "a connected peer connection with a video track now holds {:.1} KiB of heap",
        per_pc(media_bytes)
    );

    // 62 KiB when this was written; the bound leaves room for a few new fields and a different
    // allocator's rounding but not for a buffer (the one removed here was 64 KiB on its own).
    assert!(
        per_pc(connected_bytes) < 96.0,
        "a connected peer connection now holds {:.1} KiB of heap",
        per_pc(connected_bytes)
    );
}
