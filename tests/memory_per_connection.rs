//! What a peer connection holds on to: live heap bytes per connection, idle and connected, to put
//! next to pion's `benchmarks/pion-compare/go` figure for the same shape (one data channel, no media).
//!
//! `cargo test --release --test memory_per_connection -- --ignored --nocapture`
//!
//! A counting allocator wraps the system one, so the figure is the bytes the library asks for and
//! has not given back, not the pages the allocator happens to keep: it does not move with the
//! platform's malloc, and a second run gives the same number.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::sim::Sim;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};

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
#[ignore = "a measurement, run by hand"]
fn memory_per_connection() {
    let pairs: usize = std::env::var("PAIRS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

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
}
