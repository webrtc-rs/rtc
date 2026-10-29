//! Steady-state allocation tests.
//!
//! pion's `TestRecordDoesNotAllocateInSteadyState` asserts `testing.AllocsPerRun` is zero once
//! the TWCC recorder has been warmed up. The Rust equivalent needs a counting allocator — the
//! one from `benchmarks/pion-compare/src/main.rs`, adapted to count per thread so the test
//! harness's own allocations on other threads never pollute the measurement.
//!
//! A fresh allocation in the per-packet path is not a cosmetic problem: it shows up as jitter
//! and collector pressure exactly when the packet rate is highest, and on the sending side it
//! is the difference between pacing working and the pacer's queue backing up behind malloc.

use rtc_interceptor::{
    AttributedPacket, Interceptor, Packet, RTPHeaderExtension, StreamInfo, TaggedPacket,
    TwccReceiverBuilder,
};
use sansio::Protocol;
use shared::marshal::Marshal;
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------
// The counting allocator
// ---------------------------------------------------------------------------------------

thread_local! {
    /// Allocations made by the thread that is currently measuring. Const-initialized, so
    /// reading it never allocates (which would make the counter count itself).
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

struct CountingOnThisThread;

unsafe impl GlobalAlloc for CountingOnThisThread {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|count| count.set(count.get() + 1));
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.with(|count| count.set(count.get() + 1));
        unsafe { std::alloc::System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingOnThisThread = CountingOnThisThread;

/// How many allocations the closure made on this thread.
fn allocations_of(mut measured: impl FnMut()) -> u64 {
    ALLOCS.with(|count| count.set(0));
    measured();
    ALLOCS.with(|count| count.replace(0))
}

// ---------------------------------------------------------------------------------------
// The steady state
// ---------------------------------------------------------------------------------------

/// The transport-cc header extension URI.
const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

/// The arrival-time map's maximum size, mirroring pion's `maxNumberOfPackets`.
const MAX_NUMBER_OF_PACKETS: u32 = 1 << 15;

/// The map's minimum capacity, mirroring pion's `minCapacity`.
const MIN_CAPACITY: u32 = 128;

/// A received RTP packet carrying transport-cc sequence `twcc_sequence`, arriving `micros`
/// after the epoch.
fn received_packet(
    epoch: Instant,
    ssrc: u32,
    sequence: u16,
    twcc_sequence: u16,
    micros: u64,
) -> TaggedPacket {
    let mut packet = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            ssrc,
            sequence_number: sequence,
            payload_type: 96,
            ..Default::default()
        },
        payload: vec![0u8; 100].into(),
    };

    let extension = rtp::extension::transport_cc_extension::TransportCcExtension {
        transport_sequence: twcc_sequence,
    };
    let encoded = extension.marshal().expect("marshal the extension");
    packet
        .header
        .set_extension(3, encoded.freeze())
        .expect("set the extension");

    TaggedPacket {
        now: epoch + Duration::from_micros(micros),
        transport: shared::TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

/// pion `TestRecordDoesNotAllocateInSteadyState`: once the recorder's arrival-time map has
/// grown to its cap, recording an in-order packet allocates nothing — no map resizing, no
/// boxing, no defensive copies. The warm-up grows the map without building feedback (building
/// allocates by nature; pion avoids it the same way), so the measured loop sees the true
/// per-packet floor. Packets are pre-built and consumed by value, so every allocation counted
/// belongs to the interceptor.
#[test]
fn twcc_recording_allocates_nothing_in_steady_state() {
    let ssrc = 5000u32;
    let epoch = Instant::now();

    let mut receiver = TwccReceiverBuilder::new().build();
    receiver.bind_remote_stream(&StreamInfo {
        ssrc,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_string(),
            id: 3,
        }],
        ..Default::default()
    });

    // Warm up until the arrival-time map stops resizing, then measure a further run. pion
    // uses `maxNumberOfPackets + minCapacity` warm-up records for the same reason.
    let warm_up = MAX_NUMBER_OF_PACKETS + MIN_CAPACITY;
    let measured = 1000u32;

    // Everything the loops hand to the interceptor is built before counting starts, so only
    // the interceptor's own work is measured.
    let mut packets: Vec<_> = (0..warm_up + measured)
        .map(|index| {
            received_packet(
                epoch,
                ssrc,
                index as u16,
                index as u16,
                u64::from(index) * 1000,
            )
        })
        .collect();

    // Warm up until the arrival-time map stops resizing.
    let warm_up_packets: Vec<TaggedPacket> = packets.drain(..warm_up as usize).collect();
    for packet in warm_up_packets {
        receiver.handle_read(packet).expect("handle_read");
        while receiver.poll_read().is_some() {}
    }

    // Settle, then measure the steady state.
    let mut remaining = packets.into_iter();
    let allocations = allocations_of(|| {
        while let Some(packet) = remaining.next() {
            receiver.handle_read(packet).expect("handle_read");
            while receiver.poll_read().is_some() {}
        }
    });

    assert_eq!(
        0, allocations,
        "the interceptor allocated {allocations} times while recording {measured} in-order packets"
    );
}
