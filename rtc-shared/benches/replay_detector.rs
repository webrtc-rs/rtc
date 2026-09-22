//! Replay-detector cost per packet.
//!
//! Run with `cargo bench --package rtc-shared --bench replay_detector`.
//!
//! Every DTLS record and every SRTP and SRTCP packet passes one `check` and, once authenticated,
//! one `accept`. This measures that pair on its own, for both detectors:
//!
//! * `SlidingWindow` is DTLS's: a 48-bit record sequence number that never wraps.
//! * `WrappedSlidingWindow` is SRTP's: the 16-bit RTP sequence number, which wraps at 65535 and
//!   must not mistake the wrap for a replay.
//!
//! Each runs at window 64, the default for DTLS, SRTP and SRTCP alike, and 1024, a window sized
//! for a high-rate stream with deep reordering. The window is a multi-word bitmask that shifts on
//! every advance, so its size is the main cost variable.
//!
//! * `in-order` is the common case: every packet advances the window by one.
//! * `reordered` swaps each adjacent pair, so every other packet lands inside the window behind
//!   the newest — the bit-test path rather than the shift path.
//! * `duplicate` re-checks a packet already accepted: what a replayed or retransmitted duplicate
//!   costs to reject.

use criterion::{Criterion, criterion_main};
use rtc_shared::replay_detector::{
    ReplayDetector, SlidingWindowDetector, WrappedSlidingWindowDetector,
};
use std::hint::black_box;

/// DTLS record sequence numbers are 48 bits.
const DTLS_MAX_SEQ: u64 = (1 << 48) - 1;
/// RTP sequence numbers are 16 bits.
const RTP_MAX_SEQ: u64 = u16::MAX as u64;

const WINDOWS: [usize; 2] = [64, 1024];

/// `wraps` says whether the detector is meant to handle `max_seq` rolling over to zero; the
/// pre-flight check crosses the wrap only for one that is.
fn run_cases(
    c: &mut Criterion,
    name: &str,
    max_seq: u64,
    wraps: bool,
    detector: impl Fn(usize) -> Box<dyn ReplayDetector>,
) {
    let mut group = c.benchmark_group(format!("ReplayDetector/{name}"));
    // Wrapping keeps a long run inside the detector's domain; for the 48-bit counter it never
    // happens in practice.
    let next = |seq: u64| if seq == max_seq { 0 } else { seq + 1 };

    for window in WINDOWS {
        // Both patterns must take the accept path, including across a wrap, or the numbers below
        // would be the cost of rejecting.
        for (pattern, reorder) in [("in-order", 0), ("reordered", 1)] {
            let mut check = detector(window);
            let mut seq = if wraps {
                max_seq - 2 * window as u64
            } else {
                0
            };
            for _ in 0..4 * window {
                assert!(
                    check.check(seq ^ reorder),
                    "{name} {pattern}/{window} rejected {seq}"
                );
                check.accept();
                seq = next(seq);
            }
        }

        let mut in_order = detector(window);
        let mut seq = 0;
        group.bench_function(format!("in-order/{window}"), |b| {
            b.iter(|| {
                let fresh = in_order.check(black_box(seq));
                in_order.accept();
                seq = next(seq);
                fresh
            });
        });

        // 1, 0, 3, 2, …: each odd-indexed packet arrives just ahead of its predecessor.
        let mut reordered = detector(window);
        let mut seq = 0;
        group.bench_function(format!("reordered/{window}"), |b| {
            b.iter(|| {
                let fresh = reordered.check(black_box(seq ^ 1));
                reordered.accept();
                seq = next(seq);
                fresh
            });
        });

        let mut duplicate = detector(window);
        for seq in 0..window as u64 {
            assert!(duplicate.check(seq));
            duplicate.accept();
        }
        let seen = window as u64 / 2;
        group.bench_function(format!("duplicate/{window}"), |b| {
            b.iter(|| {
                let fresh = duplicate.check(black_box(seen));
                debug_assert!(!fresh);
                fresh
            });
        });
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    run_cases(&mut c, "SlidingWindow", DTLS_MAX_SEQ, false, |window| {
        Box::new(SlidingWindowDetector::new(window, DTLS_MAX_SEQ))
    });
    run_cases(
        &mut c,
        "WrappedSlidingWindow",
        RTP_MAX_SEQ,
        true,
        |window| Box::new(WrappedSlidingWindowDetector::new(window, RTP_MAX_SEQ)),
    );
}

criterion_main!(benches);
