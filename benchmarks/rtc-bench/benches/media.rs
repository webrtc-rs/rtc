//! Per-packet cost of the RTP path through a connected peer, charged to each side separately.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-bench --bench media
//! cargo bench --package rtc-bench --bench media --features crypto-aws-lc-rs
//! ```
//!
//! One connected pair streams one track, offerer to answerer, over a lossless zero-latency wire.
//! Virtual time advances by the media's packet interval per packet, so periodic work — RTCP
//! sender and receiver reports, TWCC feedback, ICE consent checks — happens at its real rate and
//! is amortised across packets exactly as it would be in a call.
//!
//! * `Track/Send/*` is the offerer's CPU per packet: `write_rtp` through the interceptor chain and
//!   SRTP encryption to `poll_write`, plus its share of periodic work, including processing the
//!   RTCP feedback that comes back.
//! * `Track/Receive/*` is the answerer's CPU per packet: `handle_read` through SRTP decryption,
//!   the interceptor chain and track demultiplexing to `poll_read`, plus generating that feedback.
//!
//! The split comes from [`Peer::busy`](rtc_bench::Peer::busy): every call into a peer is timed
//! and charged to it. Packets are sent in bursts of 16 between pumps so the stopwatch reads are
//! amortised to a small fraction of the per-packet cost.
//!
//! Each case runs with no interceptors and with `register_default_interceptors`. The difference
//! between the two is the per-packet cost of NACK, RTCP reports and TWCC. Audio and video differ
//! in packet size (160 B against 1200 B), which separates fixed per-packet overhead from the
//! per-byte cost of SRTP.
//!
//! Throughput is reported in packets per second of that side's CPU — the rate one core could
//! sustain for this stream if it did nothing else.
//!
//! `4-video-tracks` and `16-video-tracks` send round-robin across that many video tracks, each at
//! its own 1000 packets per second, with the default interceptors. Per-packet cost that grows
//! with track count is routing — SSRC-to-track lookup, extension parsing, per-stream interceptor
//! state — rather than cryptography, so these run once per provider like the rest but are best
//! read against the single-track `video` row.
//!
//! The `rtc-srtp` benches measure SRTP alone; `rtc-rtp` measures packet marshalling alone.

use criterion::{Criterion, Throughput, criterion_main};
use rtc_bench::fixtures::{self, Interceptors, MediaKind};
use rtc_bench::{PairBuilder, PeerPair, providers};
use std::sync::Arc;
use std::time::Duration;

/// Packets queued between pumps. Large enough to amortise the per-call stopwatch, small enough
/// that at video rate the burst spans 16 ms of virtual time rather than a jitter-buffer's worth.
const BURST: u64 = 16;

#[derive(Clone, Copy)]
enum Side {
    Sender,
    Receiver,
}

/// Streams `packets` across the pair's tracks and returns the CPU time charged to `side`.
///
/// `stream_rtp` fails if any packet is not delivered: a path that drops packets would still
/// produce a timing, of the wrong thing.
fn stream(pair: &mut PeerPair, packets: u64, side: Side) -> Duration {
    pair.offerer.reset_accounting();
    pair.answerer.reset_accounting();
    pair.stream_rtp(packets, BURST).unwrap();
    match side {
        Side::Sender => pair.offerer.busy(),
        Side::Receiver => pair.answerer.busy(),
    }
}

fn benchmark_rtp(c: &mut Criterion) {
    let mut group = c.benchmark_group("Track");
    group.throughput(Throughput::Elements(1));

    for (name, provider) in providers() {
        let certificates = (
            fixtures::certificate(provider.as_ref()).unwrap(),
            fixtures::certificate(provider.as_ref()).unwrap(),
        );

        let mut cases: Vec<(String, Interceptors, Vec<MediaKind>)> = Vec::new();
        for interceptors in [Interceptors::None, Interceptors::Default] {
            for kind in [MediaKind::Audio, MediaKind::Video] {
                cases.push((kind.label().to_owned(), interceptors, vec![kind]));
            }
        }
        for tracks in [4, 16] {
            cases.push((
                format!("{tracks}-video-tracks"),
                Interceptors::Default,
                vec![MediaKind::Video; tracks],
            ));
        }

        for (label, interceptors, kinds) in cases {
            let builder = PeerPair::builder(Arc::clone(&provider))
                .certificates(certificates.0.clone(), certificates.1.clone())
                .interceptors(interceptors);
            let mut pair = kinds
                .iter()
                .fold(builder, |builder: PairBuilder, kind| builder.track(*kind))
                .connect()
                .unwrap();

            // The first packet on each track opens it at the receiver; keep that one-off out of
            // the samples.
            stream(&mut pair, BURST * kinds.len() as u64, Side::Sender);

            let id = format!("{label}/{}/{name}", interceptors.label());
            group.bench_function(format!("Send/{id}"), |b| {
                b.iter_custom(|iters| stream(&mut pair, iters, Side::Sender));
            });
            group.bench_function(format!("Receive/{id}"), |b| {
                b.iter_custom(|iters| stream(&mut pair, iters, Side::Receiver));
            });
        }
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_rtp(&mut c);
}

criterion_main!(benches);
