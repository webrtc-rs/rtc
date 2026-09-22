//! Data-channel throughput through the whole stack.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-bench --bench data_channel
//! cargo bench --package rtc-bench --bench data_channel --features crypto-aws-lc-rs
//! ```
//!
//! Each iteration sends 256 KiB from the offerer's data channel and drives the pair until the
//! answerer's application has read every byte. The path is the one a browser's data channel
//! takes: `send` → SCTP fragmentation, bundling and congestion window → DTLS record protection →
//! wire → DTLS → SCTP reassembly and SACK → `poll_read`, with SACKs flowing back the other way.
//!
//! The connection is established once, outside the measurement, and reused, so this is
//! steady-state throughput and never includes a handshake.
//!
//! What the number means: bytes per second of **both peers together** on one core, over a
//! lossless zero-latency wire. It is the CPU ceiling of the stack, not a prediction of throughput
//! over a network, where RTT and loss bound SCTP long before the CPU does.
//!
//! * `reliable/*` sweeps message size from 64 B, where per-message overhead dominates, up to
//!   64 KiB, the default `max-message-size` (RFC 8841).
//! * `unreliable/*` is unordered with `maxRetransmits: 0` — the configuration used for game state
//!   and telemetry. On a lossless wire nothing is abandoned, so a difference from `reliable/*` is
//!   the cost of ordering and the reliability bookkeeping alone.
//!
//! The `rtc-sctp` benches measure the association without DTLS or the data-channel layer, which
//! separates SCTP's share of this cost from the rest.

use bytes::BytesMut;
use criterion::{BatchSize, Criterion, SamplingMode, Throughput, criterion_main};
use rtc::data_channel::RTCDataChannelInit;
use rtc_bench::{PeerPair, fixtures, providers};
use std::sync::Arc;

/// Bytes moved per iteration: enough messages at every size that per-transfer setup, such as the
/// final SACK round trip, is amortised.
const BATCH_BYTES: usize = 256 * 1024;

const RELIABLE_SIZES: [usize; 4] = [64, 1024, 16 * 1024, 64 * 1024];
const UNRELIABLE_SIZES: [usize; 2] = [1024, 16 * 1024];

fn size_label(size: usize) -> String {
    if size >= 1024 && size.is_multiple_of(1024) {
        format!("{}KiB", size / 1024)
    } else {
        format!("{size}B")
    }
}

fn benchmark_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("DataChannel/Throughput");
    group.sampling_mode(SamplingMode::Flat).sample_size(30);

    let reliable = RTCDataChannelInit {
        ordered: true,
        ..Default::default()
    };
    let unreliable = RTCDataChannelInit {
        ordered: false,
        max_retransmits: Some(0),
        ..Default::default()
    };

    for (name, provider) in providers() {
        let certificates = (
            fixtures::certificate(provider.as_ref()).unwrap(),
            fixtures::certificate(provider.as_ref()).unwrap(),
        );

        let cases = RELIABLE_SIZES
            .iter()
            .map(|size| ("reliable", &reliable, *size))
            .chain(
                UNRELIABLE_SIZES
                    .iter()
                    .map(|size| ("unreliable", &unreliable, *size)),
            );

        for (mode, init, size) in cases {
            let mut pair = PeerPair::builder(Arc::clone(&provider))
                .certificates(certificates.0.clone(), certificates.1.clone())
                .data_channel(init.clone())
                .connect()
                .unwrap();

            let payload = fixtures::payload(size);
            let count = (BATCH_BYTES / size).max(1);
            group.throughput(Throughput::Bytes((count * size) as u64));
            group.bench_function(format!("{mode}/{}/{name}", size_label(size)), |b| {
                b.iter_batched(
                    // The application's copy into an owned buffer is not the stack's cost.
                    || {
                        (0..count)
                            .map(|_| BytesMut::from(&payload[..]))
                            .collect::<Vec<_>>()
                    },
                    |messages| pair.transfer(messages).unwrap(),
                    BatchSize::PerIteration,
                );
            });
        }
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_throughput(&mut c);
}

criterion_main!(benches);
