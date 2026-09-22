//! Heap allocations per packet and per message, charged to the side that made them.
//!
//! Run with `cargo bench --package rtc-bench --bench allocations`.
//!
//! # Not a criterion benchmark
//!
//! Criterion measures time. This counts allocations — every `alloc`, `alloc_zeroed` and `realloc`
//! the stack makes — with a counting global allocator, and prints a table. The workloads are the
//! same ones `media` and `data_channel` time, on the same in-memory harness, and each allocation
//! is charged to the peer whose call made it, just as CPU time is.
//!
//! Allocation counts are close to deterministic: the same revision allocates the same number of
//! times per packet on any machine, so unlike a timing, a count from a laptop can be compared with
//! one from CI. Averages over thousands of operations settle to the second decimal; a change of a
//! whole allocation per packet is never noise.
//!
//! The counts are allocation *traffic*, not retained memory: frees are not subtracted, so a buffer
//! allocated and dropped on every packet counts once per packet. That is the number that
//! allocator pressure and cache behaviour follow.
//!
//! Each workload is warmed up before counting, so one-time growth — the first time a queue or map
//! reaches its working size — is excluded.

use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelInit;
use rtc_bench::allocations::{Allocations, CountingAllocator};
use rtc_bench::fixtures::{self, Interceptors, MediaKind};
use rtc_bench::{PeerPair, providers};
use std::sync::Arc;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const WARM_UP_PACKETS: u64 = 2_000;
const PACKETS: u64 = 20_000;
const BURST: u64 = 16;

const WARM_UP_BYTES: usize = 1 << 20;
const TRANSFER_BYTES: usize = 8 << 20;

fn row(workload: &str, unit: &str, operations: u64, send: Allocations, receive: Allocations) {
    let (send_count, send_bytes) = send.per(operations);
    let (receive_count, receive_bytes) = receive.per(operations);
    println!(
        "| {workload} | {unit} | {send_count:.2} | {send_bytes:.0} | {receive_count:.2} | \
         {receive_bytes:.0} |"
    );
}

fn main() {
    let (name, provider) = providers().into_iter().next().expect("a provider");
    let certificates = (
        fixtures::certificate(provider.as_ref()).unwrap(),
        fixtures::certificate(provider.as_ref()).unwrap(),
    );
    let builder = || {
        PeerPair::builder(Arc::clone(&provider))
            .certificates(certificates.0.clone(), certificates.1.clone())
    };

    println!("Heap allocations per operation, crypto provider {name}.\n");
    println!(
        "| Workload | Per | Send allocs | Send bytes | Receive allocs | Receive bytes |\n\
         |---|---|---:|---:|---:|---:|"
    );

    let media: [(&str, Vec<MediaKind>); 3] = [
        ("audio", vec![MediaKind::Audio]),
        ("video", vec![MediaKind::Video]),
        ("4-video-tracks", vec![MediaKind::Video; 4]),
    ];
    for interceptors in [Interceptors::None, Interceptors::Default] {
        for (label, kinds) in &media {
            let mut pair = kinds
                .iter()
                .fold(builder().interceptors(interceptors), |builder, kind| {
                    builder.track(*kind)
                })
                .connect()
                .unwrap();

            pair.stream_rtp(WARM_UP_PACKETS, BURST).unwrap();
            pair.offerer.reset_accounting();
            pair.answerer.reset_accounting();
            pair.stream_rtp(PACKETS, BURST).unwrap();

            row(
                &format!("`Track/{label}/{}`", interceptors.label()),
                "packet",
                PACKETS,
                pair.offerer.allocations(),
                pair.answerer.allocations(),
            );
        }
    }

    for (mode, init) in [
        (
            "reliable",
            RTCDataChannelInit {
                ordered: true,
                ..Default::default()
            },
        ),
        (
            "unreliable",
            RTCDataChannelInit {
                ordered: false,
                max_retransmits: Some(0),
                ..Default::default()
            },
        ),
    ] {
        for size in [1024, 16 * 1024] {
            let mut pair = builder().data_channel(init.clone()).connect().unwrap();
            let payload = fixtures::payload(size);
            let messages = |bytes: usize| {
                (0..bytes / size)
                    .map(|_| BytesMut::from(&payload[..]))
                    .collect::<Vec<_>>()
            };

            pair.transfer(messages(WARM_UP_BYTES)).unwrap();
            let batch = messages(TRANSFER_BYTES);
            let count = batch.len() as u64;
            pair.offerer.reset_accounting();
            pair.answerer.reset_accounting();
            pair.transfer(batch).unwrap();

            row(
                &format!("`DataChannel/{mode}/{}KiB`", size / 1024),
                "message",
                count,
                pair.offerer.allocations(),
                pair.answerer.allocations(),
            );
        }
    }

    println!(
        "\nSend is the offerer, receive the answerer; each includes the RTCP, SACKs and consent \
         traffic it handles in return. The workload's own buffers — the data-channel payloads it \
         hands to `send` — are built outside the counted region."
    );
}
