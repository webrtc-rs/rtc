//! ICE candidate parsing and serialisation.
//!
//! Run with `cargo bench --package rtc-ice --bench bench`.
//!
//! Every trickled candidate is parsed once on arrival and every local one serialised once for
//! signaling, so this is not a per-packet path. It matters where signaling volume does: a server
//! terminating thousands of peers parses a candidate for each of them, several times over during
//! an ICE restart. The inputs cover the forms that parse differently: IPv4 and IPv6 host, an mDNS
//! `.local` host as browsers send by default, and server-reflexive and relay candidates, which
//! carry a related address.
//!
//! Connectivity checks — STUN binding requests and responses — are covered end to end by
//! `rtc-bench`'s `PeerConnection/Connect/*`, and STUN message handling by the `rtc-stun` benches.

use criterion::{Criterion, criterion_main};
use rtc_ice::candidate::unmarshal_candidate;
use std::hint::black_box;

const CANDIDATES: [(&str, &str); 5] = [
    (
        "host-ipv4",
        "4273957277 1 udp 2130706431 10.0.75.1 53634 typ host",
    ),
    (
        "host-ipv6",
        "750 1 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host",
    ),
    (
        "host-mdns",
        "1380287402 1 udp 2130706431 e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local 60542 typ host",
    ),
    (
        "srflx",
        "647372371 1 udp 1694498815 191.228.238.68 53991 typ srflx raddr 192.168.0.1 rport 53991",
    ),
    (
        "relay",
        "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001",
    ),
];

fn benchmark_candidate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ICE/Candidate");

    for (label, raw) in CANDIDATES {
        group.bench_function(format!("unmarshal/{label}"), |b| {
            b.iter(|| unmarshal_candidate(black_box(raw)).unwrap());
        });

        let candidate = unmarshal_candidate(raw).unwrap();
        group.bench_function(format!("marshal/{label}"), |b| {
            b.iter(|| black_box(&candidate).marshal());
        });
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_candidate(&mut c);
}

criterion_main!(benches);
