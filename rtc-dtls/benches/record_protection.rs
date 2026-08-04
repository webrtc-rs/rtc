//! DTLS record-protection benchmarks.
//!
//! Measures the per-record cost of each record cipher after the G3 crypto-provider migration,
//! and separates it from one-time key-schedule setup:
//!
//! * `Setup/*` constructs a cipher, so it covers the provider lookup, key import, and key
//!   schedule. This happens once per DTLS epoch.
//! * `Encrypt/*` and `Decrypt/*` protect and unprotect a single record on an already-keyed
//!   cipher. This is the hot path and the number that matters for throughput.
//!
//! The split exists because the provider indirection is deliberately concentrated in setup: a
//! keyed cipher object is obtained once and then used per record with no further provider
//! dispatch. A regression in `Encrypt/*` would mean that property broke.
//!
//! Every cipher runs against each enabled built-in provider under identical inputs, so the two
//! backends are directly comparable.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-dtls --bench record_protection
//! cargo bench --package rtc-dtls --bench record_protection --no-default-features --features aws-lc-rs
//! ```

use std::sync::Arc;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, criterion_main};

use crypto::RTCCryptoProvider;
use rtc_dtls::content::ContentType;
use rtc_dtls::crypto::crypto_cbc::CryptoCbc;
use rtc_dtls::crypto::crypto_gcm::CryptoGcm;
use rtc_dtls::record_layer::record_layer_header::{
    PROTOCOL_VERSION1_2, RECORD_LAYER_HEADER_SIZE, RecordLayerHeader,
};

/// A 1200-byte record, sized to a typical WebRTC MTU-bound payload.
const PAYLOAD_LEN: usize = 1200;

const KEY_128: &[u8] = &[
    0x60, 0xb4, 0x1f, 0x04, 0x77, 0x89, 0x80, 0xfc, 0x4b, 0xc2, 0xfc, 0x2c, 0x3f, 0x38, 0x3d, 0x37,
];
const KEY_256: &[u8] = &[
    0x60, 0xb4, 0x1f, 0x04, 0x77, 0x89, 0x80, 0xfc, 0x4b, 0xc2, 0xfc, 0x2c, 0x3f, 0x38, 0x3d, 0x37,
    0xf7, 0x1a, 0x31, 0x5e, 0x63, 0x1d, 0x4f, 0x5e, 0x05, 0x6f, 0xfc, 0xd8, 0x3e, 0xc3, 0x11, 0x22,
];
const IV_GCM: &[u8] = &[0xf7, 0x1a, 0x31, 0x5e];
const MAC_SHA1: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
];

/// A DTLS 1.2 application-data record: marshalled header followed by the payload.
///
/// The header must be marshalled rather than zero-filled, because `decrypt` re-parses it from
/// the ciphertext buffer.
fn record() -> (RecordLayerHeader, Vec<u8>) {
    let header = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 1,
        sequence_number: 1,
        content_len: PAYLOAD_LEN as u16,
    };
    let mut raw = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + PAYLOAD_LEN);
    header.marshal(&mut raw).unwrap();
    raw.extend((0..PAYLOAD_LEN).map(|index| index as u8));
    (header, raw)
}

/// The built-in providers compiled into this benchmark.
fn providers() -> Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> {
    let mut providers: Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(("ring", Arc::new(crypto::providers::RingProvider::default())));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push((
        "aws-lc-rs",
        Arc::new(crypto::providers::AwsLcRsProvider::default()),
    ));
    assert!(
        !providers.is_empty(),
        "enable `ring` or `aws-lc-rs` to run these benchmarks"
    );
    providers
}

fn benchmark_gcm(group: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        // One-time cost: provider dispatch, key import, key schedule.
        group.bench_function(format!("Setup/AES-128-GCM/{name}"), |b| {
            b.iter(|| {
                CryptoGcm::new(Arc::clone(&provider), KEY_128, IV_GCM, KEY_128, IV_GCM).unwrap()
            });
        });

        let mut cipher =
            CryptoGcm::new(Arc::clone(&provider), KEY_128, IV_GCM, KEY_128, IV_GCM).unwrap();
        let (header, raw) = record();

        group.bench_function(format!("Encrypt/AES-128-GCM/{name}"), |b| {
            b.iter(|| cipher.encrypt(&header, &raw).unwrap());
        });

        let encrypted = cipher.encrypt(&header, &raw).unwrap();
        group.bench_function(format!("Decrypt/AES-128-GCM/{name}"), |b| {
            b.iter(|| cipher.decrypt(&encrypted).unwrap());
        });
    }
}

fn benchmark_cbc(group: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        group.bench_function(format!("Setup/AES-256-CBC/{name}"), |b| {
            b.iter(|| {
                CryptoCbc::new(Arc::clone(&provider), KEY_256, MAC_SHA1, KEY_256, MAC_SHA1).unwrap()
            });
        });

        let mut cipher =
            CryptoCbc::new(Arc::clone(&provider), KEY_256, MAC_SHA1, KEY_256, MAC_SHA1).unwrap();
        let (header, raw) = record();

        group.bench_function(format!("Encrypt/AES-256-CBC/{name}"), |b| {
            b.iter(|| cipher.encrypt(&header, &raw).unwrap());
        });

        let encrypted = cipher.encrypt(&header, &raw).unwrap();
        group.bench_function(format!("Decrypt/AES-256-CBC/{name}"), |b| {
            b.iter(|| cipher.decrypt(&encrypted).unwrap());
        });
    }
}

fn benches() {
    let mut criterion = Criterion::default().configure_from_args();
    let mut group = criterion.benchmark_group("DTLS");
    benchmark_gcm(&mut group);
    benchmark_cbc(&mut group);
    group.finish();
}

criterion_main!(benches);
