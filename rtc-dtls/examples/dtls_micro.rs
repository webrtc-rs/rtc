//! Fixed-work DTLS AES-GCM record-protection micro-benchmark for `perf`/`poop`.
//!
//! Builds one representative application-data record, then encrypts (or
//! decrypts) it in a tight loop with no per-iteration setup, isolating the
//! steady-state per-record cost of the record-protection path that wraps
//! every DataChannel packet.
//!
//! Usage: dtls_micro <encrypt|decrypt> [payload_len] [iterations]

use std::hint::black_box;

use rtc_dtls::content::ContentType;
use rtc_dtls::crypto::crypto_gcm::CryptoGcm;
use rtc_dtls::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "encrypt".to_string());
    let payload_len: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1200);
    let iters: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);

    let local_key = [0x11u8; 16];
    let local_iv = [0x22u8; 4];
    let remote_key = [0x33u8; 16];
    let remote_iv = [0x44u8; 4];

    // Encrypt-side and decrypt-side contexts that mirror each other.
    let sender = CryptoGcm::new(&local_key, &local_iv, &remote_key, &remote_iv);
    let receiver = CryptoGcm::new(&remote_key, &remote_iv, &local_key, &local_iv);

    let header = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 1,
        sequence_number: 1,
        content_len: payload_len as u16,
    };
    let mut raw = Vec::with_capacity(13 + payload_len);
    header.marshal(&mut raw).unwrap();
    raw.extend(std::iter::repeat_n(0x5au8, payload_len));

    match mode.as_str() {
        "encrypt" => {
            for _ in 0..iters {
                let out = sender.encrypt(&header, black_box(&raw)).unwrap();
                black_box(&out);
            }
        }
        "decrypt" => {
            let encrypted = sender.encrypt(&header, &raw).unwrap();
            for _ in 0..iters {
                let out = receiver.decrypt(black_box(&encrypted)).unwrap();
                black_box(&out);
            }
        }
        other => {
            eprintln!("unknown mode: {other} (expected encrypt|decrypt)");
            std::process::exit(2);
        }
    }
}
