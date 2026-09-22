//! Times the AES paths rtc runs on RustCrypto, as an application depending on rtc builds them.
//!
//! Run through `python3 scripts/bench.py external`, which builds this crate three ways and compares
//! them; see README.md. Run on its own with `cargo run --release`.
//!
//! SRTP AES-CM, DTLS AES-CCM and AES-CBC, and SRTP key derivation use RustCrypto's `aes`, whose
//! hardware backend was once only compiled in on aarch64 when the *consumer* passed
//! `--cfg aes_armv8`. A consumer that did not got the constant-time software backend, silently and
//! many times slower. These timings show which backend a build got: a consumer build should match
//! the in-repository build and be far faster than the forced software backend.
//!
//! AES-GCM runs on ring or aws-lc-rs and is timed as a control that no cfg affects.
//!
//! Each case is timed in six rounds, interleaved with the other cases in rotated order, and the
//! upper median is reported. No confidence intervals: this answers "which backend", not "how many
//! nanoseconds exactly" — use the criterion suites for that.

use std::hint::black_box;
use std::time::Instant;

use rtc_crypto::{AeadAlgorithm, CbcAlgorithm, StreamCipherAlgorithm, default_provider};

const PAYLOAD: usize = 1200;

fn main() {
    let provider = default_provider().expect("a crypto provider feature is enabled");
    let crypto = provider.crypto();

    let mut ctr = crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &[7; 16])
        .unwrap();
    let mut ccm = crypto.new_aead(AeadAlgorithm::Aes128Ccm, &[7; 16]).unwrap();
    let mut cbc_encrypt = crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &[7; 32]).unwrap();
    let mut cbc_decrypt = crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &[7; 32]).unwrap();
    let mut gcm = crypto.new_aead(AeadAlgorithm::Aes128Gcm, &[7; 16]).unwrap();

    let iv = [3; 16];
    let nonce = [9; 12];

    type Case<'a> = Box<dyn FnMut(&mut [u8], &mut [u8]) + 'a>;
    let mut cases: Vec<(&str, Case)> = vec![
        (
            "AES-128-CTR (SRTP AES-CM)",
            Box::new(|data, _| ctr.apply_keystream(black_box(&iv), data).unwrap()),
        ),
        (
            "AES-128-CCM seal (DTLS)",
            Box::new(|data, tag| {
                ccm.seal_in_place(black_box(&nonce), &[], data, tag)
                    .unwrap()
            }),
        ),
        (
            "AES-256-CBC encrypt (DTLS)",
            Box::new(|data, _| cbc_encrypt.encrypt_blocks(black_box(&iv), data).unwrap()),
        ),
        (
            "AES-256-CBC decrypt (DTLS)",
            Box::new(|data, _| cbc_decrypt.decrypt_blocks(black_box(&iv), data).unwrap()),
        ),
        (
            "AES-128-GCM seal (control)",
            Box::new(|data, tag| {
                gcm.seal_in_place(black_box(&nonce), &[], data, tag)
                    .unwrap()
            }),
        ),
    ];

    println!("target_arch: {}", std::env::consts::ARCH);
    println!("cfg aes_armv8: {}", cfg!(aes_armv8));
    println!("cfg aes_backend=\"soft\": {}", cfg!(aes_backend = "soft"));
    println!("payload: {PAYLOAD} bytes");

    const ROUNDS: usize = 6;
    const ITERATIONS: usize = 20_000;
    let mut data = vec![0x5a; PAYLOAD];
    let mut tag = [0; 16];
    let mut samples = vec![Vec::with_capacity(ROUNDS); cases.len()];
    for round in 0..ROUNDS {
        for offset in 0..cases.len() {
            let index = (round + offset) % cases.len();
            let run = &mut cases[index].1;
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                run(black_box(&mut data), &mut tag);
            }
            samples[index].push(start.elapsed().as_secs_f64() * 1e9 / ITERATIONS as f64);
        }
    }
    for ((name, _), times) in cases.iter().zip(&mut samples) {
        times.sort_by(f64::total_cmp);
        println!("{name}: {:.1} ns", times[ROUNDS / 2]);
    }
}
