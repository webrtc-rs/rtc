//! AES-GCM seal+open micro-benchmark: RustCrypto `aes-gcm` vs `ring::aead`.
//!
//! Both arms operate on an identical buffer layout: `size` plaintext bytes
//! followed by a 16-byte tag slot, matching how rtc's SRTP cipher keeps the tag
//! detached from the payload. Only the AEAD backend differs, so the wall-time
//! delta a harness like `crap`/`poop` reports (and the kperf cycle/instruction
//! counts under sudo) is attributable to the crypto, not to setup or process
//! startup (which is identical for both commands).
//!
//! See README.md for the exact reproduction recipe (build variants + crap).

use std::env;
use std::time::Instant;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as RcNonce};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};

const TAG_LEN: usize = 16;
const NONCE: [u8; 12] = [0x24; 12];
const AAD: [u8; 12] = [0x11; 12]; // stand-in for the RTP header used as AAD

const HELP: &str = "\
aead-bench - AES-GCM seal+open micro-benchmark: RustCrypto aes-gcm vs ring::aead

USAGE:
    aead-bench <backend> <bits> <size> <iters>
    aead-bench --help

ARGS:
    <backend>   AEAD implementation to exercise:
                  rustcrypto  - the `aes-gcm` crate (software unless built with
                                --cfg aes_armv8 --cfg polyval_armv8 on aarch64)
                  ring        - `ring::aead` (single-pass, hardware-accelerated)
    <bits>      AES key size in bits: 128 or 256
    <size>      plaintext bytes per packet (e.g. 1200 for an MTU-sized SRTP packet)
    <iters>     number of seal+open iterations to time (e.g. 100000)

The per-op timing (one seal + one open) is printed to stderr. Intended to be
driven head-to-head by `crap` (macOS) / `poop` (Linux); see README.md.";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return;
    }
    if args.len() != 5 {
        eprintln!("{HELP}");
        std::process::exit(2);
    }
    let backend = args[1].as_str();
    let bits: usize = args[2].parse().expect("bits");
    let size: usize = args[3].parse().expect("size");
    let iters: usize = args[4].parse().expect("iters");
    assert!(bits == 128 || bits == 256, "bits must be 128 or 256");

    let key = vec![0x42u8; bits / 8];
    // Buffer = plaintext (size) followed by a 16-byte tag slot.
    let mut buf = vec![0xABu8; size + TAG_LEN];
    let mut sink: u64 = 0;

    let start = Instant::now();
    match backend {
        "rustcrypto" if bits == 128 => {
            let c = Aes128Gcm::new(GenericArray::from_slice(&key));
            sink = run_rustcrypto(&c, &mut buf, size, iters);
        }
        "rustcrypto" => {
            let c = Aes256Gcm::new(GenericArray::from_slice(&key));
            sink = run_rustcrypto(&c, &mut buf, size, iters);
        }
        "ring" => {
            let alg = if bits == 128 {
                &AES_128_GCM
            } else {
                &AES_256_GCM
            };
            let k = LessSafeKey::new(UnboundKey::new(alg, &key).expect("key"));
            for _ in 0..iters {
                let (pt, tag_slot) = buf.split_at_mut(size);
                let tag = k
                    .seal_in_place_separate_tag(nonce(), Aad::from(&AAD), pt)
                    .expect("seal");
                tag_slot.copy_from_slice(tag.as_ref());
                sink ^= buf[0] as u64 ^ buf[size] as u64;
                // ring's open wants ciphertext||tag contiguous; the whole buf is that.
                let pt = k
                    .open_in_place(nonce(), Aad::from(&AAD), &mut buf)
                    .expect("open");
                sink ^= pt[0] as u64;
            }
        }
        _ => {
            eprintln!("unknown backend {backend:?}\n\n{HELP}");
            std::process::exit(2);
        }
    }
    let el = start.elapsed();
    let ns_per = el.as_nanos() as f64 / iters as f64;
    // ns/op here covers one seal + one open.
    eprintln!(
        "{backend} aes{bits} size={size} iters={iters} -> {ns_per:.1} ns/op(seal+open) \
         {:.2} ms total  sink={sink}",
        el.as_secs_f64() * 1e3
    );
}

fn nonce() -> Nonce {
    Nonce::assume_unique_for_key(NONCE)
}

fn run_rustcrypto<C: AeadInPlace>(c: &C, buf: &mut [u8], size: usize, iters: usize) -> u64 {
    let mut sink = 0u64;
    let n = RcNonce::from_slice(&NONCE);
    for _ in 0..iters {
        let (pt, tag_slot) = buf.split_at_mut(size);
        let tag = c.encrypt_in_place_detached(n, &AAD, pt).expect("encrypt");
        tag_slot.copy_from_slice(&tag);
        sink ^= buf[0] as u64 ^ buf[size] as u64;
        let (pt, tag_slot) = buf.split_at_mut(size);
        c.decrypt_in_place_detached(n, &AAD, pt, GenericArray::from_slice(tag_slot))
            .expect("decrypt");
        sink ^= buf[0] as u64;
    }
    sink
}
