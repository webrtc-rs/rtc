use bytes::BytesMut;
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, criterion_main};
use rtc_srtp::{context::Context, protection_profile::ProtectionProfile};
use shared::marshal::Marshal;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

const MASTER_KEY: &[u8] = &[
    96, 180, 31, 4, 119, 137, 128, 252, 75, 194, 252, 44, 63, 56, 61, 55,
];
const MASTER_SALT: &[u8] = &[247, 26, 49, 94, 99, 29, 79, 94, 5, 111, 252, 216, 62, 195];
const RAW_RTCP: &[u8] = &[
    0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
];

fn benchmark_encrypt_rtp_aes_128_cm_hmac_sha1(g: &mut BenchmarkGroup<WallTime>) {
    let mut ctx = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap();

    let mut pld = BytesMut::new();
    for i in 0..1200 {
        pld.extend_from_slice(&[i as u8]);
    }

    g.bench_function("Encrypt/RTP", |b| {
        let mut seq = 1;
        b.iter_batched(
            || {
                let pkt = rtp::packet::Packet {
                    header: rtp::header::Header {
                        sequence_number: seq,
                        timestamp: seq.into(),
                        extension_profile: 48862,
                        marker: true,
                        padding: false,
                        extension: true,
                        payload_type: 96,
                        ..Default::default()
                    },
                    payload: pld.clone().into(),
                };
                seq += 1;
                pkt.marshal().unwrap()
            },
            |pkt_raw| {
                ctx.encrypt_rtp(&pkt_raw).unwrap();
            },
            criterion::BatchSize::LargeInput,
        );
    });
}

fn benchmark_decrypt_rtp_aes_128_cm_hmac_sha1(g: &mut BenchmarkGroup<WallTime>) {
    let mut setup_ctx = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap();

    let mut ctx = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap();

    let mut pld = BytesMut::new();
    for i in 0..1200 {
        pld.extend_from_slice(&[i as u8]);
    }

    g.bench_function("Decrypt/RTP", |b| {
        let mut seq = 1;
        b.iter_batched(
            || {
                let pkt = rtp::packet::Packet {
                    header: rtp::header::Header {
                        sequence_number: seq,
                        timestamp: seq.into(),
                        extension_profile: 48862,
                        marker: true,
                        padding: false,
                        extension: true,
                        payload_type: 96,
                        ..Default::default()
                    },
                    payload: pld.clone().into(),
                };
                seq += 1;
                setup_ctx.encrypt_rtp(&pkt.marshal().unwrap()).unwrap()
            },
            |encrypted| ctx.decrypt_rtp(&encrypted).unwrap(),
            criterion::BatchSize::LargeInput,
        );
    });
}

fn benchmark_encrypt_rtcp_aes_128_cm_hmac_sha1(g: &mut BenchmarkGroup<WallTime>) {
    let mut ctx = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap();

    g.bench_function("Encrypt/RTCP", |b| {
        b.iter(|| {
            ctx.encrypt_rtcp(RAW_RTCP).unwrap();
        });
    });
}

fn benchmark_decrypt_rtcp_aes_128_cm_hmac_sha1(g: &mut BenchmarkGroup<WallTime>) {
    let encrypted = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap()
    .encrypt_rtcp(RAW_RTCP)
    .unwrap();

    let mut ctx = Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider(),
    )
    .unwrap();

    g.bench_function("Decrypt/RTCP", |b| {
        b.iter(|| ctx.decrypt_rtcp(&encrypted).unwrap());
    });
}

/// The built-in providers compiled into this benchmark, so the two backends can be compared
/// under identical inputs.
fn providers() -> Vec<(&'static str, std::sync::Arc<dyn crypto::RTCCryptoProvider>)> {
    let mut providers: Vec<(&'static str, std::sync::Arc<dyn crypto::RTCCryptoProvider>)> =
        Vec::new();
    #[cfg(feature = "ring")]
    providers.push((
        "ring",
        std::sync::Arc::new(crypto::providers::RingProvider::default()),
    ));
    #[cfg(feature = "aws-lc-rs")]
    providers.push((
        "aws-lc-rs",
        std::sync::Arc::new(crypto::providers::AwsLcRsProvider::default()),
    ));
    assert!(
        !providers.is_empty(),
        "enable `ring` or `aws-lc-rs` to run these benchmarks"
    );
    providers
}

/// Context construction: provider dispatch, SRTP key derivation (RFC 3711 section 4.3), and the
/// cipher key schedule. Paid once per one-way context, not per packet — the counterpart to the
/// `Encrypt/*` and `Decrypt/*` hot-path measurements above.
fn benchmark_context_setup(g: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        for (label, profile) in [
            (
                "AES-128-CM-HMAC-SHA1-80",
                ProtectionProfile::Aes128CmHmacSha1_80,
            ),
            ("AEAD-AES-128-GCM", ProtectionProfile::AeadAes128Gcm),
        ] {
            g.bench_function(format!("Setup/{label}/{name}"), |b| {
                b.iter(|| {
                    Context::new(
                        MASTER_KEY,
                        &master_salt_for(profile),
                        profile,
                        None,
                        None,
                        std::sync::Arc::clone(&provider),
                    )
                    .unwrap()
                });
            });
        }
    }
}

/// AEAD-AES-128-GCM packet path, per provider.
fn benchmark_aead_aes_128_gcm(g: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let salt = master_salt_for(profile);
        let mut encrypt_ctx = Context::new(
            MASTER_KEY,
            &salt,
            profile,
            None,
            None,
            std::sync::Arc::clone(&provider),
        )
        .unwrap();
        let mut decrypt_ctx = Context::new(
            MASTER_KEY,
            &salt,
            profile,
            None,
            None,
            std::sync::Arc::clone(&provider),
        )
        .unwrap();

        let mut pld = BytesMut::new();
        for i in 0..1200 {
            pld.extend_from_slice(&[i as u8]);
        }

        g.bench_function(format!("Encrypt/RTP/AEAD-AES-128-GCM/{name}"), |b| {
            let mut seq = 1;
            b.iter_batched(
                || {
                    let pkt = rtp::packet::Packet {
                        header: rtp::header::Header {
                            sequence_number: seq,
                            timestamp: seq.into(),
                            ssrc: 0xcafebabe,
                            ..Default::default()
                        },
                        payload: pld.clone().freeze(),
                    };
                    seq = seq.wrapping_add(1);
                    pkt.marshal().unwrap()
                },
                |raw| encrypt_ctx.encrypt_rtp(&raw).unwrap(),
                criterion::BatchSize::SmallInput,
            );
        });

        // Pre-encrypt a run of packets so decryption never replays an index, which the replay
        // detector would reject.
        let mut encrypted = Vec::new();
        for seq in 1..=1024u16 {
            let pkt = rtp::packet::Packet {
                header: rtp::header::Header {
                    sequence_number: seq,
                    timestamp: seq.into(),
                    ssrc: 0xcafebabe,
                    ..Default::default()
                },
                payload: pld.clone().freeze(),
            };
            let raw = pkt.marshal().unwrap();
            encrypted.push(encrypt_ctx.encrypt_rtp(&raw).unwrap());
        }

        let mut index = 0usize;
        g.bench_function(format!("Decrypt/RTP/AEAD-AES-128-GCM/{name}"), |b| {
            b.iter(|| {
                let packet = &encrypted[index % encrypted.len()];
                index += 1;
                let _ = decrypt_ctx.decrypt_rtp(packet);
            });
        });
    }
}

/// The master salt length differs per protection profile.
fn master_salt_for(profile: ProtectionProfile) -> Vec<u8> {
    let mut salt = MASTER_SALT.to_vec();
    salt.resize(profile.salt_len(), 0x5a);
    salt
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    let mut g = c.benchmark_group("SRTP");

    benchmark_encrypt_rtp_aes_128_cm_hmac_sha1(&mut g);
    benchmark_decrypt_rtp_aes_128_cm_hmac_sha1(&mut g);
    benchmark_encrypt_rtcp_aes_128_cm_hmac_sha1(&mut g);
    benchmark_decrypt_rtcp_aes_128_cm_hmac_sha1(&mut g);
    benchmark_aead_aes_128_gcm(&mut g);
    benchmark_context_setup(&mut g);

    g.finish();
}

criterion_main!(benches);
