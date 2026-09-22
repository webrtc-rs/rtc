//! What it costs to stand a peer connection up: build, negotiate, connect.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtc-bench --bench peer_connection
//! cargo bench --package rtc-bench --bench peer_connection --features crypto-aws-lc-rs
//! ```
//!
//! Each stage is measured on its own, because they scale differently and are paid at different
//! times:
//!
//! * `Build/*` constructs an `RTCPeerConnection`. `generate-certificate` is the key generation a
//!   peer does at construction when it is not handed a certificate; `with-certificate` is
//!   everything else. An application that reuses certificates pays only the second.
//! * `Signaling/*` is the full offer/answer exchange — `create_offer`, both
//!   `set_*_description` pairs and `create_answer` — on already-built peers. SDP generation and
//!   parsing grow with the number of media sections, so it is swept over track count.
//! * `Connect/*` starts from negotiated peers and drives ICE connectivity checks, the DTLS
//!   handshake and, for a data channel, the SCTP association and DCEP open, to completion. It is
//!   CPU time on a zero-latency wire, not the wall-clock time to connect over a network: see the
//!   `rtc-bench` crate documentation.
//!
//! `Build` and `Connect` depend on the crypto provider and are reported per provider. Signaling
//! does no cryptography beyond reading the certificate fingerprint and is reported once.

use criterion::{BatchSize, Criterion, SamplingMode, criterion_main};
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc_bench::fixtures::{self, MediaKind};
use rtc_bench::{PairBuilder, PeerPair, providers};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

fn benchmark_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("PeerConnection/Build");

    for (name, provider) in providers() {
        group.bench_function(format!("generate-certificate/{name}"), |b| {
            b.iter(|| fixtures::certificate(provider.as_ref()).unwrap());
        });

        let certificate = fixtures::certificate(provider.as_ref()).unwrap();
        group.bench_function(format!("with-certificate/{name}"), |b| {
            b.iter_batched(
                || certificate.clone(),
                |certificate| {
                    RTCPeerConnectionBuilder::new()
                        .with_configuration(
                            RTCConfigurationBuilder::new()
                                .with_certificates(vec![certificate])
                                .build(),
                        )
                        .with_setting_engine(
                            SettingEngineBuilder::new()
                                .with_crypto_provider(Arc::clone(&provider))
                                .build(),
                        )
                        .build(Instant::now())
                        .unwrap()
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn benchmark_signaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("PeerConnection/Signaling");
    // Sixteen media sections take over half a millisecond; linear sampling would not fit.
    group.sampling_mode(SamplingMode::Flat);
    let (_, provider) = providers().into_iter().next().expect("a provider");
    let offerer_certificate = fixtures::certificate(provider.as_ref()).unwrap();
    let answerer_certificate = fixtures::certificate(provider.as_ref()).unwrap();
    let builder = || {
        PeerPair::builder(Arc::clone(&provider))
            .certificates(offerer_certificate.clone(), answerer_certificate.clone())
    };

    let mut cases: Vec<(String, Box<dyn Fn() -> PairBuilder + '_>)> = vec![
        (
            "data-channel".to_owned(),
            Box::new(|| builder().data_channel(RTCDataChannelInit::default())),
        ),
        (
            "audio+video".to_owned(),
            Box::new(|| builder().track(MediaKind::Audio).track(MediaKind::Video)),
        ),
        (
            "audio+video+data-channel".to_owned(),
            Box::new(|| {
                builder()
                    .track(MediaKind::Audio)
                    .track(MediaKind::Video)
                    .data_channel(RTCDataChannelInit::default())
            }),
        ),
    ];
    // SDP work grows with media sections, which is what an SFU fanning out many tracks pays.
    for tracks in [4, 16] {
        cases.push((
            format!("{tracks}-video-tracks"),
            Box::new(move || {
                (0..tracks).fold(builder(), |builder, _| builder.track(MediaKind::Video))
            }),
        ));
    }

    for (label, pair) in &cases {
        group.bench_function(format!("offer-answer/{label}"), |b| {
            b.iter_batched(
                || pair().build().unwrap(),
                |mut pair| {
                    pair.negotiate().unwrap();
                    pair
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

fn benchmark_connect(c: &mut Criterion) {
    let mut group = c.benchmark_group("PeerConnection/Connect");
    // A handshake is milliseconds, not nanoseconds: flat sampling and fewer samples keep a run
    // to a sensible length without losing the ability to see a change of a few percent.
    group.sampling_mode(SamplingMode::Flat).sample_size(30);

    for (name, provider) in providers() {
        let offerer_certificate = fixtures::certificate(provider.as_ref()).unwrap();
        let answerer_certificate = fixtures::certificate(provider.as_ref()).unwrap();
        let negotiated = |builder: PairBuilder| {
            let mut pair = builder
                .certificates(offerer_certificate.clone(), answerer_certificate.clone())
                .build()
                .unwrap();
            pair.negotiate().unwrap();
            pair
        };

        group.bench_function(format!("data-channel/{name}"), |b| {
            b.iter_batched(
                || {
                    negotiated(
                        PeerPair::builder(Arc::clone(&provider))
                            .data_channel(RTCDataChannelInit::default()),
                    )
                },
                |mut pair| {
                    pair.connect().unwrap();
                    black_box(pair)
                },
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("media/{name}"), |b| {
            b.iter_batched(
                || {
                    negotiated(
                        PeerPair::builder(Arc::clone(&provider))
                            .track(MediaKind::Audio)
                            .track(MediaKind::Video),
                    )
                },
                |mut pair| {
                    pair.connect().unwrap();
                    black_box(pair)
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

fn benches() {
    let mut c = Criterion::default().configure_from_args();
    benchmark_build(&mut c);
    benchmark_signaling(&mut c);
    benchmark_connect(&mut c);
}

criterion_main!(benches);
