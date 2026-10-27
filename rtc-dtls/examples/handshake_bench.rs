//! Full DTLS 1.2 handshakes and steady-state application data between two in-memory endpoints,
//! the counterpart of `benchmarks/pion-compare/go/dtls.go`.
//!
//! Both sides use one self-signed ECDSA P-256 certificate, certificate verification off and the
//! default cipher suites (ECDHE-ECDSA-AES128-GCM), as WebRTC does. Prints
//! `name  N ns/op  0 B/op  0 allocs/op` so `compare.py` can read it.
//!
//! Usage: handshake_bench [handshakes] [records]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use rtc_dtls::config::{ConfigBuilder, HandshakeConfig};
use rtc_dtls::crypto::Certificate;
use rtc_dtls::crypto_provider::{RTCCryptoProvider, default_provider};
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use shared::TransportProtocol;

fn builder(provider: &Arc<dyn RTCCryptoProvider>, cert: &Certificate) -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_certificates(vec![cert.clone()])
        .with_insecure_skip_verify(true)
}

struct Pair {
    client: Endpoint,
    server: Endpoint,
    c_addr: SocketAddr,
    s_addr: SocketAddr,
}

impl Pair {
    /// Moves datagrams both ways until nothing is in flight. Returns (client_done, server_done).
    fn pump(&mut self, now: Instant) -> (bool, bool, u64) {
        let (mut cd, mut sd, mut bytes) = (false, false, 0u64);
        for _ in 0..64 {
            let mut moved = false;
            while let Some(t) = self.client.poll_transmit() {
                moved = true;
                bytes += t.message.len() as u64;
                let events = self
                    .server
                    .read(now, self.c_addr, t.transport.ecn, BytesMut::from(&t.message[..]))
                    .expect("server read");
                for e in events {
                    match e {
                        EndpointEvent::HandshakeComplete => sd = true,
                        EndpointEvent::ApplicationData(b) => {
                            std::hint::black_box(&b);
                        }
                        _ => {}
                    }
                }
            }
            while let Some(t) = self.server.poll_transmit() {
                moved = true;
                let events = self
                    .client
                    .read(now, self.s_addr, t.transport.ecn, BytesMut::from(&t.message[..]))
                    .expect("client read");
                for e in events {
                    if matches!(e, EndpointEvent::HandshakeComplete) {
                        cd = true;
                    }
                }
            }
            if !moved {
                break;
            }
        }
        (cd, sd, bytes)
    }
}

fn connected(cc: &Arc<HandshakeConfig>, sc: &Arc<HandshakeConfig>) -> Pair {
    let c_addr = SocketAddr::from(([127, 0, 0, 1], 4444));
    let s_addr = SocketAddr::from(([127, 0, 0, 1], 4445));
    let mut p = Pair {
        client: Endpoint::new(c_addr, TransportProtocol::UDP, None),
        server: Endpoint::new(s_addr, TransportProtocol::UDP, Some(sc.clone())),
        c_addr,
        s_addr,
    };
    let now = Instant::now();
    p.client
        .connect(now, s_addr, cc.clone(), None)
        .expect("connect");
    let (mut cd, mut sd) = (false, false);
    while !(cd && sd) {
        let (c, s, _) = p.pump(now);
        cd |= c;
        sd |= s;
        assert!(c || s || (cd && sd), "handshake stalled");
    }
    p
}

fn main() {
    let mut args = std::env::args().skip(1);
    let handshakes: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let records: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);

    let provider = default_provider().expect("a crypto provider");
    let cert = Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
        .expect("certificate");
    let cc = Arc::new(builder(&provider, &cert).build(true, None).expect("client cfg"));
    let sc = Arc::new(builder(&provider, &cert).build(false, None).expect("server cfg"));

    // Warm up.
    for _ in 0..5 {
        std::hint::black_box(connected(&cc, &sc));
    }

    let start = Instant::now();
    for _ in 0..handshakes {
        std::hint::black_box(connected(&cc, &sc));
    }
    let ns = start.elapsed().as_nanos() as u64 / handshakes as u64;
    println!("dtls handshake ecdsa-p256 aes128-gcm  {ns} ns/op  0 B/op  0 allocs/op");

    let mut p = connected(&cc, &sc);
    let payload = vec![0x5au8; 1200];
    let now = Instant::now();
    let start = Instant::now();
    for _ in 0..records {
        p.client.write(now, p.s_addr, &payload).expect("write");
        p.pump(now);
    }
    let ns = start.elapsed().as_nanos() as u64 / records as u64;
    println!("dtls app data 1200B write+read  {ns} ns/op  0 B/op  0 allocs/op");
}
