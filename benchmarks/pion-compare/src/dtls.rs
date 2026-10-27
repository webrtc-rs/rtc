//! DTLS 1.2 between two in-memory endpoints: whole handshakes, and steady-state application data.
//! Both sides use one self-signed ECDSA P-256 certificate, certificate verification off and the
//! default cipher suites, as WebRTC does. The Go half is `go/dtls.go`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use rtc_dtls::config::{ConfigBuilder, HandshakeConfig};
use rtc_dtls::crypto::Certificate;
use rtc_dtls::crypto_provider::default_provider;
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use shared::TransportProtocol;

pub struct Configs {
    client: Arc<HandshakeConfig>,
    server: Arc<HandshakeConfig>,
}

impl Configs {
    pub fn new() -> Self {
        let provider = default_provider().expect("a crypto provider");
        let cert =
            Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
                .expect("certificate");
        let build = |client: bool| {
            Arc::new(
                ConfigBuilder::default()
                    .with_crypto_provider(provider.clone())
                    .with_certificates(vec![cert.clone()])
                    .with_insecure_skip_verify(true)
                    .build(client, None)
                    .expect("config"),
            )
        };
        Self { client: build(true), server: build(false) }
    }
}

pub struct Pair {
    client: Endpoint,
    server: Endpoint,
    c_addr: SocketAddr,
    s_addr: SocketAddr,
    now: Instant,
}

impl Pair {
    /// Moves datagrams both ways until nothing is in flight; reports which side finished its
    /// handshake meanwhile.
    fn pump(&mut self) -> (bool, bool) {
        let (mut cd, mut sd) = (false, false);
        loop {
            let mut moved = false;
            while let Some(t) = self.client.poll_transmit() {
                moved = true;
                let events = self
                    .server
                    .read(self.now, self.c_addr, t.transport.ecn, BytesMut::from(&t.message[..]))
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
                    .read(self.now, self.s_addr, t.transport.ecn, BytesMut::from(&t.message[..]))
                    .expect("client read");
                cd |= events.iter().any(|e| matches!(e, EndpointEvent::HandshakeComplete));
            }
            if !moved {
                return (cd, sd);
            }
        }
    }

    /// A full handshake between a fresh client and a fresh server.
    pub fn connect(cfg: &Configs) -> Self {
        let c_addr = SocketAddr::from(([127, 0, 0, 1], 4444));
        let s_addr = SocketAddr::from(([127, 0, 0, 1], 4445));
        let now = Instant::now();
        let mut p = Pair {
            client: Endpoint::new(c_addr, TransportProtocol::UDP, None),
            server: Endpoint::new(s_addr, TransportProtocol::UDP, Some(cfg.server.clone())),
            c_addr,
            s_addr,
            now,
        };
        p.client.connect(now, s_addr, cfg.client.clone(), None).expect("connect");
        let (mut cd, mut sd) = (false, false);
        while !(cd && sd) {
            let (c, s) = p.pump();
            assert!(c || s, "handshake stalled");
            cd |= c;
            sd |= s;
        }
        p
    }

    /// One application record from the client, delivered to the server.
    pub fn send(&mut self, payload: &[u8]) {
        self.client.write(self.now, self.s_addr, payload).expect("write");
        self.pump();
    }
}
