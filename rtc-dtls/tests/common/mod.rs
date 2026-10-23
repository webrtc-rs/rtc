//! A lossless in-memory DTLS "network" for tests that drive two [`Endpoint`]s through a handshake
//! and need to look at what each side did: the events it raised, the error it stopped with, and
//! every datagram that crossed (so alerts can be read off the wire).
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use rtc_dtls::config::{ConfigBuilder, HandshakeConfig};
use rtc_dtls::crypto::Certificate;
use rtc_dtls::crypto_provider::{RTCCryptoProvider, default_provider};
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use shared::TransportProtocol;
use shared::error::Error;

pub fn client_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 4444))
}

pub fn server_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 4445))
}

pub fn provider() -> Arc<dyn RTCCryptoProvider> {
    default_provider().expect("a built-in crypto provider")
}

pub fn certificate() -> Certificate {
    Certificate::generate_self_signed(vec!["localhost".to_owned()], provider().crypto())
        .expect("self-signed certificate")
}

/// A builder with the provider set and certificate verification off, as most tests want.
pub fn builder() -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_insecure_skip_verify(true)
}

/// Which way a datagram went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

/// What a handshake attempt ended up as.
pub struct Outcome {
    pub client: Endpoint,
    pub server: Endpoint,
    pub client_complete: bool,
    pub server_complete: bool,
    pub client_error: Option<Error>,
    pub server_error: Option<Error>,
    /// Application data each side received, in order.
    pub client_data: Vec<Vec<u8>>,
    pub server_data: Vec<Vec<u8>>,
    /// Every datagram, in the order it crossed.
    pub log: Vec<(Dir, Vec<u8>)>,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.client_complete && self.server_complete
    }

    /// The `(level, description)` of every plaintext (epoch 0) alert record sent in `dir`.
    pub fn alerts(&self, dir: Dir) -> Vec<(u8, u8)> {
        let mut out = vec![];
        for (d, datagram) in &self.log {
            if *d != dir {
                continue;
            }
            let mut rest = &datagram[..];
            while rest.len() >= 13 {
                let content_type = rest[0];
                let epoch = u16::from_be_bytes([rest[3], rest[4]]);
                let len = u16::from_be_bytes([rest[11], rest[12]]) as usize;
                if rest.len() < 13 + len {
                    break;
                }
                if content_type == 21 && epoch == 0 && len == 2 {
                    out.push((rest[13], rest[14]));
                }
                rest = &rest[13 + len..];
            }
        }
        out
    }

    /// The connection state of the client's / server's association, once it exists.
    pub fn client_state(&self) -> Option<&rtc_dtls::state::State> {
        self.client.get_connection_state(server_addr())
    }

    pub fn server_state(&self) -> Option<&rtc_dtls::state::State> {
        self.server.get_connection_state(client_addr())
    }
}

/// Runs a client built from `client` against a server built from `server`, until both finish or
/// one side fails. The server config is `None` to run a client against nothing.
pub fn handshake(client: ConfigBuilder, server: ConfigBuilder) -> Outcome {
    let client_config: HandshakeConfig = client
        .build(true, None)
        .expect("the client configuration builds");
    let server_config: HandshakeConfig = server
        .build(false, None)
        .expect("the server configuration builds");
    handshake_configs(client_config, server_config)
}

pub fn handshake_configs(
    client_config: HandshakeConfig,
    server_config: HandshakeConfig,
) -> Outcome {
    handshake_tampered(client_config, server_config, |_, _| {})
}

/// As [`handshake_configs`], with `tamper` free to rewrite every datagram before it is delivered.
pub fn handshake_tampered(
    client_config: HandshakeConfig,
    server_config: HandshakeConfig,
    mut tamper: impl FnMut(Dir, &mut Vec<u8>),
) -> Outcome {
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(Arc::new(server_config)),
    );
    let mut out = Outcome {
        client_complete: false,
        server_complete: false,
        client_error: None,
        server_error: None,
        client_data: vec![],
        server_data: vec![],
        log: vec![],
        client: Endpoint::new(client_addr(), TransportProtocol::UDP, None),
        server: Endpoint::new(server_addr(), TransportProtocol::UDP, None),
    };
    let now = Instant::now();
    if let Err(err) = client.connect(now, server_addr(), Arc::new(client_config), None) {
        out.client_error = Some(err);
    }

    for _ in 0..64 {
        let mut moved = false;
        while let Some(transmit) = client.poll_transmit() {
            moved = true;
            let mut datagram = transmit.message.to_vec();
            tamper(Dir::ClientToServer, &mut datagram);
            out.log.push((Dir::ClientToServer, datagram.clone()));
            if out.server_error.is_some() {
                continue;
            }
            match server.read(
                now,
                client_addr(),
                transmit.transport.ecn,
                BytesMut::from(&datagram[..]),
            ) {
                Ok(events) => record(&mut out.server_complete, &mut out.server_data, events),
                Err(err) => out.server_error = Some(err),
            }
        }
        while let Some(transmit) = server.poll_transmit() {
            moved = true;
            let mut datagram = transmit.message.to_vec();
            tamper(Dir::ServerToClient, &mut datagram);
            out.log.push((Dir::ServerToClient, datagram.clone()));
            if out.client_error.is_some() {
                continue;
            }
            match client.read(
                now,
                server_addr(),
                transmit.transport.ecn,
                BytesMut::from(&datagram[..]),
            ) {
                Ok(events) => record(&mut out.client_complete, &mut out.client_data, events),
                Err(err) => out.client_error = Some(err),
            }
        }
        if !moved || out.ok() {
            break;
        }
    }
    out.client = client;
    out.server = server;
    out
}

fn record(complete: &mut bool, data: &mut Vec<Vec<u8>>, events: Vec<EndpointEvent>) {
    for event in events {
        match event {
            EndpointEvent::HandshakeComplete => *complete = true,
            EndpointEvent::ApplicationData(bytes) => data.push(bytes.to_vec()),
            _ => {}
        }
    }
}

/// Sends `payload` from the client and returns what the server received.
pub fn client_sends(out: &mut Outcome, payload: &[u8]) -> Vec<u8> {
    let now = Instant::now();
    out.client
        .write(now, server_addr(), payload)
        .expect("client write");
    let transmit = out.client.poll_transmit().expect("a record");
    let events = out
        .server
        .read(now, client_addr(), transmit.transport.ecn, transmit.message)
        .expect("server read");
    events
        .into_iter()
        .find_map(|event| match event {
            EndpointEvent::ApplicationData(bytes) => Some(bytes.to_vec()),
            _ => None,
        })
        .expect("application data")
}
