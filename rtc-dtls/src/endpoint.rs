//! The Sans-I/O DTLS endpoint.
//!
//! An [`Endpoint`](crate::endpoint::Endpoint) multiplexes several DTLS associations by remote address. Feed it inbound
//! datagrams, poll it for the datagrams to send and for [`EndpointEvent`](crate::endpoint::EndpointEvent)s, and drive its timers
//! with `handle_timeout`/`poll_timeout`. It owns no sockets and reads no clock.
//!
//! [`EndpointEvent::HandshakeComplete`](crate::endpoint::EndpointEvent::HandshakeComplete) is the signal an application waits for: from that point
//! application data can be written, and the SRTP keying material can be exported from the
//! completed handshake.
use crate::conn::DTLSConn;
use shared::error::{Error, Result};
use shared::{EcnCodepoint, TransportContext};
use shared::{TransportMessage, TransportProtocol};

use crate::config::HandshakeConfig;
use crate::state::State;
use bytes::BytesMut;
use std::collections::hash_map::Keys;
use std::collections::{HashMap, VecDeque, hash_map::Entry::Vacant};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// What the endpoint reports to its caller.
#[non_exhaustive]
pub enum EndpointEvent {
    /// The handshake finished; application data may now be sent, and SRTP keys can be exported.
    HandshakeComplete,
    /// Decrypted application data arrived.
    ApplicationData(BytesMut),
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and connections-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint {
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,
    transmits: VecDeque<TransportMessage<BytesMut>>,
    connections: HashMap<SocketAddr, DTLSConn>,
    server_config: Option<Arc<HandshakeConfig>>,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(
        local_addr: SocketAddr,
        protocol: TransportProtocol,
        server_config: Option<Arc<HandshakeConfig>>,
    ) -> Self {
        Self {
            local_addr,
            transport_protocol: protocol,
            transmits: VecDeque::new(),
            connections: HashMap::new(),
            server_config,
        }
    }

    /// Replace the server configuration, affecting new incoming associations only
    pub fn set_server_config(&mut self, server_config: Option<Arc<HandshakeConfig>>) {
        self.server_config = server_config;
    }

    /// Get the next packet to transmit
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<TransportMessage<BytesMut>> {
        self.transmits.pop_front()
    }

    /// Get keys of Connections
    pub fn get_connections_keys(&self) -> Keys<'_, SocketAddr, DTLSConn> {
        self.connections.keys()
    }

    /// Get Connection State
    pub fn get_connection_state(&self, remote: SocketAddr) -> Option<&State> {
        if let Some(conn) = self.connections.get(&remote) {
            Some(conn.connection_state())
        } else {
            None
        }
    }

    /// Initiate an Association
    pub fn connect(
        &mut self,
        remote: SocketAddr,
        client_config: Arc<HandshakeConfig>,
        initial_state: Option<State>,
    ) -> Result<()> {
        if remote.port() == 0 {
            return Err(Error::InvalidRemoteAddress(remote));
        }

        if let Vacant(e) = self.connections.entry(remote) {
            let mut conn = DTLSConn::new(client_config, true, initial_state);
            conn.handshake()?;

            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        transport_protocol: self.transport_protocol,
                    },
                    message: payload,
                });
            }

            e.insert(conn);
        }

        Ok(())
    }

    /// Process stop remote
    pub fn stop(&mut self, remote: SocketAddr) -> Option<DTLSConn> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.close();
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        transport_protocol: self.transport_protocol,
                    },
                    message: payload,
                });
            }
        }
        self.connections.remove(&remote)
    }

    /// Process close
    pub fn close(&mut self) -> Result<()> {
        for (remote_addr, conn) in self.connections.iter_mut() {
            conn.close();
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: *remote_addr,
                        ecn: None,
                        transport_protocol: self.transport_protocol,
                    },
                    message: payload,
                });
            }
        }
        self.connections.clear();

        Ok(())
    }

    /// Process an incoming UDP datagram
    pub fn read(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) -> Result<Vec<EndpointEvent>> {
        if let Vacant(e) = self.connections.entry(remote) {
            if let Some(server_config) = &self.server_config {
                let handshake_config = server_config.clone();
                let conn = DTLSConn::new(handshake_config, false, None);
                e.insert(conn);
            } else {
                return Err(Error::NoServerConfig);
            }
        }

        // Handle packet on existing association, if any
        let mut messages = vec![];
        if let Some(conn) = self.connections.get_mut(&remote) {
            let is_handshake_completed_before = conn.is_handshake_completed();
            conn.read(&data)?;
            if !conn.is_handshake_completed() {
                conn.handshake()?;
                // Drain any queued future-epoch packets (e.g. Finished that arrived
                // before ChangeCipherSpec bumped remote_epoch). If draining sets
                // handshake_rx, run handshake() again so the FSM can advance.
                let is_handshake = conn.handle_incoming_queued_packets()?;
                if is_handshake && !conn.is_handshake_completed() {
                    conn.handshake()?;
                }
            }
            if !is_handshake_completed_before && conn.is_handshake_completed() {
                messages.push(EndpointEvent::HandshakeComplete)
            }
            while let Some(message) = conn.incoming_application_data() {
                messages.push(EndpointEvent::ApplicationData(message));
            }
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now,
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn,
                        transport_protocol: self.transport_protocol,
                    },
                    message: payload,
                });
            }
        }

        Ok(messages)
    }

    /// Queues application data for `remote`.
    ///
    /// # Errors
    ///
    /// Fails if there is no association with `remote`, or its handshake has not completed.
    pub fn write(&mut self, remote: SocketAddr, data: &[u8]) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.write(data)?;
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        transport_protocol: self.transport_protocol,
                    },
                    message: payload,
                });
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }

    /// Advances `remote`'s association to `now`, driving handshake retransmissions.
    ///
    /// # Errors
    ///
    /// Fails if the handshake has exhausted its retransmissions.
    pub fn handle_timeout(&mut self, remote: SocketAddr, now: Instant) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            if let Some(current_retransmit_timer) = &conn.current_retransmit_timer
                && now >= *current_retransmit_timer
            {
                if conn.current_retransmit_timer.take().is_some() && !conn.is_handshake_completed()
                {
                    conn.handshake_timeout(now)?;
                }
                while let Some(payload) = conn.outgoing_raw_packet() {
                    self.transmits.push_back(TransportMessage {
                        now,
                        transport: TransportContext {
                            local_addr: self.local_addr,
                            peer_addr: remote,
                            ecn: None,
                            transport_protocol: self.transport_protocol,
                        },
                        message: payload,
                    });
                }
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }

    /// When `remote`'s association next needs [`Self::handle_timeout`].
    pub fn poll_timeout(&self, remote: SocketAddr, eto: &mut Instant) -> Result<()> {
        if let Some(conn) = self.connections.get(&remote) {
            if let Some(current_retransmit_timer) = &conn.current_retransmit_timer
                && *current_retransmit_timer < *eto
            {
                *eto = *current_retransmit_timer;
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuiteId;
    use crate::config::ConfigBuilder;
    use crate::crypto::Certificate;
    use crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom};

    fn client_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 4444))
    }

    fn server_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 4445))
    }

    struct FailingRandom;

    impl RTCRandom for FailingRandom {
        fn fill(&self, _output: &mut [u8]) -> std::result::Result<(), CryptoError> {
            Err(CryptoError::RandomnessFailed)
        }
    }

    struct FailingRandomProvider {
        provider: Arc<dyn RTCCryptoProvider>,
    }

    impl RTCCryptoProvider for FailingRandomProvider {
        fn name(&self) -> &'static str {
            "failing-random"
        }

        fn crypto(&self) -> &dyn RTCCrypto {
            self.provider.crypto()
        }

        fn random(&self) -> &dyn RTCRandom {
            &FailingRandom
        }
    }

    fn config(
        provider: Arc<dyn RTCCryptoProvider>,
        is_client: bool,
        suite: CipherSuiteId,
    ) -> Result<Arc<HandshakeConfig>> {
        let mut builder = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![suite])
            .with_insecure_skip_verify(true);
        let is_psk = matches!(
            suite,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm
                | CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8
                | CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256
        );
        if is_psk {
            builder = builder.with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd, 0xef]))));
            if is_client {
                builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()));
            }
        } else if !is_client {
            builder = builder.with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?]);
        }
        Ok(Arc::new(builder.build(is_client, None)?))
    }

    fn transfer(
        source: &mut Endpoint,
        destination: &mut Endpoint,
        source_addr: SocketAddr,
    ) -> Result<Vec<EndpointEvent>> {
        let mut events = Vec::new();
        while let Some(transmit) = source.poll_transmit() {
            events.extend(destination.read(
                Instant::now(),
                source_addr,
                transmit.transport.ecn,
                transmit.message,
            )?);
        }
        Ok(events)
    }

    fn handshake_and_exchange(
        client_provider: Arc<dyn RTCCryptoProvider>,
        server_provider: Arc<dyn RTCCryptoProvider>,
        suite: CipherSuiteId,
    ) -> Result<()> {
        let client_config = config(client_provider, true, suite)?;
        let server_config = config(server_provider, false, suite)?;
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
        client.connect(server_addr(), client_config, None)?;

        let mut client_complete = false;
        let mut server_complete = false;
        for _ in 0..32 {
            for event in transfer(&mut client, &mut server, client_addr())? {
                server_complete |= matches!(event, EndpointEvent::HandshakeComplete);
            }
            for event in transfer(&mut server, &mut client, server_addr())? {
                client_complete |= matches!(event, EndpointEvent::HandshakeComplete);
            }
            if client_complete && server_complete {
                break;
            }
        }
        assert!(
            client_complete && server_complete,
            "DTLS handshake did not complete"
        );

        client.write(server_addr(), b"provider-backed DTLS")?;
        let transmit = client
            .poll_transmit()
            .expect("application write produces a DTLS record");
        let replay = transmit.message.clone();
        let events = server.read(
            Instant::now(),
            client_addr(),
            transmit.transport.ecn,
            transmit.message,
        )?;
        assert!(events.into_iter().any(|event| matches!(
            event,
            EndpointEvent::ApplicationData(data) if data.as_ref() == b"provider-backed DTLS"
        )));
        assert!(
            server
                .read(Instant::now(), client_addr(), None, replay)?
                .is_empty()
        );
        Ok(())
    }

    #[cfg(feature = "crypto-ring")]
    #[test]
    fn ring_provider_completes_handshake_and_record_exchange() -> Result<()> {
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::RingProvider::new());
        handshake_and_exchange(
            provider.clone(),
            provider,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        )
    }

    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    fn aws_lc_rs_provider_completes_handshake_and_record_exchange() -> Result<()> {
        let provider: Arc<dyn RTCCryptoProvider> =
            Arc::new(crypto::providers::AwsLcRsProvider::new());
        handshake_and_exchange(
            provider.clone(),
            provider,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        )
    }

    #[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    #[test]
    fn ring_and_aws_lc_rs_complete_cross_provider_handshakes() -> Result<()> {
        let ring: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::RingProvider::new());
        let aws: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::AwsLcRsProvider::new());
        for suite in [
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ] {
            handshake_and_exchange(ring.clone(), aws.clone(), suite)?;
            handshake_and_exchange(aws.clone(), ring.clone(), suite)?;
        }
        Ok(())
    }

    #[test]
    fn failing_random_provider_aborts_client_hello_cleanly() -> Result<()> {
        let base = crypto::default_provider().map_err(|error| Error::Crypto(error.to_string()))?;
        let provider: Arc<dyn RTCCryptoProvider> =
            Arc::new(FailingRandomProvider { provider: base });
        let config = config(
            provider,
            true,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        )?;
        let mut endpoint = Endpoint::new(client_addr(), TransportProtocol::UDP, None);

        let result = endpoint.connect(server_addr(), config, None);
        assert!(matches!(result, Err(Error::Crypto(_))));
        Ok(())
    }
}
