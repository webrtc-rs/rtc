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
        now: Instant,
        remote: SocketAddr,
        client_config: Arc<HandshakeConfig>,
        initial_state: Option<State>,
    ) -> Result<()> {
        if remote.port() == 0 {
            return Err(Error::InvalidRemoteAddress(remote));
        }

        if let Vacant(e) = self.connections.entry(remote) {
            let mut conn = DTLSConn::new(client_config, true, initial_state);
            conn.handshake(now)?;

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

            e.insert(conn);
        }

        Ok(())
    }

    /// Process stop remote
    ///
    /// `now` stamps the close_notify this queues. Like [`Self::connect`], the instant is a
    /// parameter rather than something the endpoint samples: it owns no sockets and reads no
    /// clock.
    pub fn stop(&mut self, now: Instant, remote: SocketAddr) -> Option<DTLSConn> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.close();
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
        self.connections.remove(&remote)
    }

    /// Process close
    ///
    /// `now` stamps the close_notify queued for every live association.
    pub fn close(&mut self, now: Instant) -> Result<()> {
        for (remote_addr, conn) in self.connections.iter_mut() {
            conn.close();
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(TransportMessage {
                    now,
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
                conn.handshake(now)?;
                // Drain any queued future-epoch packets (e.g. Finished that arrived
                // before ChangeCipherSpec bumped remote_epoch). If draining sets
                // handshake_rx, run handshake() again so the FSM can advance.
                let is_handshake = conn.handle_incoming_queued_packets()?;
                if is_handshake && !conn.is_handshake_completed() {
                    conn.handshake(now)?;
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
    pub fn write(&mut self, now: Instant, remote: SocketAddr, data: &[u8]) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.write(data)?;
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
    pub fn poll_timeout(&self, remote: &SocketAddr) -> Option<Instant> {
        if let Some(conn) = self.connections.get(remote) {
            conn.current_retransmit_timer
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuiteId;
    use crate::config::{ClientAuthType, ConfigBuilder, ExtendedMasterSecretType};
    use crate::crypto::Certificate;
    use crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom};
    use std::time::Duration;

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

    /// Builds a config offering `suites`, with whichever credentials they need — pass both
    /// families to get a server holding a psk callback and certificates both.
    fn config(
        provider: Arc<dyn RTCCryptoProvider>,
        is_client: bool,
        suites: &[CipherSuiteId],
    ) -> Result<Arc<HandshakeConfig>> {
        let mut builder = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(suites.to_vec())
            .with_insecure_skip_verify(true);
        let is_psk = |suite: &CipherSuiteId| {
            matches!(
                suite,
                CipherSuiteId::Tls_Psk_With_Aes_128_Ccm
                    | CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8
                    | CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256
            )
        };
        if suites.iter().any(is_psk) {
            builder = builder.with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd, 0xef]))));
            if is_client {
                builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()));
            }
        }
        if !is_client && suites.iter().any(|suite| !is_psk(suite)) {
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
        client_suite: CipherSuiteId,
        server_suites: &[CipherSuiteId],
    ) -> Result<()> {
        let server_config = config(server_provider, false, server_suites)?;
        let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
        exchange_with_server(&mut server, client_provider, client_addr(), client_suite)
    }

    /// Drives one client through a handshake and a record exchange against an existing server,
    /// so several clients can be served by the one endpoint and configuration.
    fn exchange_with_server(
        server: &mut Endpoint,
        client_provider: Arc<dyn RTCCryptoProvider>,
        client_addr: SocketAddr,
        client_suite: CipherSuiteId,
    ) -> Result<()> {
        let client_config = config(client_provider, true, &[client_suite])?;
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        client.connect(Instant::now(), server_addr(), client_config, None)?;

        let mut client_complete = false;
        let mut server_complete = false;
        for _ in 0..32 {
            for event in transfer(&mut client, server, client_addr)? {
                server_complete |= matches!(event, EndpointEvent::HandshakeComplete);
            }
            for event in transfer(server, &mut client, server_addr())? {
                client_complete |= matches!(event, EndpointEvent::HandshakeComplete);
            }
            if client_complete && server_complete {
                break;
            }
        }
        assert!(
            client_complete && server_complete,
            "DTLS handshake did not complete for a {client_suite:?} client"
        );

        client.write(Instant::now(), server_addr(), b"provider-backed DTLS")?;
        let transmit = client
            .poll_transmit()
            .expect("application write produces a DTLS record");
        let replay = transmit.message.clone();
        let events = server.read(
            Instant::now(),
            client_addr,
            transmit.transport.ecn,
            transmit.message,
        )?;
        assert!(events.into_iter().any(|event| matches!(
            event,
            EndpointEvent::ApplicationData(data) if data.as_ref() == b"provider-backed DTLS"
        )));
        assert!(
            server
                .read(Instant::now(), client_addr, None, replay)?
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
            &[CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
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
            &[CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
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
            handshake_and_exchange(ring.clone(), aws.clone(), suite, &[suite])?;
            handshake_and_exchange(aws.clone(), ring.clone(), suite, &[suite])?;
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
            &[CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
        )?;
        let mut endpoint = Endpoint::new(client_addr(), TransportProtocol::UDP, None);

        let result = endpoint.connect(Instant::now(), server_addr(), config, None);
        assert!(matches!(result, Err(Error::Crypto(_))));
        Ok(())
    }

    #[cfg(feature = "crypto-ring")]
    #[test]
    fn one_server_config_serves_psk_and_certificate_clients() -> Result<()> {
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::RingProvider::new());
        let certificate_and_psk_suites = [
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ];

        let server_config = config(provider.clone(), false, &certificate_and_psk_suites)?;
        let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));

        for (index, client_suite) in certificate_and_psk_suites.into_iter().enumerate() {
            let client_addr = SocketAddr::from(([127, 0, 0, 1], 4446 + index as u16));
            exchange_with_server(&mut server, provider.clone(), client_addr, client_suite)?;
        }

        Ok(())
    }

    /// Options for [`configured`], beyond what [`config`] covers.
    #[derive(Clone, Copy)]
    struct Options {
        mtu: usize,
        chain_len: usize,
        client_certificate: bool,
        extended_master_secret: ExtendedMasterSecretType,
    }

    impl Default for Options {
        fn default() -> Self {
            Options {
                mtu: 1200,
                chain_len: 1,
                client_certificate: false,
                extended_master_secret: ExtendedMasterSecretType::Request,
            }
        }
    }

    /// Like [`config`], with a chosen MTU, a server certificate chain of `chain_len` copies
    /// (so the Certificate message can be made to fragment), optional mutual authentication,
    /// and an extended-master-secret policy.
    fn configured(
        provider: Arc<dyn RTCCryptoProvider>,
        is_client: bool,
        suite: CipherSuiteId,
        options: Options,
    ) -> Result<Arc<HandshakeConfig>> {
        let is_psk = matches!(
            suite,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm
                | CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8
                | CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256
        );
        let mut builder = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![suite])
            .with_insecure_skip_verify(true)
            .with_mtu(options.mtu)
            .with_extended_master_secret(options.extended_master_secret);
        if is_psk {
            builder = builder.with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd, 0xef]))));
            if is_client {
                builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()));
            }
        } else if !is_client || options.client_certificate {
            let mut certificate =
                Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
            let der = certificate.certificate[0].clone();
            certificate
                .certificate
                .extend(std::iter::repeat_n(der, options.chain_len - 1));
            builder = builder.with_certificates(vec![certificate]);
        }
        if !is_client && options.client_certificate {
            builder = builder.with_client_auth(ClientAuthType::RequireAnyClientCert);
        }
        Ok(Arc::new(builder.build(is_client, None)?))
    }

    /// Delivers everything `source` has queued one record at a time, in reverse order: later
    /// messages of a flight before earlier ones, fragments last to first, Finished before
    /// ChangeCipherSpec.
    fn transfer_reversed(
        source: &mut Endpoint,
        destination: &mut Endpoint,
        source_addr: SocketAddr,
    ) -> Result<Vec<EndpointEvent>> {
        let mut records = Vec::new();
        while let Some(transmit) = source.poll_transmit() {
            records.extend(
                crate::record_layer::unpack_datagram(&transmit.message)?.map(BytesMut::from),
            );
        }
        let mut events = Vec::new();
        for record in records.into_iter().rev() {
            events.extend(destination.read(Instant::now(), source_addr, None, record)?);
        }
        Ok(events)
    }

    fn completes(events: &[EndpointEvent]) -> bool {
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
    }

    /// Runs the handshake to completion, optionally reversing every flight.
    fn run_handshake(
        client: &mut Endpoint,
        server: &mut Endpoint,
        client_addr: SocketAddr,
        reverse_flights: bool,
    ) -> Result<()> {
        let (mut client_complete, mut server_complete) = (false, false);
        for _ in 0..32 {
            server_complete |= completes(&if reverse_flights {
                transfer_reversed(client, server, client_addr)?
            } else {
                transfer(client, server, client_addr)?
            });
            client_complete |= completes(&if reverse_flights {
                transfer_reversed(server, client, server_addr())?
            } else {
                transfer(server, client, server_addr())?
            });
            if client_complete && server_complete {
                return Ok(());
            }
        }
        panic!("handshake did not complete (client {client_complete}, server {server_complete})");
    }

    fn application_data(events: Vec<EndpointEvent>) -> Vec<BytesMut> {
        events
            .into_iter()
            .filter_map(|event| match event {
                EndpointEvent::ApplicationData(data) => Some(data),
                _ => None,
            })
            .collect()
    }

    /// Sends application data both ways, alone and packed two records to a datagram.
    fn exchange_application_data(
        client: &mut Endpoint,
        server: &mut Endpoint,
        client_addr: SocketAddr,
    ) -> Result<()> {
        send_application_data(client, server, client_addr, server_addr())?;
        send_application_data(server, client, server_addr(), client_addr)
    }

    fn send_application_data(
        source: &mut Endpoint,
        destination: &mut Endpoint,
        source_addr: SocketAddr,
        destination_addr: SocketAddr,
    ) -> Result<()> {
        for size in [0usize, 1, 16, 1200] {
            let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
            source.write(Instant::now(), destination_addr, &payload)?;
            let received = application_data(transfer(source, destination, source_addr)?);
            assert_eq!(received.len(), 1);
            assert_eq!(&received[0][..], &payload[..]);
        }

        let mut packed = BytesMut::new();
        for payload in [&b"first"[..], &[7u8; 1000][..]] {
            source.write(Instant::now(), destination_addr, payload)?;
            packed.extend_from_slice(&source.poll_transmit().expect("a record").message);
        }
        let received =
            application_data(destination.read(Instant::now(), source_addr, None, packed)?);
        assert_eq!(received.len(), 2);
        assert_eq!(&received[0][..], b"first");
        assert_eq!(&received[1][..], &[7u8; 1000][..]);
        Ok(())
    }

    const ALL_SUITES: [CipherSuiteId; 8] = [
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
    ];

    /// Out-of-order delivery of every flight, one record per datagram: a fragmented
    /// certificate chain arrives last fragment first, later messages ahead of earlier ones,
    /// and each Finished ahead of its ChangeCipherSpec. The server also sees its peer's
    /// ChangeCipherSpec before it has the keys. Queued records are drained once the keys are
    /// installed and the epoch advances.
    #[test]
    fn handshake_survives_reordered_and_fragmented_flights() -> Result<()> {
        let provider =
            crypto::default_provider().map_err(|error| Error::Crypto(error.to_string()))?;
        let options = Options {
            mtu: 256,
            chain_len: 4,
            ..Options::default()
        };
        for suite in ALL_SUITES {
            let server_config = configured(provider.clone(), false, suite, options)?;
            let mut server =
                Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
            let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
            client.connect(
                Instant::now(),
                server_addr(),
                configured(provider.clone(), true, suite, options)?,
                None,
            )?;

            run_handshake(&mut client, &mut server, client_addr(), true)?;
            exchange_application_data(&mut client, &mut server, client_addr())?;
        }
        Ok(())
    }

    /// Mutual authentication (CertificateVerify over the cached transcript) with and without the
    /// extended master secret (session hash over the cached transcript).
    #[test]
    fn handshake_with_client_certificate_and_ems_policies() -> Result<()> {
        let provider =
            crypto::default_provider().map_err(|error| Error::Crypto(error.to_string()))?;
        for extended_master_secret in [
            ExtendedMasterSecretType::Require,
            ExtendedMasterSecretType::Disable,
        ] {
            let options = Options {
                client_certificate: true,
                extended_master_secret,
                ..Options::default()
            };
            let suite = CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256;
            let server_config = configured(provider.clone(), false, suite, options)?;
            let mut server =
                Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
            let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
            client.connect(
                Instant::now(),
                server_addr(),
                configured(provider.clone(), true, suite, options)?,
                None,
            )?;

            run_handshake(&mut client, &mut server, client_addr(), false)?;
            assert!(
                !server
                    .get_connection_state(client_addr())
                    .expect("server association")
                    .peer_certificates
                    .is_empty()
            );
            exchange_application_data(&mut client, &mut server, client_addr())?;
        }
        Ok(())
    }

    /// Lost flights recovered by retransmission: the server's certificate flight is lost once
    /// and resent on its timer; then the server's final flight is held back until the client
    /// has retransmitted its own final flight, which the completed server must absorb.
    #[test]
    fn handshake_recovers_lost_flights_and_final_flight_retransmission() -> Result<()> {
        let provider =
            crypto::default_provider().map_err(|error| Error::Crypto(error.to_string()))?;
        let suite = CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256;
        let options = Options {
            mtu: 256,
            chain_len: 4,
            ..Options::default()
        };
        let server_config = configured(provider.clone(), false, suite, options)?;
        let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let start = Instant::now();
        client.connect(
            start,
            server_addr(),
            configured(provider.clone(), true, suite, options)?,
            None,
        )?;

        transfer(&mut client, &mut server, client_addr())?; // ClientHello
        transfer(&mut server, &mut client, server_addr())?; // HelloVerifyRequest
        transfer(&mut client, &mut server, client_addr())?; // ClientHello with cookie
        while server.poll_transmit().is_some() {} // flight 4 lost
        server.handle_timeout(client_addr(), start + Duration::from_secs(60))?;
        transfer(&mut server, &mut client, server_addr())?; // flight 4 again

        // Flight 5 reaches the server, which completes; its flight 6 is held back.
        assert!(completes(&transfer(
            &mut client,
            &mut server,
            client_addr()
        )?));
        let mut flight6 = Vec::new();
        while let Some(transmit) = server.poll_transmit() {
            flight6.push(transmit.message);
        }
        assert!(!flight6.is_empty());

        // The client retransmits flight 5; the completed server discards it quietly.
        client.handle_timeout(server_addr(), start + Duration::from_secs(120))?;
        let events = transfer(&mut client, &mut server, client_addr())?;
        assert!(application_data(events).is_empty());

        let mut client_complete = false;
        for datagram in flight6 {
            client_complete |=
                completes(&client.read(Instant::now(), server_addr(), None, datagram)?);
        }
        assert!(client_complete);
        exchange_application_data(&mut client, &mut server, client_addr())?;
        Ok(())
    }
}
