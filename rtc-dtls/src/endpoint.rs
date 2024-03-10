use crate::conn::DTLSConn;
use shared::error::{Error, Result};
use shared::{EcnCodepoint, TransportContext};
use shared::{Protocol, Transmit};

use crate::config::HandshakeConfig;
use crate::state::State;
use bytes::BytesMut;
use std::collections::hash_map::Keys;
use std::collections::{hash_map::Entry::Vacant, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub enum EndpointEvent {
    HandshakeComplete,
    ApplicationData(BytesMut),
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and connections-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint {
    local_addr: SocketAddr,
    protocol: Protocol,
    transmits: VecDeque<Transmit<BytesMut>>,
    connections: HashMap<SocketAddr, DTLSConn>,
    server_config: Option<Arc<HandshakeConfig>>,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(
        local_addr: SocketAddr,
        protocol: Protocol,
        server_config: Option<Arc<HandshakeConfig>>,
    ) -> Self {
        Self {
            local_addr,
            protocol,
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
    pub fn poll_transmit(&mut self) -> Option<Transmit<BytesMut>> {
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
                self.transmits.push_back(Transmit {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        protocol: self.protocol,
                    },
                    payload,
                });
            }

            e.insert(conn);
        }

        Ok(())
    }

    /// Process close
    pub fn close(&mut self, remote: SocketAddr) -> Option<DTLSConn> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.close();
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(Transmit {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        protocol: self.protocol,
                    },
                    payload,
                });
            }
        }
        self.connections.remove(&remote)
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
                conn.handle_incoming_queued_packets()?;
            }
            if !is_handshake_completed_before && conn.is_handshake_completed() {
                messages.push(EndpointEvent::HandshakeComplete)
            }
            while let Some(message) = conn.incoming_application_data() {
                messages.push(EndpointEvent::ApplicationData(message));
            }
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(Transmit {
                    now,
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn,
                        protocol: self.protocol,
                    },
                    payload,
                });
            }
        }

        Ok(messages)
    }

    pub fn write(&mut self, remote: SocketAddr, data: &[u8]) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.write(data)?;
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(Transmit {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.local_addr,
                        peer_addr: remote,
                        ecn: None,
                        protocol: self.protocol,
                    },
                    payload,
                });
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }

    pub fn handle_timeout(&mut self, remote: SocketAddr, now: Instant) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
            if let Some(current_retransmit_timer) = &conn.current_retransmit_timer {
                if now >= *current_retransmit_timer {
                    if conn.current_retransmit_timer.take().is_some()
                        && !conn.is_handshake_completed()
                    {
                        conn.handshake_timeout(now)?;
                    }
                    while let Some(payload) = conn.outgoing_raw_packet() {
                        self.transmits.push_back(Transmit {
                            now,
                            transport: TransportContext {
                                local_addr: self.local_addr,
                                peer_addr: remote,
                                ecn: None,
                                protocol: self.protocol,
                            },
                            payload,
                        });
                    }
                }
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }

    pub fn poll_timeout(&self, remote: SocketAddr, eto: &mut Instant) -> Result<()> {
        if let Some(conn) = self.connections.get(&remote) {
            if let Some(current_retransmit_timer) = &conn.current_retransmit_timer {
                if *current_retransmit_timer < *eto {
                    *eto = *current_retransmit_timer;
                }
            }
            Ok(())
        } else {
            Err(Error::InvalidRemoteAddress(remote))
        }
    }
}
