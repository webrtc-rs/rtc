use crate::config::{ClientConfig, ServerConfig};
use crate::conn::DTLSConn;
use crate::{EcnCodepoint, Transmit};

use shared::error::{Error, Result};

use bytes::BytesMut;
use std::collections::hash_map::Keys;
use std::collections::{hash_map::Entry::Vacant, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

/// Event resulting from processing a single datagram
#[allow(clippy::large_enum_variant)] // Not passed around extensively
pub enum DatagramEvent {
    /// The datagram is redirected to its `Connection`
    ConnectionEvent(ConnectionEvent),
    /// The datagram has resulted in starting a new `Connection`
    NewConnection(DTLSConn),
}

/// Events sent from an Endpoint to an Connection
#[derive(Debug)]
pub struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram(Transmit),
}

/// Events sent from an Connection to an Endpoint
#[derive(Debug)]
pub struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and connections-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint {
    transmits: VecDeque<Transmit>,
    connections: HashMap<SocketAddr, DTLSConn>,
    server_config: Option<Arc<ServerConfig>>,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(server_config: Option<Arc<ServerConfig>>) -> Self {
        Self {
            transmits: VecDeque::new(),
            connections: HashMap::new(),
            server_config,
        }
    }

    /// Get the next packet to transmit
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Replace the server configuration, affecting new incoming associations only
    pub fn set_server_config(&mut self, server_config: Option<Arc<ServerConfig>>) {
        self.server_config = server_config;
    }

    /// Get keys of Connections
    pub fn get_connections_keys(&self) -> Keys<'_, SocketAddr, DTLSConn> {
        self.connections.keys()
    }

    /// Initiate an Association
    pub fn connect(&mut self, config: ClientConfig, remote: SocketAddr) -> Result<()> {
        if remote.port() == 0 {
            return Err(Error::InvalidRemoteAddress(remote));
        }

        if let Vacant(e) = self.connections.entry(remote) {
            let mut conn = DTLSConn::new(config.handshake_config, true, config.initial_state);
            conn.handshake()?;

            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(Transmit {
                    now: Instant::now(),
                    remote,
                    ecn: None,
                    local_ip: None,
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
                    remote,
                    ecn: None,
                    local_ip: None,
                    payload,
                });
            }
        }
        self.connections.remove(&remote)
    }

    /// Process an incoming UDP datagram
    pub fn read(
        &mut self,
        remote: SocketAddr,
        now: Instant,
        local_ip: Option<IpAddr>,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) -> Result<Vec<BytesMut>> {
        if let Vacant(e) = self.connections.entry(remote) {
            let server_config = self.server_config.as_ref().unwrap();
            let handshake_config = server_config.handshake_config.clone();
            let conn = DTLSConn::new(handshake_config, false, None);
            e.insert(conn);
        }

        // Handle packet on existing association, if any
        let mut messages = vec![];
        if let Some(conn) = self.connections.get_mut(&remote) {
            conn.read(&data)?;
            if !conn.is_handshake_completed() {
                conn.handshake()?;
                conn.handle_incoming_queued_packets()?;
            }
            while let Some(message) = conn.incoming_application_data() {
                messages.push(message);
            }
            while let Some(payload) = conn.outgoing_raw_packet() {
                self.transmits.push_back(Transmit {
                    now,
                    remote,
                    ecn,
                    local_ip,
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
                    remote,
                    ecn: None,
                    local_ip: None,
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
                            remote,
                            ecn: None,
                            local_ip: None,
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

    pub fn poll_timeout(&mut self, remote: SocketAddr, eto: &mut Instant) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&remote) {
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
