use crate::config::{ConnectionId, ConnectionIdGenerator, EndpointConfig, ServerConfig};
use crate::conn::DTLSConn;
use crate::Transmit;
use fxhash::FxHashMap;
use rand::rngs::StdRng;
use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and connections-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint {
    rng: StdRng,
    transmits: VecDeque<Transmit>,
    connection_ids: FxHashMap<ConnectionId, ConnectionHandle>,
    local_cid_generator: Box<dyn ConnectionIdGenerator>,
    config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig>>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint<T>")
            .field("rng", &self.rng)
            .field("transmits", &self.transmits)
            .field("connection_ids", &self.connection_ids)
            .field("config", &self.config)
            .field("server_config", &self.server_config)
            .finish()
    }
}

/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> usize {
        x.0
    }
}

/// Event resulting from processing a single datagram
#[allow(clippy::large_enum_variant)] // Not passed around extensively
pub enum DatagramEvent {
    /// The datagram is redirected to its `Connection`
    ConnectionEvent(ConnectionEvent),
    /// The datagram has resulted in starting a new `Connection`
    NewConnection(DTLSConn),
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error("endpoint stopping")]
    EndpointStopping,
    /// The number of active connections on the local endpoint is at the limit
    ///
    /// Try using longer connection IDs.
    #[error("too many connections")]
    TooManyConnections,
    /// The domain name supplied was malformed
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    /// The remote [`SocketAddr`] supplied was malformed
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    /// No default client configuration was set up
    ///
    /// Use `Endpoint::connect_with` to specify a client configuration.
    #[error("no default client config")]
    NoDefaultClientConfig,
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
