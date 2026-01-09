//! MdnsConfiguration for mDNS connections.
//!
//! This module provides the [`MdnsConfig`] struct for configuring mDNS client and server behavior.
//!
//! # Examples
//!
//! ## Client MdnsConfiguration
//!
//! For a client that only sends queries:
//!
//! ```rust
//! use rtc_mdns::MdnsConfig;
//! use std::time::Duration;
//!
//! let config = MdnsConfig::default()
//!     .with_query_interval(Duration::from_millis(500)); // Retry every 500ms
//! ```
//!
//! ## Server MdnsConfiguration
//!
//! For a server that responds to queries:
//!
//! ```rust
//! use rtc_mdns::MdnsConfig;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//!
//! let config = MdnsConfig::default()
//!     .with_local_names(vec![
//!         "mydevice.local".to_string(),
//!         "mydevice._http._tcp.local".to_string(),
//!     ])
//!     .with_local_addr(SocketAddr::new(
//!         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
//!         5353,
//!     ));
//! ```
//!
//! ## Combined Client/Server
//!
//! For a connection that both queries and responds:
//!
//! ```rust
//! use rtc_mdns::MdnsConfig;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use std::time::Duration;
//!
//! let config = MdnsConfig::default()
//!     .with_query_interval(Duration::from_secs(1))
//!     .with_local_names(vec!["myhost.local".to_string()])
//!     .with_local_addr(SocketAddr::new(
//!         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
//!         5353,
//!     ));
//! ```

use std::net::SocketAddr;
use std::time::Duration;

/// Default interval between query retries (1 second)
pub(crate) const DEFAULT_QUERY_INTERVAL: Duration = Duration::from_secs(1);

/// Default query timeout (None - queries never timeout automatically)
///
/// Set a timeout using [`MdnsConfig::with_query_timeout`] to have queries
/// automatically emit [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout) events.
pub(crate) const DEFAULT_QUERY_TIMEOUT: Option<Duration> = None;

/// Maximum number of DNS records to process per message section
///
/// This limits processing to prevent excessive CPU usage on malformed packets.
pub(crate) const MAX_MESSAGE_RECORDS: usize = 3;

/// Default TTL (Time To Live) for mDNS response records (120 seconds)
pub(crate) const RESPONSE_TTL: u32 = 120;

/// MdnsConfiguration for an mDNS connection.
///
/// Use the builder pattern to construct a configuration:
///
/// ```rust
/// use rtc_mdns::MdnsConfig;
/// use std::time::Duration;
///
/// let config = MdnsConfig::new()
///     .with_query_interval(Duration::from_millis(500))
///     .with_local_names(vec!["myhost.local".to_string()]);
/// ```
///
/// # Fields
///
/// - `query_interval`: How often to retry unanswered queries (default: 1 second)
/// - `query_timeout`: Maximum time to wait for a query answer (default: None - no timeout)
/// - `local_names`: Names this connection will respond to (empty by default)
/// - `local_addr`: IP address to advertise in responses (required for server mode)
#[derive(Clone, Debug)]
pub struct MdnsConfig {
    /// How often to retry unanswered queries.
    ///
    /// When a query is started, it will be retried at this interval until
    /// either an answer is received or the query is cancelled.
    ///
    /// Default: 1 second
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Retry queries every 500ms for faster discovery
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_millis(500));
    /// ```
    pub query_interval: Duration,

    /// Maximum time to wait for a query to be answered.
    ///
    /// When set, queries that haven't received an answer within this duration
    /// will emit [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout) and
    /// be automatically cancelled.
    ///
    /// When `None`, queries will retry indefinitely until answered or
    /// manually cancelled.
    ///
    /// Default: None (no automatic timeout)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Timeout queries after 5 seconds
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    /// ```
    pub query_timeout: Option<Duration>,

    /// Local names that this connection will respond to.
    ///
    /// When an mDNS query arrives for any of these names, the connection
    /// will automatically generate a response with the configured `local_addr`.
    ///
    /// Names should be in `.local` format (e.g., `"myhost.local"`).
    /// Trailing dots are optional and will be normalized internally.
    ///
    /// Default: empty (no names to respond to)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec![
    ///         "mydevice.local".to_string(),
    ///         "printer.local".to_string(),
    ///     ]);
    /// ```
    pub local_names: Vec<String>,

    /// Local address to advertise in mDNS responses.
    ///
    /// This IP address will be included in A record responses when
    /// queries for `local_names` are received.
    ///
    /// **Required** if `local_names` is non-empty, otherwise responses
    /// cannot be generated.
    ///
    /// Default: None
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec!["myhost.local".to_string()])
    ///     .with_local_addr(SocketAddr::new(
    ///         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
    ///         5353,
    ///     ));
    /// ```
    pub local_addr: Option<SocketAddr>,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            query_interval: DEFAULT_QUERY_INTERVAL,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            local_names: Vec::new(),
            local_addr: None,
        }
    }
}

impl MdnsConfig {
    /// Create a new configuration with default values.
    ///
    /// Equivalent to [`MdnsConfig::default()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the query retry interval.
    ///
    /// Queries will be retried at this interval until answered or cancelled.
    /// A value of zero will use the default interval (1 second).
    ///
    /// # Arguments
    ///
    /// * `interval` - Duration between query retries
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_millis(250));
    /// ```
    pub fn with_query_interval(mut self, interval: Duration) -> Self {
        self.query_interval = interval;
        self
    }

    /// Set the query timeout.
    ///
    /// When set, queries that don't receive an answer within this duration
    /// will emit [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout)
    /// and be automatically removed from the pending list.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration to wait for a query answer
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Queries will timeout after 5 seconds
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    ///
    /// // Combined with retry interval: retry every 500ms, give up after 3s
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_millis(500))
    ///     .with_query_timeout(Duration::from_secs(3));
    /// ```
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = Some(timeout);
        self
    }

    /// Set the local names to respond to.
    ///
    /// When mDNS queries for these names are received, the connection
    /// will automatically generate responses with the configured `local_addr`.
    ///
    /// # Arguments
    ///
    /// * `names` - List of hostnames (e.g., `["myhost.local"]`)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec!["server.local".to_string()]);
    /// ```
    pub fn with_local_names(mut self, names: Vec<String>) -> Self {
        self.local_names = names;
        self
    }

    /// Set the local address to advertise in responses.
    ///
    /// This address will be included in A record responses. The port
    /// is typically 5353 for mDNS.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address containing the IP to advertise
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_addr(SocketAddr::new(
    ///         IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    ///         5353,
    ///     ));
    /// ```
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }
}
