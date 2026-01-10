//! Sans-I/O mDNS Connection implementation.
//!
//! This module provides [`Mdns`], a sans-I/O implementation of an mDNS client/server
//! that implements the [`sansio::Protocol`] trait for integration with any I/O framework.
//!
//! # Overview
//!
//! The [`Mdns`] struct handles the mDNS protocol logic without performing any I/O.
//! The caller is responsible for:
//!
//! 1. **Network I/O**: Reading/writing UDP packets to/from 224.0.0.251:5353
//! 2. **Timing**: Calling `handle_timeout()` when `poll_timeout()` expires
//! 3. **Event Processing**: Handling events from `poll_event()`
//!
//! # Client Usage
//!
//! To query for a hostname:
//!
//! ```rust
//! use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
//! use sansio::Protocol;
//! use std::time::Instant;
//!
//! let mut mdns_client = Mdns::new(MdnsConfig::default());
//!
//! // Start a query - this queues a packet to send
//! let query_id = mdns_client.query("printer.local");
//!
//! // Get the packet to send over the network
//! if let Some(packet) = mdns_client.poll_write() {
//!     // Send packet.message to packet.transport.peer_addr via UDP
//!     println!("Send {} bytes to {}", packet.message.len(), packet.transport.peer_addr);
//! }
//!
//! // When a response packet arrives, call handle_read()
//! // Then check poll_event() for QueryAnswered events
//! ```
//!
//! # Server Usage
//!
//! To respond to queries:
//!
//! ```rust
//! use rtc_mdns::{MdnsConfig, Mdns};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! let config = MdnsConfig::default()
//!     .with_local_names(vec!["myserver.local".to_string()])
//!     .with_local_ip(
//!         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
//!     );
//!
//! let mut mdns_client = Mdns::new(config);
//!
//! // When a query packet arrives, call handle_read()
//! // The connection automatically queues responses for configured local_names
//! // Retrieve them with poll_write()
//! ```
//!
//! # Query Lifecycle
//!
//! 1. Call [`Mdns::query()`] with the hostname to resolve
//! 2. Retrieve the query packet from [`poll_write()`](sansio::Protocol::poll_write)
//! 3. Send the packet to the mDNS multicast address
//! 4. When responses arrive, pass them to [`handle_read()`](sansio::Protocol::handle_read)
//! 5. Check [`poll_event()`](sansio::Protocol::poll_event) for [`MdnsEvent::QueryAnswered`]
//! 6. If no answer, call [`handle_timeout()`](sansio::Protocol::handle_timeout) to trigger retries

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};

use crate::config::{DEFAULT_QUERY_INTERVAL, MAX_MESSAGE_RECORDS, MdnsConfig, RESPONSE_TTL};
use crate::message::header::Header;
use crate::message::name::Name;
use crate::message::parser::Parser;
use crate::message::question::Question;
use crate::message::resource::a::AResource;
use crate::message::resource::{Resource, ResourceHeader};
use crate::message::{DNSCLASS_INET, DnsType, Message};
use shared::error::{Error, Result};

/// The mDNS multicast group address (224.0.0.251).
pub const MDNS_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The standard mDNS port (5353).
pub const MDNS_PORT: u16 = 5353;

/// mDNS multicast destination address (224.0.0.251:5353).
///
/// All mDNS queries and responses should be sent to this address.
///
/// # Example
///
/// ```rust
/// use rtc_mdns::MDNS_DEST_ADDR;
///
/// assert_eq!(MDNS_DEST_ADDR.to_string(), "224.0.0.251:5353");
/// ```
pub const MDNS_DEST_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_IPV4), MDNS_PORT);

/// Unique identifier for tracking mDNS queries.
///
/// Each call to [`Mdns::query()`] returns a unique ID that can be used to:
/// - Track which query was answered in [`MdnsEvent::QueryAnswered`]
/// - Cancel a pending query with [`Mdns::cancel_query()`]
/// - Check if a query is still pending with [`Mdns::is_query_pending()`]
pub type QueryId = u64;

/// A pending mDNS query.
///
/// This struct tracks the state of an active query, including when it was
/// started and when the next retry should occur.
#[derive(Debug, Clone)]
pub struct Query {
    /// Unique identifier for this query.
    pub id: QueryId,
    /// The name being queried, with trailing dot (e.g., `"myhost.local."`).
    pub name_with_suffix: String,
    /// When the query was started.
    pub start_time: Instant,
    /// When the next retry should be sent.
    pub next_retry: Instant,
}

/// Events emitted by the mDNS connection.
///
/// Poll for events using [`poll_event()`](sansio::Protocol::poll_event) after
/// calling [`handle_read()`](sansio::Protocol::handle_read) or
/// [`handle_timeout()`](sansio::Protocol::handle_timeout).
///
/// # Example
///
/// ```rust,ignore
/// while let Some(event) = mdns.poll_event() {
///     match event {
///         MdnsEvent::QueryAnswered(query_id, addr) => {
///             println!("Query {} resolved to {}", query_id, addr);
///         }
///         MdnsEvent::QueryTimeout(query_id) => {
///             println!("Query {} timed out", query_id);
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub enum MdnsEvent {
    /// A query was successfully answered.
    ///
    /// Contains the query ID and the resolved IP address.
    /// The query is automatically removed from the pending list.
    QueryAnswered(QueryId, IpAddr),

    /// A query timed out without receiving an answer.
    ///
    /// This event is emitted when [`MdnsConfig::query_timeout`](crate::MdnsConfig::query_timeout)
    /// is set and a query exceeds its timeout duration. The query is automatically
    /// removed from the pending list when this event is emitted.
    ///
    /// To enable query timeouts, configure the connection with
    /// [`MdnsConfig::with_query_timeout`](crate::MdnsConfig::with_query_timeout):
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    /// ```
    QueryTimeout(QueryId),
}

/// Sans-I/O mDNS Connection.
///
/// This implements a sans-I/O mDNS client/server that can:
/// - Send mDNS queries and receive answers
/// - Respond to mDNS questions for configured local names
///
/// # Sans-I/O Pattern
///
/// This struct implements [`sansio::Protocol`], which means it doesn't perform
/// any I/O itself. Instead, the caller is responsible for:
///
/// 1. Calling [`handle_read()`](sansio::Protocol::handle_read) when packets arrive
/// 2. Sending packets from [`poll_write()`](sansio::Protocol::poll_write)
/// 3. Calling [`handle_timeout()`](sansio::Protocol::handle_timeout) on schedule
/// 4. Processing events from [`poll_event()`](sansio::Protocol::poll_event)
///
/// # Example: Complete Event Loop
///
/// ```rust
/// use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
/// use sansio::Protocol;
/// use std::time::{Duration, Instant};
///
/// let mut mdns = Mdns::new(MdnsConfig::default());
///
/// // Start a query
/// let query_id = mdns.query("device.local");
///
/// // Simulate an event loop iteration
/// let now = Instant::now();
///
/// // 1. Send queued packets (would go to network in real code)
/// while let Some(packet) = mdns.poll_write() {
///     println!("Would send {} bytes to {}", packet.message.len(), packet.transport.peer_addr);
/// }
///
/// // 2. Handle timeout if due
/// if let Some(deadline) = mdns.poll_timeout() {
///     if deadline <= now {
///         mdns.handle_timeout(now).ok();
///     }
/// }
///
/// // 3. Process any events
/// while let Some(event) = mdns.poll_event() {
///     match event {
///         MdnsEvent::QueryAnswered(query_id, addr) => {
///             println!("Query {} answered: {}", query_id, addr);
///         }
///         MdnsEvent::QueryTimeout(id) => {
///             println!("Query {} timed out", id);
///         }
///     }
/// }
/// ```
///
/// # Example: Multiple Concurrent Queries
///
/// ```rust
/// use rtc_mdns::{MdnsConfig, Mdns};
/// use sansio::Protocol;
///
/// let mut mdns = Mdns::new(MdnsConfig::default());
///
/// // Start multiple queries - each gets a unique ID
/// let id1 = mdns.query("printer.local");
/// let id2 = mdns.query("server.local");
/// let id3 = mdns.query("nas.local");
///
/// assert_eq!(mdns.pending_query_count(), 3);
/// assert!(mdns.is_query_pending(id1));
/// assert!(mdns.is_query_pending(id2));
/// assert!(mdns.is_query_pending(id3));
///
/// // Cancel one query
/// mdns.cancel_query(id2);
/// assert_eq!(mdns.pending_query_count(), 2);
/// assert!(!mdns.is_query_pending(id2));
/// ```
pub struct Mdns {
    /// MdnsConfiguration
    config: MdnsConfig,

    /// Local names with trailing dots (for matching questions)
    local_names: Vec<String>,

    /// Pending queries
    queries: Vec<Query>,

    /// Next query ID to assign
    next_query_id: QueryId,

    /// Query retry interval
    query_interval: Duration,

    /// Query timeout (None = no automatic timeout)
    query_timeout: Option<Duration>,

    /// Outgoing packet queue
    write_outs: VecDeque<TaggedBytesMut>,

    /// Event queue
    event_outs: VecDeque<MdnsEvent>,

    /// Next timeout for query retries
    next_timeout: Option<Instant>,

    /// Whether the connection is closed
    closed: bool,
}

impl Mdns {
    /// Create a new mDNS connection with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - MdnsConfiguration for the connection
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use std::time::Duration;
    ///
    /// // Client-only configuration
    /// let client = Mdns::new(MdnsConfig::default());
    ///
    /// // Server configuration
    /// use std::net::{IpAddr, Ipv4Addr};
    /// let server = Mdns::new(
    ///     MdnsConfig::default()
    ///         .with_local_names(vec!["myhost.local".to_string()])
    ///         .with_local_ip(
    ///             IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ///         )
    /// );
    /// ```
    pub fn new(config: MdnsConfig) -> Self {
        let local_names = config
            .local_names
            .iter()
            .map(|name| {
                if name.ends_with('.') {
                    name.clone()
                } else {
                    format!("{name}.")
                }
            })
            .collect();

        let query_interval = if config.query_interval == Duration::ZERO {
            DEFAULT_QUERY_INTERVAL
        } else {
            config.query_interval
        };

        let query_timeout = config.query_timeout;

        Self {
            config,
            local_names,
            queries: Vec::new(),
            next_query_id: 1,
            query_interval,
            query_timeout,
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            next_timeout: None,
            closed: false,
        }
    }

    /// Start a new mDNS query for the given name.
    ///
    /// This method queues an mDNS query packet to be sent. The query will be
    /// automatically retried at the configured interval until either:
    /// - An answer is received (emits [`MdnsEvent::QueryAnswered`])
    /// - The query times out (emits [`MdnsEvent::QueryTimeout`] if `query_timeout` is set)
    /// - The query is cancelled with [`cancel_query()`](Self::cancel_query)
    /// - The connection is closed
    ///
    /// # Arguments
    ///
    /// * `name` - The hostname to query (e.g., `"mydevice.local"`)
    ///
    /// # Returns
    ///
    /// A unique [`QueryId`] that can be used to track this query.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    ///
    /// // Start a query
    /// let query_id = mdns.query("printer.local");
    ///
    /// // The query packet is now queued
    /// let packet = mdns.poll_write().expect("query packet should be queued");
    /// assert_eq!(packet.transport.peer_addr.to_string(), "224.0.0.251:5353");
    ///
    /// // Track the query
    /// assert!(mdns.is_query_pending(query_id));
    /// ```
    pub fn query(&mut self, name: &str) -> QueryId {
        let name_with_suffix = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let id = self.next_query_id;
        self.next_query_id += 1;

        let now = Instant::now();
        let query = Query {
            id,
            name_with_suffix: name_with_suffix.clone(),
            start_time: now,
            next_retry: now + self.query_interval, // Schedule first retry after interval
        };
        self.queries.push(query);

        // Send the initial query immediately
        self.send_question(&name_with_suffix, now);

        // Update timeout
        self.update_next_timeout();

        id
    }

    /// Cancel a pending query.
    ///
    /// Removes the query from the pending list. No more retry packets will
    /// be sent and no events will be emitted for this query.
    ///
    /// # Arguments
    ///
    /// * `query_id` - The ID returned by [`query()`](Self::query)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    /// let query_id = mdns.query("device.local");
    ///
    /// assert!(mdns.is_query_pending(query_id));
    /// mdns.cancel_query(query_id);
    /// assert!(!mdns.is_query_pending(query_id));
    /// ```
    pub fn cancel_query(&mut self, query_id: QueryId) {
        self.queries.retain(|q| q.id != query_id);
        self.update_next_timeout();
    }

    /// Check if a query is still pending.
    ///
    /// A query is pending until it is either answered or cancelled.
    ///
    /// # Arguments
    ///
    /// * `query_id` - The ID returned by [`query()`](Self::query)
    ///
    /// # Returns
    ///
    /// `true` if the query is still waiting for an answer, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    /// let query_id = mdns.query("device.local");
    ///
    /// // Query is pending until answered or cancelled
    /// assert!(mdns.is_query_pending(query_id));
    /// ```
    pub fn is_query_pending(&self, query_id: QueryId) -> bool {
        self.queries.iter().any(|q| q.id == query_id)
    }

    /// Get the number of pending queries.
    ///
    /// # Returns
    ///
    /// The count of queries that are still waiting for answers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    /// assert_eq!(mdns.pending_query_count(), 0);
    ///
    /// mdns.query("device1.local");
    /// mdns.query("device2.local");
    /// assert_eq!(mdns.pending_query_count(), 2);
    /// ```
    pub fn pending_query_count(&self) -> usize {
        self.queries.len()
    }

    fn send_question(&mut self, name: &str, now: Instant) {
        let packed_name = match Name::new(name) {
            Ok(pn) => pn,
            Err(err) => {
                log::warn!("Failed to construct mDNS packet: {err}");
                return;
            }
        };

        let raw_query = {
            let mut msg = Message {
                header: Header::default(),
                questions: vec![Question {
                    typ: DnsType::A,
                    class: DNSCLASS_INET,
                    name: packed_name,
                }],
                ..Default::default()
            };

            match msg.pack() {
                Ok(v) => v,
                Err(err) => {
                    log::error!("Failed to construct mDNS packet {err}");
                    return;
                }
            }
        };

        log::trace!("Queuing mDNS query for {name}");
        self.write_outs.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                peer_addr: MDNS_DEST_ADDR,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&raw_query[..]),
        });
    }

    fn send_answer(&mut self, local_ip: IpAddr, name: &str, now: Instant) {
        let packed_name = match Name::new(name) {
            Ok(n) => n,
            Err(err) => {
                log::warn!("Failed to pack name for answer: {err}");
                return;
            }
        };

        let raw_answer = {
            let mut msg = Message {
                header: Header {
                    response: true,
                    authoritative: true,
                    ..Default::default()
                },
                answers: vec![Resource {
                    header: ResourceHeader {
                        typ: DnsType::A,
                        class: DNSCLASS_INET,
                        name: packed_name,
                        ttl: RESPONSE_TTL,
                        ..Default::default()
                    },
                    body: Some(Box::new(AResource {
                        a: match local_ip {
                            IpAddr::V4(ip) => ip.octets(),
                            IpAddr::V6(_) => {
                                log::warn!("Cannot send IPv6 address in A record");
                                return;
                            }
                        },
                    })),
                }],
                ..Default::default()
            };

            match msg.pack() {
                Ok(v) => v,
                Err(err) => {
                    log::error!("Failed to pack answer: {err}");
                    return;
                }
            }
        };

        log::trace!("Queuing mDNS answer for {name} -> {local_ip}");
        self.write_outs.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: SocketAddr::new(local_ip, MDNS_PORT),
                peer_addr: MDNS_DEST_ADDR,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&raw_answer[..]),
        });
    }

    fn process_message(&mut self, msg: &TaggedBytesMut) {
        let mut parser = Parser::default();
        if let Err(err) = parser.start(&msg.message) {
            log::error!("Failed to parse mDNS packet: {err}");
            return;
        }

        let src = msg.transport.peer_addr;

        // Process questions (respond if we have local names)
        self.process_questions(&mut parser, src, msg.now);

        // Process answers (check if they match pending queries)
        self.process_answers(&mut parser, src);
    }

    fn process_questions(&mut self, parser: &mut Parser<'_>, _src: SocketAddr, now: Instant) {
        // Collect names that need answers first to avoid borrow issues
        let mut names_to_answer: Vec<String> = Vec::new();

        for _ in 0..=MAX_MESSAGE_RECORDS {
            let q = match parser.question() {
                Ok(q) => q,
                Err(err) => {
                    if err == Error::ErrSectionDone {
                        break;
                    }
                    log::error!("Failed to parse question: {err}");
                    return;
                }
            };

            // Check if we should answer this question
            for local_name in &self.local_names {
                if *local_name == q.name.data {
                    names_to_answer.push(q.name.data.clone());
                    break;
                }
            }
        }

        // Skip remaining questions
        let _ = parser.skip_all_questions();

        // Now send answers
        if let Some(local_ip) = self.config.local_ip {
            for name in names_to_answer {
                log::trace!(
                    "Found question for local name: {}, responding with {}",
                    name,
                    local_ip
                );
                self.send_answer(local_ip, &name, now);
            }
        } else if !names_to_answer.is_empty() {
            log::warn!("Received questions for local names but no local_addr configured");
        }
    }

    fn process_answers(&mut self, parser: &mut Parser<'_>, src: SocketAddr) {
        for _ in 0..=MAX_MESSAGE_RECORDS {
            let answer = match parser.answer_header() {
                Ok(a) => a,
                Err(err) => {
                    if err != Error::ErrSectionDone {
                        log::warn!("Failed to parse answer: {err}");
                    }
                    return;
                }
            };

            // Only process A and AAAA records
            if answer.typ != DnsType::A && answer.typ != DnsType::Aaaa {
                continue;
            }

            // Check if this answer matches any pending queries
            let mut matched_query_ids = Vec::new();
            for query in &self.queries {
                if query.name_with_suffix == answer.name.data {
                    matched_query_ids.push(query.id);
                }
            }

            // Emit events and remove matched queries
            for query_id in matched_query_ids {
                self.event_outs
                    .push_back(MdnsEvent::QueryAnswered(query_id, src.ip()));
                self.queries.retain(|q| q.id != query_id);
            }
        }
    }

    fn update_next_timeout(&mut self) {
        self.next_timeout = self.queries.iter().map(|q| q.next_retry).min();
    }
}

impl sansio::Protocol<TaggedBytesMut, (), ()> for Mdns {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = MdnsEvent;
    type Error = Error;
    type Time = Instant;

    /// Process an incoming mDNS packet.
    ///
    /// Call this method when a UDP packet is received on the mDNS multicast
    /// address (224.0.0.251:5353).
    ///
    /// The connection will:
    /// - Parse the packet as an mDNS message
    /// - If it contains questions for our `local_names`, queue response packets
    /// - If it contains answers matching pending queries, emit events
    ///
    /// # Arguments
    ///
    /// * `msg` - The received packet with transport context
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrConnectionClosed`] if the connection has been closed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bytes::BytesMut;
    /// use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
    /// use std::time::Instant;
    ///
    /// // When a packet arrives from the network:
    /// let msg = TaggedBytesMut {
    ///     now: Instant::now(),
    ///     transport: TransportContext {
    ///         local_addr: "0.0.0.0:5353".parse().unwrap(),
    ///         peer_addr: src_addr,
    ///         transport_protocol: TransportProtocol::UDP,
    ///         ecn: None,
    ///     },
    ///     message: BytesMut::from(&packet_data[..]),
    /// };
    /// mdns.handle_read(msg)?;
    ///
    /// // Check for events
    /// while let Some(event) = mdns.poll_event() {
    ///     // handle event
    /// }
    /// ```
    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        if self.closed {
            return Err(Error::ErrConnectionClosed);
        }
        self.process_message(&msg);
        self.update_next_timeout();
        Ok(())
    }

    /// mDNS doesn't produce read outputs.
    ///
    /// Answers to queries are delivered via `poll_event()`
    /// as [`MdnsEvent::QueryAnswered`] events instead.
    ///
    /// # Returns
    ///
    /// Always returns `None`.
    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    /// Handle write requests (not used).
    ///
    /// Queries are initiated via the [`query()`](Mdns::query) method instead
    /// of through this interface.
    fn handle_write(&mut self, _msg: ()) -> Result<()> {
        Ok(())
    }

    /// Get the next packet to send.
    ///
    /// Call this method repeatedly until it returns `None` to retrieve all
    /// queued packets. Packets should be sent via UDP to the address specified
    /// in `packet.transport.peer_addr` (typically 224.0.0.251:5353).
    ///
    /// Packets are queued when:
    /// - A query is started with [`query()`](Mdns::query)
    /// - A query retry is triggered by `handle_timeout()`
    /// - A response is generated for a matching question
    ///
    /// # Returns
    ///
    /// The next packet to send, or `None` if the queue is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    /// mdns.query("device.local");
    ///
    /// // Send all queued packets
    /// while let Some(packet) = mdns.poll_write() {
    ///     // socket.send_to(&packet.message, packet.transport.peer_addr).await?;
    ///     println!("Send to {}", packet.transport.peer_addr);
    /// }
    /// ```
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_outs.pop_front()
    }

    /// Handle external events (not used).
    ///
    /// mDNS does not use external events. This method does nothing.
    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    /// Get the next event.
    ///
    /// Call this method repeatedly until it returns `None` to process all
    /// queued events. Events are generated when:
    /// - An mDNS answer matches a pending query ([`MdnsEvent::QueryAnswered`])
    ///
    /// # Returns
    ///
    /// The next event, or `None` if the queue is empty.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// while let Some(event) = mdns.poll_event() {
    ///     match event {
    ///         MdnsEvent::QueryAnswered(query_id, addr) => {
    ///             println!("Query {} resolved to {}", query_id, addr);
    ///         }
    ///         MdnsEvent::QueryTimeout(id) => {
    ///             println!("Query {} timed out", id);
    ///         }
    ///     }
    /// }
    /// ```
    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.event_outs.pop_front()
    }

    /// Handle timeout - retry pending queries.
    ///
    /// Call this method when the deadline from `poll_timeout()`
    /// is reached. This triggers retry logic for pending queries.
    ///
    /// For each query whose retry time has passed, a new query packet will
    /// be queued and can be retrieved with `poll_write()`.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrConnectionClosed`] if the connection has been closed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    /// use std::time::{Duration, Instant};
    ///
    /// let mut mdns = Mdns::new(
    ///     MdnsConfig::default().with_query_interval(Duration::from_millis(100))
    /// );
    /// mdns.query("device.local");
    ///
    /// // Consume initial packet
    /// mdns.poll_write();
    ///
    /// // Simulate time passing
    /// let future = Instant::now() + Duration::from_millis(150);
    /// mdns.handle_timeout(future).unwrap();
    ///
    /// // A retry packet should be queued
    /// assert!(mdns.poll_write().is_some());
    /// ```
    fn handle_timeout(&mut self, now: Self::Time) -> Result<()> {
        if self.closed {
            return Err(Error::ErrConnectionClosed);
        }

        if let Some(next_timeout) = self.next_timeout.as_ref()
            && next_timeout <= &now
        {
            // Check for timed out queries first
            if let Some(timeout_duration) = self.query_timeout {
                let mut timed_out_ids = Vec::new();
                for query in &self.queries {
                    if now.duration_since(query.start_time) >= timeout_duration {
                        timed_out_ids.push(query.id);
                    }
                }

                // Emit timeout events and remove timed out queries
                for query_id in timed_out_ids {
                    log::debug!("Query {} timed out after {:?}", query_id, timeout_duration);
                    self.event_outs.push_back(MdnsEvent::QueryTimeout(query_id));
                    self.queries.retain(|q| q.id != query_id);
                }
            }

            // Retry queries that are due
            let mut names_to_query = Vec::new();
            for query in &mut self.queries {
                if query.next_retry <= now {
                    names_to_query.push(query.name_with_suffix.clone());
                    query.next_retry = now + self.query_interval;
                }
            }

            for name in names_to_query {
                self.send_question(&name, now);
            }

            self.update_next_timeout();
        }
        Ok(())
    }

    /// Get the next timeout deadline.
    ///
    /// Returns the time at which `handle_timeout()` should
    /// be called next. Use this to schedule your event loop's sleep/wait.
    ///
    /// # Returns
    ///
    /// - `Some(instant)` if there are pending queries that need retries
    /// - `None` if there are no pending queries
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    ///
    /// // No queries, no timeout
    /// assert!(mdns.poll_timeout().is_none());
    ///
    /// // Start a query
    /// mdns.query("device.local");
    ///
    /// // Now there's a timeout scheduled
    /// assert!(mdns.poll_timeout().is_some());
    /// ```
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.next_timeout
    }

    /// Close the connection.
    ///
    /// This clears all pending queries and queued packets/events.
    /// After closing, `handle_read()` and
    /// `handle_timeout()` will return
    /// [`Error::ErrConnectionClosed`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(MdnsConfig::default());
    /// mdns.query("device.local");
    ///
    /// assert_eq!(mdns.pending_query_count(), 1);
    ///
    /// mdns.close().unwrap();
    ///
    /// // All state is cleared
    /// assert_eq!(mdns.pending_query_count(), 0);
    /// assert!(mdns.poll_write().is_none());
    /// assert!(mdns.poll_timeout().is_none());
    /// ```
    fn close(&mut self) -> Result<()> {
        self.closed = true;
        self.queries.clear();
        self.write_outs.clear();
        self.event_outs.clear();
        self.next_timeout = None;
        Ok(())
    }
}

#[cfg(test)]
mod mdns_test;
