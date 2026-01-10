//! # rtc-mdns
//!
//! A sans-I/O implementation of mDNS (Multicast DNS) for Rust.
//!
//! This crate provides an mDNS client/server that implements the [`sansio::Protocol`] trait,
//! allowing it to be integrated with any I/O framework (tokio, async-std, smol, or synchronous I/O).
//!
//! ## What is mDNS?
//!
//! Multicast DNS (mDNS) is a protocol that allows devices on a local network to discover
//! each other without a central DNS server. It's commonly used for:
//!
//! - Service discovery (finding printers, media servers, etc.)
//! - WebRTC ICE candidate gathering (resolving `.local` hostnames)
//! - Zero-configuration networking (Bonjour, Avahi)
//!
//! ## Sans-I/O Design
//!
//! This crate follows the [sans-I/O](https://sans-io.readthedocs.io/) pattern, which means:
//!
//! - **No runtime dependency**: Works with tokio, async-std, smol, or blocking I/O
//! - **Testable**: Protocol logic can be tested without network I/O
//! - **Predictable**: No hidden threads, timers, or background tasks
//! - **Composable**: Easy to integrate with existing event loops
//!
//! The caller is responsible for:
//! 1. Reading packets from the network and calling `handle_read()`
//! 2. Sending packets returned by `poll_write()`
//! 3. Calling `handle_timeout()` when `poll_timeout()` expires
//! 4. Processing events from `poll_event()`
//!
//! ## Features
//!
//! - **Query Support**: Send mDNS queries and receive answers
//! - **Server Support**: Respond to mDNS questions for configured local names
//! - **Automatic Retries**: Queries are automatically retried at configurable intervals
//! - **Multiple Queries**: Track multiple concurrent queries by ID
//!
//! ## Quick Start
//!
//! ### Client: Query for a hostname
//!
//! ```rust
//! use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
//! use sansio::Protocol;
//! use std::time::{Duration, Instant};
//!
//! // Create an mDNS connection
//! let config = MdnsConfig::default()
//!     .with_query_interval(Duration::from_secs(1));
//! let mut conn = Mdns::new(config);
//!
//! // Start a query - returns a unique ID to track this query
//! let query_id = conn.query("mydevice.local");
//! assert!(conn.is_query_pending(query_id));
//!
//! // Get the packet to send (would be sent via UDP to 224.0.0.251:5353)
//! let packet = conn.poll_write().expect("should have a query packet");
//! assert_eq!(packet.transport.peer_addr.to_string(), "224.0.0.251:5353");
//!
//! // When a response arrives, call handle_read() and check for events
//! // Events will contain QueryAnswered with the resolved address
//! ```
//!
//! ### Server: Respond to queries
//!
//! ```rust
//! use rtc_mdns::{MdnsConfig, Mdns};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! // MdnsConfigure with local names to respond to
//! let config = MdnsConfig::default()
//!     .with_local_names(vec!["myhost.local".to_string()])
//!     .with_local_ip(
//!         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
//!     );
//!
//! let conn = Mdns::new(config);
//!
//! // When queries for "myhost.local" arrive via handle_read(),
//! // the connection will automatically queue response packets
//! // that can be retrieved via poll_write()
//! ```
//!
//! ## Integration with Tokio
//!
//! Here's a complete example showing how to integrate with tokio:
//!
//! ```rust,ignore
//! use bytes::BytesMut;
//! use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent, MDNS_DEST_ADDR};
//! use sansio::Protocol;
//! use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
//! use std::net::SocketAddr;
//! use std::time::{Duration, Instant};
//! use tokio::net::UdpSocket;
//!
//! async fn run_mdns_query(name: &str) -> Option<SocketAddr> {
//!     let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
//!     let socket = UdpSocket::bind(bind_addr).await.unwrap();
//!
//!     let mut conn = Mdns::new(MdnsConfig::default());
//!     let query_id = conn.query(name);
//!
//!     let timeout = Instant::now() + Duration::from_secs(5);
//!     let mut buf = vec![0u8; 1500];
//!
//!     loop {
//!         // Send queued packets
//!         while let Some(pkt) = conn.poll_write() {
//!             socket.send_to(&pkt.message, pkt.transport.peer_addr).await.ok();
//!         }
//!
//!         if Instant::now() >= timeout {
//!             return None; // Query timed out
//!         }
//!
//!         // Wait for packets or timeout
//!         tokio::select! {
//!             Ok((len, src)) = socket.recv_from(&mut buf) => {
//!                 let msg = TaggedBytesMut {
//!                     now: Instant::now(),
//!                     transport: TransportContext {
//!                         local_addr: bind_addr,
//!                         peer_addr: src,
//!                         transport_protocol: TransportProtocol::UDP,
//!                         ecn: None,
//!                     },
//!                     message: BytesMut::from(&buf[..len]),
//!                 };
//!                 conn.handle_read(msg).ok();
//!             }
//!             _ = tokio::time::sleep(Duration::from_millis(100)) => {
//!                 conn.handle_timeout(Instant::now()).ok();
//!             }
//!         }
//!
//!         // Check for answers
//!         while let Some(event) = conn.poll_event() {
//!             if let MdnsEvent::QueryAnswered(id, addr) = event {
//!                 if id == query_id {
//!                     return Some(addr);
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Event Loop Pattern
//!
//! The typical event loop for using this crate:
//!
//! ```text
//! loop {
//!     // 1. Send any queued packets
//!     while let Some(packet) = conn.poll_write() {
//!         socket.send_to(&packet.message, packet.transport.peer_addr);
//!     }
//!
//!     // 2. Wait for network activity or timeout
//!     select! {
//!         packet = socket.recv_from() => {
//!             conn.handle_read(packet);
//!         }
//!         _ = sleep_until(conn.poll_timeout()) => {
//!             conn.handle_timeout(Instant::now());
//!         }
//!     }
//!
//!     // 3. Process events
//!     while let Some(event) = conn.poll_event() {
//!         match event {
//!             MdnsEvent::QueryAnswered(id, addr) => { /* handle answer */ }
//!             MdnsEvent::QueryTimeout(id) => { /* handle timeout */ }
//!         }
//!     }
//! }
//! ```
//!
//! ## Protocol Details
//!
//! - **Multicast Address**: 224.0.0.251:5353 (IPv4)
//! - **Record Types**: Supports A (IPv4) and AAAA (IPv6) queries
//! - **TTL**: Responses use a default TTL of 120 seconds
//! - **Compression**: DNS name compression is supported for efficiency

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub(crate) mod config;
pub(crate) mod message;
pub(crate) mod proto;
pub(crate) mod socket;

pub use config::MdnsConfig;
pub use proto::{MDNS_DEST_ADDR, MDNS_MULTICAST_IPV4, MDNS_PORT, Mdns, MdnsEvent, QueryId};

// Re-export socket utilities for convenience
pub use shared::ifaces;
pub use socket::MulticastSocket;
