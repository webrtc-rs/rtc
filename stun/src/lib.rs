#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use bytes::BytesMut;
use retty::transport::EcnCodepoint;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

pub mod addr;
pub mod agent;
pub mod attributes;
pub mod checks;
pub mod client;
pub mod error_code;
pub mod fingerprint;
pub mod integrity;
pub mod message;
pub mod textattrs;
pub mod uattrs;
pub mod uri;
pub mod xoraddr;

// IANA assigned ports for "stun" protocol.
pub const DEFAULT_PORT: u16 = 3478;
pub const DEFAULT_TLS_PORT: u16 = 5349;

/// Incoming/outgoing Transmit
#[derive(Debug)]
pub struct Transmit {
    /// Received/Sent time
    pub now: Instant,
    /// The socket this datagram should be sent to
    pub remote: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Optional local IP address for the datagram
    pub local_ip: Option<IpAddr>,
    /// Payload of the datagram
    pub payload: BytesMut,
}
