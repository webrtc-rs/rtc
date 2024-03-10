#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use std::time::Instant;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "marshal")]
pub mod marshal;

#[cfg(feature = "replay")]
pub mod replay_detector;

pub mod error;
pub mod util;

pub use retty::transport::{EcnCodepoint, Protocol, TransportContext};

/// Incoming/outgoing Transmit
pub struct Transmit<T> {
    /// Received/Sent time
    pub now: Instant,
    /// Transport Context
    pub transport: TransportContext,
    /// Payload of the datagram
    pub payload: T,
}
