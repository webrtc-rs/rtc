#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! Shared types and utilities for the Sans-I/O WebRTC stack.
//!
//! This crate holds what every other crate in the [`rtc`](https://docs.rs/rtc) stack needs:
//! the common [`Error`](error::Error) type, the [`Marshal`](marshal::Marshal)/[`Unmarshal`](marshal::Unmarshal)
//! traits that every protocol codec implements, and the transport plumbing that carries
//! bytes between the network and a protocol state machine.
//!
//! # Key types
//!
//! * [`TransportContext`] / [`TransportMessage`] — a datagram plus the 4-tuple and protocol
//!   it arrived on or should be sent on. Every layer in the stack passes these around
//!   instead of touching sockets.
//! * [`marshal`] — [`Marshal`](marshal::Marshal), [`Unmarshal`](marshal::Unmarshal) and
//!   [`MarshalSize`](marshal::MarshalSize), the wire-format traits shared by STUN, RTP,
//!   RTCP, SDP, DTLS and SCTP.
//! * [`error`] — the crate-wide [`Error`](error::Error) enum and `Result` alias, re-exported
//!   by the higher-level crates so callers import from one place.
//! * [`crypto`], [`replay_detector`] — primitives shared by DTLS and SRTP.
//! * [`tcp_framing`] — RFC 4571 length-prefixed framing, for ICE-TCP candidates.
//! * [`ifaces`] — local interface enumeration used during ICE candidate gathering.
//!
//! # Feature flags
//!
//! `crypto`, `ifaces`, `marshal` and `replay` are all enabled by default; each gates the
//! correspondingly named module so that dependents can compile only what they use.
//!
//! # Example
//!
//! Every protocol codec in the stack implements the same three traits, so encoding and decoding
//! look the same whichever layer you are at:
//!
//! ```
//! use bytes::Bytes;
//! use rtc_shared::marshal::{Marshal, MarshalSize, Unmarshal};
//!
//! # fn round_trip<T: Marshal + Unmarshal + PartialEq + std::fmt::Debug>(value: T)
//! # -> Result<(), Box<dyn std::error::Error>> {
//! // Size the buffer, encode into it, then decode the result back.
//! let n = value.marshal_size();
//! let encoded = value.marshal()?;
//! assert_eq!(encoded.len(), n);
//!
//! let mut buf = Bytes::from(encoded.to_vec());
//! assert_eq!(T::unmarshal(&mut buf)?, value);
//! # Ok(())
//! # }
//! ```
//!
//! Most applications do not depend on this crate directly — the [`rtc`](https://docs.rs/rtc)
//! crate re-exports what it needs as `rtc::shared`.

#[cfg(target_family = "windows")]
#[macro_use]
extern crate bitflags;

#[cfg(feature = "ifaces")]
/// Local network interface enumeration, used to gather ICE host candidates.
pub mod ifaces;

#[cfg(feature = "marshal")]
/// The wire-format traits every protocol codec in the stack implements.
pub mod marshal;

#[cfg(feature = "replay")]
/// Replay protection for sequence-numbered packets, as DTLS and SRTP require.
pub mod replay_detector;

/// The crate-wide error type shared by every protocol in the stack.
pub mod error;
/// `serde` helpers for types that have no natural serialized form, such as [`std::time::Instant`].
pub mod serde;
pub mod tcp_framing;
/// Conversions between monotonic, Unix and NTP time.
pub mod time;
pub(crate) mod transport;
/// Small shared helpers: packet demultiplexing predicates and random-string generation.
pub mod util;

pub use transport::{
    EcnCodepoint, FiveTuple, FourTuple, TaggedBytesMut, TransportContext, TransportMessage,
    TransportProtocol,
};
