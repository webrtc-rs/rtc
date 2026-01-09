#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "ifaces")]
pub mod ifaces;

#[cfg(feature = "marshal")]
pub mod marshal;

#[cfg(feature = "replay")]
pub mod replay_detector;

pub mod error;
pub mod time;
pub(crate) mod transport;
pub mod util;

pub use transport::{
    EcnCodepoint, FiveTuple, FourTuple, TaggedBytesMut, TransportContext, TransportMessage,
    TransportProtocol,
};
