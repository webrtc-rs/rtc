#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "marshal")]
pub mod marshal;

#[cfg(feature = "replay")]
pub mod replay_detector;

pub mod error;
pub mod util;

pub use sansio::{Context, Handler, InboundPipeline, OutboundPipeline, Pipeline, Protocol};

pub use sansio_transport::{
    EcnCodepoint, FiveTuple, FourTuple, TaggedBytesMut, TransportContext, TransportMessage,
    TransportProtocol,
};
