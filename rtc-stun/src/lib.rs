#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

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

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("At most one of the features \"aws-lc-rs\" and \"ring\" can be enabled.");
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("At least one of the features \"aws-lc-rs\" and \"ring\" must be enabled.");
#[cfg(feature = "aws-lc-rs")]
extern crate aws_lc_rs as ring;
