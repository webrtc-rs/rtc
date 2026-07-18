#![warn(rust_2018_idioms)]
#![allow(dead_code)]

mod cipher;
pub mod config;
pub mod context;
mod key_derivation;
pub mod option;
pub mod protection_profile;

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("At most one of the features \"aws-lc-rs\" and \"ring\" can be enabled.");
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("At least one of the features \"aws-lc-rs\" and \"ring\" must be enabled.");
#[cfg(feature = "aws-lc-rs")]
extern crate aws_lc_rs as ring;
