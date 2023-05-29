#![warn(rust_2018_idioms)]
#![allow(dead_code)]

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "marshal")]
pub mod marshal;

pub mod error;
