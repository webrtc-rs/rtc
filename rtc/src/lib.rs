#![warn(rust_2018_idioms)]
#![allow(dead_code)]

/*
#[macro_use]
extern crate lazy_static;
*/
pub mod api;
pub(crate) mod constants;
pub(crate) mod handlers;
mod messages;
pub mod peer_connection;
pub mod rtp_transceiver;
pub mod stats;
pub mod transports;

/*pub mod track;

// re-export sub-crates
pub use {data, dtls, ice, interceptor, mdns, media, rtcp, rtp, sctp, sdp, srtp, stun, turn, util};
*/
