#![warn(rust_2018_idioms)]
#![allow(dead_code)]

/*
#[macro_use]
extern crate lazy_static;
*/
pub mod api;
pub mod peer_connection;
pub mod rtp_transceiver;
pub mod stats;
pub mod transports;

/*pub mod track;

// re-export sub-crates
pub use {data, dtls, ice, interceptor, mdns, media, rtcp, rtp, sctp, sdp, srtp, stun, turn, util};
*/

pub(crate) const UNSPECIFIED_STR: &str = "Unspecified";

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

pub(crate) const SDP_ATTRIBUTE_RID: &str = "rid";
pub(crate) const SDP_ATTRIBUTE_SIMULCAST: &str = "simulcast";
pub(crate) const GENERATED_CERTIFICATE_ORIGIN: &str = "WebRTC";
pub(crate) const SDES_REPAIR_RTP_STREAM_ID_URI: &str =
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
