#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use rand::{rng, Rng};

pub mod peer_connection;
//TODO: pub(crate) mod statistics;
pub mod data_channel;
pub mod media;
pub mod transport;

pub(crate) const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub(crate) const UNSPECIFIED_STR: &str = "Unspecified";

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

pub(crate) const SDP_ATTRIBUTE_RID: &str = "rid";
pub(crate) const SDP_ATTRIBUTE_SIMULCAST: &str = "simulcast";
pub(crate) const GENERATED_CERTIFICATE_ORIGIN: &str = "WebRTC";
pub(crate) const MEDIA_SECTION_APPLICATION: &str = "application";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
pub(crate) fn math_rand_alpha(n: usize) -> String {
    let mut rng = rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.random_range(0..RUNES_ALPHA.len());
            RUNES_ALPHA[idx] as char
        })
        .collect();

    rand_string
}
