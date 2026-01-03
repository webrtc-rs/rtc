use crate::error::{Error, Result};
use rand::{Rng, rng};
use std::net::{SocketAddr, ToSocketAddrs};

// match_range is a MatchFunc that accepts packets with the first byte in [lower..upper]
fn match_range(lower: u8, upper: u8) -> impl Fn(&[u8]) -> bool {
    move |buf: &[u8]| -> bool {
        if buf.is_empty() {
            return false;
        }
        let b = buf[0];
        b >= lower && b <= upper
    }
}

/// MatchFuncs as described in RFC7983
/// <https://tools.ietf.org/html/rfc7983>
///              +----------------+
///              |        [0..3] -+--> forward to STUN
///              |                |
///              |      [16..19] -+--> forward to ZRTP
///              |                |
///  packet -->  |      [20..63] -+--> forward to DTLS
///              |                |
///              |      [64..79] -+--> forward to TURN Channel
///              |                |
///              |    [128..191] -+--> forward to RTP/RTCP
///              +----------------+
/// match_dtls is a MatchFunc that accepts packets with the first byte in [20..63]
/// as defied in RFC7983
pub fn match_dtls(b: &[u8]) -> bool {
    match_range(20, 63)(b)
}

// match_srtp_or_srtcp is a MatchFunc that accepts packets with the first byte in [128..191]
// as defied in RFC7983
pub fn match_srtp_or_srtcp(b: &[u8]) -> bool {
    match_range(128, 191)(b)
}

pub fn is_rtcp(buf: &[u8]) -> bool {
    // Not long enough to determine RTP/RTCP
    if buf.len() < 4 {
        return false;
    }

    let rtcp_packet_type = buf[1];
    (192..=223).contains(&rtcp_packet_type)
}

/// match_srtp is a MatchFunc that only matches SRTP and not SRTCP
pub fn match_srtp(buf: &[u8]) -> bool {
    match_srtp_or_srtcp(buf) && !is_rtcp(buf)
}

/// match_srtcp is a MatchFunc that only matches SRTCP and not SRTP
pub fn match_srtcp(buf: &[u8]) -> bool {
    match_srtp_or_srtcp(buf) && is_rtcp(buf)
}

/// lookup host to SocketAddr
pub fn lookup_host<T>(use_ipv4: bool, host: T) -> Result<SocketAddr>
where
    T: ToSocketAddrs,
{
    for remote_addr in host.to_socket_addrs()? {
        if (use_ipv4 && remote_addr.is_ipv4()) || (!use_ipv4 && remote_addr.is_ipv6()) {
            return Ok(remote_addr);
        }
    }

    Err(Error::ErrAddressParseFailed)
}

const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const RUNES_ALPHA_NUMBER: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
pub fn math_rand_alpha(n: usize) -> String {
    generate_crypto_random_string(n, RUNES_ALPHA)
}

/// math_rand_alpha generates a mathematical random alphabet and number sequence of the requested length.
pub fn math_rand_alpha_number(n: usize) -> String {
    generate_crypto_random_string(n, RUNES_ALPHA_NUMBER)
}

//TODO: generates a random string for cryptographic usage.
pub fn generate_crypto_random_string(n: usize, runes: &[u8]) -> String {
    let mut rng = rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.random_range(0..runes.len());
            runes[idx] as char
        })
        .collect();

    rand_string
}
