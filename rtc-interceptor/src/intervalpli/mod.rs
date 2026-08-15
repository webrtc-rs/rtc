//! Interval PLI interceptor (internal module).
//!
//! Asks each bound remote stream for a keyframe on a fixed interval. Useful when bridging to a
//! protocol that has no receiver feedback of its own, so nothing else would ever request one.
//!
//! `IntervalPliInterceptor` is re-exported from the crate root, where the user-facing
//! documentation lives so that rustdoc renders it.
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) §6.3.1 — Picture Loss Indication
pub(crate) mod generator;

use crate::stream_info::StreamInfo;

/// Whether a stream negotiated PLI feedback (`a=rtcp-fb:… nack pli`).
///
/// PLI is carried as the `pli` parameter of `nack`, not a feedback type of its own — so a stream
/// with plain `nack` (retransmission) does not accept PLI, and one with `nack pli` does.
pub(crate) fn stream_supports_pli(info: &StreamInfo) -> bool {
    info.rtcp_feedback
        .iter()
        .any(|fb| fb.typ == "nack" && fb.parameter == "pli")
}
