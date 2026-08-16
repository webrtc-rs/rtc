//! RFC 8888 congestion control feedback (internal module).
//!
//! Records when each packet of each remote stream arrived, and reports it back to the sender on
//! an interval as an [RFC 8888] `CcFeedbackReport`. The sender's congestion control reads those
//! arrival times to estimate what the path is doing.
//!
//! This is the standardised replacement for `draft-holmer-rmcat-transport-wide-cc`, which browsers
//! ship today as TWCC. Both occupy RTCP packet type 205 and are told apart by FMT — 11 here, 15
//! there — so a peer negotiating one is unaffected by the other.
//!
//! # References
//!
//! - [RFC 8888](https://www.rfc-editor.org/rfc/rfc8888) — RTCP Congestion Control Feedback
//!
//! [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888
pub(crate) mod recorder;
pub(crate) mod sender;
pub(crate) mod stream_log;
