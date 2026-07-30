//! RTCP report interceptors (internal module).
//!
//! `SenderReportInterceptor` and `ReceiverReportInterceptor` are re-exported from the crate
//! root, where the user-facing documentation and examples live so that rustdoc renders them.
//!
//! # References
//!
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP (Sender/Receiver Reports)
//! - [RFC 3611](https://datatracker.ietf.org/doc/html/rfc3611) - RTCP Extended Reports (XR)
pub(crate) mod receiver;
pub(crate) mod receiver_stream;
pub(crate) mod sender;
pub(crate) mod sender_stream;
