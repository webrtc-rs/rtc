//! RTP feedback conversion (internal module).
//!
//! Turns the two congestion control feedback formats — `draft-holmer-rmcat-transport-wide-cc`
//! (TWCC) and [RFC 8888] — into one record of what happened to each packet that was sent: when it
//! left here, whether it arrived, and when. That record is what a bandwidth estimator consumes.
//!
//! # No interceptor here
//!
//! This is pure data transformation, fully testable without a chain, and that is deliberate: the
//! estimator uses this module directly rather than through an interceptor, so the two are not
//! coupled through the pipeline.
//!
//! # References
//!
//! - [RFC 8888](https://www.rfc-editor.org/rfc/rfc8888) — RTCP Congestion Control Feedback
//! - [draft-holmer-rmcat-transport-wide-cc-extensions-01](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
//!
//! [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888
pub(crate) mod acknowledgement;
pub(crate) mod convert;
pub(crate) mod history;
