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
//! A wrapping interceptor was considered and **dropped**. It would have had nowhere to put what
//! it learned: the chain is built by moving each layer into the one above, so an interceptor
//! sitting innermost on write — where the send history must be, to record the release instant —
//! is not something the application still holds. Every way of getting the reports back out cost
//! more than the feature was worth: a public accessor on the derive macro widens the API of every
//! interceptor; a shared handle puts the crate's first `Mutex` into a design that has none; and
//! `poll_event` is closed, since `Eout` is `()` for every interceptor and widening it breaks them
//! all. Upstream's equivalent has no importers anywhere, and writes its reports into an
//! `Attributes` map that nothing reads — which is the same conclusion reached a different way.
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
