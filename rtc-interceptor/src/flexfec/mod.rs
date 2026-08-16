//! FlexFEC (internal module).
//!
//! Forward error correction over a **separate repair SSRC**, negotiated by
//! `a=ssrc-group:FEC-FR <primary> <repair>` — structurally the same shape as RTX, and unlike
//! RED/ULPFEC, which multiplexes repair into the media stream's own payload.
//!
//! # Two formats, deliberately kept apart
//!
//! [`draft03`] implements `video/flexfec-03`, which is what browsers negotiate today. RFC 8627
//! states that its payload formats are **not** backward compatible with the earlier drafts, so a
//! draft-03 round trip is evidence about browser interoperability and says nothing about RFC
//! conformance. The two live in separate modules with separate vectors for that reason.
//!
//! # References
//!
//! - [draft-ietf-payload-flexible-fec-scheme-03](https://datatracker.ietf.org/doc/html/draft-ietf-payload-flexible-fec-scheme-03)
//! - [RFC 8627](https://www.rfc-editor.org/rfc/rfc8627) — the published scheme
pub(crate) mod bit_array;
pub(crate) mod coverage;
pub(crate) mod draft03;
