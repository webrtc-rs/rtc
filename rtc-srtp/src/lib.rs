#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! SRTP and SRTCP for the Sans-I/O WebRTC stack.
//!
//! The Secure Real-time Transport Protocol ([RFC 3711]) as WebRTC keys it: protection
//! profiles negotiated through DTLS-SRTP ([RFC 5764]), with keying material exported from
//! the DTLS handshake rather than signalled.
//!
//! # Structure
//!
//! * [`context`] — [`Context`](context::Context), the encrypt/decrypt state for one
//!   direction: `encrypt_rtp`/`decrypt_rtp` and the RTCP equivalents, plus the replay
//!   protection and rollover-counter tracking the RFC requires.
//! * [`protection_profile`] — the negotiable profiles (AES-128-CM-SHA1-80,
//!   AEAD-AES-128-GCM, and friends) and their key/salt lengths.
//! * [`config`], [`option`] — how a context is built, including replay-window sizing.
//!
//! Most applications do not depend on this crate directly — the
//! [`rtc`](https://docs.rs/rtc) crate creates the contexts from the DTLS handshake and
//! applies them to media as one layer of the peer-connection pipeline.
//!
//! [RFC 3711]: https://datatracker.ietf.org/doc/html/rfc3711
//! [RFC 5764]: https://datatracker.ietf.org/doc/html/rfc5764

mod cipher;
/// Session configuration: keys, protection profile, and replay-protection options.
pub mod config;
/// The encrypt/decrypt state for one SRTP/SRTCP session.
pub mod context;
mod key_derivation;
/// Per-context options, currently the replay-detector factory.
pub mod option;
/// The DTLS-SRTP protection profiles and their key, salt and tag lengths.
pub mod protection_profile;

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("At most one of the features \"aws-lc-rs\" and \"ring\" can be enabled.");
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("At least one of the features \"aws-lc-rs\" and \"ring\" must be enabled.");
#[cfg(feature = "aws-lc-rs")]
extern crate aws_lc_rs as ring;
