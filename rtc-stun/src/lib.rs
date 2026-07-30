#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! STUN for the Sans-I/O WebRTC stack.
//!
//! Session Traversal Utilities for NAT ([RFC 5389], superseding [RFC 3489]), plus the
//! attributes ICE ([RFC 8445]) and TURN ([RFC 5766]) layer on top. In WebRTC, STUN does
//! double duty: it discovers a peer's server-reflexive address, and its binding
//! request/response exchange *is* the ICE connectivity check.
//!
//! # Structure
//!
//! * [`message`] — [`Message`](message::Message), the STUN message itself: build one from
//!   attributes, marshal it, unmarshal one off the wire.
//! * [`attributes`], [`textattrs`], [`uattrs`], [`xoraddr`], [`error_code`] — the attribute
//!   types, including `XOR-MAPPED-ADDRESS`, `USERNAME`, `REALM` and `ERROR-CODE`.
//! * [`integrity`], [`fingerprint`] — `MESSAGE-INTEGRITY` (HMAC-SHA1) and `FINGERPRINT`
//!   (CRC-32), the two attributes whose values depend on the encoded message.
//! * [`agent`], [`client`] — transaction tracking and a Sans-I/O client for talking to a
//!   STUN server.
//! * [`uri`] — parsing `stun:`/`stuns:` URLs.
//! * [`checks`] — validation helpers for received messages.
//!
//! # Example
//!
//! ```
//! use rtc_stun::attributes::ATTR_SOFTWARE;
//! use rtc_stun::message::{BINDING_REQUEST, Message, TransactionId};
//! use rtc_stun::textattrs::TextAttribute;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut msg = Message::new();
//! msg.build(&[
//!     Box::new(TransactionId::new()),
//!     Box::new(BINDING_REQUEST),
//!     Box::new(TextAttribute::new(ATTR_SOFTWARE, "webrtc-rs".to_owned())),
//! ])?;
//!
//! // `build` encodes as it goes, so `raw` is ready to send.
//! assert!(!msg.raw.is_empty());
//!
//! let mut decoded = Message::new();
//! decoded.raw = msg.raw.clone();
//! decoded.decode()?;
//! assert_eq!(decoded.typ, BINDING_REQUEST);
//! # Ok(())
//! # }
//! ```
//!
//! Most applications do not depend on this crate directly — [`rtc-ice`] and
//! [`rtc-turn`] build on it, and the [`rtc`](https://docs.rs/rtc) crate drives those.
//!
//! [RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389
//! [RFC 3489]: https://datatracker.ietf.org/doc/html/rfc3489
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 5766]: https://datatracker.ietf.org/doc/html/rfc5766
//! [`rtc-ice`]: https://docs.rs/rtc-ice
//! [`rtc-turn`]: https://docs.rs/rtc-turn

#[macro_use]
extern crate lazy_static;

/// Socket-address helpers shared by the address attributes.
pub mod addr;
/// Transaction tracking: which requests are outstanding and when they time out.
pub mod agent;
/// The STUN attribute types and the raw attribute representation.
pub mod attributes;
/// Validation helpers for received messages and attributes.
pub mod checks;
/// A Sans-I/O STUN client for talking to a STUN server.
pub mod client;
/// The `ERROR-CODE` attribute and the codes defined by STUN, TURN and ICE.
pub mod error_code;
/// The `FINGERPRINT` attribute, a CRC-32 over the message.
pub mod fingerprint;
/// The `MESSAGE-INTEGRITY` attribute, an HMAC-SHA1 over the message.
pub mod integrity;
/// The STUN message itself: header, attributes, and encoding.
pub mod message;
/// Text-valued attributes such as `USERNAME`, `REALM` and `SOFTWARE`.
pub mod textattrs;
/// The `UNKNOWN-ATTRIBUTES` attribute, listing attributes a server could not process.
pub mod uattrs;
/// Parsing `stun:` and `stuns:` URIs.
pub mod uri;
/// The `XOR-MAPPED-ADDRESS` attribute, whose value is masked with the magic cookie.
pub mod xoraddr;

/// IANA assigned ports for "stun" protocol.
pub const DEFAULT_PORT: u16 = 3478;
/// The default port for `stuns:` (STUN over TLS/DTLS).
pub const DEFAULT_TLS_PORT: u16 = 5349;

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("At most one of the features \"aws-lc-rs\" and \"ring\" can be enabled.");
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("At least one of the features \"aws-lc-rs\" and \"ring\" must be enabled.");
#[cfg(feature = "aws-lc-rs")]
extern crate aws_lc_rs as ring;
