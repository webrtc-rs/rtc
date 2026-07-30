#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! SDP parsing and serialization.
//!
//! The Session Description Protocol ([RFC 8866], superseding [RFC 4566]) as WebRTC uses
//! it: offers and answers, media sections, and the attributes that carry codecs, ICE
//! candidates, DTLS fingerprints and header-extension mappings ([RFC 8285]).
//!
//! # Structure
//!
//! * [`SessionDescription`] — a whole session description: `unmarshal` one from a string,
//!   `marshal` it back, or build one up section by section.
//! * [`MediaDescription`] — one `m=` section, with its attributes, formats and connection
//!   data.
//! * [`extmap`] — `a=extmap` header-extension declarations and the well-known extension
//!   URIs.
//! * [`direction`] — `sendrecv`/`sendonly`/`recvonly`/`inactive`.
//!
//! # Example
//!
//! ```
//! use rtc_sdp::SessionDescription;
//! use std::io::Cursor;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let sdp = "v=0\r\n\
//!            o=- 0 0 IN IP4 127.0.0.1\r\n\
//!            s=-\r\n\
//!            t=0 0\r\n\
//!            m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
//!            a=mid:0\r\n\
//!            a=sendrecv\r\n";
//!
//! let desc = SessionDescription::unmarshal(&mut Cursor::new(sdp))?;
//! for media in &desc.media_descriptions {
//!     assert_eq!(media.media_name.media, "audio");
//!     assert_eq!(media.attribute("mid").flatten(), Some("0"));
//! }
//!
//! // Printing it back yields valid SDP.
//! assert!(desc.marshal().starts_with("v=0"));
//! # Ok(())
//! # }
//! ```
//!
//! This crate is deliberately a *syntax* layer: it parses and prints SDP faithfully and
//! leaves negotiation semantics ([RFC 8829]) to the [`rtc`](https://docs.rs/rtc) crate,
//! which re-exports it as `rtc::sdp`.
//!
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 4566]: https://datatracker.ietf.org/doc/html/rfc4566
//! [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285
//! [RFC 8829]: https://datatracker.ietf.org/doc/html/rfc8829

/// Session and media descriptions — the `v=`/`m=` structure of an SDP document.
pub mod description;
/// Transmission direction (`sendrecv`, `sendonly`, `recvonly`, `inactive`).
pub mod direction;
/// `a=extmap` RTP header-extension declarations and the well-known extension URIs.
pub mod extmap;
/// Parsing helpers plus the codec and connection-role types shared across descriptions.
pub mod util;

pub(crate) mod lexer;

pub use description::{media::MediaDescription, session::SessionDescription};
