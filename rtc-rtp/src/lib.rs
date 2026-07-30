#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! RTP packets, header extensions and packetization.
//!
//! The Real-time Transport Protocol ([RFC 3550]) wire format, plus the pieces WebRTC needs
//! around it: one-byte and two-byte header extensions ([RFC 8285]) and per-codec
//! packetizers that turn encoded frames into RTP payloads.
//!
//! # Structure
//!
//! * [`Packet`] / [`Header`] — the packet and its header: `unmarshal` one off the wire,
//!   `marshal` one back, get and set header extensions by id.
//! * [`packetizer`] — [`Packetizer`](packetizer::Packetizer), which fragments a frame into
//!   MTU-sized payloads, and the per-codec [`Payloader`](packetizer::Payloader)
//!   implementations in [`codec`] (VP8, VP9, H.264, H.265, AV1, Opus, G.711).
//! * [`sequence`] — [`Sequencer`](sequence::Sequencer), for sequence numbers that start at a
//!   random offset as the RFC requires.
//! * [`extension`] — the typed header extensions: audio level ([RFC 6464]), video
//!   orientation, transport-wide CC, and the SDES stream ids used for simulcast.
//!
//! # Example
//!
//! ```
//! use bytes::Bytes;
//! use rtc_rtp::Packet;
//! use shared::marshal::{Marshal, Unmarshal};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // A minimal RTP packet: version 2, payload type 96, one byte of payload.
//! let raw = Bytes::from_static(&[
//!     0x80, 0x60, 0x00, 0x01, // V=2, PT=96, seq=1
//!     0x00, 0x00, 0x00, 0x20, // timestamp
//!     0xDE, 0xAD, 0xBE, 0xEF, // ssrc
//!     0xAA, // payload
//! ]);
//!
//! let mut buf = raw.clone();
//! let packet = Packet::unmarshal(&mut buf)?;
//! assert_eq!(packet.header.payload_type, 96);
//! assert_eq!(packet.header.sequence_number, 1);
//! assert_eq!(packet.header.ssrc, 0xDEAD_BEEF);
//!
//! // Re-encoding reproduces the original bytes.
//! assert_eq!(packet.marshal()?, raw);
//! # Ok(())
//! # }
//! ```
//!
//! Most applications do not depend on this crate directly — the
//! [`rtc`](https://docs.rs/rtc) crate re-exports it as `rtc::rtp`, and an application
//! usually meets these types when reading or writing media on a track.
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
//! [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285
//! [RFC 6464]: https://datatracker.ietf.org/doc/html/rfc6464

/// Per-codec payloaders and depacketizers (VP8, VP9, AV1, H.264, H.265, Opus, G.711).
pub mod codec;
/// The typed RTP header extensions ([RFC 8285]).
///
/// [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285
pub mod extension;
/// The RTP header, its extensions, and the bit masks that encode it.
pub mod header;
/// A whole RTP packet: header plus payload.
pub mod packet;
/// Turning encoded frames into RTP packets, and back again.
pub mod packetizer;
/// Sequence-number generation, starting from a random offset as the RFC requires.
pub mod sequence;

pub use header::Header;
pub use packet::Packet;
