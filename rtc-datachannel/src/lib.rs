#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! WebRTC data channels over SCTP.
//!
//! The Data Channel Establishment Protocol ([RFC 8832]) and the SCTP-based data channel
//! layer ([RFC 8831]): the `DATA_CHANNEL_OPEN` handshake, the reliability and ordering
//! parameters, and the payload protocol identifiers that distinguish string from binary
//! messages.
//!
//! # Structure
//!
//! * [`data_channel`] — one channel's state and its read/write surface over an SCTP
//!   stream, including partial-reliability settings (`maxPacketLifeTime`,
//!   `maxRetransmits`).
//! * [`message`] — the DCEP messages themselves: `DataChannelOpen`, `DataChannelAck`, and
//!   the channel-type encoding.
//!
//! Most applications do not depend on this crate directly — the
//! [`rtc`](https://docs.rs/rtc) crate layers it over [`rtc-sctp`] and exposes
//! `RTCDataChannel`.
//!
//! [RFC 8832]: https://datatracker.ietf.org/doc/html/rfc8832
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
//! [`rtc-sctp`]: https://docs.rs/rtc-sctp

/// One data channel's state and its read/write surface over an SCTP stream.
pub mod data_channel;
/// The DCEP messages exchanged to open, acknowledge and close a channel.
pub mod message;
