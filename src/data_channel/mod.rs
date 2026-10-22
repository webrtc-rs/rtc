//! Peer-to-peer Data API
//!
//! This module implements the RTCDataChannel interface as defined in the
//! [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#rtcdatachannel).
//!
//! Data channels enable peer-to-peer exchange of arbitrary application data with low latency
//! and optional reliability. They are useful for scenarios like gaming, real-time text chat,
//! file transfer, and other applications that benefit from low-latency communication.
//!
//! # Examples
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::data_channel::RTCDataChannelInit;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! let init = RTCDataChannelInit {
//!     ordered: true,
//!     max_retransmits: Some(3),
//!     ..Default::default()
//! };
//!
//! // Create a data channel with label "my-channel"
//! let dc = pc.create_data_channel("my-channel", Some(init))?;
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! * [W3C WebRTC - RTCDataChannel](https://www.w3.org/TR/webrtc/#rtcdatachannel)
//! * [RFC 8831 - WebRTC Data Channels](https://datatracker.ietf.org/doc/html/rfc8831)
//! * [RFC 8832 - WebRTC Data Channel Establishment Protocol](https://datatracker.ietf.org/doc/html/rfc8832)

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use bytes::BytesMut;
use sansio::Protocol;
use shared::error::{Error, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

pub(crate) mod init;
pub(crate) mod internal;
pub(crate) mod message;
pub(crate) mod parameters;
pub(crate) mod registry;
pub(crate) mod state;

/// Handle identifying a data channel within a particular peer connection.
///
/// This is a connection-local handle, not the SCTP stream identifier the channel occupies on
/// the wire — for that, see [`RTCDataChannel::stream_id`]. It is assigned when the channel is
/// created, is stable for the channel's lifetime, and is never reused by a later channel.
///
/// The two are separate because they become known at different times. RFC 8832 §6 makes the
/// parity of a stream identifier depend on the DTLS role — even for the client, odd for the
/// server — and that role is not resolved until a remote description has been applied. A
/// channel created before then has no stream id yet, but the application still needs a way to
/// name it: to hold on to it, to match it against events, and to pass to
/// [`RTCPeerConnection::data_channel`]. That is this handle.
///
/// It is a `usize`, like [`RTCRtpTransceiverId`], both to match the crate's convention for
/// connection-local handles and so that it cannot be silently confused with a
/// [`sctp::StreamId`], which is a `u16`.
///
/// [`RTCPeerConnection::data_channel`]: crate::peer_connection::RTCPeerConnection::data_channel
/// [`RTCRtpTransceiverId`]: crate::rtp_transceiver::RTCRtpTransceiverId
pub type RTCDataChannelId = usize;

/// The SCTP stream identifier a data channel occupies on the wire.
///
/// Re-exported next to [`RTCDataChannelId`] because the two are easy to confuse and the
/// distinction matters: this is the RFC 8832 §6 wire value, that is a connection-local handle.
/// See [`RTCDataChannel::stream_id`].
pub use sctp::StreamId;

pub use init::RTCDataChannelInit;

pub use message::RTCDataChannelMessage;

pub use state::RTCDataChannelState;

/// A lock-free view of one channel's [`outstanding_bytes`](RTCDataChannel::outstanding_bytes).
///
/// Cloning is cheap and every clone observes the same counter. The core is the only writer, so
/// a reader sees a value the core really held at some point, never a torn one.
#[derive(Clone, Debug, Default)]
pub struct OutstandingBytes(Arc<AtomicUsize>);

impl OutstandingBytes {
    /// The bytes handed to `send`/`send_text` that SCTP has not yet released.
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    /// Whether the channel this handle was taken from has been removed from its peer
    /// connection.
    ///
    /// The core holds the only other reference, so once it drops the channel this handle is the
    /// last one standing. A driver that caches a handle uses this to keep reporting a closed
    /// channel as closed rather than serving its final value forever. It assumes the caller
    /// holds exactly one clone.
    pub fn is_detached(&self) -> bool {
        Arc::strong_count(&self.0) == 1
    }

    pub(crate) fn add(&self, n: usize) {
        self.0.fetch_add(n, Ordering::AcqRel);
    }

    pub(crate) fn release(&self, n: usize) {
        // Saturating subtraction, so a stray release can never wrap the counter around. A plain
        // compare-exchange loop rather than `fetch_update`, which newer toolchains deprecate in
        // favour of a method the MSRV does not have.
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            match self.0.compare_exchange_weak(
                current,
                current.saturating_sub(n),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Represents a WebRTC data channel for bidirectional peer-to-peer data transfer.
///
/// The `RTCDataChannel` interface represents a network channel which can be used for
/// bidirectional peer-to-peer transfers of arbitrary data. Each data channel is associated
/// with an [`RTCPeerConnection`] and provides configurable delivery semantics including
/// ordered/unordered delivery and reliable/unreliable transport.
///
/// # Specification
///
/// * [W3C WebRTC - RTCDataChannel](https://www.w3.org/TR/webrtc/#dom-rtcdatachannel)
/// * [MDN - RTCDataChannel](https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel)
pub struct RTCDataChannel<'a> {
    pub(crate) id: RTCDataChannelId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCDataChannel<'_> {
    /// The label distinguishing this DataChannel from others on the same peer connection.
    ///
    /// Labels are not required to be unique: an application may create several channels with
    /// the same label.
    pub fn label(&self) -> &str {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .label
            .as_str()
    }

    /// Whether the DataChannel delivers messages in order.
    ///
    /// `false` means out-of-order delivery is allowed.
    pub fn ordered(&self) -> bool {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .ordered
    }

    /// The length of the time window, in milliseconds, during which transmissions and
    /// retransmissions may occur in unreliable mode, or `None` if the channel is reliable.
    pub fn max_packet_life_time(&self) -> Option<u16> {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .max_packet_life_time
    }

    /// The maximum number of retransmissions attempted in unreliable mode, or `None` if the
    /// channel is reliable.
    pub fn max_retransmits(&self) -> Option<u16> {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .max_retransmits
    }

    /// The name of the sub-protocol used with this DataChannel, or the empty string if none
    /// was negotiated.
    pub fn protocol(&self) -> &str {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .protocol
            .as_str()
    }

    /// Whether this DataChannel was negotiated out-of-band by the application (`true`), or
    /// established in-band over DCEP (`false`).
    pub fn negotiated(&self) -> bool {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .negotiated
    }

    /// The handle identifying this DataChannel within its peer connection.
    ///
    /// Available immediately, stable for the channel's lifetime, and never reused by a later
    /// channel. Use it to address this channel — pass it to
    /// [`RTCPeerConnection::data_channel`], or match it against the id carried by an
    /// [`RTCDataChannelEvent`].
    ///
    /// This is **not** the SCTP stream identifier: see [`Self::stream_id`], which is what
    /// W3C's `RTCDataChannel.id` and RFC 8832 §6 refer to.
    ///
    /// [`RTCPeerConnection::data_channel`]: crate::peer_connection::RTCPeerConnection::data_channel
    /// [`RTCDataChannelEvent`]: crate::peer_connection::event::RTCDataChannelEvent
    pub fn id(&self) -> RTCDataChannelId {
        self.id
    }

    /// The SCTP stream identifier carrying this DataChannel, or `None` if one has not been
    /// assigned yet.
    ///
    /// This is W3C's `RTCDataChannel.id`: "The value is initially null, which is what will be
    /// returned if the ID was not provided at channel creation time, and the DTLS role of the
    /// SCTP transport has not yet been negotiated."
    ///
    /// It is `Some` from the outset for a channel negotiated out-of-band (created with
    /// [`RTCDataChannelInit::negotiated`]) and for one opened by the remote peer, since both
    /// already have a stream id. For a channel this endpoint opens in-band it stays `None`
    /// until the SCTP connected procedure assigns one, because RFC 8832 §6 requires an even
    /// identifier from the DTLS client and an odd one from the DTLS server, and which of those
    /// this endpoint is may still be unknown. Once set it does not change.
    pub fn stream_id(&self) -> Option<StreamId> {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .stream_id
    }

    /// The current state of the DataChannel.
    pub fn ready_state(&self) -> RTCDataChannelState {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .ready_state
    }

    /// The threshold at which the buffered amount is considered high.
    ///
    /// When the buffered amount rises from below this threshold to at or above it, the
    /// `BufferedAmountHigh` event fires. It is `u32::MAX` on a new DataChannel — that is,
    /// effectively disabled — and the application may change it at any time with
    /// [`Self::set_buffered_amount_high_threshold`].
    pub fn buffered_amount_high_threshold(&self) -> u32 {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .buffered_amount_high_threshold
    }

    /// Sets the threshold at which the buffered amount is considered high.
    ///
    /// See [`Self::buffered_amount_high_threshold`].
    pub fn set_buffered_amount_high_threshold(&mut self, threshold: u32) {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        let dc = self
            .peer_connection
            .data_channels
            .get_mut(&self.id)
            .unwrap();
        dc.buffered_amount_high_threshold = threshold;
        if let Some(data_channel) = dc.data_channel.as_mut() {
            let _ = data_channel.set_buffered_amount_high_threshold(threshold);
        }
    }

    /// The threshold at which the buffered amount is considered low.
    ///
    /// When the buffered amount falls from above this threshold to at or below it, the
    /// `BufferedAmountLow` event fires. It is `0` on a new DataChannel, and the application
    /// may change it at any time with [`Self::set_buffered_amount_low_threshold`].
    pub fn buffered_amount_low_threshold(&self) -> u32 {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .buffered_amount_low_threshold
    }

    /// Sets the threshold at which the buffered amount is considered low.
    ///
    /// See [`Self::buffered_amount_low_threshold`].
    pub fn set_buffered_amount_low_threshold(&mut self, threshold: u32) {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        let dc = self
            .peer_connection
            .data_channels
            .get_mut(&self.id)
            .unwrap();
        dc.buffered_amount_low_threshold = threshold;
        if let Some(data_channel) = dc.data_channel.as_mut() {
            let _ = data_channel.set_buffered_amount_low_threshold(threshold);
        }
    }

    /// Rejects a send the write path could not carry out.
    ///
    /// The condition mirrors what `DataChannelHandler::handle_write` requires: the channel
    /// must be registered *and* its SCTP stream established. Checking it here, synchronously,
    /// is what makes the failure visible — the handler runs later, on the pipeline's write
    /// pass, where an `Err` is only logged and cannot reach the caller. The same holds for
    /// `SctpHandler::handle_write`'s max-message-size check.
    fn ensure_sendable(&self, data_len: usize) -> Result<()> {
        let dc = self
            .peer_connection
            .data_channels
            .get(&self.id)
            .ok_or(Error::ErrDataChannelClosed)?;

        if dc.data_channel.is_none() {
            // No stream yet: either it is still being negotiated, or it is already gone.
            return Err(if dc.ready_state == RTCDataChannelState::Connecting {
                Error::ErrDataChannelNotOpen
            } else {
                Error::ErrDataChannelClosed
            });
        }

        // W3C `send()`: data larger than `maxMessageSize` throws.
        if let Some(max_message_size) = self.peer_connection.sctp_transport().max_message_size()
            && data_len > max_message_size as usize
        {
            return Err(Error::ErrOutboundPacketTooLarge);
        }

        Ok(())
    }

    /// Sends a binary message to the DataChannel peer.
    ///
    /// # Parameters
    ///
    /// - `now`: The instant the send is issued; it travels with the message through the pipeline.
    /// - `data`: The payload, taken by value so it can be enqueued without a copy.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrDataChannelNotOpen`] if the channel's SCTP stream has not been established
    ///   yet — wait for the channel's open event before sending.
    /// - [`Error::ErrDataChannelClosed`] once the channel is gone.
    /// - [`Error::ErrOutboundPacketTooLarge`] if `data` is larger than the negotiated
    ///   [`max_message_size`](crate::peer_connection::transport::RTCSctpTransport::max_message_size).
    ///
    /// The check is made here, synchronously, rather than deeper in the pipeline where an error
    /// could only be logged. A rejected send never charges [`Self::outstanding_bytes`].
    pub fn send(&mut self, now: Instant, data: BytesMut) -> Result<()> {
        let data_len = data.len();
        self.ensure_sendable(data_len)?;
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::DataChannelMessage(
                self.id,
                RTCDataChannelMessage {
                    is_string: false,
                    data,
                },
            ),
        })?;
        // Count only after a successful enqueue, so a failed send never leaks the
        // counter upward (those bytes never entered the SCTP send pipeline). This
        // is the synchronous send-boundary accounting used for back-pressure.
        if let Some(dc) = self.peer_connection.data_channels.get(&self.id) {
            dc.outstanding_bytes.add(data_len);
        }
        Ok(())
    }

    /// Sends a text message to the DataChannel peer.
    ///
    /// # Errors
    ///
    /// Identical to [`Self::send`].
    pub fn send_text(&mut self, now: Instant, s: impl Into<String>) -> Result<()> {
        let s = s.into();
        self.ensure_sendable(s.len())?;
        let data = BytesMut::from(s.as_str());
        let data_len = data.len();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::DataChannelMessage(
                self.id,
                RTCDataChannelMessage {
                    is_string: true,
                    data,
                },
            ),
        })?;
        if let Some(dc) = self.peer_connection.data_channels.get(&self.id) {
            dc.outstanding_bytes.add(data_len);
        }
        Ok(())
    }

    /// Bytes handed to [`send`](Self::send)/[`send_text`](Self::send_text) that
    /// SCTP has not yet released (acknowledged or abandoned) — the true amount of
    /// outstanding send-side memory for this channel, including bytes still queued
    /// in the app→core→SCTP pipeline (the SCTP stream's own `buffered_amount`
    /// counts only post-packetization). Used for synchronous send back-pressure.
    pub fn outstanding_bytes(&self) -> usize {
        self.peer_connection
            .data_channels
            .get(&self.id)
            .map(|dc| dc.outstanding_bytes.get())
            .unwrap_or(0)
    }

    /// A shared handle onto [`outstanding_bytes`](Self::outstanding_bytes) that can be read
    /// without borrowing the peer connection.
    ///
    /// A sans-I/O core is normally driven behind a lock, and back-pressure wants to be checked
    /// far more often than the core makes progress. The handle lets a driver sample the
    /// counter lock-free, so a sender waiting for room does not contend with the I/O loop
    /// that is trying to make room.
    pub fn outstanding_bytes_handle(&self) -> OutstandingBytes {
        self.peer_connection
            .data_channels
            .get(&self.id)
            .map(|dc| dc.outstanding_bytes.clone())
            .unwrap_or_default()
    }

    /// Closes the data channel.
    ///
    /// Moves the channel to `Closing` and starts the DCEP/SCTP teardown. Closing a channel that
    /// is already `Closed` is a no-op and succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrDataChannelClosed`] if no channel with this id is registered on the
    /// peer connection any more.
    pub fn close(&mut self) -> Result<()> {
        if let Some(dc) = self.peer_connection.data_channels.get_mut(&self.id) {
            if dc.ready_state == RTCDataChannelState::Closed {
                return Ok(());
            }
            dc.ready_state = RTCDataChannelState::Closing;
            dc.close()
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }
}

#[cfg(test)]
mod outstanding_bytes_tests {
    use super::*;

    #[test]
    fn clones_observe_the_same_counter() {
        let owner = OutstandingBytes::default();
        let reader = owner.clone();
        owner.add(100);
        owner.add(28);
        assert_eq!(reader.get(), 128);
        owner.release(28);
        assert_eq!(reader.get(), 100);
    }

    #[test]
    fn release_saturates_at_zero() {
        let counter = OutstandingBytes::default();
        counter.add(10);
        counter.release(25);
        assert_eq!(counter.get(), 0, "an over-release must not wrap");
    }

    #[test]
    fn detached_once_the_core_drops_its_reference() {
        let core_side = OutstandingBytes::default();
        let driver_side = core_side.clone();
        assert!(!driver_side.is_detached());
        drop(core_side);
        assert!(driver_side.is_detached());
        assert_eq!(
            driver_side.get(),
            0,
            "a detached handle keeps its final value"
        );
    }

    #[test]
    fn readers_never_observe_a_torn_value() {
        let owner = OutstandingBytes::default();
        let reader = owner.clone();
        let reading = std::thread::spawn(move || {
            let mut last = 0;
            for _ in 0..200_000 {
                let seen = reader.get();
                assert!(
                    seen % 16 == 0,
                    "saw {seen}, not a multiple of the 16-byte step"
                );
                last = seen;
            }
            last
        });
        for _ in 0..50_000 {
            owner.add(16);
            owner.release(16);
        }
        reading.join().expect("reader thread panicked");
    }
}
