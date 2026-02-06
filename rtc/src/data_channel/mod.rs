//! Peer-to-peer Data API
//!
//! This module implements the RTCDataChannel interface as defined in the
//! [W3C WebRTC specification](https://w3c.github.io/webrtc-pc/#rtcdatachannel).
//!
//! Data channels enable peer-to-peer exchange of arbitrary application data with low latency
//! and optional reliability. They are useful for scenarios like gaming, real-time text chat,
//! file transfer, and other applications that benefit from low-latency communication.
//!
//! # Examples
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::data_channel::RTCDataChannelInit;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build()?;
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
//! # Specifications
//!
//! * [W3C WebRTC - RTCDataChannel](https://w3c.github.io/webrtc-pc/#rtcdatachannel)
//! * [RFC 8831 - WebRTC Data Channels](https://www.rfc-editor.org/rfc/rfc8831.html)
//! * [RFC 8832 - WebRTC Data Channel Establishment Protocol](https://www.rfc-editor.org/rfc/rfc8832.html)

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::RTCMessage;
use bytes::BytesMut;
use interceptor::{Interceptor, NoopInterceptor};
use sansio::Protocol;
use shared::error::{Error, Result};

pub(crate) mod init;
pub(crate) mod internal;
pub(crate) mod message;
pub(crate) mod parameters;
pub(crate) mod state;

/// Identifier for a data channel within a particular peer connection.
///
/// Each data channel has a unique 16-bit identifier within its peer connection.
pub type RTCDataChannelId = u16;

pub use init::RTCDataChannelInit;

pub use message::RTCDataChannelMessage;

pub use state::RTCDataChannelState;

/// Represents a WebRTC data channel for bidirectional peer-to-peer data transfer.
///
/// The `RTCDataChannel` interface represents a network channel which can be used for
/// bidirectional peer-to-peer transfers of arbitrary data. Each data channel is associated
/// with an [`RTCPeerConnection`] and provides configurable delivery semantics including
/// ordered/unordered delivery and reliable/unreliable transport.
///
/// # Specifications
///
/// * [W3C WebRTC - RTCDataChannel](https://w3c.github.io/webrtc-pc/#dom-rtcdatachannel)
/// * [MDN - RTCDataChannel](https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel)
pub struct RTCDataChannel<'a, I = NoopInterceptor>
where
    I: Interceptor,
{
    pub(crate) id: RTCDataChannelId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection<I>,
}

impl<I> RTCDataChannel<'_, I>
where
    I: Interceptor,
{
    /// label represents a label that can be used to distinguish this
    /// DataChannel object from other DataChannel objects. Scripts are
    /// allowed to create multiple DataChannel objects with the same label.
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

    /// Ordered returns true if the DataChannel is ordered, and false if
    /// out-of-order delivery is allowed.
    pub fn ordered(&self) -> bool {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .ordered
    }

    /// max_packet_lifetime represents the length of the time window (msec) during
    /// which transmissions and retransmissions may occur in unreliable mode.
    pub fn max_packet_life_time(&self) -> Option<u16> {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .max_packet_life_time
    }

    /// max_retransmits represents the maximum number of retransmissions that are
    /// attempted in unreliable mode.
    pub fn max_retransmits(&self) -> Option<u16> {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .max_retransmits
    }

    /// protocol represents the name of the sub-protocol used with this
    /// DataChannel.
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

    /// negotiated represents whether this DataChannel was negotiated by the
    /// application (true), or not (false).
    pub fn negotiated(&self) -> bool {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .negotiated
    }

    /// ID represents the ID for this DataChannel. The value is initially
    /// null, which is what will be returned if the ID was not provided at
    /// channel creation time, and the DTLS role of the SCTP transport has not
    /// yet been negotiated. Otherwise, it will return the ID that was either
    /// selected by the script or generated. After the ID is set to a non-null
    /// value, it will not change.
    pub fn id(&self) -> RTCDataChannelId {
        self.id
    }

    /// ready_state represents the state of the DataChannel object.
    pub fn ready_state(&self) -> RTCDataChannelState {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .ready_state
    }

    /// buffered_amount_high_threshold represents the threshold at which the
    /// bufferedAmount is considered to be high. When the bufferedAmount increases
    /// from below this threshold to equal or above it, the BufferedAmountHigh
    /// event fires. buffered_amount_high_threshold is initially u32::MAX on each new
    /// DataChannel, but the application may change its value at any time.
    /// The threshold is set to u32::MAX by default.
    pub fn buffered_amount_high_threshold(&self) -> u32 {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .buffered_amount_high_threshold
    }

    /// set_buffered_amount_high_threshold sets the threshold at which the
    /// bufferedAmount is considered to be high.
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

    /// buffered_amount_low_threshold represents the threshold at which the
    /// bufferedAmount is considered to be low. When the bufferedAmount decreases
    /// from above this threshold to equal or below it, the BufferedAmountLow
    /// event fires. buffered_amount_low_threshold is initially zero on each new
    /// DataChannel, but the application may change its value at any time.
    /// The threshold is set to 0 by default.
    pub fn buffered_amount_low_threshold(&self) -> u32 {
        // peer_connection is mutable borrow, its data_channels won't be resized,
        // so, unwrap() here is safe.
        self.peer_connection
            .data_channels
            .get(&self.id)
            .unwrap()
            .buffered_amount_low_threshold
    }

    /// set_buffered_amount_low_threshold sets the threshold at which the
    /// bufferedAmount is considered to be low.
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

    /// send sends the binary message to the DataChannel peer
    pub fn send(&mut self, data: BytesMut) -> Result<()> {
        if self.peer_connection.data_channels.contains_key(&self.id) {
            self.peer_connection
                .handle_write(RTCMessage::DataChannelMessage(
                    self.id,
                    RTCDataChannelMessage {
                        is_string: false,
                        data,
                    },
                ))
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// send_text sends the text message to the DataChannel peer
    pub fn send_text(&mut self, s: impl Into<String>) -> Result<()> {
        if self.peer_connection.data_channels.contains_key(&self.id) {
            self.peer_connection
                .handle_write(RTCMessage::DataChannelMessage(
                    self.id,
                    RTCDataChannelMessage {
                        is_string: true,
                        data: BytesMut::from(s.into().as_str()),
                    },
                ))
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

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
