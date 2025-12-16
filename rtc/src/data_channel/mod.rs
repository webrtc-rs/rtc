use crate::data_channel::state::RTCDataChannelState;
use crate::peer_connection::RTCPeerConnection;
use bytes::Bytes;
use shared::error::{Error, Result};

pub(crate) mod event;
pub(crate) mod init;
pub(crate) mod state;

/// Identifier for a data channel within a particular peer connection
pub type RTCDataChannelId = u16;

#[derive(Default, Clone)]
pub enum BinaryType {
    #[default]
    String,
    Blob,
    ArrayBuffer,
}

#[derive(Default, Clone)]
pub(crate) struct RTCDataChannelInternal {
    label: String,
    ordered: bool,
    max_packet_lifetime: Option<u16>,
    max_retransmits: Option<u16>,
    protocol: String,
    negotiated: bool,
    ready_state: RTCDataChannelState,
    buffered_amount_low_threshold: usize,
    binary_type: BinaryType,
}

/// DataChannel represents a WebRTC DataChannel
/// The DataChannel interface represents a network channel
/// which can be used for bidirectional peer-to-peer transfers of arbitrary data
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel
/// [W3C]: https://w3c.github.io/webrtc-pc/#dom-rtcdatachannel
pub struct RTCDataChannel<'a> {
    pub(crate) channel_id: RTCDataChannelId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCDataChannel<'_> {
    /// label represents a label that can be used to distinguish this
    /// DataChannel object from other DataChannel objects. Scripts are
    /// allowed to create multiple DataChannel objects with the same label.
    pub fn label(&self) -> Result<String> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.label.clone())
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// Ordered returns true if the DataChannel is ordered, and false if
    /// out-of-order delivery is allowed.
    pub fn ordered(&self) -> Result<bool> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.ordered)
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// max_packet_lifetime represents the length of the time window (msec) during
    /// which transmissions and retransmissions may occur in unreliable mode.
    pub fn max_packet_lifetime(&self) -> Result<Option<u16>> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.max_packet_lifetime)
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// max_retransmits represents the maximum number of retransmissions that are
    /// attempted in unreliable mode.
    pub fn max_retransmits(&self) -> Result<Option<u16>> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.max_retransmits)
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// protocol represents the name of the sub-protocol used with this
    /// DataChannel.
    pub fn protocol(&self) -> Result<String> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.protocol.clone())
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// negotiated represents whether this DataChannel was negotiated by the
    /// application (true), or not (false).
    pub fn negotiated(&self) -> Result<bool> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.negotiated)
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// ID represents the ID for this DataChannel. The value is initially
    /// null, which is what will be returned if the ID was not provided at
    /// channel creation time, and the DTLS role of the SCTP transport has not
    /// yet been negotiated. Otherwise, it will return the ID that was either
    /// selected by the script or generated. After the ID is set to a non-null
    /// value, it will not change.
    pub fn id(&self) -> RTCDataChannelId {
        self.channel_id
    }

    /// ready_state represents the state of the DataChannel object.
    pub fn ready_state(&self) -> Result<RTCDataChannelState> {
        if let Some(dc) = self
            .peer_connection
            .internal
            .data_channels
            .get(&self.channel_id)
        {
            Ok(dc.ready_state)
        } else {
            Err(Error::ErrDataChannelClosed)
        }
    }

    /// buffered_amount represents the number of bytes of application data
    /// (UTF-8 text and binary data) that have been queued using send(). Even
    /// though the data transmission can occur in parallel, the returned value
    /// MUST NOT be decreased before the current task yielded back to the event
    /// loop to prevent race conditions. The value does not include framing
    /// overhead incurred by the protocol, or buffering done by the operating
    /// system or network hardware. The value of buffered_amount slot will only
    /// increase with each call to the send() method as long as the ready_state is
    /// open; however, buffered_amount does not reset to zero once the channel
    /// closes.
    pub async fn buffered_amount(&self) -> Result<usize> {
        //TODO:
        Ok(0)
    }

    /// buffered_amount_low_threshold represents the threshold at which the
    /// bufferedAmount is considered to be low. When the bufferedAmount decreases
    /// from above this threshold to equal or below it, the bufferedamountlow
    /// event fires. buffered_amount_low_threshold is initially zero on each new
    /// DataChannel, but the application may change its value at any time.
    /// The threshold is set to 0 by default.
    pub async fn buffered_amount_low_threshold(&self) -> Result<usize> {
        //TODO:
        Ok(0)
    }

    /// send sends the binary message to the DataChannel peer
    pub fn send(&mut self, _data: &Bytes) -> Result<()> {
        Ok(())
    }

    /// send_text sends the text message to the DataChannel peer
    pub fn send_text(&mut self, _s: impl Into<String>) -> Result<()> {
        Ok(())
    }
}
