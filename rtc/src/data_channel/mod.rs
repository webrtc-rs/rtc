use crate::data_channel::state::RTCDataChannelState;

pub(crate) mod event;
pub(crate) mod init;
pub(crate) mod state;

#[derive(Default, Clone)]
pub struct RTCDataChannelId;

#[derive(Default, Clone)]
pub enum BinaryType {
    #[default]
    String,
    Blob,
    ArrayBuffer,
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
#[derive(Default, Clone)]
pub struct RTCDataChannel {
    label: String,
    ordered: bool,
    max_packet_lifetime: Option<u16>,
    max_retransmits: Option<u16>,
    protocol: String,
    negotiated: bool,
    id: RTCDataChannelId,
    ready_state: RTCDataChannelState,
    buffered_amount_low_threshold: usize,
    binary_type: BinaryType,
}
