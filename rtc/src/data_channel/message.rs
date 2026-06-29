use bytes::BytesMut;

/// RTCDataChannelMessage represents a message received from the
/// data channel. IsString will be set to true if the incoming
/// message is of the string type. Otherwise, the message is of
/// a binary type.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct RTCDataChannelMessage {
    /// Whether the message is a text message (UTF-8 encoded string).
    pub is_string: bool,
    /// The payload data of the message.
    pub data: BytesMut,
}
