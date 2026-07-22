/// Negotiated RTP header extension parameters.
///
/// Represents an RFC 5285 RTP header extension that has been negotiated
/// between sender and receiver.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#dictionary-rtcrtpheaderextensionparameters-members)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpHeaderExtensionParameters {
    /// URI identifying the header extension
    pub uri: String,
    /// Local identifier for this extension (1-14 for one-byte, 1-255 for two-byte)
    pub id: u16,
    /// Whether this extension should be encrypted
    pub encrypted: bool,
}
