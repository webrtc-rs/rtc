/// RTP header extension capability.
///
/// Defines an RFC 5285 RTP header extension supported by a codec.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#dom-rtcrtpcapabilities-headerextensions)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpHeaderExtensionCapability {
    /// URI identifying the header extension
    pub uri: String,
}
