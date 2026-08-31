/// RTP header extension capability.
///
/// Defines an RFC 5285 RTP header extension supported by a codec.
///
/// ## Specifications
///
/// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpcapabilities-headerextensions)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpHeaderExtensionCapability {
    /// URI identifying the header extension
    pub uri: String,
}
