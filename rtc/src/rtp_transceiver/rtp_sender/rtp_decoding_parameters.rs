use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

/// RTP decoding parameters for a single encoding in a simulcast or layered stream.
///
/// Contains both the codec configuration and RTP-level parameters (SSRC, RID, etc.)
/// for receiving and decoding a specific spatial/temporal layer of a media stream.
///
/// In simulcast scenarios, a single track may have multiple `RTCRtpDecodingParameters`,
/// each representing a different quality level or layer. Each encoding has its own
/// SSRC and optionally a RID (RTP stream identifier) like "q", "h", or "f" for
/// quarter/half/full resolution.
///
/// # Fields
///
/// * `rtp_coding_parameters` - Contains SSRC, RID, and redundancy settings
/// * `codec` - The RTP codec configuration (MIME type, clock rate, etc.)
///
/// # Examples
///
/// ## Single encoding (non-simulcast)
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpDecodingParameters, RTCRtpCodingParameters};
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpCodec;
///
/// let params = RTCRtpDecodingParameters {
///     rtp_coding_parameters: RTCRtpCodingParameters {
///         ssrc: Some(12345),
///         ..Default::default()
///     },
///     codec: RTCRtpCodec {
///         mime_type: "video/VP8".to_string(),
///         clock_rate: 90000,
///         ..Default::default()
///     },
/// };
/// ```
///
/// ## Simulcast with multiple layers
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpDecodingParameters, RTCRtpCodingParameters};
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpCodec;
///
/// // Three spatial layers for simulcast
/// let layers = vec![
///     RTCRtpDecodingParameters {
///         rtp_coding_parameters: RTCRtpCodingParameters {
///             rid: "q".to_string(),  // quarter resolution
///             ssrc: Some(100),
///             ..Default::default()
///         },
///         codec: RTCRtpCodec {
///             mime_type: "video/VP8".to_string(),
///             clock_rate: 90000,
///             ..Default::default()
///         },
///     },
///     RTCRtpDecodingParameters {
///         rtp_coding_parameters: RTCRtpCodingParameters {
///             rid: "h".to_string(),  // half resolution
///             ssrc: Some(200),
///             ..Default::default()
///         },
///         codec: RTCRtpCodec {
///             mime_type: "video/VP8".to_string(),
///             clock_rate: 90000,
///             ..Default::default()
///         },
///     },
///     RTCRtpDecodingParameters {
///         rtp_coding_parameters: RTCRtpCodingParameters {
///             rid: "f".to_string(),  // full resolution
///             ssrc: Some(300),
///             ..Default::default()
///         },
///         codec: RTCRtpCodec {
///             mime_type: "video/VP8".to_string(),
///             clock_rate: 90000,
///             ..Default::default()
///         },
///     },
/// ];
/// ```
///
/// # Specifications
///
/// * [ORTC RTCRtpDecodingParameters](http://draft.ortc.org/#dom-rtcrtpdecodingparameters)
/// * [RFC 8851 - RTP Payload Format Restrictions](https://www.rfc-editor.org/rfc/rfc8851.html)
/// * [RFC 8852 - RTP Stream Identifier Source Description (SDES)](https://www.rfc-editor.org/rfc/rfc8852.html)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpDecodingParameters {
    /// Base coding parameters (RID, SSRC, RTX, FEC)
    pub rtp_coding_parameters: RTCRtpCodingParameters,
    /// Codec to use for this encoding
    pub codec: RTCRtpCodec,
}
