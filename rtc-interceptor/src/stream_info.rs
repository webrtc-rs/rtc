//! Stream information types for interceptor binding.
//!
//! This module provides types that describe media streams for interceptor binding.
//! When a stream is bound to an interceptor chain, [`StreamInfo`] provides all the
//! necessary metadata about the stream's codec, SSRC, and supported features.
//!
//! # Stream Binding
//!
//! Interceptors need to know about streams before they can process packets:
//!
//! - **Local streams** (outgoing): Bind with [`Interceptor::bind_local_stream`]
//! - **Remote streams** (incoming): Bind with [`Interceptor::bind_remote_stream`]
//!
//! # Feature Detection
//!
//! Interceptors use [`StreamInfo`] to detect which features are supported:
//!
//! - **NACK support**: Check [`rtcp_feedback`](StreamInfo::rtcp_feedback) for `type: "nack"`
//! - **TWCC support**: Check [`rtp_header_extensions`](StreamInfo::rtp_header_extensions) for the TWCC URI
//! - **RTX support**: Check if [`ssrc_rtx`](StreamInfo::ssrc_rtx) and [`payload_type_rtx`](StreamInfo::payload_type_rtx) are set

/// RTP header extension as negotiated via SDP (RFC 5285).
///
/// Represents a header extension that can be used to add metadata to RTP packets,
/// such as audio levels, video orientation, or custom application data.
///
/// # Common Extension URIs
///
/// | URI | Description |
/// |-----|-------------|
/// | `urn:ietf:params:rtp-hdrext:ssrc-audio-level` | Audio level indication |
/// | `urn:ietf:params:rtp-hdrext:toffset` | Transmission time offset |
/// | `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time` | Absolute send time |
/// | `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01` | TWCC sequence number |
#[derive(Default, Debug, Clone)]
pub struct RTPHeaderExtension {
    /// URI identifying the extension type (e.g., "urn:ietf:params:rtp-hdrext:ssrc-audio-level")
    pub uri: String,
    /// Local identifier (1-14 for one-byte, 1-255 for two-byte) used in RTP packets to reference this extension
    pub id: u16,
}

/// RTCP feedback mechanism negotiated for the stream.
///
/// Specifies additional RTCP packet types that can be used for feedback
/// between peers, such as NACK for retransmissions or PLI for picture loss.
///
/// # Common Feedback Types
///
/// | Type | Parameter | Description | RFC |
/// |------|-----------|-------------|-----|
/// | `nack` | (empty) | Generic NACK for retransmission | RFC 4585 |
/// | `nack` | `pli` | Picture Loss Indication | RFC 4585 |
/// | `nack` | `fir` | Full Intra Request | RFC 5104 |
/// | `ccm` | `fir` | Codec Control Message: FIR | RFC 5104 |
/// | `goog-remb` | (empty) | Google REMB for bandwidth estimation | - |
/// | `transport-cc` | (empty) | Transport-wide CC feedback | draft-holmer |
///
/// See: <https://draft.ortc.org/#dom-rtcrtcpfeedback>
#[derive(Default, Debug, Clone)]
pub struct RTCPFeedback {
    /// Type of feedback mechanism.
    ///
    /// Valid values: "ack", "ccm", "nack", "goog-remb", "transport-cc"
    ///
    /// See: <https://draft.ortc.org/#dom-rtcrtcpfeedback>
    pub typ: String,

    /// Parameter value that depends on the feedback type.
    ///
    /// For example, `typ="nack"` with `parameter="pli"` enables Picture Loss Indicator packets.
    /// An empty string indicates the base feedback type without additional parameters.
    pub parameter: String,
}

/// Stream context passed to interceptor bind/unbind callbacks.
///
/// Contains all relevant information about a media stream (audio or video)
/// when it's bound to or unbound from an interceptor. This includes codec
/// parameters, SSRC, RTP extensions, and RTCP feedback mechanisms.
///
/// Used by [`Interceptor::bind_local_stream`](crate::Interceptor::bind_local_stream),
/// [`Interceptor::unbind_local_stream`](crate::Interceptor::unbind_local_stream),
/// [`Interceptor::bind_remote_stream`](crate::Interceptor::bind_remote_stream), and
/// [`Interceptor::unbind_remote_stream`](crate::Interceptor::unbind_remote_stream).
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{StreamInfo, RTCPFeedback, RTPHeaderExtension};
///
/// let info = StreamInfo {
///     ssrc: 0x12345678,
///     clock_rate: 90000,
///     mime_type: "video/VP8".to_string(),
///     payload_type: 96,
///     // Enable NACK for retransmission
///     rtcp_feedback: vec![RTCPFeedback {
///         typ: "nack".to_string(),
///         parameter: String::new(),
///     }],
///     ..Default::default()
/// };
/// ```
#[derive(Default, Debug, Clone)]
pub struct StreamInfo {
    /// Synchronization Source identifier (SSRC) of the stream.
    ///
    /// Uniquely identifies the source of an RTP stream within an RTP session.
    pub ssrc: u32,

    /// RTX (Retransmission) SSRC for RFC 4588 retransmission.
    ///
    /// When set, retransmissions will use this separate SSRC instead of the
    /// original stream's SSRC. This allows the receiver to distinguish between
    /// original and retransmitted packets.
    pub ssrc_rtx: Option<u32>,

    /// FEC (Forward Error Correction) SSRC.
    ///
    /// SSRC used for FEC packets if separate-stream FEC is configured.
    pub ssrc_fec: Option<u32>,

    /// RTP payload type (e.g., 96 for VP8, 111 for Opus).
    ///
    /// Dynamic payload types (96-127) are typically used for modern codecs.
    pub payload_type: u8,

    /// RTX payload type for RFC 4588 retransmission.
    ///
    /// When set along with `ssrc_rtx`, retransmitted packets will use this
    /// payload type to distinguish them from original packets.
    pub payload_type_rtx: Option<u8>,

    /// FEC payload type.
    ///
    /// Payload type used for FEC packets if configured.
    pub payload_type_fec: Option<u8>,

    /// Negotiated RTP header extensions for this stream.
    ///
    /// Contains the list of header extensions that can be used with this stream,
    /// such as TWCC sequence numbers, audio levels, or video orientation.
    pub rtp_header_extensions: Vec<RTPHeaderExtension>,

    /// MIME type of the codec (e.g., "video/VP8", "audio/opus").
    pub mime_type: String,

    /// Clock rate in Hz (e.g., 90000 for video, 48000 for Opus audio).
    ///
    /// Used to convert between RTP timestamps and wall-clock time.
    pub clock_rate: u32,

    /// Number of audio channels (0 for video, 1 for mono, 2 for stereo).
    pub channels: u16,

    /// Format-specific parameters from SDP (fmtp line).
    ///
    /// Contains codec-specific parameters like "profile-level-id" for H.264
    /// or "minptime" for audio codecs.
    pub sdp_fmtp_line: String,

    /// RTCP feedback mechanisms negotiated for this stream.
    ///
    /// Specifies which RTCP feedback types (NACK, PLI, REMB, etc.) are
    /// supported for this stream.
    pub rtcp_feedback: Vec<RTCPFeedback>,
}
