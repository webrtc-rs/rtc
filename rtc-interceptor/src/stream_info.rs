use std::collections::HashMap;

/// Generic key/value store used by interceptors to attach metadata to streams.
///
/// Interceptors can use attributes to store arbitrary data associated with
/// a stream. Both keys and values are `usize`, allowing interceptors to use
/// type IDs or custom identifiers as keys.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::stream_info::Attributes;
///
/// let mut attributes = Attributes::new();
/// attributes.insert(1, 42); // Store some metadata with key 1
/// ```
pub type Attributes = HashMap<usize, usize>;

/// RTP header extension as negotiated via SDP (RFC 5285).
///
/// Represents a header extension that can be used to add metadata to RTP packets,
/// such as audio levels, video orientation, or custom application data.
#[derive(Default, Debug, Clone)]
pub struct RTPHeaderExtension {
    /// URI identifying the extension type (e.g., "urn:ietf:params:rtp-hdrext:ssrc-audio-level")
    pub uri: String,
    /// Local identifier (1-14) used in RTP packets to reference this extension
    pub id: u16,
}

/// Association between an auxiliary stream and its primary stream.
///
/// Used for streams like RTX (retransmission), FEC (forward error correction),
/// or RED (redundant encoding) that are associated with a primary media stream.
#[derive(Default, Debug, Clone)]
pub struct AssociatedStreamInfo {
    /// SSRC of the associated auxiliary stream
    pub ssrc: u32,
    /// Payload type of the associated stream
    pub payload_type: u8,
}

/// RTCP feedback mechanism negotiated for the stream.
///
/// Specifies additional RTCP packet types that can be used for feedback
/// between peers, such as NACK for retransmissions or PLI for picture loss.
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
    pub parameter: String,
}

/// Stream context passed to interceptor bind/unbind callbacks.
///
/// Contains all relevant information about a media stream (audio or video)
/// when it's bound to or unbound from an interceptor. This includes codec
/// parameters, SSRC, RTP extensions, and RTCP feedback mechanisms.
///
/// Used by `Interceptor::bind_local_stream()`, `Interceptor::unbind_local_stream()`,
/// `Interceptor::bind_remote_stream()`, and `Interceptor::unbind_remote_stream()`.
#[derive(Default, Debug, Clone)]
pub struct StreamInfo {
    /// Unique identifier for the stream
    pub id: String,
    /// Arbitrary metadata attached by interceptors
    pub attributes: Attributes,
    /// Synchronization Source identifier (SSRC) of the stream
    pub ssrc: u32,
    /// RTP payload type (e.g., 96 for VP8, 111 for Opus)
    pub payload_type: u8,
    /// Negotiated RTP header extensions for this stream
    pub rtp_header_extensions: Vec<RTPHeaderExtension>,
    /// MIME type of the codec (e.g., "video/VP8", "audio/opus")
    pub mime_type: String,
    /// Clock rate in Hz (e.g., 90000 for video, 48000 for audio)
    pub clock_rate: u32,
    /// Number of audio channels (0 for video)
    pub channels: u16,
    /// Format-specific parameters from SDP (fmtp line)
    pub sdp_fmtp_line: String,
    /// RTCP feedback mechanisms negotiated for this stream
    pub rtcp_feedback: Vec<RTCPFeedback>,
    /// Optional association to a related stream (RTX, FEC, etc.)
    pub associated_stream: Option<AssociatedStreamInfo>,
}
