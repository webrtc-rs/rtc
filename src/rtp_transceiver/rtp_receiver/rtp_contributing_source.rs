use std::time::Duration;

/// Information about a contributing source (CSRC) or synchronization source (SSRC).
///
/// The `RTCRtpContributingSource` and `RTCRtpSynchronizationSource` dictionaries contain
/// information about a given contributing source (CSRC) or synchronization source (SSRC)
/// respectively. These sources are identified by their source identifiers and are used
/// in the RTP header to identify the sources of the media in an RTP stream.
///
/// # W3C Specification
/// Corresponds to the `RTCRtpContributingSource` dictionary in the
/// [WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource).
#[derive(Default, Debug, Clone)]
pub struct RTCRtpContributingSource {
    /// The timestamp indicating the most recent time a frame originating from this source
    /// was delivered to the receiver. The timestamp is relative to the system clock.
    ///
    /// # W3C Specification
    /// Corresponds to the `timestamp` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-timestamp).
    pub timestamp: Duration,

    /// The CSRC or SSRC identifier of the contributing or synchronization source.
    ///
    /// # W3C Specification
    /// Corresponds to the `source` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-source).
    pub source: u32,

    /// The audio level of the contributing source, ranging from 0 to 1.
    /// A value of 0 indicates silence, and 1 indicates the maximum audio level.
    ///
    /// # W3C Specification
    /// Corresponds to the `audioLevel` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-audiolevel).
    pub audio_level: f64,

    /// The RTP timestamp of the media. This is the timestamp at which the media was sampled,
    /// as defined in RFC 3550 section 5.1.
    ///
    /// # W3C Specification
    /// Corresponds to the `rtpTimestamp` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-rtptimestamp).
    pub rtp_timestamp: u32,
}

/// Synchronization source information.
///
/// This is a type alias for `RTCRtpContributingSource` because both CSRC and SSRC
/// share the same structure and attributes.
///
/// # W3C Specification
/// Corresponds to the `RTCRtpSynchronizationSource` dictionary in the
/// [WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpsynchronizationsource).
pub type RTCRtpSynchronizationSource = RTCRtpContributingSource;
