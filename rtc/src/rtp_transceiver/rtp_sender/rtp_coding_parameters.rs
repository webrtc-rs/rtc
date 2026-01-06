use crate::rtp_transceiver::{RtpStreamId, SSRC};

/// RTP coding parameters providing information for encoding and decoding.
///
/// Contains the RTP-level parameters that identify and configure a specific
/// encoding or decoding of a media stream. This includes the SSRC, optional
/// RID for simulcast identification, and parameters for retransmission (RTX)
/// and forward error correction (FEC).
///
/// # Fields
///
/// * `rid` - RTP stream identifier, used in simulcast to identify quality layers (e.g., "q", "h", "f")
/// * `ssrc` - Synchronization source identifier, uniquely identifies this RTP stream
/// * `rtx` - Optional retransmission parameters for packet loss recovery
/// * `fec` - Optional forward error correction parameters
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpCodingParameters;
///
/// // Basic parameters without retransmission or FEC
/// let params = RTCRtpCodingParameters {
///     rid: "".to_string(),
///     ssrc: Some(12345),
///     rtx: None,
///     fec: None,
/// };
/// ```
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpRtxParameters};
///
/// // Simulcast layer with retransmission
/// let params = RTCRtpCodingParameters {
///     rid: "h".to_string(),  // half resolution layer
///     ssrc: Some(12345),
///     rtx: Some(RTCRtpRtxParameters {
///         ssrc: 12346,  // RTX uses different SSRC
///     }),
///     fec: None,
/// };
/// ```
///
/// # Specifications
///
/// * [ORTC RTCRtpCodingParameters](http://draft.ortc.org/#dom-rtcrtpcodingparameters)
/// * [RFC 4588 - RTP Retransmission Payload Format](https://www.rfc-editor.org/rfc/rfc4588.html)
/// * [RFC 8852 - RTP Stream Identifier](https://www.rfc-editor.org/rfc/rfc8852.html)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCodingParameters {
    /// RTP stream identifier for simulcast/layered streams
    pub rid: RtpStreamId,

    /// Synchronization source identifier
    pub ssrc: Option<SSRC>,
    /// RTX (retransmission) parameters
    pub rtx: Option<RTCRtpRtxParameters>,
    /// FEC (forward error correction) parameters
    pub fec: Option<RTCRtpFecParameters>,
}

/// RTX parameters for retransmission streams.
///
/// Configures a separate RTP stream used for retransmitting lost packets.
/// The RTX stream uses its own SSRC to avoid interfering with the original
/// media stream.
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpRtxParameters;
///
/// let rtx = RTCRtpRtxParameters {
///     ssrc: 67890,  // Different from the main stream's SSRC
/// };
/// ```
///
/// # Specifications
///
/// * [ORTC RTCRtpRtxParameters](https://draft.ortc.org/#dom-rtcrtprtxparameters)
/// * [RFC 4588 - RTP Retransmission Payload Format](https://www.rfc-editor.org/rfc/rfc4588.html)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpRtxParameters {
    /// SSRC for the RTX stream
    pub ssrc: SSRC,
}

/// FEC parameters for forward error correction streams.
///
/// Configures a separate RTP stream used for forward error correction,
/// allowing receivers to recover from packet loss without retransmission.
/// The FEC stream uses its own SSRC.
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpFecParameters;
///
/// let fec = RTCRtpFecParameters {
///     ssrc: 99999,  // Different from the main stream's SSRC
/// };
/// ```
///
/// # Specifications
///
/// * [ORTC RTCRtpFecParameters](https://draft.ortc.org/#dom-rtcrtpfecparameters)
/// * [RFC 5109 - RTP Payload Format for Generic FEC](https://www.rfc-editor.org/rfc/rfc5109.html)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpFecParameters {
    /// SSRC for the FEC stream
    pub ssrc: SSRC,
}
