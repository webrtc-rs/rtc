use crate::rtp_transceiver::{RtpStreamId, SSRC};

/// RTP coding parameters providing information for encoding and decoding.
///
/// This is a subset of the ORTC specification since this implementation
/// doesn't perform encoding/decoding directly.
///
/// ## Specifications
///
/// * [ORTC](http://draft.ortc.org/#dom-rtcrtpcodingparameters)
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
/// ## Specifications
///
/// * [ORTC](https://draft.ortc.org/#dom-rtcrtprtxparameters)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpRtxParameters {
    /// SSRC for the RTX stream
    pub ssrc: SSRC,
}

/// FEC parameters for forward error correction streams.
///
/// ## Specifications
///
/// * [ORTC](https://draft.ortc.org/#dom-rtcrtpfecparameters)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpFecParameters {
    /// SSRC for the FEC stream
    pub ssrc: SSRC,
}
