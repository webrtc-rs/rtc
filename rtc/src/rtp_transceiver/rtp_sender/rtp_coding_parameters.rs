use crate::rtp_transceiver::SSRC;

/// RTPCodingParameters provides information relating to both encoding and decoding.
/// This is a subset of the RFC since Pion WebRTC doesn't implement encoding/decoding itself
/// <http://draft.ortc.org/#dom-rtcrtpcodingparameters>
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCodingParameters {
    pub rid: String,

    pub ssrc: Option<SSRC>,
    pub rtx: Option<RTCRtpRtxParameters>,
}

/// RTPRtxParameters dictionary contains information relating to retransmission (RTX) settings.
/// <https://draft.ortc.org/#dom-rtcrtprtxparameters>
#[derive(Default, Debug, Clone)]
pub struct RTCRtpRtxParameters {
    pub ssrc: SSRC,
}
